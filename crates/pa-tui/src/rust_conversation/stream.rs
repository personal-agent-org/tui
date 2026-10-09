//! The Run delivery stream this client can actually resume (§19.3).
//!
//! The instance serves `GET /v1/runs/{run_id}/stream` LIVE (`x-pa-stream.mode: live`): one
//! connection stays open, frames are pushed as they commit, a keep-alive comment arrives
//! after 15 s without a frame, and the connection ends behind the terminal frame or behind
//! one id-less `cursor` marker (`response_bound`, `reauthenticate`, `slow_consumer`,
//! `unavailable`, or `resume_expired` on a gap). So there is no total timeout here: a quiet
//! Run is not a failed request. What bounds a connection is [`IDLE_TIMEOUT`] between bytes —
//! three heartbeats — and every frame is printed the moment it is applied.
//!
//! `Last-Event-ID` resumes strictly after the last frame this reducer durably applied, not
//! after the last bytes read: an unterminated final frame is not dispatched, and a marker
//! never advances the cursor. Only an applied terminal frame is a finished Run. A connection
//! that ends without one is resumed from the cursor; a body that closes with nothing new —
//! what an older, finite-batch instance answers once caught up — ends the invocation as
//! `Disconnected`, never as success and never as an inferred cancellation.

use super::*;
use reqwest::header::{ACCEPT, COOKIE};
use std::io::Write;
use std::time::Duration;

/// Local ceiling on one frame, not a server-negotiated permission to send larger ones.
const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Local ceiling on one response, matching the instance's per-response frame bound.
const MAX_FRAMES_PER_RESPONSE: usize = 257;
/// How many connections in a row may end behind a marker having applied nothing before
/// this invocation reports where it got to.
const MAX_RESUMES: u32 = 16;

/// One dispatched server-sent event.
#[derive(Default)]
struct Frame {
    id: Option<String>,
    event: Option<String>,
    data: Option<String>,
}

/// Bounded SSE framing. UTF-8 is decoded at a line boundary, never at a network chunk
/// boundary, and EOF is deliberately not an event boundary.
#[derive(Default)]
struct Decoder {
    line: Vec<u8>,
    frame: Frame,
    frame_bytes: usize,
    after_cr: bool,
    first_line_read: bool,
}

impl Decoder {
    fn push(&mut self, byte: u8) -> Result<Option<Frame>, ReadError> {
        // CR, LF and CRLF are each one line ending, even across network chunks.
        if std::mem::replace(&mut self.after_cr, false) && byte == b'\n' {
            return Ok(None);
        }
        if self.frame_bytes == MAX_FRAME_BYTES {
            return Err(ReadError::InvalidFrame);
        }
        self.frame_bytes += 1;
        match byte {
            b'\r' | b'\n' => {
                self.after_cr = byte == b'\r';
                self.end_line()
            }
            _ => {
                self.line.push(byte);
                Ok(None)
            }
        }
    }

    fn end_line(&mut self) -> Result<Option<Frame>, ReadError> {
        let line = std::str::from_utf8(&self.line).map_err(|_| ReadError::InvalidFrame)?;
        let first = !std::mem::replace(&mut self.first_line_read, true);
        let line = if first {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        let dispatched = if line.is_empty() {
            self.frame_bytes = 0;
            // The id buffer is not carried into the next event: a frame without its own id
            // must not inherit one, or an acknowledged cursor would cover an unapplied frame.
            (self.frame.data.is_some()).then(|| std::mem::take(&mut self.frame))
        } else {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value).to_owned();
            match field {
                "id" => self.frame.id = Some(value),
                "event" => self.frame.event = Some(value),
                "data" => match &mut self.frame.data {
                    Some(data) => {
                        data.push('\n');
                        data.push_str(&value);
                    }
                    None => self.frame.data = Some(value),
                },
                // `retry` and comments are framing metadata this client does not act on.
                _ => {}
            }
            None
        };
        self.line.clear();
        Ok(dispatched)
    }
}

/// What one connection did to the reducer's cursor, and how it ended.
struct Applied {
    frames: usize,
    cursor: i64,
    /// The `cursor` marker's reason, when the connection ended behind one (never an expiry).
    marker: Option<String>,
    /// How the Run ended, once its terminal frame was applied.
    terminal: Option<String>,
}

impl Applied {
    fn at(cursor: i64) -> Self {
        Self {
            frames: 0,
            cursor,
            marker: None,
            terminal: None,
        }
    }
}

/// How long a live connection may go without a single byte, heartbeats included.
///
/// Three of the instance's 15 s heartbeats: long enough that one late heartbeat is not a lost
/// connection, short enough that a connection a proxy silently dropped is noticed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// How long the instance may take to answer with its response head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// The wait before a reconnect that should not be immediate: 1 s, 2 s, then 5 s.
const BACKOFF: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
];
/// A marker that ended a connection this soon, having carried nothing, is reconnected with
/// backoff: an instance answering `reauthenticate` at once must not become a request storm.
const BRIEF_CONNECTION: Duration = Duration::from_secs(1);
/// How many transport failures in a row (an unanswered request, a body that broke off, or
/// [`IDLE_TIMEOUT`] of silence) are ridden out before reporting one.
const MAX_TRANSPORT_FAILURES: u32 = 3;

/// The follow loop's clock, separate so tests can run it in milliseconds.
struct Pace {
    idle: Duration,
    head: Duration,
    backoff: [Duration; 3],
    brief: Duration,
}

const LIVE: Pace = Pace {
    idle: IDLE_TIMEOUT,
    head: HEAD_TIMEOUT,
    backoff: BACKOFF,
    brief: BRIEF_CONNECTION,
};

/// How a follow ended without an error.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// The terminal frame was applied, naming how the Run ended.
    Terminal(String),
    /// The stream went quiet without one; the outcome is not determined.
    Disconnected,
}

/// Follows one Run's delivery stream, resuming from the last frame it durably applied.
///
/// The stream endpoint is derived from the instance's verified endpoint set, never typed:
/// §19.2 forbids a client persisting or guessing a stream URL of its own.
pub async fn follow(
    server: String,
    run: String,
    after: Option<i64>,
    allow_loopback_http: bool,
) -> Result<(), ReadError> {
    let origin = origin(&server, allow_loopback_http)?;
    if !contract::canonical_uuid(&run) {
        return Err(ReadError::InvalidSelector);
    }
    let cursor = after.unwrap_or(0);
    if cursor < 0 {
        return Err(ReadError::InvalidSelector);
    }
    let (session, trust) = session::verified_session(&origin).await?;
    let url = trust.run_stream.replace("{run_id}", &run);
    // The substitution may not leave the pinned origin or smuggle a second path segment.
    if !url.starts_with(&format!("{}/", trust.canonical_origin)) || url.contains('{') {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let http = stream_client()?;
    let mut output = std::io::stdout().lock();
    run_follow(&http, &url, &session, cursor, &mut output, &LIVE)
        .await
        .map(|_| ())
}

/// The HTTP client for a live stream: a bounded connect, and NO total timeout.
///
/// A total timeout is what made a quiet live Run look like a transport error: the response
/// is supposed to stay open for minutes. Liveness is judged between bytes instead, by
/// [`Pace::idle`] in [`once`].
fn stream_client() -> Result<reqwest::Client, ReadError> {
    pa_oidc::tls::http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .connect_timeout(HEAD_TIMEOUT)
        .build()
        .map_err(|_| ReadError::Transport)
}

/// The follow loop over a verified endpoint: connect, render, and reconnect until it ends.
async fn run_follow(
    http: &reqwest::Client,
    url: &str,
    session: &SessionToken,
    mut cursor: i64,
    output: &mut impl Write,
    pace: &Pace,
) -> Result<Ended, ReadError> {
    writeln!(output, "Run delivery · resuming after {cursor}").map_err(|_| ReadError::Output)?;
    output.flush().map_err(|_| ReadError::Output)?;
    // Connections in a row that applied nothing, and transport failures in a row.
    let mut barren: u32 = 0;
    let mut failures: u32 = 0;
    let ended = loop {
        let opened = std::time::Instant::now();
        let mut applied = Applied::at(cursor);
        let result = once(http, url, session, &mut applied, &mut *output, pace).await;
        // The cursor is the last frame APPLIED, and a connection that failed half-way still
        // applied what it printed: the next one resumes exactly there.
        cursor = applied.cursor;
        match result {
            Ok(()) => failures = 0,
            Err(ReadError::Transport) if failures + 1 < MAX_TRANSPORT_FAILURES => {
                failures += 1;
                tokio::time::sleep(pace.backoff[failures.min(2) as usize]).await;
                continue;
            }
            Err(error) => {
                // A transport that gave up leaves a resume point worth printing; a gap or a
                // refusal does not — resuming there would only be refused again.
                if error == ReadError::Transport {
                    writeln!(output, "\nResume with --after {cursor}")
                        .map_err(|_| ReadError::Output)?;
                }
                return Err(error);
            }
        }
        if let Some(kind) = applied.terminal {
            break Ended::Terminal(kind);
        }
        if applied.frames > 0 {
            barren = 0;
        } else {
            barren += 1;
        }
        match applied.marker.as_deref() {
            // Every marker is "reconnect with Last-Event-ID"; only the pace differs.
            // `unavailable` is the instance failing to read its own frames, and a marker that
            // ended an empty connection at once would otherwise be answered by a tight loop.
            Some(reason) => {
                let brief = applied.frames == 0 && opened.elapsed() < pace.brief;
                if reason == "unavailable" || brief {
                    let rung = (barren.max(1) - 1).min(2) as usize;
                    tokio::time::sleep(pace.backoff[rung]).await;
                }
                if barren > MAX_RESUMES {
                    break Ended::Disconnected;
                }
            }
            // The body closed with no marker. With frames, the next connection continues
            // from them (an older instance's finite batch, or a dropped live connection);
            // without, there is nothing pending for this cursor and polling would be a
            // client-side loop, not a resume.
            None if applied.frames > 0 => {}
            None => break Ended::Disconnected,
        }
    };
    match &ended {
        Ended::Terminal(kind) => {
            writeln!(output, "\nRun ended: {kind}").map_err(|_| ReadError::Output)?;
        }
        Ended::Disconnected => {
            writeln!(output, "\nResume with --after {cursor}").map_err(|_| ReadError::Output)?;
            writeln!(
                output,
                "Disconnected. No terminal frame was delivered, so this Run's outcome is not determined."
            )
            .map_err(|_| ReadError::Output)?;
        }
    }
    output.flush().map_err(|_| ReadError::Output)?;
    Ok(ended)
}

/// One connection: request, then reduce and print each frame as its bytes arrive.
async fn once(
    http: &reqwest::Client,
    url: &str,
    session: &SessionToken,
    applied: &mut Applied,
    output: &mut impl Write,
    pace: &Pace,
) -> Result<(), ReadError> {
    let mut request = http
        .get(url)
        .header(ACCEPT, "text/event-stream")
        .header(COOKIE, session.header()?)
        .header(contract::CSRF_HEADER, "1");
    if applied.cursor > 0 {
        request = request.header("last-event-id", applied.cursor.to_string());
    }
    let response = tokio::time::timeout(pace.head, request.send())
        .await
        .map_err(|_| ReadError::Transport)?
        .map_err(|_| ReadError::Transport)?;
    match response.status().as_u16() {
        200 => {}
        401 => return Err(ReadError::AuthenticationRequired),
        403 | 404 => return Err(ReadError::NotAuthorized),
        _ => return Err(ReadError::Transport),
    }
    let event_stream = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
        });
    if !event_stream {
        return Err(ReadError::InvalidResponse);
    }

    let mut seen = 0;
    let mut decoder = Decoder::default();
    let mut chunks = response.bytes_stream();
    // Any byte — a heartbeat comment included — is liveness. `pace.idle` without one is a
    // dead transport, reported as such so the loop resumes from the applied cursor.
    while let Some(chunk) = tokio::time::timeout(pace.idle, chunks.next())
        .await
        .map_err(|_| ReadError::Transport)?
    {
        let chunk = chunk.map_err(|_| ReadError::Transport)?;
        for byte in chunk.iter().copied() {
            let Some(frame) = decoder.push(byte)? else {
                continue;
            };
            if seen == MAX_FRAMES_PER_RESPONSE {
                return Err(ReadError::InvalidFrame);
            }
            seen += 1;
            reduce(&frame, applied, &mut *output)?;
            // The terminal frame and a marker are each the last thing a connection carries.
            if applied.terminal.is_some() || applied.marker.is_some() {
                return output.flush().map_err(|_| ReadError::Output);
            }
        }
        output.flush().map_err(|_| ReadError::Output)?;
    }
    Ok(())
}

/// Applies one frame, or records why it cannot be applied.
fn reduce(frame: &Frame, applied: &mut Applied, output: &mut impl Write) -> Result<(), ReadError> {
    let data = frame.data.as_deref().ok_or(ReadError::InvalidFrame)?;
    let payload: serde_json::Value =
        serde_json::from_str(data).map_err(|_| ReadError::InvalidFrame)?;
    let Some(id) = frame.id.as_deref() else {
        // The instance's own truncation marker: it names where to resume, and it is not a
        // frame, so it may not move the cursor by itself.
        if frame.event.as_deref() == Some("cursor") {
            let resume = payload
                .get("resume_from")
                .and_then(serde_json::Value::as_i64)
                .ok_or(ReadError::InvalidFrame)?;
            // A gap marker names a position this client never reached: the retained frames
            // no longer cover its cursor. Nothing is applied across it (§19.3); the caller
            // must re-read state instead of resuming.
            if payload.get("reason").and_then(serde_json::Value::as_str) == Some("resume_expired") {
                return Err(ReadError::ResumeExpired);
            }
            if resume != applied.cursor {
                return Err(ReadError::InvalidFrame);
            }
            // Every other reason — the bound, reauthentication, a slow consumer, an
            // unavailable read, or one this client does not know — means "reconnect from
            // here"; only the pace of the reconnect differs.
            let reason = payload
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("response_bound");
            applied.marker = Some(reason.to_owned());
            return Ok(());
        }
        return Err(ReadError::InvalidFrame);
    };
    let sequence: i64 = id.parse().map_err(|_| ReadError::InvalidFrame)?;
    // The wire id and the payload sequence are one cursor, not two.
    if payload.get("sequence").and_then(serde_json::Value::as_i64) != Some(sequence) {
        return Err(ReadError::InvalidFrame);
    }
    if sequence <= applied.cursor {
        return Err(ReadError::InvalidFrame);
    }
    let kind = payload
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or(ReadError::InvalidFrame)?;
    if frame.event.as_deref() != Some(kind) {
        return Err(ReadError::InvalidFrame);
    }
    // JSON escaping also prevents a frame kind from injecting terminal controls.
    writeln!(
        output,
        "{sequence} {}",
        serde_json::to_string(kind).map_err(|_| ReadError::Output)?
    )
    .map_err(|_| ReadError::Output)?;
    applied.cursor = sequence;
    applied.frames += 1;
    // §19.3: only a terminal frame may report a Run finished, and it is the last frame the
    // subscription carries.
    if payload.get("terminal").and_then(serde_json::Value::as_bool) == Some(true)
        || kind == "terminal"
    {
        let named = payload
            .get("terminal_kind")
            .and_then(serde_json::Value::as_str)
            .filter(|named| ["completed", "failed", "canceled", "outcome_unknown"].contains(named))
            .unwrap_or("unnamed");
        applied.terminal = Some(named.to_owned());
    }
    Ok(())
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
