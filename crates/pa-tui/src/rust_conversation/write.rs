//! Explicit Conversation mutations; no implicit retry, Run query, or streaming claim.
use super::*;
use crate::generated::rust_conversation_write as write_contract;
use std::path::Path;

struct ProtectedTurn(write_contract::SubmitTurnRequest);

impl Drop for ProtectedTurn {
    fn drop(&mut self) {
        self.0.text.zeroize();
        self.0.idempotency_key.zeroize();
    }
}

/// Only the chosen bounded regular file is message input. Never an ambient path or stdin.
#[cfg(unix)]
fn text_file(path: &Path) -> Result<Zeroizing<String>, ReadError> {
    use rustix::fs::{fstat, open, FileType, Mode, OFlags};
    use std::io::Read;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ReadError::InvalidTextFile)?;
    let stat = fstat(&fd).map_err(|_| ReadError::InvalidTextFile)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(ReadError::InvalidTextFile);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::from(fd)
        .take(write_contract::MAX_TEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadError::InvalidTextFile)?;
    if bytes.is_empty() || bytes.len() > write_contract::MAX_TEXT_BYTES {
        return Err(ReadError::InvalidTextFile);
    }
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| ReadError::InvalidTextFile)?
            .to_owned(),
    ))
}

#[cfg(not(unix))]
fn text_file(_: &Path) -> Result<Zeroizing<String>, ReadError> {
    Err(ReadError::UnsupportedSessionHandoff)
}

// A POST can have committed even if its response was lost, truncated, malformed or too
// large. Never turn a transport failure into "nothing happened" or retry it implicitly.
async fn receipt(
    request: reqwest::RequestBuilder,
    expected_status: u16,
) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let response = request
        .send()
        .await
        .map_err(|_| ReadError::CommitUnconfirmed)?;
    match response.status().as_u16() {
        401 => return Err(ReadError::AuthenticationRequired),
        403 | 404 => return Err(ReadError::NotAuthorized),
        409 => return Err(ReadError::Conflict),
        400 | 413 | 415 | 422 => return Err(ReadError::InvalidSelector),
        status if status == expected_status => {}
        _ => return Err(ReadError::CommitUnconfirmed),
    }
    let json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
        });
    let no_store = response
        .headers()
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("no-store"))
        });
    const MAX_RECEIPT_BYTES: usize = 8192;
    if !json
        || !no_store
        || response
            .content_length()
            .is_some_and(|v| v > MAX_RECEIPT_BYTES as u64)
    {
        return Err(ReadError::CommitUnconfirmed);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ReadError::CommitUnconfirmed)?;
        if chunk.len() > MAX_RECEIPT_BYTES - bytes.len() {
            return Err(ReadError::CommitUnconfirmed);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn created(bytes: &[u8]) -> Result<write_contract::CreateConversationResponse, ReadError> {
    let value: write_contract::CreateConversationResponse =
        serde_json::from_slice(bytes).map_err(|_| ReadError::CommitUnconfirmed)?;
    value
        .validate()
        .map_err(|()| ReadError::CommitUnconfirmed)?;
    Ok(value)
}

fn admitted(
    bytes: &[u8],
    expected_turn: i64,
) -> Result<write_contract::SubmitTurnResponse, ReadError> {
    let value: write_contract::SubmitTurnResponse =
        serde_json::from_slice(bytes).map_err(|_| ReadError::CommitUnconfirmed)?;
    value
        .validate()
        .map_err(|()| ReadError::CommitUnconfirmed)?;
    if let write_contract::SubmitTurnResponse::Variant1(started) = &value {
        if started.replayed != started.turn_sequence.is_absent() {
            return Err(ReadError::CommitUnconfirmed);
        }
        if let write_contract::Optional::Value(turn) = started.turn_sequence {
            if expected_turn.checked_add(1) != Some(turn) {
                return Err(ReadError::CommitUnconfirmed);
            }
        }
    }
    Ok(value)
}

fn output(value: &impl serde::Serialize, note: &str) -> Result<(), ReadError> {
    // Generated receipts contain only IDs/positions. JSON escaping also prevents any
    // response string from injecting terminal controls. Input text is never echoed.
    let mut rendered = Zeroizing::new(serde_json::to_vec(value).map_err(|_| ReadError::Output)?);
    rendered.push(b'\n');
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&rendered)
        .and_then(|()| stdout.flush())
        .map_err(|_| ReadError::Output)?;
    eprintln!("{note}");
    Ok(())
}

/// Create exactly one Conversation. Lost acknowledgements require investigation, not retry.
pub async fn create_from_stdin(
    server: String,
    main: bool,
    allow_loopback_http: bool,
) -> Result<(), ReadError> {
    let origin = origin(&server, allow_loopback_http)?;
    let body = write_contract::CreateConversationRequest {
        main: write_contract::Optional::Value(main),
    };
    body.validate().map_err(|()| ReadError::InvalidSelector)?;
    let client = Client::new(origin, session_from_stdin().await?)?;
    let request = write_contract::create_conversation(
        &client.http,
        &client.origin,
        &body,
        client.session.header_for(write_contract::SESSION_COOKIE)?,
    )
    .map_err(|()| ReadError::InvalidSelector)?;
    let value = created(&receipt(request, write_contract::CREATE_CONVERSATION_STATUS).await?)?;
    output(&value, "Conversation created. No Run was started.")
}

/// Admit exactly the selected Human text under a stable key and expected head. This
/// neither reads a Run nor assumes a Run.read Grant from Conversation ownership.
pub async fn submit_from_stdin(
    server: String,
    branch: String,
    expected_turn: i64,
    idempotency_key: String,
    text_path: std::path::PathBuf,
    allow_loopback_http: bool,
) -> Result<(), ReadError> {
    let origin = origin(&server, allow_loopback_http)?;
    if !contract::canonical_uuid(&branch) {
        return Err(ReadError::InvalidSelector);
    }
    let text = text_file(&text_path)?;
    let body = ProtectedTurn(write_contract::SubmitTurnRequest {
        expected_turn,
        idempotency_key,
        // §11.1 mentions are optional; this command submits plain text.
        mentions: write_contract::Optional::Absent,
        text: text.to_string(),
    });
    body.0.validate().map_err(|()| ReadError::InvalidSelector)?;
    let client = Client::new(origin, session_from_stdin().await?)?;
    let request = write_contract::submit_turn(
        &client.http,
        &client.origin,
        &branch,
        &body.0,
        client.session.header_for(write_contract::SESSION_COOKIE)?,
    )
    .map_err(|()| ReadError::InvalidSelector)?;
    let value = admitted(
        &receipt(request, write_contract::SUBMIT_TURN_STATUS).await?,
        expected_turn,
    )?;
    output(
        &value,
        "Turn accepted or queued only. Run status and Run read authority are not determined.",
    )
}

#[cfg(test)]
#[path = "write_tests.rs"]
mod tests;
