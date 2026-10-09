//! Consume a run's Server-Sent-Events stream and forward decoded AG-UI events to the UI.
//!
//! `POST /chats/{id}/runs` responds with `text/event-stream`; the `X-Run-Id` header names
//! the run (so we can show/cancel it) and each SSE `data:` frame is a `BusRecord`. We tail
//! the byte stream, cut frames at line boundaries (so multibyte UTF-8 — e.g. umlauts — is
//! never split mid-character), and translate each event into a `StreamMsg`.

use std::sync::Arc;

use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc::UnboundedSender;

use crate::agui;
use crate::api::ApiClient;
use crate::app::AppMsg;

#[path = "sse/decoder.rs"]
mod decoder;

/// A decoded streaming event, ready for the app state to fold into the live message.
#[derive(Debug)]
pub enum StreamMsg {
    RunId(String),
    Text(String),
    Thinking(String),
    ToolStart {
        id: String,
        name: String,
    },
    ToolArgs {
        id: String,
        delta: String,
    },
    ToolResult {
        id: String,
        content: String,
    },
    Usage {
        model: Option<String>,
        input: i64,
        output: i64,
        cost: Option<f64>,
    },
    /// The stream dropped and is being re-attached: clear the live turn so the server's
    /// replay (Last-Event-ID 0) rebuilds it cleanly instead of duplicating the text so far.
    Reset,
    Finished,
    /// Transport failed without a terminal event. The canonical Run outcome is unknown.
    Disconnected(String),
    Error(String),
}

/// Why `consume` stopped tailing a stream.
enum Outcome {
    /// An explicit AG-UI terminal event was applied.
    Done,
    /// EOF, malformed/oversized data, or transport loss requires replay, never success.
    Transient,
}

/// Max re-attach attempts before giving up on a dropped run stream.
const MAX_RECONNECTS: u32 = 8;

fn backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis((500 * attempt as u64).min(3000))
}

/// Which streaming endpoint a turn POSTs to.
pub enum RunKind {
    New,
    Side,
    Rerun,
}

/// Start a turn (new run, `/btw` side query, or rerun): POST, then relay every event.
pub async fn stream_run(
    client: Arc<ApiClient>,
    kind: RunKind,
    chat_id: String,
    body: serde_json::Value,
    tx: UnboundedSender<AppMsg>,
) {
    let opened = match kind {
        RunKind::New => client.open_run_stream(&chat_id, &body).await,
        RunKind::Side => client.open_btw_stream(&chat_id, &body).await,
        RunKind::Rerun => client.open_rerun_stream(&chat_id, &body).await,
    };
    let resp = match opened {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(AppMsg::Stream(StreamMsg::Disconnected(format!("{e:#}"))));
            return;
        }
    };
    let run_id = resp
        .headers()
        .get("X-Run-Id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    if let Some(rid) = &run_id {
        let _ = tx.send(AppMsg::Stream(StreamMsg::RunId(rid.clone())));
    }
    // `/btw` side runs are ephemeral (not persisted) → not re-attachable; everything else is.
    let reconnect_id = match kind {
        RunKind::Side => None,
        _ => run_id,
    };
    pump(client, chat_id, reconnect_id, resp, &tx).await;
}

/// Attach to an EXISTING run's live stream (reconnect-on-open / background-resumed).
/// The run id is already known, so we announce it before replaying the stream.
pub async fn attach_run(
    client: Arc<ApiClient>,
    chat_id: String,
    run_id: String,
    tx: UnboundedSender<AppMsg>,
) {
    let _ = tx.send(AppMsg::Stream(StreamMsg::RunId(run_id.clone())));
    let resp = match client.attach_run_stream(&chat_id, &run_id).await {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(AppMsg::Stream(StreamMsg::Disconnected(format!("{e:#}"))));
            return;
        }
    };
    pump(client, chat_id, Some(run_id), resp, &tx).await;
}

/// Tail a run's stream and, when it drops mid-run, re-attach (replaying from the start so
/// the live turn is rebuilt) until it finishes or the retry budget is spent. `run_id` is
/// `None` for streams that can't be re-attached (ephemeral `/btw`), which then fail hard.
async fn pump(
    client: Arc<ApiClient>,
    chat_id: String,
    run_id: Option<String>,
    first: reqwest::Response,
    tx: &UnboundedSender<AppMsg>,
) {
    let mut resp = Some(first);
    let mut attempts: u32 = 0;
    loop {
        let replay = resp.is_none();
        // Obtain the next response: the initial one, or a fresh re-attach.
        let r = match resp.take() {
            Some(r) => r,
            None => {
                let Some(rid) = run_id.as_deref() else {
                    return;
                };
                match client.attach_run_stream(&chat_id, rid).await {
                    Ok(r) => r,
                    Err(_) => {
                        attempts += 1;
                        if attempts > MAX_RECONNECTS {
                            let _ = tx.send(AppMsg::Stream(StreamMsg::Disconnected(
                                crate::i18n::t(crate::i18n::Msg::StreamReconnectFailed),
                            )));
                            return;
                        }
                        tokio::time::sleep(backoff(attempts)).await;
                        continue;
                    }
                }
            }
        };

        match consume(r, tx, replay).await {
            Outcome::Done => return,
            Outcome::Transient => {
                // No run id → can't replay; surface the loss.
                if run_id.is_none() {
                    let _ = tx.send(AppMsg::Stream(StreamMsg::Disconnected(crate::i18n::t(
                        crate::i18n::Msg::StreamLost,
                    ))));
                    return;
                }
                attempts += 1;
                if attempts > MAX_RECONNECTS {
                    let _ = tx.send(AppMsg::Stream(StreamMsg::Disconnected(crate::i18n::t(
                        crate::i18n::Msg::StreamReconnectFailed,
                    ))));
                    return;
                }
                tokio::time::sleep(backoff(attempts)).await;
            }
        }
    }
}

/// Tail an SSE response, decode each `data:` frame, and relay it as a `StreamMsg`.
/// HTTP success and clean EOF are not a canonical terminal event.
async fn consume(resp: reqwest::Response, tx: &UnboundedSender<AppMsg>, replay: bool) -> Outcome {
    let is_sse = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"));
    if !is_sse {
        return Outcome::Transient;
    }
    consume_chunks(resp.bytes_stream(), tx, replay).await
}

async fn consume_chunks<S, B, E>(
    stream: S,
    tx: &UnboundedSender<AppMsg>,
    mut replay: bool,
) -> Outcome
where
    S: Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
{
    futures_util::pin_mut!(stream);
    let mut decoder = decoder::Decoder::default();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(_) => return Outcome::Transient,
        };
        for &byte in chunk.as_ref() {
            match decoder.push(byte) {
                Ok(Some(data)) => match dispatch(&data, tx, &mut replay) {
                    Ok(true) => return Outcome::Done,
                    Ok(false) => {}
                    Err(()) => return Outcome::Transient,
                },
                Ok(None) => {}
                Err(_) => return Outcome::Transient,
            }
        }
    }
    Outcome::Transient
}

/// Map one BusRecord's AG-UI event to a StreamMsg. Returns true on a terminal event.
fn dispatch(data: &str, tx: &UnboundedSender<AppMsg>, replay: &mut bool) -> Result<bool, ()> {
    let Some(record) = agui::parse_bus_record(data) else {
        return Err(());
    };
    let ev = record.ev;
    let terminal = matches!(ev.kind.as_str(), agui::RUN_FINISHED | agui::RUN_ERROR);
    // Build the entire presentation message before touching the UI, including Reset.
    // Missing rendered fields are not empty deltas/default tool results: skipping such
    // an event and accepting a later terminal would conceal an incomplete replay.
    let msg = match ev.kind.as_str() {
        agui::TEXT_MESSAGE_CONTENT => Some(StreamMsg::Text(ev.delta.ok_or(())?)),
        agui::THINKING_CONTENT => Some(StreamMsg::Thinking(ev.delta.ok_or(())?)),
        agui::TOOL_CALL_START => Some(StreamMsg::ToolStart {
            id: ev.tool_call_id.ok_or(())?,
            name: ev.tool_call_name.ok_or(())?,
        }),
        agui::TOOL_CALL_ARGS => Some(StreamMsg::ToolArgs {
            id: ev.tool_call_id.ok_or(())?,
            delta: ev.delta.ok_or(())?,
        }),
        agui::TOOL_CALL_RESULT => Some(StreamMsg::ToolResult {
            id: ev.tool_call_id.ok_or(())?,
            content: ev.content.ok_or(())?,
        }),
        agui::RUN_FINISHED => Some(StreamMsg::Finished),
        agui::RUN_ERROR => Some(StreamMsg::Error(ev.message.ok_or(())?)),
        agui::CUSTOM if ev.name.as_deref() == Some(agui::CUSTOM_USAGE) => {
            let v = ev.value.ok_or(())?;
            // UsagePayload requires model_name; token counts default to zero and cost
            // may be absent/null. Wrong-typed present fields are never guessed away.
            let count = |key| {
                v.get(key)
                    .map(|value| value.as_i64().ok_or(()))
                    .transpose()
                    .map(|count| count.unwrap_or(0))
            };
            Some(StreamMsg::Usage {
                model: Some(
                    v.get("model_name")
                        .and_then(|value| value.as_str())
                        .ok_or(())?
                        .into(),
                ),
                input: count("input_tokens")?,
                output: count("output_tokens")?,
                cost: v
                    .get("cost_usd")
                    .filter(|value| !value.is_null())
                    .map(|value| value.as_f64().ok_or(()))
                    .transpose()?,
            })
        }
        _ => None,
    };
    // A successful handshake, heartbeat, malformed frame or empty replay proves no
    // replacement content. Reset exactly once, after validating the complete first
    // replay record and before applying it. Unrendered AG-UI kinds remain extensible.
    if std::mem::replace(replay, false) {
        let _ = tx.send(AppMsg::Stream(StreamMsg::Reset));
    }
    if let Some(msg) = msg {
        let _ = tx.send(AppMsg::Stream(msg));
    }
    Ok(terminal)
}

#[cfg(test)]
#[path = "sse/tests.rs"]
mod tests;
