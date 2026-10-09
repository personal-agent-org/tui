use super::*;
use std::io::{Read, Write};
use tokio::sync::mpsc;

fn serve_response(
    body: &[u8],
    content_type: &'static str,
) -> (String, std::thread::JoinHandle<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_vec();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
        String::from_utf8(request).unwrap()
    });
    (format!("http://{address}"), server)
}

async fn response(body: &[u8]) -> reqwest::Response {
    response_with_type(body, "text/event-stream").await
}

async fn response_with_type(body: &[u8], content_type: &'static str) -> reqwest::Response {
    let (url, server) = serve_response(body, content_type);
    let response = pa_oidc::tls::http_client_builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap();
    server.join().unwrap();
    response
}

#[tokio::test]
async fn clean_eof_without_terminal_requires_resume_not_success() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let response = response(
        b"data: {\"v\":1,\"run_id\":\"r\",\"seq\":1,\"ev\":{\"type\":\"TEXT_MESSAGE_CONTENT\",\"delta\":\"partial\"}}\n\n",
    )
    .await;
    let outcome = consume(response, &tx, false).await;
    assert!(matches!(outcome, Outcome::Transient));
    assert!(
        matches!(rx.try_recv(), Ok(AppMsg::Stream(StreamMsg::Text(text))) if text == "partial")
    );
    assert!(rx.try_recv().is_err(), "EOF must not fabricate Finished");
}

#[tokio::test]
async fn malformed_frame_cannot_be_skipped_to_claim_a_later_success() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let response = response(
        b"data: {broken\n\ndata: {\"v\":1,\"run_id\":\"r\",\"seq\":2,\"ev\":{\"type\":\"RUN_FINISHED\"}}\n\n",
    )
    .await;
    let outcome = consume(response, &tx, false).await;
    assert!(matches!(outcome, Outcome::Transient));
    assert!(
        rx.try_recv().is_err(),
        "invalid input must stop application before terminal"
    );
}

fn event(kind: &str, extra: serde_json::Value) -> String {
    let mut ev = extra;
    ev["type"] = kind.into();
    format!(
        "data: {}\n\n",
        serde_json::json!({"v":1,"run_id":"r","seq":1,"ev":ev})
    )
}

async fn chunks(parts: Vec<Result<Vec<u8>, ()>>) -> (Outcome, Vec<StreamMsg>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let outcome = consume_chunks(futures_util::stream::iter(parts), &tx, false).await;
    let mut messages = Vec::new();
    while let Ok(AppMsg::Stream(message)) = rx.try_recv() {
        messages.push(message);
    }
    (outcome, messages)
}

#[tokio::test]
async fn only_explicit_terminal_events_finish_or_fail_the_run() {
    for (kind, is_success) in [(agui::RUN_FINISHED, true), (agui::RUN_ERROR, false)] {
        let data = event(kind, serde_json::json!({"message":"failure"}));
        let (outcome, messages) = chunks(vec![Ok(data.into_bytes()), Err(())]).await;
        assert!(matches!(outcome, Outcome::Done));
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            StreamMsg::Finished => assert!(is_success),
            StreamMsg::Error(message) => {
                assert!(!is_success);
                assert_eq!(message, "failure");
            }
            other => panic!("wrong terminal projection: {other:?}"),
        }
    }
}

#[tokio::test]
async fn every_byte_boundary_preserves_utf8_and_crlf_frame_semantics() {
    let data = format!(
        "\u{feff}: heartbeat\n\n{}{}",
        event(
            agui::TEXT_MESSAGE_CONTENT,
            serde_json::json!({"delta":"Grüße 👋"})
        ),
        event(agui::RUN_FINISHED, serde_json::json!({})),
    )
    .replace('\n', "\r\n")
    .into_bytes();
    for split in 0..=data.len() {
        let (outcome, messages) =
            chunks(vec![Ok(data[..split].to_vec()), Ok(data[split..].to_vec())]).await;
        assert!(matches!(outcome, Outcome::Done), "split {split}");
        assert!(
            matches!(&messages[..], [StreamMsg::Text(text), StreamMsg::Finished] if text == "Grüße 👋")
        );
    }
    let (_, messages) = chunks(data.into_iter().map(|byte| Ok(vec![byte])).collect()).await;
    assert!(
        matches!(&messages[..], [StreamMsg::Text(text), StreamMsg::Finished] if text == "Grüße 👋")
    );
}

#[tokio::test]
async fn bare_cr_line_endings_and_multiline_data_are_valid_sse() {
    let data = b"data: {\"v\":1,\"run_id\":\"r\",\rdata: \"seq\":1,\"ev\":{\"type\":\"RUN_FINISHED\"}}\r\r";
    let (outcome, messages) = chunks(data.iter().map(|byte| Ok(vec![*byte])).collect()).await;
    assert!(matches!(outcome, Outcome::Done));
    assert!(matches!(&messages[..], [StreamMsg::Finished]));
}

#[tokio::test]
async fn truncation_at_every_terminal_frame_boundary_never_claims_success() {
    let data = event(agui::RUN_FINISHED, serde_json::json!({})).into_bytes();
    for end in 0..data.len() {
        let (outcome, messages) = chunks(vec![Ok(data[..end].to_vec())]).await;
        assert!(matches!(outcome, Outcome::Transient), "truncated at {end}");
        assert!(
            messages.is_empty(),
            "truncated terminal was dispatched at {end}"
        );
    }
}

#[tokio::test]
async fn invalid_utf8_and_malformed_json_never_skip_forward_to_terminal() {
    for invalid in [
        b"data: \xff\n\n".as_slice(),
        b"data:\n\n",
        b"data\n\n",
        b"data: []\n\n",
        b"data: {\"ev\":{\"type\":\"RUN_FINISHED\"}}\n\n",
    ] {
        let terminal = event(agui::RUN_FINISHED, serde_json::json!({}));
        let (outcome, messages) = chunks(vec![Ok([invalid, terminal.as_bytes()].concat())]).await;
        assert!(matches!(outcome, Outcome::Transient));
        assert!(messages.is_empty());
    }
}

#[tokio::test]
async fn oversized_lines_and_multiline_frames_stop_before_any_terminal() {
    let terminal = event(agui::RUN_FINISHED, serde_json::json!({}));
    let single_line = vec![b'x'; decoder::MAX_FRAME_BYTES + 1];
    let many_lines = b"data: x\n".repeat(decoder::MAX_FRAME_BYTES / 8 + 1);
    let many_comments = b": x\n".repeat(decoder::MAX_FRAME_BYTES / 4 + 1);
    for oversized in [single_line, many_lines, many_comments] {
        let (outcome, messages) =
            chunks(vec![Ok(oversized), Ok(terminal.as_bytes().to_vec())]).await;
        assert!(matches!(outcome, Outcome::Transient));
        assert!(messages.is_empty());
    }
}

#[tokio::test]
async fn heartbeat_only_eof_and_transport_error_require_resume() {
    for parts in [vec![Ok(b": heartbeat\n\n".to_vec())], vec![Err(())]] {
        let (outcome, messages) = chunks(parts).await;
        assert!(matches!(outcome, Outcome::Transient));
        assert!(messages.is_empty());
    }
}

#[tokio::test]
async fn non_reattachable_stream_loss_is_disconnected_not_a_run_failure() {
    let first = response(b": heartbeat\n\n").await;
    let client = Arc::new(ApiClient::new(&crate::config::Config::default()).unwrap());
    let (tx, mut rx) = mpsc::unbounded_channel();
    pump(client, "c".into(), None, first, &tx).await;
    assert!(matches!(
        rx.try_recv(),
        Ok(AppMsg::Stream(StreamMsg::Disconnected(_)))
    ));
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn clean_eof_reconnects_by_get_and_replays_once_before_terminal() {
    let partial = event(
        agui::TEXT_MESSAGE_CONTENT,
        serde_json::json!({"delta":"partial"}),
    );
    let terminal = event(agui::RUN_FINISHED, serde_json::json!({}));
    let first = response(partial.as_bytes()).await;
    let replay = format!("{partial}{terminal}");
    let (server_url, server) = serve_response(replay.as_bytes(), "text/event-stream");
    let client = Arc::new(
        ApiClient::new(&crate::config::Config {
            server: server_url,
            access_token: "local-fixture-not-a-credential".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        pump(client, "c".into(), Some("r".into()), first, &tx),
    )
    .await
    .unwrap();
    let request = server.join().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /api/v1/chats/c/runs/r/stream http/1.1\r\n"));
    assert!(request.contains("\r\nlast-event-id: 0\r\n"));
    assert!(request.contains("\r\nauthorization: bearer local-fixture-not-a-credential\r\n"));
    assert!(
        matches!(rx.try_recv(), Ok(AppMsg::Stream(StreamMsg::Text(text))) if text == "partial")
    );
    assert!(matches!(
        rx.try_recv(),
        Ok(AppMsg::Stream(StreamMsg::Reset))
    ));
    assert!(
        matches!(rx.try_recv(), Ok(AppMsg::Stream(StreamMsg::Text(text))) if text == "partial")
    );
    assert!(matches!(
        rx.try_recv(),
        Ok(AppMsg::Stream(StreamMsg::Finished))
    ));
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn invalid_or_empty_replay_preserves_previous_partial_output() {
    let terminal = event(agui::RUN_FINISHED, serde_json::json!({}));
    for (body, content_type) in [
        (terminal.as_bytes(), "application/json"),
        (b"".as_slice(), "text/event-stream"),
        (b": heartbeat\n\n".as_slice(), "text/event-stream"),
        (b"data: {broken\n\n".as_slice(), "text/event-stream"),
        (
            b"data: {\"ev\":{\"type\":\"RUN_FINISHED\"}}\n\n".as_slice(),
            "text/event-stream",
        ),
    ] {
        let response = response_with_type(body, content_type).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let outcome = consume(response, &tx, true).await;
        assert!(matches!(outcome, Outcome::Transient));
        assert!(
            rx.try_recv().is_err(),
            "invalid replay must not reset the previous turn"
        );
    }
}

#[test]
fn frame_limit_is_inclusive_and_resets_only_at_frame_boundary() {
    let mut decoder = decoder::Decoder::default();
    let frame = format!(":{}\n\n", "x".repeat(decoder::MAX_FRAME_BYTES - 3));
    assert_eq!(frame.len(), decoder::MAX_FRAME_BYTES);
    for byte in frame.bytes() {
        assert_eq!(decoder.push(byte), Ok(None));
    }
    for byte in b": next\n\n" {
        assert_eq!(decoder.push(*byte), Ok(None));
    }
    for _ in 0..decoder::MAX_FRAME_BYTES {
        assert_eq!(decoder.push(b'x'), Ok(None));
    }
    assert_eq!(decoder.push(b'\n'), Err(decoder::DecodeError::TooLarge));
}

#[tokio::test]
async fn malformed_rendered_event_cannot_reset_or_skip_forward_to_success() {
    for (kind, fields) in [
        (agui::TEXT_MESSAGE_CONTENT, serde_json::json!({})),
        (agui::THINKING_CONTENT, serde_json::json!({})),
        (agui::TOOL_CALL_ARGS, serde_json::json!({"toolCallId":"t"})),
        (agui::TOOL_CALL_ARGS, serde_json::json!({"delta":"{}"})),
        (
            agui::TOOL_CALL_START,
            serde_json::json!({"toolCallName":"search"}),
        ),
        (agui::TOOL_CALL_START, serde_json::json!({"toolCallId":"t"})),
        (
            agui::TOOL_CALL_RESULT,
            serde_json::json!({"toolCallId":"t"}),
        ),
        (agui::TOOL_CALL_RESULT, serde_json::json!({"content":"ok"})),
        (agui::RUN_ERROR, serde_json::json!({})),
        (agui::CUSTOM, serde_json::json!({"name":agui::CUSTOM_USAGE})),
        (
            agui::CUSTOM,
            serde_json::json!({"name":agui::CUSTOM_USAGE,"value":{}}),
        ),
        (
            agui::CUSTOM,
            serde_json::json!({"name":agui::CUSTOM_USAGE,"value":{"model_name":"m","input_tokens":"10"}}),
        ),
        (
            agui::CUSTOM,
            serde_json::json!({"name":agui::CUSTOM_USAGE,"value":{"model_name":"m","cost_usd":"1.0"}}),
        ),
    ] {
        for replay in [false, true] {
            let body = format!(
                "{}{}",
                event(kind, fields.clone()),
                event(agui::RUN_FINISHED, serde_json::json!({})),
            );
            let (tx, mut rx) = mpsc::unbounded_channel();
            let outcome = consume_chunks(
                futures_util::stream::iter(vec![Ok::<_, ()>(body.into_bytes())]),
                &tx,
                replay,
            )
            .await;
            assert!(matches!(outcome, Outcome::Transient), "accepted {kind}");
            assert!(
                rx.try_recv().is_err(),
                "malformed {kind} caused UI mutation"
            );
        }
    }
}

#[tokio::test]
async fn current_producer_payloads_including_empty_deltas_remain_renderable() {
    // Mirrors realtime/protocol/converter.py and contracts/ag_ui.py UsagePayload.
    // ThinkingPartDelta explicitly substitutes an empty string; FunctionToolResultEvent
    // may supply an empty call id. Missing fields must not be confused with these values.
    let events = [
        event(
            agui::TEXT_MESSAGE_CONTENT,
            serde_json::json!({"messageId":"r#1","delta":"hello"}),
        ),
        event(agui::THINKING_CONTENT, serde_json::json!({"delta":""})),
        event(
            agui::TOOL_CALL_START,
            serde_json::json!({"toolCallId":"t","toolCallName":"search"}),
        ),
        event(
            agui::TOOL_CALL_ARGS,
            serde_json::json!({"toolCallId":"t","delta":""}),
        ),
        event(
            agui::TOOL_CALL_RESULT,
            serde_json::json!({"toolCallId":"","content":"","isError":false}),
        ),
        event(
            agui::CUSTOM,
            serde_json::json!({"name":agui::CUSTOM_USAGE,"value":{"run_id":"r","model_name":"m","cost_usd":null}}),
        ),
        event(
            agui::RUN_FINISHED,
            serde_json::json!({"runId":"r","threadId":"c"}),
        ),
    ];
    let (outcome, messages) = chunks(vec![Ok(events.concat().into_bytes())]).await;
    assert!(matches!(outcome, Outcome::Done));
    assert!(matches!(&messages[0], StreamMsg::Text(text) if text == "hello"));
    assert!(matches!(&messages[1], StreamMsg::Thinking(text) if text.is_empty()));
    assert!(
        matches!(&messages[2], StreamMsg::ToolStart { id, name } if id == "t" && name == "search")
    );
    assert!(
        matches!(&messages[3], StreamMsg::ToolArgs { id, delta } if id == "t" && delta.is_empty())
    );
    assert!(
        matches!(&messages[4], StreamMsg::ToolResult { id, content } if id.is_empty() && content.is_empty())
    );
    assert!(
        matches!(&messages[5], StreamMsg::Usage { model, input: 0, output: 0, cost: None } if model.as_deref() == Some("m"))
    );
    assert!(matches!(&messages[6], StreamMsg::Finished));
    assert_eq!(messages.len(), 7);
}

#[tokio::test]
async fn unrendered_agui_events_remain_extensible_without_becoming_terminal() {
    let events = [
        event(
            "STATE_SNAPSHOT",
            serde_json::json!({"snapshot":{"future":true}}),
        ),
        event(
            agui::CUSTOM,
            serde_json::json!({"name":"future.namespace","value":{"future":true}}),
        ),
        event("FUTURE_ADDITIVE_EVENT", serde_json::json!({"future":true})),
    ];
    let (outcome, messages) = chunks(vec![Ok(events.concat().into_bytes())]).await;
    assert!(matches!(outcome, Outcome::Transient));
    assert!(messages.is_empty());
}
