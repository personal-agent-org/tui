use super::*;
use serde_json::json;
use std::io::{Read, Write};

const BRANCH: &str = "01990000-0000-7000-8000-000000000001";

/// The instance's own RFC 3339 instant. The renderer must print exactly these bytes.
const CREATED_AT: &str = "2026-03-04T05:06:07.123456+02:00";

/// A one-message page whose parts are absent, so the flat text is the rendered body.
fn page(text: &str) -> Vec<u8> {
    page_of(json!([
        {"turn_sequence":1,"role":"agent","created_at":CREATED_AT,"text":text,"parts":[]}
    ]))
}

/// A one-message page whose parts carry the published `{kind, text}` shape.
fn page_with_parts(text: &str, parts: serde_json::Value) -> Vec<u8> {
    page_of(json!([
        {"turn_sequence":1,"role":"agent","created_at":CREATED_AT,"text":text,"parts":parts}
    ]))
}

/// One complete message, every published field present.
fn msg(turn: i64, role: &str, text: &str) -> serde_json::Value {
    json!({"turn_sequence":turn,"role":role,"created_at":CREATED_AT,"text":text,"parts":[]})
}

fn page_of(messages: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&based(json!({"messages":messages,"next_after_turn":null}))).unwrap()
}

/// §18.3's read basis every published page carries: label, policy basis, watermark and
/// the bounded-staleness state. Added where a fixture leaves them out, so each invalid
/// fixture below is refused for the one thing it breaks.
fn based(mut page: serde_json::Value) -> serde_json::Value {
    let object = page.as_object_mut().unwrap();
    for (key, value) in [
        ("label", json!("01990000-0000-7000-8000-0000000000cc")),
        (
            "policy_basis",
            json!("01990000-0000-7000-8000-0000000000dd"),
        ),
        ("watermark", serde_json::Value::Null),
        (
            "staleness",
            json!({"source":"primary","behind":false,"pending":0}),
        ),
    ] {
        object.entry(key).or_insert(value);
    }
    page
}

fn session() -> SessionToken {
    token(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap()
}

fn token(bytes: &[u8]) -> Result<SessionToken, ReadError> {
    SessionToken::from_bytes(Zeroizing::new(bytes.to_vec()))
}

#[test]
fn protected_session_input_is_exact_bounded_and_header_debug_is_sensitive() {
    for suffix in ["", "\n", "\r\n"] {
        let token = format!("{}{suffix}", "a".repeat(64));
        let parsed = self::token(token.as_bytes()).unwrap();
        let header = parsed.header().unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains(&"a".repeat(64)));
    }
    for invalid in [
        "a".repeat(63),
        "a".repeat(65),
        "z".repeat(64),
        format!("{}\nextra", "a".repeat(64)),
        format!("pa_session={}", "a".repeat(64)),
    ] {
        assert!(matches!(
            token(invalid.as_bytes()),
            Err(ReadError::InvalidSessionHandoff)
        ));
    }
}

#[test]
fn origins_never_accept_credentials_or_ambient_cleartext_authority() {
    for invalid in [
        "https://user:secret@example.test",
        "https://secret@example.test",
        "https://example.test/?token=secret",
        "https://example.test/#secret",
        "https://example.test/v1",
        "http://example.test",
        "http://localhost",
        "http://127.0.0.1.example.test",
        "file:///secret",
    ] {
        assert!(origin(invalid, false).is_err());
        assert!(origin(invalid, true).is_err());
    }
    assert!(origin("http://127.0.0.1:1234", false).is_err());
    assert!(origin("http://127.0.0.1:1234", true).is_ok());
    assert!(origin("http://[::1]:1234", true).is_ok());
    assert!(origin("https://example.test", false).is_ok());
}

#[test]
fn generated_closed_schema_and_canonical_page_order_are_not_best_effort() {
    for invalid in [
        json!({"messages":[]}),
        json!({"messages":[],"next_after_turn":null,"extra":1}),
        json!({"messages":[msg(1,"system","x")],"next_after_turn":null}),
        json!({"messages":[{"turn_sequence":1,"role":"agent","created_at":CREATED_AT,"parts":[]}],"next_after_turn":null}),
        json!({"messages":[{"turn_sequence":1,"role":"agent","text":"x","parts":[]}],"next_after_turn":null}),
        json!({"messages":[{"turn_sequence":1,"role":"agent","created_at":CREATED_AT,"text":"x"}],"next_after_turn":null}),
        json!({"messages":[{"turn_sequence":1,"role":"agent","created_at":1,"text":"x","parts":[]}],"next_after_turn":null}),
        json!({"messages":[msg(0,"agent","x")],"next_after_turn":null}),
        json!({"messages":[{"turn_sequence":1,"role":"agent","created_at":CREATED_AT,"text":"x","parts":[],"extra":1}],"next_after_turn":null}),
        json!({"messages":[{"turn_sequence":1,"role":"agent","created_at":CREATED_AT,"text":"x","parts":[{"kind":"text"}]}],"next_after_turn":null}),
        json!({"messages":[{"turn_sequence":1,"role":"agent","created_at":CREATED_AT,"text":"x","parts":[{"kind":"prose","text":"x"}]}],"next_after_turn":null}),
        json!({"messages":[{"turn_sequence":1,"role":"agent","created_at":CREATED_AT,"text":"x","parts":[{"kind":"text","text":"x","extra":1}]}],"next_after_turn":null}),
        json!({"messages":[msg(2,"agent","x"),msg(2,"human","y")],"next_after_turn":null}),
        json!({"messages":[msg(2,"agent","x"),msg(1,"human","y")],"next_after_turn":null}),
        json!({"messages":[],"next_after_turn":1}),
    ] {
        assert!(matches!(
            Snapshot::decode(&serde_json::to_vec(&based(invalid)).unwrap(), 0, 200),
            Err(ReadError::InvalidResponse)
        ));
    }
    assert!(Snapshot::decode(&page("x"), 1, 200).is_err());
    assert!(
        Snapshot::decode(&page("x"), 0, 1).is_err(),
        "a full page must supply continuation"
    );
    let full = based(json!({"messages":[msg(3,"human","x")],"next_after_turn":3}));
    assert!(Snapshot::decode(&serde_json::to_vec(&full).unwrap(), 0, 1).is_ok());
}

#[test]
fn truncation_invalid_utf8_and_plaintext_limit_fail_before_rendering() {
    let valid = page("Grüße 👋");
    for cut in 0..valid.len() {
        assert!(Snapshot::decode(&valid[..cut], 0, 200).is_err());
    }
    assert!(Snapshot::decode(b"\xff", 0, 200).is_err());
    assert!(Snapshot::decode(
        &page(&"x".repeat(contract::MAX_PLAINTEXT_BYTES + 1)),
        0,
        200
    )
    .is_err());
}

#[test]
fn renderer_cannot_emit_terminal_escape_sequences_or_infer_run_completion() {
    let snapshot = Snapshot::decode(
        &page_with_parts(
            "flat fallback",
            json!([
                {"kind":"text","text":"Grüße\n\u{1b}]52;c;secret\u{7}\t\u{202e}text"},
                {"kind":"action_call","text":"run\u{1b}[2Jstep"}
            ]),
        ),
        0,
        200,
    )
    .unwrap();
    let rendered = snapshot.render();
    assert!(rendered.contains("Grüße"));
    assert!(rendered.contains("Run status is not determined by this read."));
    assert!(
        !rendered.contains('\u{1b}')
            && !rendered.contains('\u{7}')
            && !rendered.contains('\u{202e}')
    );
    // Nothing in this read claims a Run finished, whatever the parts say.
    assert!(!rendered.to_ascii_lowercase().contains("completed"));
    // The instant is printed as received, never localised or re-formatted.
    assert!(rendered.contains(CREATED_AT));
    let escaped =
        Snapshot::decode(&page("\u{1b}]8;;https://attacker.test\u{7}link"), 0, 200).unwrap();
    assert!(!escaped.render().contains('\u{1b}'));
}

#[test]
fn renderer_labels_non_text_parts_and_falls_back_to_flat_text() {
    let snapshot = Snapshot::decode(
        &page_with_parts(
            "flat text that parts supersede",
            json!([
                {"kind":"text","text":"first line\nsecond line"},
                {"kind":"reasoning_status","text":"thinking"},
                {"kind":"action_call","text":"read_branch\nbranch=1"},
                {"kind":"action_result","text":"ok"},
                {"kind":"refusal","text":"declined"},
                {"kind":"structured_data","text":"{\"a\":1}"},
                {"kind":"media","text":""}
            ]),
        ),
        0,
        200,
    )
    .unwrap();
    let rendered = snapshot.render();
    assert!(rendered.contains(&format!("\nAssistant · 1 · {CREATED_AT}\n")));
    // Text parts are the body: no label, no invented ordering.
    assert!(rendered.contains("\n  first line\n  second line\n"));
    // Every other kind is labelled with its published wire name, on each of its lines.
    assert!(rendered.contains("\n  [reasoning_status] thinking\n"));
    assert!(rendered.contains("\n  [action_call] read_branch\n  [action_call] branch=1\n"));
    assert!(rendered.contains("\n  [action_result] ok\n"));
    assert!(rendered.contains("\n  [refusal] declined\n"));
    assert!(rendered.contains("\n  [structured_data] {\"a\":1}\n"));
    // An empty part is reported rather than dropped.
    assert!(rendered.contains("\n  [media]\n"));
    // Parts present means the flat text is not printed a second time.
    assert!(!rendered.contains("flat text that parts supersede"));

    // Parts absent means the flat text is still the body.
    let flat = Snapshot::decode(&page("only flat text"), 0, 200).unwrap();
    let flat = flat.render();
    assert!(flat.contains("\n  only flat text\n"));
    assert!(flat.contains(CREATED_AT));
    assert!(!flat.contains('['));
}

#[test]
fn a_media_part_may_name_its_artifact_version_and_nothing_else_may_stand_in() {
    let media = |artifact: serde_json::Value| {
        let mut part = json!({"kind":"media","text":""});
        if !artifact.is_null() {
            part["artifact"] = artifact;
        }
        Snapshot::decode(&page_with_parts("", json!([part])), 0, 200)
    };
    let artifact = json!({"artifact_id":"01990000-0000-7000-8000-0000000000ee","version":3});
    assert!(media(artifact).is_ok());
    // Absent is the published "not a media reference".
    assert!(media(serde_json::Value::Null).is_ok());
    // An explicit null, a non-canonical id, version 0 or an extra member is not published.
    let mut explicit_null = json!({"kind":"media","text":""});
    explicit_null["artifact"] = serde_json::Value::Null;
    assert!(Snapshot::decode(&page_with_parts("", json!([explicit_null])), 0, 200).is_err());
    for bad in [
        json!({"artifact_id":"not-a-uuid","version":1}),
        json!({"artifact_id":"01990000-0000-7000-8000-0000000000ee","version":0}),
        json!({"artifact_id":"01990000-0000-7000-8000-0000000000ee","version":1,"url":"x"}),
    ] {
        assert!(media(bad.clone()).is_err(), "{bad}");
    }
}

struct Reply {
    status: u16,
    headers: &'static str,
    body: Vec<u8>,
}

fn server(replies: Vec<Reply>) -> (reqwest::Url, std::thread::JoinHandle<Vec<String>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let task = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
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
                "HTTP/1.1 {} Response\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
                reply.status,
                reply.headers,
                reply.body.len()
            )
            .unwrap();
            stream.write_all(&reply.body).unwrap();
            requests.push(String::from_utf8(request).unwrap());
        }
        requests
    });
    (url, task)
}

const JSON_HEADERS: &str = "Content-Type: application/json\r\nCache-Control: no-store\r\n";

#[tokio::test]
async fn actual_adapter_reload_replaces_and_malformed_reply_purges_previous_page() {
    let (url, task) = server(vec![
        Reply {
            status: 200,
            headers: JSON_HEADERS,
            body: page("stored answer"),
        },
        Reply {
            status: 200,
            headers: JSON_HEADERS,
            body: page("stored answer"),
        },
        Reply {
            status: 200,
            headers: JSON_HEADERS,
            body: b"{\"messages\":[".to_vec(),
        },
    ]);
    let client = Client::new(url, session()).unwrap();
    let mut view = View::default();
    view.reload(&client, BRANCH, 0, 200).await.unwrap();
    let first = view.snapshot.as_ref().unwrap().render();
    view.reload(&client, BRANCH, 0, 200).await.unwrap();
    assert_eq!(*first, *view.snapshot.as_ref().unwrap().render());
    assert_eq!(first.matches("stored answer").count(), 1);
    assert!(matches!(
        view.reload(&client, BRANCH, 0, 200).await,
        Err(ReadError::InvalidResponse)
    ));
    assert!(view.snapshot.is_none());
    for request in task.join().unwrap() {
        assert!(request.starts_with(&format!(
            "GET /v1/branches/{BRANCH}/messages?after_turn=0&limit=200 HTTP/1.1\r\n"
        )));
        let request = request.to_ascii_lowercase();
        assert!(request.contains("\r\npa-csrf: 1\r\n"));
        assert!(request.contains("\r\ncookie: pa_session="));
        assert!(!request.contains("authorization:"));
    }
}

#[tokio::test]
async fn denial_and_expiry_do_not_parse_or_expose_error_body_and_clear_old_page() {
    for (status, expected) in [
        (401, ReadError::AuthenticationRequired),
        (403, ReadError::NotAuthorized),
        (404, ReadError::NotAuthorized),
    ] {
        let (url, task) = server(vec![Reply {
            status,
            headers: JSON_HEADERS,
            body: page("must never appear"),
        }]);
        let client = Client::new(url, session()).unwrap();
        let mut view = View {
            snapshot: Some(Snapshot::decode(&page("previous authorized text"), 0, 200).unwrap()),
        };
        assert_eq!(
            view.reload(&client, BRANCH, 0, 200).await.unwrap_err(),
            expected
        );
        assert!(view.snapshot.is_none());
        task.join().unwrap();
    }
}

#[tokio::test]
async fn redirect_wrong_media_type_and_cacheable_responses_are_not_read_as_messages() {
    for (status, headers) in [
        (302, "Location: http://127.0.0.1:1/credential-target\r\n"),
        (
            200,
            "Content-Type: text/html\r\nCache-Control: no-store\r\n",
        ),
        (
            200,
            "Content-Type: application/json\r\nCache-Control: public\r\n",
        ),
    ] {
        let (url, task) = server(vec![Reply {
            status,
            headers,
            body: page("not displayable"),
        }]);
        let client = Client::new(url, session()).unwrap();
        assert!(client.read(BRANCH, 0, 200).await.is_err());
        assert_eq!(task.join().unwrap().len(), 1);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn open_empty_and_complete_token_writers_time_out_and_restore_shared_flags() {
    use std::os::{fd::AsFd, unix::net::UnixStream};
    for length in [0, 64] {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let initial = rustix::fs::fcntl_getfl(&reader).unwrap();
        writer.write_all(&vec![b'a'; length]).unwrap();
        let fd = reader.as_fd().try_clone_to_owned().unwrap();
        assert!(rustix::io::fcntl_getfd(&fd)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        let start = std::time::Instant::now();
        let result = handoff::read_pipe(fd, Duration::from_millis(30)).await;
        assert!(matches!(result, Err(ReadError::InvalidSessionHandoff)));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(rustix::fs::fcntl_getfl(&reader).unwrap(), initial);
        drop(writer); // Kept open throughout the timeout: EOF did not release the read.
    }
}

#[cfg(unix)]
#[tokio::test]
async fn eof_and_oversized_pipe_handoff_are_bounded_and_restore_flags() {
    use std::os::{fd::AsFd, unix::net::UnixStream};
    for (length, eof, accepted) in [(64, true, true), (0, true, false), (67, false, false)] {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let initial = rustix::fs::fcntl_getfl(&reader).unwrap();
        writer.write_all(&vec![b'a'; length]).unwrap();
        if eof {
            writer.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let result = handoff::read_pipe(
            reader.as_fd().try_clone_to_owned().unwrap(),
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(rustix::fs::fcntl_getfl(&reader).unwrap(), initial);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_pending_handoff_restores_flags_without_a_background_reader() {
    use std::os::{fd::AsFd, unix::net::UnixStream};
    let (reader, _writer) = UnixStream::pair().unwrap();
    let initial = rustix::fs::fcntl_getfl(&reader).unwrap();
    let mut future = Box::pin(handoff::read_pipe(
        reader.as_fd().try_clone_to_owned().unwrap(),
        Duration::from_secs(5),
    ));
    tokio::select! {
        _ = &mut future => panic!("an empty open writer cannot finish a handoff"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
    }
    assert!(rustix::fs::fcntl_getfl(&reader)
        .unwrap()
        .contains(rustix::fs::OFlags::NONBLOCK));
    drop(future);
    assert_eq!(rustix::fs::fcntl_getfl(&reader).unwrap(), initial);
}

#[cfg(unix)]
#[tokio::test]
async fn ordinary_file_handoff_is_refused_without_changing_its_flags() {
    use std::os::fd::AsFd;
    let file = std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let initial = rustix::fs::fcntl_getfl(&file).unwrap();
    let result = handoff::read_pipe(
        file.as_fd().try_clone_to_owned().unwrap(),
        Duration::from_secs(1),
    )
    .await;
    assert!(matches!(result, Err(ReadError::InvalidSessionHandoff)));
    assert_eq!(rustix::fs::fcntl_getfl(&file).unwrap(), initial);
}
