use super::*;
use serde_json::json;
use std::io::{Read, Write};

const UUID: &str = "01990000-0000-7000-8000-000000000001";

fn started(replayed: bool) -> serde_json::Value {
    let mut result = json!({"run_id":UUID,"command_id":UUID,"receipt_id":UUID,"input_sequence":1,"replayed":replayed});
    if !replayed {
        result["turn_sequence"] = json!(1);
    }
    result
}

#[test]
fn actual_receipt_variants_are_complete_typed_and_do_not_claim_run_success() {
    for valid in [
        started(false),
        started(true),
        json!({"followup_id":UUID,"queue_ordinal":1,"run_id":UUID,"replayed":false}),
    ] {
        assert!(admitted(&serde_json::to_vec(&valid).unwrap(), 0).is_ok());
    }
    let mut invalid = Vec::new();
    for (field, value) in [
        ("run_id", json!("bad")),
        ("input_sequence", json!(0)),
        ("turn_sequence", json!(null)),
        ("turn_sequence", json!(2)),
        ("replayed", json!(true)),
        ("status", json!("completed")),
        ("queue_ordinal", json!(1)),
    ] {
        let mut v = started(false);
        v[field] = value;
        invalid.push(v);
    }
    let mut absent = started(false);
    absent.as_object_mut().unwrap().remove("receipt_id");
    invalid.push(absent);
    for v in invalid {
        assert!(matches!(
            admitted(&serde_json::to_vec(&v).unwrap(), 0),
            Err(ReadError::CommitUnconfirmed)
        ));
    }
    let complete = serde_json::to_vec(&started(false)).unwrap();
    for cut in 0..complete.len() {
        assert!(admitted(&complete[..cut], 0).is_err());
    }
    assert!(admitted(b"\xff", 0).is_err());
    assert!(admitted(&complete, i64::MAX).is_err());
    assert!(created(&serde_json::to_vec(&json!({"entity_key":UUID,"branch_id":UUID,"address":format!("conversation.c{}","a".repeat(32))})).unwrap()).is_ok());
    assert!(created(
        &serde_json::to_vec(&json!({"entity_key":UUID,"branch_id":UUID,"address":"\u{1b}bad"}))
            .unwrap()
    )
    .is_err());
}

#[test]
fn generated_requests_preserve_real_bounds_and_optional_is_not_nullable() {
    assert!(
        serde_json::from_value::<write_contract::CreateConversationRequest>(json!({"main":null}))
            .is_err()
    );
    let create: write_contract::CreateConversationRequest =
        serde_json::from_value(json!({})).unwrap();
    assert!(create.main.is_absent());
    assert!(create.validate().is_ok());
    for (text, key, expected, valid) in [
        ("x".into(), "key".into(), 0, true),
        ("".into(), "key".into(), 0, false),
        ("x".repeat(65537), "key".into(), 0, false),
        ("x".into(), "".into(), 0, false),
        ("x".into(), "k".repeat(257), 0, false),
        ("x".into(), "key".into(), -1, false),
    ] {
        let body = ProtectedTurn(write_contract::SubmitTurnRequest {
            text,
            idempotency_key: key,
            expected_turn: expected,
            mentions: write_contract::Optional::Absent,
        });
        assert_eq!(body.0.validate().is_ok(), valid);
    }
}

struct FixtureFile(std::path::PathBuf);
impl FixtureFile {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "pa-write-input-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        Self(path)
    }
}
impl Drop for FixtureFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
#[test]
fn selected_text_file_is_utf8_bounded_regular_and_never_a_symlink() {
    for (bytes, valid) in [
        (b"Gruesse".to_vec(), true),
        (vec![b'x'; 65536], true),
        (vec![b'x'; 65537], false),
        (vec![], false),
        (vec![255], false),
    ] {
        let fixture = FixtureFile::new(&bytes);
        assert_eq!(text_file(&fixture.0).is_ok(), valid);
    }
    assert!(text_file(&std::env::temp_dir()).is_err());
    let target = FixtureFile::new(b"explicit Human text");
    let link = FixtureFile(target.0.with_extension("link"));
    std::os::unix::fs::symlink(&target.0, &link.0).unwrap();
    assert!(text_file(&link.0).is_err());
}

fn mock(
    status: u16,
    headers: &'static str,
    body: Vec<u8>,
) -> (
    reqwest::Url,
    std::thread::JoinHandle<(String, serde_json::Value)>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin =
        reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let task = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut head = Vec::new();
        let mut one = [0];
        while !head.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut one).unwrap();
            head.push(one[0]);
            assert!(head.len() < 8192);
        }
        let head = String::from_utf8(head).unwrap();
        let length: usize = head
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .map(|(_, v)| v.trim().parse().unwrap())
            })
            .unwrap();
        let mut request = vec![0; length];
        socket.read_exact(&mut request).unwrap();
        if status != 0 {
            write!(
                socket,
                "HTTP/1.1 {status} Result\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            socket.write_all(&body).unwrap();
        }
        drop(socket);
        listener.set_nonblocking(true).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock),
            "never automatically retry or query Run"
        );
        (head, serde_json::from_slice(&request).unwrap())
    });
    (origin, task)
}

#[tokio::test]
async fn actual_generated_write_adapter_sends_only_one_post_and_exact_command_bytes() {
    let (origin, server) = mock(
        202,
        "Content-Type: application/json\r\nCache-Control: no-store\r\n",
        serde_json::to_vec(&started(false)).unwrap(),
    );
    let session = SessionToken::from_bytes(Zeroizing::new(vec![b'a'; 64])).unwrap();
    let client = Client::new(origin, session).unwrap();
    let body = ProtectedTurn(write_contract::SubmitTurnRequest {
        expected_turn: 0,
        text: "Human Grüße".into(),
        idempotency_key: "stable-command".into(),
        mentions: write_contract::Optional::Absent,
    });
    let request = write_contract::submit_turn(
        &client.http,
        &client.origin,
        UUID,
        &body.0,
        client
            .session
            .header_for(write_contract::SESSION_COOKIE)
            .unwrap(),
    )
    .unwrap();
    assert!(admitted(&receipt(request, 202).await.unwrap(), 0).is_ok());
    let (head, bytes) = server.join().unwrap();
    assert!(head.starts_with(&format!("POST /v1/branches/{UUID}/turns HTTP/1.1\r\n")));
    assert!(head.contains("pa-csrf: 1\r\n"));
    assert!(!head.contains("Human Grüße") && !head.contains("stable-command"));
    assert_eq!(
        bytes,
        json!({"expected_turn":0,"text":"Human Grüße","idempotency_key":"stable-command"})
    );
}

#[tokio::test]
async fn uncertain_or_denied_post_never_becomes_a_success_or_an_automatic_retry() {
    for (status, headers, body, expected) in [
        // The full POST was received, then the peer disappeared without acknowledging it.
        (0, "", vec![], ReadError::CommitUnconfirmed),
        (
            202,
            "Content-Type: application/json\r\nCache-Control: no-store\r\n",
            b"{".to_vec(),
            ReadError::CommitUnconfirmed,
        ),
        (
            202,
            "Content-Type: text/html\r\nCache-Control: no-store\r\n",
            b"private".to_vec(),
            ReadError::CommitUnconfirmed,
        ),
        (
            202,
            "Content-Type: application/json\r\n",
            b"private".to_vec(),
            ReadError::CommitUnconfirmed,
        ),
        (
            202,
            "Content-Type: application/json\r\nCache-Control: no-store\r\n",
            vec![b'x'; 8193],
            ReadError::CommitUnconfirmed,
        ),
        (
            302,
            "Location: /other\r\n",
            vec![],
            ReadError::CommitUnconfirmed,
        ),
        (
            503,
            "",
            b"secret error".to_vec(),
            ReadError::CommitUnconfirmed,
        ),
        (
            401,
            "",
            b"secret error".to_vec(),
            ReadError::AuthenticationRequired,
        ),
        (403, "", b"secret error".to_vec(), ReadError::NotAuthorized),
        (409, "", b"secret error".to_vec(), ReadError::Conflict),
    ] {
        let (origin, server) = mock(status, headers, body);
        let client = Client::new(
            origin,
            SessionToken::from_bytes(Zeroizing::new(vec![b'a'; 64])).unwrap(),
        )
        .unwrap();
        let body = write_contract::CreateConversationRequest {
            main: write_contract::Optional::Value(false),
        };
        let request = write_contract::create_conversation(
            &client.http,
            &client.origin,
            &body,
            client
                .session
                .header_for(write_contract::SESSION_COOKIE)
                .unwrap(),
        )
        .unwrap();
        let result = match receipt(request, 202).await {
            Ok(bytes) => admitted(&bytes, 0).map(|_| ()),
            Err(error) => Err(error),
        };
        assert_eq!(result, Err(expected));
        server.join().unwrap();
    }
}
