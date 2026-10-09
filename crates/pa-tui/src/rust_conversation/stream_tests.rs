//! A resumed stream applies frames once, in order, and never infers a Run outcome.
use super::*;

fn frames(wire: &str) -> Result<Vec<Frame>, ReadError> {
    let mut decoder = Decoder::default();
    let mut dispatched = Vec::new();
    for byte in wire.bytes() {
        if let Some(frame) = decoder.push(byte)? {
            dispatched.push(frame);
        }
    }
    Ok(dispatched)
}

fn applied() -> Applied {
    Applied::at(0)
}

#[test]
fn an_unterminated_final_frame_is_not_dispatched() {
    let complete = frames("id: 1\nevent: a\ndata: {}\n\n").expect("framing");
    assert_eq!(complete.len(), 1);
    assert_eq!(complete[0].id.as_deref(), Some("1"));
    assert_eq!(complete[0].event.as_deref(), Some("a"));
    // EOF is not an event boundary: the second frame never arrived.
    let partial = frames("id: 1\nevent: a\ndata: {}\n\nid: 2\ndata: {}").expect("framing");
    assert_eq!(partial.len(), 1);
}

#[test]
fn crlf_and_lf_are_one_line_ending_each() {
    assert_eq!(
        frames("id: 7\r\nevent: k\r\ndata: {}\r\n\r\n")
            .expect("framing")
            .len(),
        1
    );
}

#[test]
fn a_frame_is_applied_only_when_its_wire_id_kind_and_payload_agree() {
    let mut output = Vec::new();
    let mut state = applied();
    let frame = Frame {
        id: Some("4".into()),
        event: Some("run.started".into()),
        data: Some(r#"{"sequence":4,"kind":"run.started"}"#.into()),
    };
    reduce(&frame, &mut state, &mut output).expect("applied");
    assert_eq!((state.cursor, state.frames), (4, 1));
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("4 \"run.started\""));

    // The wire id and the payload sequence are one cursor, not two.
    let mismatched = Frame {
        id: Some("5".into()),
        event: Some("run.started".into()),
        data: Some(r#"{"sequence":6,"kind":"run.started"}"#.into()),
    };
    assert_eq!(
        reduce(&mismatched, &mut state, &mut Vec::new()),
        Err(ReadError::InvalidFrame)
    );
    // The named event and the payload kind are also one thing.
    let relabelled = Frame {
        id: Some("5".into()),
        event: Some("other".into()),
        data: Some(r#"{"sequence":5,"kind":"run.started"}"#.into()),
    };
    assert_eq!(
        reduce(&relabelled, &mut state, &mut Vec::new()),
        Err(ReadError::InvalidFrame)
    );
    assert_eq!((state.cursor, state.frames), (4, 1));
}

#[test]
fn a_replayed_or_out_of_order_sequence_never_advances_the_cursor() {
    let mut state = applied();
    state.cursor = 9;
    for sequence in [9, 8, 0] {
        let frame = Frame {
            id: Some(sequence.to_string()),
            event: Some("k".into()),
            data: Some(format!(r#"{{"sequence":{sequence},"kind":"k"}}"#)),
        };
        assert_eq!(
            reduce(&frame, &mut state, &mut Vec::new()),
            Err(ReadError::InvalidFrame)
        );
    }
    assert_eq!(state.cursor, 9);
}

#[test]
fn the_truncation_marker_asks_for_a_resume_without_becoming_one_more_frame() {
    let mut state = applied();
    state.cursor = 12;
    let marker = Frame {
        id: None,
        event: Some("cursor".into()),
        data: Some(r#"{"resume_from":12,"reason":"response_bound"}"#.into()),
    };
    reduce(&marker, &mut state, &mut Vec::new()).expect("marker");
    assert_eq!(state.marker.as_deref(), Some("response_bound"));
    assert_eq!((state.cursor, state.frames), (12, 0));

    // A marker naming a position this reducer did not reach is not a resume point.
    let mut elsewhere = applied();
    assert_eq!(
        reduce(&marker, &mut elsewhere, &mut Vec::new()),
        Err(ReadError::InvalidFrame)
    );
}

#[test]
fn a_resume_expired_marker_stops_the_client_instead_of_applying_across_the_gap() {
    let mut state = applied();
    state.cursor = 12;
    let marker = Frame {
        id: None,
        event: Some("cursor".into()),
        data: Some(
            r#"{"resume_from":40,"requested_from":12,"reason":"resume_expired","generation":1}"#
                .into(),
        ),
    };
    assert_eq!(
        reduce(&marker, &mut state, &mut Vec::new()),
        Err(ReadError::ResumeExpired)
    );
    // Nothing moved: the cursor still names the last applied frame and no frame was counted.
    assert_eq!(
        (state.cursor, state.frames, state.marker.is_none()),
        (12, 0, true)
    );
}

#[test]
fn an_identifierless_frame_that_is_not_the_marker_is_refused() {
    let mut state = applied();
    let frame = Frame {
        id: None,
        event: Some("run.started".into()),
        data: Some(r#"{"sequence":1,"kind":"run.started"}"#.into()),
    };
    assert_eq!(
        reduce(&frame, &mut state, &mut Vec::new()),
        Err(ReadError::InvalidFrame)
    );
}

// ---------------------------------------------------------------------------------------
// The live stream, against a local fake instance that writes its body slowly.
// ---------------------------------------------------------------------------------------

use std::io::Read as _;
use std::sync::{Arc, Mutex};

/// One thing the fake instance does on a connection, in order.
enum Step {
    /// Writes these bytes as one HTTP chunk.
    Send(String),
    /// Writes nothing for this long.
    Quiet(u64),
    /// Waits until the client has PRINTED this text, proving it rendered before the body ended.
    Rendered(&'static str),
}

/// What the client printed, readable by the fake instance while the follow is running.
#[derive(Clone, Default)]
struct Screen(Arc<Mutex<Vec<u8>>>);

impl Screen {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for Screen {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn event(sequence: i64) -> String {
    format!(
        "id: {sequence}\nevent: event\ndata: {{\"sequence\":{sequence},\"kind\":\"event\",\"generation\":1,\"terminal\":false}}\n\n"
    )
}

fn terminal(sequence: i64) -> String {
    format!(
        "id: {sequence}\nevent: terminal\ndata: {{\"sequence\":{sequence},\"kind\":\"terminal\",\"generation\":1,\"terminal\":true,\"terminal_kind\":\"completed\"}}\n\n"
    )
}

fn marker(reason: &str, resume_from: i64) -> String {
    format!("event: cursor\ndata: {{\"resume_from\":{resume_from},\"reason\":\"{reason}\"}}\n\n")
}

/// What axum's `KeepAlive::text("keep-alive")` writes.
const HEARTBEAT: &str = ":keep-alive\n\n";

/// A loopback instance serving one scripted, chunked `text/event-stream` per connection, and
/// returning the `Last-Event-ID` each connection asked with.
fn live_server(
    connections: Vec<Vec<Step>>,
    screen: Screen,
) -> (String, std::thread::JoinHandle<Vec<Option<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/v1/runs/0199a0f2-0000-7000-8000-00000000d003/stream",
        listener.local_addr().unwrap()
    );
    let task = std::thread::spawn(move || {
        let mut resumed = Vec::new();
        for steps in connections {
            let (mut socket, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0];
            while !head.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            resumed.push(head.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("last-event-id")
                    .then(|| value.trim().to_owned())
            }));
            // Write failures are ignored from here on: a client that gave up on a quiet
            // connection has closed it, which is the behaviour under test.
            let _ = socket.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            );
            for step in steps {
                match step {
                    Step::Send(text) => {
                        let _ = write!(socket, "{:x}\r\n{text}\r\n", text.len());
                        let _ = socket.flush();
                    }
                    Step::Quiet(ms) => std::thread::sleep(Duration::from_millis(ms)),
                    Step::Rendered(text) => {
                        let deadline = std::time::Instant::now() + Duration::from_secs(5);
                        while !screen.text().contains(text) {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "the client had not printed {text:?} while the connection was open"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                }
            }
            let _ = socket.write_all(b"0\r\n\r\n");
        }
        resumed
    });
    (url, task)
}

/// The live pace, scaled down: 400 ms between bytes stands in for 45 s.
const QUICK: Pace = Pace {
    idle: Duration::from_millis(400),
    head: Duration::from_secs(5),
    backoff: [
        Duration::from_millis(20),
        Duration::from_millis(40),
        Duration::from_millis(60),
    ],
    brief: Duration::from_millis(1),
};

async fn follow_live(
    connections: Vec<Vec<Step>>,
    cursor: i64,
) -> (Result<Ended, ReadError>, String, Vec<Option<String>>) {
    let screen = Screen::default();
    let (url, server) = live_server(connections, screen.clone());
    let http = stream_client().unwrap();
    let session = SessionToken::from_bytes(zeroize::Zeroizing::new(vec![b'a'; 64])).unwrap();
    let mut output = screen.clone();
    let ended = run_follow(&http, &url, &session, cursor, &mut output, &QUICK).await;
    (ended, screen.text(), server.join().unwrap())
}

#[tokio::test]
async fn a_quiet_live_run_with_heartbeats_is_followed_and_rendered_as_it_arrives() {
    let heartbeat = || Step::Send(HEARTBEAT.into());
    let (ended, screen, resumed) = follow_live(
        vec![vec![
            Step::Send(event(1)),
            // Printed while the connection is open, not when the body ends.
            Step::Rendered("1 \"event\""),
            // Five quiet stretches of 200 ms: 1 s in total, more than twice the idle bound,
            // held open by nothing but heartbeats.
            Step::Quiet(200),
            heartbeat(),
            Step::Quiet(200),
            heartbeat(),
            Step::Quiet(200),
            heartbeat(),
            Step::Quiet(200),
            heartbeat(),
            Step::Quiet(200),
            Step::Send(event(2)),
            Step::Rendered("2 \"event\""),
            Step::Send(terminal(3)),
        ]],
        0,
    )
    .await;
    assert_eq!(ended, Ok(Ended::Terminal("completed".into())));
    // One connection, asked for from the start.
    assert_eq!(resumed, vec![None]);
    assert!(screen.contains("3 \"terminal\""), "{screen}");
    assert!(screen.contains("Run ended: completed"), "{screen}");
    assert!(!screen.contains("Disconnected"), "{screen}");
}

#[tokio::test]
async fn every_cursor_reason_reconnects_with_the_last_applied_id() {
    let (ended, screen, resumed) = follow_live(
        vec![
            vec![
                Step::Send(event(1)),
                Step::Send(marker("response_bound", 1)),
            ],
            vec![
                Step::Send(event(2)),
                Step::Send(marker("reauthenticate", 2)),
            ],
            vec![Step::Send(event(3)), Step::Send(marker("slow_consumer", 3))],
            vec![Step::Send(event(4)), Step::Send(marker("unavailable", 4))],
            vec![Step::Send(event(5) + &terminal(6))],
        ],
        0,
    )
    .await;
    assert_eq!(ended, Ok(Ended::Terminal("completed".into())));
    assert_eq!(
        resumed,
        vec![
            None,
            Some("1".into()),
            Some("2".into()),
            Some("3".into()),
            Some("4".into())
        ]
    );
    for sequence in 1..=5 {
        assert!(
            screen.contains(&format!("{sequence} \"event\"")),
            "{screen}"
        );
    }
}

#[tokio::test]
async fn silence_past_the_idle_bound_is_a_dead_connection_resumed_from_the_cursor() {
    let (ended, _, resumed) = follow_live(
        vec![
            // Nothing at all — not even a heartbeat — for twice the idle bound.
            vec![Step::Send(event(1)), Step::Quiet(800)],
            vec![Step::Send(terminal(2))],
        ],
        0,
    )
    .await;
    assert_eq!(ended, Ok(Ended::Terminal("completed".into())));
    assert_eq!(resumed, vec![None, Some("1".into())]);
}

#[tokio::test]
async fn a_finite_batch_that_simply_ends_is_resumed_and_then_reported_disconnected() {
    // What an older instance serves: a batch, the body ends, and a caught-up answer is empty.
    let (ended, screen, resumed) =
        follow_live(vec![vec![Step::Send(event(3) + &event(4))], vec![]], 2).await;
    assert_eq!(ended, Ok(Ended::Disconnected));
    assert_eq!(resumed, vec![Some("2".into()), Some("4".into())]);
    assert!(screen.contains("Resume with --after 4"), "{screen}");
    assert!(screen.contains("outcome is not determined"), "{screen}");
}

#[tokio::test]
async fn a_resume_expired_marker_on_a_live_connection_stops_without_applying_across_it() {
    let (ended, screen, resumed) = follow_live(
        vec![vec![
            Step::Send(event(1)),
            Step::Quiet(100),
            Step::Send(
                "event: cursor\ndata: {\"resume_from\":40,\"reason\":\"resume_expired\"}\n\n"
                    .into(),
            ),
        ]],
        0,
    )
    .await;
    assert_eq!(ended, Err(ReadError::ResumeExpired));
    assert_eq!(resumed, vec![None]);
    assert!(screen.contains("1 \"event\""), "{screen}");
    // No resume point is offered across a gap: the only way on is to re-read state.
    assert!(!screen.contains("Resume with"), "{screen}");
}
