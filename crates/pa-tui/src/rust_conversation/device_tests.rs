//! The device flow, the store, presentation and refresh against a local fake instance.
use super::*;
use crate::rust_conversation::test_support::{key, published, readdress, scratch, server, Reply};
use serde_json::json;
use std::sync::{Arc, Mutex};

const DEVICE_CODE: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
const SESSION: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
const REFRESH: &str = "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e";
const ROTATED: &str = "8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f";
const FAMILY: &str = "01990000-0000-7000-8000-00000000f00d";
const USER_CODE: &str = "BCDF-GHJK";

fn origin_of(url: &reqwest::Url) -> String {
    url.origin().ascii_serialization()
}

fn begun(origin: &str, expires: u64, interval: u64) -> Reply {
    Reply::json(
        200,
        json!({
            "schema": BEGIN_SCHEMA,
            "device_code": DEVICE_CODE,
            "user_code": USER_CODE,
            "verification_uri": format!("{origin}/activate"),
            "verification_uri_complete": format!("{origin}/activate?user_code={USER_CODE}"),
            "expires_in_seconds": expires,
            "interval_seconds": interval,
        }),
    )
}

fn pending(retry: u64) -> Reply {
    Reply::json(
        400,
        json!({"schema": POLL_SCHEMA, "error": "authorization_pending", "retry_after_seconds": retry}),
    )
}

fn poll_error(error: &str) -> Reply {
    Reply::json(400, json!({"schema": POLL_SCHEMA, "error": error}))
}

fn granted() -> Reply {
    Reply::json(
        200,
        json!({
            "schema": POLL_SCHEMA,
            "result": "granted",
            "native_session_family_adoption": SESSION,
            "access": {"audience": "api", "expires_in_seconds": 3600,
                "session_cookie": "pa_session", "csrf_header": "pa-csrf", "family_id": FAMILY},
            "refresh_adoption": REFRESH,
        }),
    )
}

/// A sleeper that records every requested wait and returns at once.
fn recorder() -> (
    Arc<Mutex<Vec<u64>>>,
    impl FnMut(Duration) -> std::future::Ready<()>,
) {
    let waits = Arc::new(Mutex::new(Vec::new()));
    let recorded = waits.clone();
    (waits, move |wait: Duration| {
        recorded.lock().unwrap().push(wait.as_secs());
        std::future::ready(())
    })
}

fn http() -> reqwest::Client {
    session::client().unwrap()
}

fn loopback(url: &reqwest::Url) -> reqwest::Url {
    origin(url.as_str(), true).unwrap()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
#[tokio::test]
async fn the_full_flow_honours_slow_down_and_stores_the_session_privately() {
    // The document names the server's own origin, so the replies are built once it is bound.
    let (url, task) = server_for(|origin| {
        vec![
            Reply::document(&published(origin)),
            Reply::fixture_keys(),
            begun(origin, 600, 5),
            pending(5),
            Reply::json(
                400,
                json!({"schema": POLL_SCHEMA, "error": "slow_down", "next_interval_seconds": 10}),
            ),
            pending(10),
            granted(),
        ]
    });
    let directory = scratch("device-flow");
    let path = directory.join("session.toml");
    let (waits, sleep) = recorder();
    let mut prompt = Vec::new();
    let before = session::now_unix();
    login_at(&http(), &loopback(&url), &path, &mut prompt, sleep)
        .await
        .expect("granted");
    let seen = task.join().unwrap();

    // Interval, then the same interval while pending, then the slowed-down one, kept.
    assert_eq!(*waits.lock().unwrap(), vec![5, 5, 10, 10]);

    assert!(seen[0]
        .head
        .starts_with("GET /.well-known/personal-agent HTTP/1.1\r\n"));
    assert!(seen[1]
        .head
        .starts_with("GET /.well-known/personal-agent/jwks HTTP/1.1\r\n"));
    assert!(seen[2]
        .head
        .starts_with("POST /v1/device-authorizations HTTP/1.1\r\n"));
    assert!(seen[2].has_header("content-type: application/x-www-form-urlencoded"));
    assert_eq!(seen[2].body, "client_id=pa.tui");
    for poll in &seen[3..] {
        assert!(poll
            .head
            .starts_with("POST /v1/device-authorizations/tokens HTTP/1.1\r\n"));
        assert!(poll.has_header("content-type: application/x-www-form-urlencoded"));
        assert_eq!(
            poll.body,
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code\
                 &device_code={DEVICE_CODE}&client_id=pa.tui"
            )
        );
    }
    for request in &seen {
        let head = request.head.to_ascii_lowercase();
        assert!(!head.contains("\r\ncookie:") && !head.contains("\r\nauthorization:"));
    }

    // The Human sees the code and the prefilled page; the poll secret is never shown.
    let prompt = String::from_utf8(prompt).unwrap();
    assert!(prompt.contains(USER_CODE));
    assert!(prompt.contains(&format!("/activate?user_code={USER_CODE}")));
    assert!(!prompt.contains(DEVICE_CODE) && !prompt.contains(SESSION));

    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&directory), 0o700);
    let stored = session::load_at(&path).unwrap();
    assert_eq!(stored.origin, origin_of(&url));
    assert_eq!(stored.session_token, SESSION);
    assert_eq!(stored.refresh_token.as_deref(), Some(REFRESH));
    assert_eq!(stored.family_id.as_deref(), Some(FAMILY));
    assert_eq!(stored.transport, "DeviceAuthorizationSecureStore");
    let issued = stored.issued_at_unix.unwrap();
    assert!(issued >= before);
    assert_eq!(stored.expires_at_unix, Some(issued + 3600));
    assert_eq!(stored.refresh_after_unix, Some(issued + 1800));
    let _ = std::fs::remove_dir_all(directory);
}

/// Like [`server`], but the replies may name the server's own origin.
fn server_for(
    replies: impl FnOnce(&str) -> Vec<Reply>,
) -> (
    reqwest::Url,
    std::thread::JoinHandle<Vec<crate::rust_conversation::test_support::Seen>>,
) {
    crate::rust_conversation::test_support::server_with(replies)
}

#[tokio::test]
async fn slow_down_without_a_named_interval_still_adds_five_and_expiry_stops_the_poll() {
    let (url, task) = server_for(|origin| {
        vec![
            Reply::document(&published(origin)),
            Reply::fixture_keys(),
            begun(origin, 600, 5),
            poll_error("slow_down"),
            poll_error("expired_token"),
        ]
    });
    let path = scratch("device-expired").join("session.toml");
    let (waits, sleep) = recorder();
    let result = login_at(&http(), &loopback(&url), &path, &mut Vec::new(), sleep).await;
    assert_eq!(result, Err(ReadError::DeviceAuthorizationExpired));
    assert_eq!(*waits.lock().unwrap(), vec![5, 10]);
    assert_eq!(task.join().unwrap().len(), 5);
    assert!(
        !path.exists(),
        "nothing is stored for a ceremony that did not grant"
    );
}

#[tokio::test]
async fn every_terminal_poll_error_is_its_own_closed_outcome() {
    for (error, expected) in [
        ("access_denied", ReadError::DeviceAuthorizationDenied),
        ("expired_token", ReadError::DeviceAuthorizationExpired),
        ("invalid_grant", ReadError::DeviceAuthorizationInvalidGrant),
        (
            "unsupported_grant_type",
            ReadError::DeviceAuthorizationRefused,
        ),
        ("something_new", ReadError::InvalidResponse),
    ] {
        let (url, task) = server_for(|origin| {
            vec![
                Reply::document(&published(origin)),
                Reply::fixture_keys(),
                begun(origin, 600, 5),
                pending(5),
                poll_error(error),
            ]
        });
        let path = scratch("device-errors").join("session.toml");
        let (_, sleep) = recorder();
        let result = login_at(&http(), &loopback(&url), &path, &mut Vec::new(), sleep).await;
        assert_eq!(result, Err(expected), "{error}");
        task.join().unwrap();
        assert!(!path.exists());
    }
}

#[tokio::test]
async fn the_device_code_lifetime_is_budgeted_locally() {
    // Twelve seconds at five-second intervals: two polls fit, a third would outlive the code.
    let (url, task) = server_for(|origin| {
        vec![
            Reply::document(&published(origin)),
            Reply::fixture_keys(),
            begun(origin, 12, 5),
            pending(5),
            pending(5),
        ]
    });
    let path = scratch("device-budget").join("session.toml");
    let (waits, sleep) = recorder();
    let result = login_at(&http(), &loopback(&url), &path, &mut Vec::new(), sleep).await;
    assert_eq!(result, Err(ReadError::DeviceAuthorizationExpired));
    assert_eq!(*waits.lock().unwrap(), vec![5, 5]);
    assert_eq!(task.join().unwrap().len(), 5);
}

#[tokio::test]
async fn an_instance_without_the_facade_is_told_apart_and_nothing_is_begun() {
    let (url, task) = server_for(|origin| {
        let mut document = published(origin);
        document
            .as_object_mut()
            .unwrap()
            .remove("device_authorization");
        vec![Reply::document(&readdress(document)), Reply::fixture_keys()]
    });
    let path = scratch("device-unsupported").join("session.toml");
    let (_, sleep) = recorder();
    let result = login_at(&http(), &loopback(&url), &path, &mut Vec::new(), sleep).await;
    assert_eq!(result, Err(ReadError::DeviceAuthorizationUnsupported));
    assert_eq!(
        task.join().unwrap().len(),
        2,
        "the document and its key, nothing begun"
    );
}

#[tokio::test]
async fn a_document_naming_another_origin_stops_login_before_any_credential_flow() {
    let (url, task) = server_for(|_| vec![Reply::document(&published("https://localhost:9000"))]);
    let path = scratch("device-origin").join("session.toml");
    let (_, sleep) = recorder();
    let result = login_at(&http(), &loopback(&url), &path, &mut Vec::new(), sleep).await;
    assert_eq!(result, Err(ReadError::EndpointTrustUnverified));
    assert_eq!(
        task.join().unwrap().len(),
        1,
        "nothing after the refused document"
    );
}

#[test]
fn a_begin_result_may_point_only_at_the_published_verification_page() {
    let device = DeviceTrust {
        authorization: "https://pa.test/v1/device-authorizations".into(),
        token: "https://pa.test/v1/device-authorizations/tokens".into(),
        verification: "https://pa.test/activate".into(),
        client_id: "pa.tui".into(),
    };
    let result = |uri: &str, complete: Option<&str>, code: &str| {
        let begun: Begun = serde_json::from_value(json!({
            "schema": BEGIN_SCHEMA, "device_code": DEVICE_CODE, "user_code": code,
            "verification_uri": uri, "verification_uri_complete": complete,
            "expires_in_seconds": 600, "interval_seconds": 5,
        }))
        .unwrap();
        begun.check(&device)
    };
    let page = "https://pa.test/activate";
    assert!(result(
        page,
        Some("https://pa.test/activate?user_code=BCDF-GHJK"),
        USER_CODE
    )
    .is_ok());
    assert!(result(page, None, USER_CODE).is_ok());
    for (uri, complete, code) in [
        ("https://evil.test/activate", None, USER_CODE),
        (
            page,
            Some("https://evil.test/activate?user_code=BCDF-GHJK"),
            USER_CODE,
        ),
        (
            page,
            Some("https://pa.test/elsewhere?user_code=BCDF-GHJK"),
            USER_CODE,
        ),
        (
            page,
            Some("https://pa.test/activate?user_code=OTHER-CODE"),
            USER_CODE,
        ),
        (
            page,
            Some("https://pa.test/activate?user_code=BCDF-GHJK&device_code=x"),
            USER_CODE,
        ),
        (
            page,
            Some("https://pa.test/activate?user_code=BCDF-GHJK#x"),
            USER_CODE,
        ),
        (page, None, "\u{1b}]52;c;x\u{7}"),
    ] {
        assert!(result(uri, complete, code).is_err(), "{uri} {complete:?}");
    }
}

fn stored(origin: &str, trust: session::Trust, refresh_after: Option<u64>) -> Stored {
    Stored {
        origin: origin.to_owned(),
        session_token: SESSION.to_owned(),
        trust,
        transport: session::TUI_TRANSPORT.to_owned(),
        refresh_token: Some(REFRESH.to_owned()),
        family_id: Some(FAMILY.to_owned()),
        issued_at_unix: Some(1_000),
        expires_at_unix: Some(4_600),
        refresh_after_unix: refresh_after,
        family_expires_at_unix: None,
        must_change_password: false,
        refresh_in_flight: None,
    }
}

/// Stores a device session for the fake server, pinned to the trust it will serve.
async fn store_for(url: &reqwest::Url, name: &str, refresh_after: Option<u64>) -> PathBuf {
    let document = published(&origin_of(url));
    let trust = session::verify(
        &document,
        Some(&crate::rust_conversation::test_support::etag_of(&document)),
        &origin_of(url),
        &key(),
    )
    .unwrap();
    let path = scratch(name).join("session.toml");
    session::save_at(&path, &stored(&origin_of(url), trust, refresh_after)).unwrap();
    path
}

#[cfg(unix)]
#[tokio::test]
async fn the_store_refuses_files_others_could_read_or_that_are_links() {
    use std::os::unix::fs::PermissionsExt;
    let url = reqwest::Url::parse("http://127.0.0.1:9").unwrap();
    let path = store_for(&url, "store-perms", None).await;
    assert_eq!(mode(&path), 0o600);
    assert!(session::load_at(&path).is_ok());

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        session::load_at(&path).err(),
        Some(ReadError::SessionStoreUnusable)
    );

    // Replacing the store never writes through a planted link.
    let target = path.with_file_name("elsewhere");
    std::fs::write(&target, "untouched").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert_eq!(
        session::load_at(&path).err(),
        Some(ReadError::SessionStoreUnusable)
    );
    let document = published("http://127.0.0.1:9");
    let trust = session::verify(
        &document,
        Some(&crate::rust_conversation::test_support::etag_of(&document)),
        "http://127.0.0.1:9",
        &key(),
    )
    .unwrap();
    session::save_at(&path, &stored("http://127.0.0.1:9", trust, None)).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    assert_eq!(mode(&path), 0o600);
    assert!(session::load_at(&path).is_ok());

    assert_eq!(
        session::load_at(&path.with_file_name("absent.toml")).err(),
        Some(ReadError::NoStoredSession)
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn the_stored_session_is_presented_as_cookie_and_csrf_and_never_as_a_bearer() {
    let (url, task) = server_for(|origin| {
        vec![
            Reply::document(&published(origin)),
            Reply::json(
                200,
                json!({
                    "ordering": "callers_main_first,activity_at_desc,entity_key_desc",
                    "conversations": [{
                        "entity_key": "01990000-0000-7000-8000-0000000000aa",
                        "address": "conversation.conversation",
                        "main": true, "pinned": true, "hidden": false,
                        "branch_id": "01990000-0000-7000-8000-0000000000bb",
                        "created_at": "2026-09-26T10:00:00Z",
                        "updated_at": "2026-09-26T10:00:00Z",
                        "activity_at": "2026-09-26T11:00:00Z",
                        "title": "Grüße\u{1b}[2J", "label": "01990000-0000-7000-8000-0000000000cc",
                        "live_run": null, "revision": 1, "lifecycle": "active", "branch_head": 4,
                    }],
                    "next_cursor": null,
                    "label": null,
                    "policy_basis": "01990000-0000-7000-8000-0000000000dd",
                    "watermark": null,
                }),
            ),
        ]
    });
    let path = store_for(&url, "present", Some(4_000_000_000)).await;
    let http = http();
    let (token, trust) = session::present_at(&http, &loopback(&url), &path, 2_000, true)
        .await
        .unwrap();
    let rendered = super::super::conversations::fetch(&http, &trust, &token, 50, None, false)
        .await
        .unwrap();
    let seen = task.join().unwrap();
    assert_eq!(seen.len(), 2, "not due, so no refresh was sent");
    assert!(seen[1]
        .head
        .starts_with("GET /v1/conversations?limit=50 HTTP/1.1\r\n"));
    assert!(seen[1].has_header(&format!("cookie: pa_session={SESSION}")));
    assert!(seen[1].has_header("pa-csrf: 1"));
    assert!(!seen[1]
        .head
        .to_ascii_lowercase()
        .contains("\r\nauthorization:"));
    assert!(rendered.contains("Grüße") && !rendered.contains('\u{1b}'));
    assert!(rendered.contains("[main, pinned]"));
    assert!(rendered.contains("branch 01990000-0000-7000-8000-0000000000bb"));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn an_expired_session_and_an_uncacheable_page_are_not_rendered() {
    for (reply, expected) in [
        (
            Reply::json(401, json!({})),
            ReadError::AuthenticationRequired,
        ),
        (
            Reply {
                status: 200,
                headers: "Content-Type: application/json\r\n".into(),
                body: b"{}".to_vec(),
            },
            ReadError::InvalidResponse,
        ),
    ] {
        let (url, task) = server(vec![reply]);
        let document = published(&origin_of(&url));
        let trust = session::verify(
            &document,
            Some(&crate::rust_conversation::test_support::etag_of(&document)),
            &origin_of(&url),
            &key(),
        )
        .unwrap();
        let token = SessionToken::from_bytes(Zeroizing::new(SESSION.as_bytes().to_vec())).unwrap();
        let result =
            super::super::conversations::fetch(&http(), &trust, &token, 50, None, false).await;
        assert_eq!(result.err(), Some(expected));
        task.join().unwrap();
    }
}

/// The session the instance issues beside a rotation.
const NEXT_SESSION: &str = "6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a";

/// `RotatedRefresh` exactly as `sessions.rs` answers it: the body, `no-store`, and the new
/// session in a Secure/HttpOnly/SameSite=Strict cookie whose Max-Age is its life.
fn rotated(expires: i64, family_expires: i64) -> Reply {
    Reply {
        status: 200,
        headers: format!(
            "Content-Type: application/json\r\nCache-Control: no-store\r\n\
             Set-Cookie: pa_session={NEXT_SESSION}; Path=/; Secure; HttpOnly; SameSite=Strict; \
             Max-Age={expires}\r\n"
        ),
        body: serde_json::to_vec(&json!({
            "family_id": FAMILY,
            "refresh_token": ROTATED,
            "expires_in_seconds": expires,
            "family_expires_in_seconds": family_expires,
            "must_change_password": false,
        }))
        .unwrap(),
    }
}

/// The request's `Idempotency-Key`, if it carried one.
fn idempotency_key(seen: &crate::rust_conversation::test_support::Seen) -> Option<String> {
    seen.head.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("idempotency-key")
            .then(|| value.trim().to_owned())
    })
}

/// Every refresh request that reached the fake instance.
fn refreshes(
    seen: &[crate::rust_conversation::test_support::Seen],
) -> Vec<&crate::rust_conversation::test_support::Seen> {
    seen.iter()
        .filter(|request| {
            request
                .head
                .starts_with("POST /v1/sessions/refresh HTTP/1.1\r\n")
        })
        .collect()
}

#[tokio::test]
async fn a_due_session_adopts_the_rotated_session_and_presents_the_new_cookie() {
    let (url, task) = server_for(|origin| {
        vec![
            Reply::document(&published(origin)),
            rotated(3_600, 2_000_000),
        ]
    });
    let path = store_for(&url, "refresh", Some(2_800)).await;
    let (token, _) = session::present_at(&http(), &loopback(&url), &path, 3_000, true)
        .await
        .unwrap();
    // The session presented is the one the rotation issued, not the stored predecessor.
    assert_eq!(&*token.0, NEXT_SESSION.as_bytes());
    let seen = task.join().unwrap();
    assert_eq!(
        seen.len(),
        2,
        "the key is pinned; only the document and the refresh"
    );
    assert!(seen[1]
        .head
        .starts_with("POST /v1/sessions/refresh HTTP/1.1\r\n"));
    assert!(seen[1].has_header("content-type: application/json"));
    assert_eq!(seen[1].body, format!("{{\"refresh_token\":\"{REFRESH}\"}}"));
    let sent_key = idempotency_key(&seen[1]).expect("every refresh carries its recovery key");
    assert!(
        (1..=128).contains(&sent_key.len()) && sent_key.bytes().all(|byte| byte.is_ascii_graphic())
    );
    // Refresh is `security: []`: the session cookie is not sent along with it.
    assert!(!seen[1].head.to_ascii_lowercase().contains("\r\ncookie:"));

    let after = session::load_at(&path).unwrap();
    assert_eq!(after.session_token, NEXT_SESSION);
    assert_eq!(after.refresh_token.as_deref(), Some(ROTATED));
    assert!(after.refresh_in_flight.is_none());
    assert_eq!(after.issued_at_unix, Some(3_000));
    assert_eq!(after.expires_at_unix, Some(3_000 + 3_600));
    assert_eq!(after.refresh_after_unix, Some(3_000 + 1_800));
    assert_eq!(after.family_expires_at_unix, Some(3_000 + 2_000_000));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains(REFRESH) && !text.contains(SESSION));

    // The next invocation presents the adopted cookie with the CSRF proof.
    let (url2, task2) = server_for(|_| {
        vec![Reply::json(
            200,
            json!({"ordering": "callers_main_first,activity_at_desc,entity_key_desc",
                "conversations": [], "next_cursor": null, "label": null,
                "policy_basis": "01990000-0000-7000-8000-0000000000dd", "watermark": null}),
        )]
    });
    let document = published(&origin_of(&url2));
    let trust = session::verify(
        &document,
        Some(&crate::rust_conversation::test_support::etag_of(&document)),
        &origin_of(&url2),
        &key(),
    )
    .unwrap();
    super::super::conversations::fetch(&http(), &trust, &token, 50, None, false)
        .await
        .unwrap();
    let seen = task2.join().unwrap();
    assert!(seen[0].has_header(&format!("cookie: pa_session={NEXT_SESSION}")));
    assert!(seen[0].has_header("pa-csrf: 1"));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn refreshing_stops_at_the_family_end() {
    // The issued session ends with the family: there is no refresh point left before it.
    let (url, task) =
        server_for(|origin| vec![Reply::document(&published(origin)), rotated(600, 600)]);
    let path = store_for(&url, "refresh-family-end", Some(0)).await;
    session::present_at(&http(), &loopback(&url), &path, 3_000, true)
        .await
        .unwrap();
    task.join().unwrap();
    let after = session::load_at(&path).unwrap();
    assert_eq!(after.session_token, NEXT_SESSION);
    assert_eq!(after.expires_at_unix, Some(3_600));
    assert_eq!(after.family_expires_at_unix, Some(3_600));
    assert_eq!(after.refresh_after_unix, None);
    assert_eq!(after.refresh_token, None);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());

    // A family the store already knows to have ended is not asked again.
    let (url, task) = server_for(|origin| vec![Reply::document(&published(origin))]);
    let path = store_for(&url, "refresh-family-over", Some(0)).await;
    let mut stored = session::load_at(&path).unwrap();
    stored.family_expires_at_unix = Some(2_999);
    session::save_at(&path, &stored).unwrap();
    let (token, _) = session::present_at(&http(), &loopback(&url), &path, 3_000, true)
        .await
        .unwrap();
    assert_eq!(&*token.0, SESSION.as_bytes());
    assert_eq!(
        task.join().unwrap().len(),
        1,
        "no refresh for an ended family"
    );
    let after = session::load_at(&path).unwrap();
    assert_eq!(after.refresh_token, None);
    assert!(!std::fs::read_to_string(&path).unwrap().contains(REFRESH));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn an_unknown_outcome_is_recovered_once_with_the_same_key_and_body() {
    // A 5xx, and a connection closed before any answer: neither settles the rotation.
    for lost in [Reply::json(503, json!({})), Reply::empty(0)] {
        let (url, task) = server_for(|origin| {
            vec![
                Reply::document(&published(origin)),
                lost,
                rotated(3_600, 2_000_000),
            ]
        });
        let path = store_for(&url, "refresh-recover", Some(0)).await;
        let (token, _) = session::present_at(&http(), &loopback(&url), &path, 3_000, true)
            .await
            .unwrap();
        assert_eq!(&*token.0, NEXT_SESSION.as_bytes());
        let seen = task.join().unwrap();
        let sent = refreshes(&seen);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].body, sent[1].body, "the same body");
        assert_eq!(
            idempotency_key(sent[0]).unwrap(),
            idempotency_key(sent[1]).unwrap(),
            "the same key"
        );
        let after = session::load_at(&path).unwrap();
        assert_eq!(after.refresh_token.as_deref(), Some(ROTATED));
        assert!(after.refresh_in_flight.is_none());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

#[tokio::test]
async fn a_second_unknown_outcome_retires_the_credential_and_nothing_replays_it() {
    let (url, task) = server_for(|origin| {
        vec![
            Reply::document(&published(origin)),
            Reply::json(500, json!({})),
            Reply::empty(0),
        ]
    });
    let path = store_for(&url, "refresh-unknown", Some(0)).await;
    let (token, _) = session::present_at(&http(), &loopback(&url), &path, 3_000, true)
        .await
        .unwrap();
    assert_eq!(
        &*token.0,
        SESSION.as_bytes(),
        "the instance still judges it"
    );
    let seen = task.join().unwrap();
    let sent = refreshes(&seen);
    assert_eq!(
        sent.len(),
        2,
        "one presentation and its one recovery, no more"
    );
    assert!(sent
        .iter()
        .all(|request| idempotency_key(request).is_some()));
    let after = session::load_at(&path).unwrap();
    assert_eq!(after.refresh_token, None);
    assert!(after.refresh_in_flight.is_none());
    assert_eq!(after.refresh_after_unix, None);
    assert!(!std::fs::read_to_string(&path).unwrap().contains(REFRESH));

    // A later command has nothing to present: no keyless or second recovery replays it.
    let (url2, task2) = server_for(|origin| vec![Reply::document(&published(origin))]);
    let mut moved = session::load_at(&path).unwrap();
    moved.origin = origin_of(&url2);
    let document = published(&origin_of(&url2));
    moved.trust = session::verify(
        &document,
        Some(&crate::rust_conversation::test_support::etag_of(&document)),
        &origin_of(&url2),
        &key(),
    )
    .unwrap();
    session::save_at(&path, &moved).unwrap();
    session::present_at(&http(), &loopback(&url2), &path, 3_100, true)
        .await
        .unwrap();
    assert_eq!(task2.join().unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn a_refusal_or_a_conflict_is_final_and_never_recovered() {
    // 401: the family ended (30 days absolute, 7 idle), was revoked, or saw a replay.
    // 422: the key names another request. 400: the request shape was refused.
    for status in [401, 422, 400] {
        let (url, task) = server_for(|origin| {
            vec![
                Reply::document(&published(origin)),
                Reply {
                    status,
                    headers: "Content-Type: application/problem+json\r\n".into(),
                    body: b"{}".to_vec(),
                },
            ]
        });
        let path = store_for(&url, "refresh-final", Some(0)).await;
        let presented = session::present_at(&http(), &loopback(&url), &path, 3_000, true).await;
        assert!(
            presented.is_ok(),
            "{status}: the instance still judges the session"
        );
        let seen = task.join().unwrap();
        assert_eq!(refreshes(&seen).len(), 1, "{status}: no recovery attempt");
        let after = session::load_at(&path).unwrap();
        assert_eq!(after.refresh_token, None, "{status}");
        assert!(after.refresh_in_flight.is_none(), "{status}");
        assert_eq!(after.refresh_after_unix, None, "{status}");
        assert_eq!(after.session_token, SESSION, "{status}");
        assert!(!std::fs::read_to_string(&path).unwrap().contains(REFRESH));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

#[tokio::test]
async fn a_presentation_left_by_an_earlier_command_is_recovered_only_inside_its_window() {
    let left = |first_sent: u64, attempts: u8| session::InFlight {
        refresh_token: REFRESH.to_owned(),
        idempotency_key: "pa-tui-refresh-left-behind".to_owned(),
        first_sent_unix: first_sent,
        attempts,
    };
    // Inside the window, with its recovery unspent: recovered under its own key.
    let (url, task) = server_for(|origin| {
        vec![
            Reply::document(&published(origin)),
            rotated(3_600, 2_000_000),
        ]
    });
    let path = store_for(&url, "refresh-left", None).await;
    let mut stored = session::load_at(&path).unwrap();
    stored.refresh_token = None;
    stored.refresh_in_flight = Some(left(2_990, 1));
    session::save_at(&path, &stored).unwrap();
    let (token, _) = session::present_at(&http(), &loopback(&url), &path, 3_000, true)
        .await
        .unwrap();
    assert_eq!(&*token.0, NEXT_SESSION.as_bytes());
    let seen = task.join().unwrap();
    assert_eq!(
        idempotency_key(&seen[1]).as_deref(),
        Some("pa-tui-refresh-left-behind")
    );
    assert_eq!(seen[1].body, format!("{{\"refresh_token\":\"{REFRESH}\"}}"));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());

    // Past the window, or with the recovery spent: a presentation would be a replay.
    for leftover in [left(2_600, 1), left(2_990, 2)] {
        let (url, task) = server_for(|origin| vec![Reply::document(&published(origin))]);
        let path = store_for(&url, "refresh-left-late", None).await;
        let mut stored = session::load_at(&path).unwrap();
        stored.refresh_token = None;
        stored.refresh_in_flight = Some(leftover);
        session::save_at(&path, &stored).unwrap();
        session::present_at(&http(), &loopback(&url), &path, 3_000, true)
            .await
            .unwrap();
        assert_eq!(task.join().unwrap().len(), 1, "nothing presented");
        let after = session::load_at(&path).unwrap();
        assert!(after.refresh_in_flight.is_none() && after.refresh_token.is_none());
        assert!(!std::fs::read_to_string(&path).unwrap().contains(REFRESH));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_rotation_already_under_way_elsewhere_is_not_raced() {
    let (url, task) = server_for(|origin| vec![Reply::document(&published(origin))]);
    let path = store_for(&url, "refresh-locked", Some(0)).await;
    let held = session::lock_store(&path).unwrap().expect("free");
    let (token, _) = session::present_at(&http(), &loopback(&url), &path, 3_000, true)
        .await
        .unwrap();
    drop(held);
    assert_eq!(&*token.0, SESSION.as_bytes());
    assert_eq!(task.join().unwrap().len(), 1, "no second presenter");
    assert_eq!(
        session::load_at(&path).unwrap().refresh_token.as_deref(),
        Some(REFRESH)
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn a_rotation_that_never_left_the_machine_keeps_its_credential() {
    // The server answers one request and closes its listener: the refresh endpoint on this
    // origin then refuses the connection, so the request provably never arrived.
    let (url, task) = server_for(|origin| vec![Reply::document(&published(origin))]);
    let _ = http()
        .get(format!("{url}.well-known/personal-agent"))
        .send()
        .await;
    let path = store_for(&url, "refresh-unsent", Some(0)).await;
    task.join().unwrap();
    let mut stored = session::load_at(&path).unwrap();
    let trust = stored.trust.clone();
    let notice = session::rotate_refresh(&http(), &trust, &path, &mut stored, 3_000)
        .await
        .unwrap();
    assert!(notice.is_some());
    assert_eq!(stored.refresh_token.as_deref(), Some(REFRESH));
    let after = session::load_at(&path).unwrap();
    assert_eq!(after.refresh_token.as_deref(), Some(REFRESH));
    assert!(
        after.refresh_in_flight.is_none(),
        "an unsent credential keeps no key"
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn logout_revokes_with_cookie_and_csrf_and_removes_the_store() {
    let (url, task) =
        server_for(|origin| vec![Reply::document(&published(origin)), Reply::empty(204)]);
    let path = store_for(&url, "logout", Some(0)).await;
    session::logout_at(&http(), &loopback(&url), &path)
        .await
        .unwrap();
    let seen = task.join().unwrap();
    assert_eq!(seen.len(), 2, "logout does not rotate first");
    assert!(seen[1]
        .head
        .starts_with("POST /v1/sessions/current/revoke HTTP/1.1\r\n"));
    assert!(seen[1].has_header(&format!("cookie: pa_session={SESSION}")));
    assert!(seen[1].has_header("pa-csrf: 1"));
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn a_drifted_endpoint_set_fences_the_stored_session_before_it_is_sent() {
    let (url, task) = server_for(|origin| {
        let mut document = published(origin);
        document["endpoints"]["session_revoke"] = json!(format!("{origin}/v1/moved"));
        vec![Reply::document(&readdress(document))]
    });
    let path = store_for(&url, "drift", None).await;
    assert_eq!(
        session::logout_at(&http(), &loopback(&url), &path)
            .await
            .err(),
        Some(ReadError::EndpointTrustChanged)
    );
    assert_eq!(
        task.join().unwrap().len(),
        1,
        "no credential left for the drifted set"
    );
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
