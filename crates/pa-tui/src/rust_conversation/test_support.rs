//! Fixtures shared by the session and device tests: the discovery document exactly as the
//! instance publishes it, and a local fake server that records what it was sent.

use super::session::{hex_of, thumbprint, DiscoveryKey, APPENDED, KEYS_PATH, SCHEMA, TRUST_ROOT};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::time::Duration;

/// The document as `well_known.rs` publishes it: content-addressed first, then the five
/// fields appended over that address.
pub(super) fn published(origin: &str) -> serde_json::Value {
    let document = serde_json::json!({
        "schema": SCHEMA,
        "schema_revision": 1,
        "endpoints": {
            "canonical_origin": origin,
            "api": format!("{origin}/v1"),
            "session": format!("{origin}/v1/sessions"),
            "session_factor": format!("{origin}/v1/sessions/factors"),
            "session_refresh": format!("{origin}/v1/sessions/refresh"),
            "session_revoke": format!("{origin}/v1/sessions/current/revoke"),
            "device_authorization": format!("{origin}/v1/device-authorizations"),
            "device_authorization_token": format!("{origin}/v1/device-authorizations/tokens"),
            "device_verification": format!("{origin}/activate"),
            "run_stream": format!("{origin}/v1/runs/{{run_id}}/stream"),
        },
        "authentication_mode": "Local",
        "issuer": origin,
        "audiences": ["api"],
        "jwks_uri": format!("{origin}{KEYS_PATH}"),
        "public_clients": {
            "Spa": {
                "kind": "Spa",
                "public_client_id": "pa.api",
                "public_transport_kind": "SameOriginBffSessionCookie",
                "public_bootstrap_constraints": {"csrf_header": "pa-csrf"},
            },
            "Tui": {
                "schema": "personal-agent.auth.public-client-registration.v1",
                "kind": "Tui",
                "public_client_id": "pa.tui",
                "public_transport_kind": "DeviceAuthorizationSecureStore",
                "allowed_public_audiences": ["api"],
                "public_permissions": ["device_authorization.begin",
                    "device_authorization.poll", "session.refresh", "session.revoke"],
                "minimum_protocol_version": 1,
                "minimum_client_version": "2026.1.0",
            },
        },
        "device_authorization": {
            "state": "Supported",
            "authorization_endpoint": format!("{origin}/v1/device-authorizations"),
            "token_endpoint": format!("{origin}/v1/device-authorizations/tokens"),
            "client": "pa.tui",
        },
    });
    readdress(document)
}

/// The fixture instance's discovery signing key.
pub(super) fn pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

/// Another instance's key: well-formed, and not the one the fixture signs with.
pub(super) fn other_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap()
}

/// A key pair's published verification key.
pub(super) fn key_of(pair: &Ed25519KeyPair) -> DiscoveryKey {
    use base64::Engine as _;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    DiscoveryKey {
        kid: thumbprint(&x),
        x,
    }
}

/// The fixture instance's verification key.
pub(super) fn key() -> DiscoveryKey {
    key_of(&pair())
}

/// The key set as `well_known.rs` publishes it at `jwks_uri`.
pub(super) fn key_set(key: &DiscoveryKey) -> serde_json::Value {
    serde_json::json!({"keys": [{
        "kty": "OKP", "crv": "Ed25519", "x": key.x, "kid": key.kid, "alg": "EdDSA",
        "use": "sig", "key_ops": ["verify"], "trust_root": TRUST_ROOT,
    }]})
}

/// Re-publishes an edited document under its own new address and signature, as a
/// consistent (if malicious or misconfigured) instance would.
pub(super) fn readdress(document: serde_json::Value) -> serde_json::Value {
    readdress_with(document, &pair())
}

/// [`readdress`], signed by `pair`.
pub(super) fn readdress_with(
    mut document: serde_json::Value,
    pair: &Ed25519KeyPair,
) -> serde_json::Value {
    let object = document.as_object_mut().unwrap();
    for field in APPENDED {
        object.remove(field);
    }
    let digest = Sha256::digest(serde_json::to_vec(&document).unwrap());
    let address = hex_of(&digest);
    document["content_hash"] = serde_json::json!(address);
    document["etag"] = serde_json::json!(address);
    document["expires_in_seconds"] = serde_json::json!(300);
    document["signature"] = serde_json::json!(hex_of(pair.sign(&digest).as_ref()));
    document["signature_algorithm"] = serde_json::json!("EdDSA");
    document["signature_key_id"] = serde_json::json!(key_of(pair).kid);
    document["signature_trust_root"] = serde_json::json!(TRUST_ROOT);
    document
}

pub(super) fn etag_of(document: &serde_json::Value) -> String {
    format!("\"{}\"", document["content_hash"].as_str().unwrap())
}

/// One canned answer.
pub(super) struct Reply {
    pub status: u16,
    pub headers: String,
    pub body: Vec<u8>,
}

impl Reply {
    /// A `no-store` JSON answer, as every authentication endpoint gives.
    pub(super) fn json(status: u16, body: serde_json::Value) -> Self {
        Self {
            status,
            headers: "Content-Type: application/json\r\nCache-Control: no-store\r\n".into(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    /// The discovery document, with the validator it is served under.
    pub(super) fn document(document: &serde_json::Value) -> Self {
        Self {
            status: 200,
            headers: format!(
                "Content-Type: application/json\r\nCache-Control: public, max-age=300\r\nETag: {}\r\n",
                etag_of(document)
            ),
            body: serde_json::to_vec(document).unwrap(),
        }
    }

    /// The published key set, cacheable like the document.
    pub(super) fn keys(set: &serde_json::Value) -> Self {
        Self {
            status: 200,
            headers: "Content-Type: application/json\r\nCache-Control: public, max-age=300\r\n"
                .into(),
            body: serde_json::to_vec(set).unwrap(),
        }
    }

    /// The fixture instance's own key set.
    pub(super) fn fixture_keys() -> Self {
        Self::keys(&key_set(&key()))
    }

    pub(super) fn empty(status: u16) -> Self {
        Self {
            status,
            headers: String::new(),
            body: Vec::new(),
        }
    }
}

/// One request as it arrived: the head (lowercased header names are not assumed) and body.
pub(super) struct Seen {
    pub head: String,
    pub body: String,
}

impl Seen {
    pub(super) fn has_header(&self, line: &str) -> bool {
        self.head
            .to_ascii_lowercase()
            .contains(&format!("\r\n{}\r\n", line.to_ascii_lowercase()))
    }
}

/// A loopback HTTP server answering `replies` in order, one connection each.
pub(super) fn server(replies: Vec<Reply>) -> (reqwest::Url, std::thread::JoinHandle<Vec<Seen>>) {
    server_with(|_| replies)
}

/// [`server`], with replies built from the server's own origin (`http://127.0.0.1:port`).
pub(super) fn server_with(
    replies: impl FnOnce(&str) -> Vec<Reply>,
) -> (reqwest::Url, std::thread::JoinHandle<Vec<Seen>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let replies = replies(&url.origin().ascii_serialization());
    let task = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            let mut byte = [0];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
                assert!(head.len() < 16_384);
            }
            let head = String::from_utf8(head).unwrap();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            if reply.status == 0 {
                // A lost answer: the request arrived and the connection closes unanswered.
                drop(stream);
                seen.push(Seen {
                    head,
                    body: String::from_utf8(body).unwrap(),
                });
                continue;
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
            seen.push(Seen {
                head,
                body: String::from_utf8(body).unwrap(),
            });
        }
        seen
    });
    (url, task)
}

/// A fresh private directory for one test's store.
pub(super) fn scratch(name: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let directory = std::env::temp_dir().join(format!(
        "pa-tui-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}
