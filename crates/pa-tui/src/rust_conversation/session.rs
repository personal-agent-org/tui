//! Authentication bootstrap, endpoint trust and the local session store (§5.2, §7.2, §19.2).
//!
//! Two ceremonies open a session, and both are described by the instance itself: §19.2
//! requires every endpoint to be derived from the instance's published endpoint set, so each
//! comes from the verified `/.well-known/personal-agent` document and none is typed here.
//!
//! - The RFC 8628 device authorization (`device.rs`), which is the TUI's registered bootstrap
//!   (§7.2: "TUI uses `DeviceAuthorizationSecureStore`"). It delivers a session family plus
//!   its first refresh credential, both kept in the store below.
//! - The local-password ceremony: `POST {session}` proves the primary credential and, when
//!   the instance answers with the pre-authentication continuation, the TOTP factor is
//!   completed at `POST {session_factor}`. Its rotating refresh credential is deliberately
//!   neither used nor written to disk.
//!
//! Either way the session is presented as the `pa_session` cookie plus the `pa-csrf` header:
//! the instance has no bearer path. Not the legacy `~/.config/personal-agent/tui/config.toml`.

use super::*;
use reqwest::header::{ACCEPT, COOKIE, ETAG, SET_COOKIE};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The credential-free document a client reads before it trusts anything (§19.2).
const WELL_KNOWN_PATH: &str = "/.well-known/personal-agent";
/// The exact schema this client knows how to verify.
pub(super) const SCHEMA: &str = "personal-agent.well-known.v1";
/// Where the instance publishes the key its discovery signature verifies against. The
/// document's `jwks_uri` must name exactly this URL on the pinned origin.
pub(super) const KEYS_PATH: &str = "/.well-known/personal-agent/jwks";
/// The trust root the publisher names for its detached signature, and the published key's.
pub(super) const TRUST_ROOT: &str = "deployment_discovery_ed25519.v1";
/// The one signature algorithm this client verifies (RFC 8037 Ed25519).
pub(super) const SIGNATURE_ALGORITHM: &str = "EdDSA";
/// This release's public client id for the terminal (§7.2 line 2561).
pub(super) const TUI_CLIENT_ID: &str = "pa.tui";
/// The one credential-transport profile this client kind is registered with (§7.2).
pub(super) const TUI_TRANSPORT: &str = "DeviceAuthorizationSecureStore";
/// The audience every Human session, device-approved or not, is valid for.
pub(super) const AUDIENCE: &str = "api";
/// How the password ceremony's session is recorded in the store.
const PASSWORD_TRANSPORT: &str = "LocalPasswordSession";
/// The fields the publisher appends *after* it content-addresses the document, and which
/// therefore have to be removed again before the digest can be recomputed.
pub(super) const APPENDED: [&str; 7] = [
    "content_hash",
    "etag",
    "expires_in_seconds",
    "signature",
    "signature_algorithm",
    "signature_key_id",
    "signature_trust_root",
];
/// A published key set holds one key in this release; a few are tolerated for rollover.
const MAX_KEY_SET_BYTES: usize = 8_192;
/// A discovery document is small; anything larger is not this document.
const MAX_DOCUMENT_BYTES: usize = 65_536;
/// A login or factor receipt carries identifiers only.
const MAX_RECEIPT_BYTES: usize = 8_192;
/// The password and the optional one-time code, one per line, and nothing else.
const MAX_CREDENTIAL_BYTES: usize = 4_096;

/// What this client pins about one instance: the exact endpoint set it may use, the digest
/// the instance published it under, and the detached signature it published over it.
///
/// `ClientEndpointSetEvidence::Instance` in §19.2 is exactly this pair — the endpoint set
/// plus the well-known revision it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trust {
    /// Lowercase hex SHA-256 over the document as published, before the appended fields.
    pub content_hash: String,
    /// The publisher's detached Ed25519 signature over that digest, as published, verified.
    pub signature: String,
    /// The trust root the publisher names for that signature.
    pub signature_trust_root: String,
    /// The RFC 7638 thumbprint of the key the signature verified against. A store written
    /// before the signature was verifiable lacks it and so fences as drift.
    #[serde(default)]
    pub signature_key_id: String,
    /// That key's public half (RFC 8037 `x`, base64url). Pinned: a later invocation verifies
    /// against this key and never fetches a replacement for it.
    #[serde(default)]
    pub signature_key: String,
    /// The origin the document claims to be, which must be the pinned one.
    pub canonical_origin: String,
    /// The derived endpoint set. §19.2: a client may use no endpoint it had to type.
    pub api: String,
    /// `OpenSession`.
    pub session: String,
    /// `CompleteAuthenticationFactor`.
    pub session_factor: String,
    /// `RevokeCurrentSession`.
    pub session_revoke: String,
    /// `StreamRunDelivery`, still carrying its `{run_id}` placeholder.
    pub run_stream: String,
    /// `RefreshSession`. Absent from a store written before this field existed, which then
    /// no longer equals the live document and fences as drift.
    #[serde(default)]
    pub session_refresh: String,
    /// The RFC 8628 facade, when the document names one for this client's exact profile.
    /// `None` is the explicit "unsupported by this instance", never a guessed endpoint.
    #[serde(default)]
    pub device: Option<DeviceTrust>,
}

/// §7.2 `OptionalDeviceAuthorizationDiscovery::Supported`, checked against this release's
/// own expectation of the TUI registration (kind, client id, transport, audience).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrust {
    /// `BeginDeviceAuthorization`.
    pub authorization: String,
    /// `PollDeviceAuthorization`.
    pub token: String,
    /// The page a Human approves on; `verification_uri` must be exactly this.
    pub verification: String,
    /// The registered public client id (`pa.tui`).
    pub client_id: String,
}

/// The one instance session this client holds, and the trust it was obtained under.
///
/// This is the TUI's `DeviceAuthorizationSecureStore` partition. No OS keyring backend is
/// linked into this build, so it is one mode-0600 file in a mode-0700 directory owned by
/// this user; secrets never reach argv, the environment or stdout.
#[derive(Serialize, Deserialize)]
pub struct Stored {
    /// The canonical origin this session belongs to. A session is never presented to
    /// another origin, whatever the invocation asks for.
    pub origin: String,
    /// The session cookie's value, as lowercase hex.
    pub session_token: String,
    /// The endpoint-trust binding in force when the session was opened.
    pub trust: Trust,
    /// Which ceremony opened it: `DeviceAuthorizationSecureStore` or `LocalPasswordSession`.
    #[serde(default)]
    pub transport: String,
    /// The family's current refresh credential, lowercase hex, not yet presented. Before it
    /// is presented it moves into [`Stored::refresh_in_flight`] together with the
    /// `Idempotency-Key` it is sent under, in one atomic store write.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// The session family, as the instance named it.
    #[serde(default)]
    pub family_id: Option<String>,
    /// Unix seconds: when the session was delivered, when the instance said it ends, and
    /// from when on this client rotates the refresh credential before presenting it.
    #[serde(default)]
    pub issued_at_unix: Option<u64>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
    #[serde(default)]
    pub refresh_after_unix: Option<u64>,
    /// Unix seconds: when the family itself ends (the instance's
    /// `family_expires_in_seconds`). No refresh is sent from then on.
    #[serde(default)]
    pub family_expires_at_unix: Option<u64>,
    /// Whether the family is still confined to the password change (§5.2).
    #[serde(default)]
    pub must_change_password: bool,
    /// A presented refresh credential whose outcome is not yet known, with its key.
    #[serde(default)]
    pub refresh_in_flight: Option<InFlight>,
}

/// One presented refresh credential and the `Idempotency-Key` it was presented under.
///
/// §7.2 `RefreshRotationCommandRevision`: a lost answer is recovered by presenting the same
/// credential, key and body once more inside the instance's recovery window. Nothing else
/// may present it again -- another key, no key, a second recovery or a late one is a replay
/// that revokes the whole family -- so the credential never exists on disk without its key.
#[derive(Serialize, Deserialize)]
pub struct InFlight {
    /// The presented credential, lowercase hex.
    pub refresh_token: String,
    /// The key it was presented under: 1..=128 visible ASCII bytes.
    pub idempotency_key: String,
    /// Unix seconds of the first presentation; the recovery window runs from here.
    pub first_sent_unix: u64,
    /// Presentations made or begun: 1 after the first, 2 once the one recovery is spent.
    pub attempts: u8,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
    }
}

impl Drop for Stored {
    fn drop(&mut self) {
        self.session_token.zeroize();
        if let Some(refresh) = self.refresh_token.as_mut() {
            refresh.zeroize();
        }
    }
}

/// Seconds since the Unix epoch, by this machine's clock.
pub(super) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// A transport failure, told apart only where the distinction changes what the user does:
/// an untrusted certificate is a trust decision, not a network fault.
pub(super) fn transport(error: &reqwest::Error) -> ReadError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        let text = current.to_string();
        if text.contains("UnknownIssuer")
            || text.contains("invalid peer certificate")
            || text.contains("CaUsedAsEndEntity")
        {
            return ReadError::TlsUntrusted;
        }
        source = current.source();
    }
    ReadError::Transport
}

pub(super) fn client() -> Result<reqwest::Client, ReadError> {
    pa_oidc::tls::http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| ReadError::Transport)
}

/// The origin this invocation pins, in its one canonical spelling.
pub(super) fn pinned(origin: &reqwest::Url) -> String {
    origin.origin().ascii_serialization()
}

/// Reads a bounded response body without letting a declared or actual length grow it.
pub(super) async fn bounded(
    response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, ReadError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(ReadError::InvalidResponse);
    }
    let mut bytes = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|_| ReadError::Transport)?;
        if chunk.len() > maximum - bytes.len() {
            return Err(ReadError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(super) fn is_json(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
}

pub(super) fn no_store(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
        })
}

pub(super) fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn text<'a>(document: &'a serde_json::Value, field: &str) -> Result<&'a str, ReadError> {
    document
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(ReadError::EndpointTrustUnverified)
}

/// One published discovery verification key, reduced to what the signature check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DiscoveryKey {
    /// The RFC 7638 thumbprint the document's `signature_key_id` names.
    pub kid: String,
    /// The Ed25519 public key, base64url without padding (RFC 8037 `x`).
    pub x: String,
}

impl Trust {
    /// The key this trust was verified against, when it was.
    pub(super) fn discovery_key(&self) -> Option<DiscoveryKey> {
        (!self.signature_key_id.is_empty() && !self.signature_key.is_empty()).then(|| {
            DiscoveryKey {
                kid: self.signature_key_id.clone(),
                x: self.signature_key.clone(),
            }
        })
    }
}

/// The 32 key bytes of a canonical base64url `x`; a padded, non-canonical or wrongly sized
/// spelling is not the published key.
fn ed25519_public(x: &str) -> Result<Vec<u8>, ReadError> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = engine
        .decode(x)
        .map_err(|_| ReadError::EndpointTrustUnverified)?;
    if bytes.len() != 32 || engine.encode(&bytes) != x {
        return Err(ReadError::EndpointTrustUnverified);
    }
    Ok(bytes)
}

/// The RFC 7638 thumbprint of an `OKP`/`Ed25519` key: SHA-256 over its required members in
/// lexicographic order, base64url.
pub(super) fn thumbprint(x: &str) -> String {
    use base64::Engine as _;
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The bytes of a value already checked to be lowercase hex.
fn bytes_of_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                _ => byte - b'a' + 10,
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

/// Selects the key `kid` from a published key set and checks it is the key it claims to be:
/// exactly one member names it, it is an Ed25519 verification key under this trust root, and
/// its id is its own thumbprint.
pub(super) fn select_key(keys: &serde_json::Value, kid: &str) -> Result<DiscoveryKey, ReadError> {
    let set = keys
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or(ReadError::EndpointTrustUnverified)?;
    let mut named = set
        .iter()
        .filter(|key| key.get("kid").and_then(serde_json::Value::as_str) == Some(kid));
    let key = named.next().ok_or(ReadError::EndpointTrustUnverified)?;
    if named.next().is_some() {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let verifies = key
        .get("key_ops")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")));
    if text(key, "kty")? != "OKP"
        || text(key, "crv")? != "Ed25519"
        || text(key, "alg")? != SIGNATURE_ALGORITHM
        || text(key, "use")? != "sig"
        || text(key, "trust_root")? != TRUST_ROOT
        || !verifies
    {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let x = text(key, "x")?;
    ed25519_public(x)?;
    if thumbprint(x) != kid {
        return Err(ReadError::EndpointTrustUnverified);
    }
    Ok(DiscoveryKey {
        kid: kid.to_owned(),
        x: x.to_owned(),
    })
}

/// Verifies one fetched discovery document against the origin the invocation pinned and the
/// key its signature names.
///
/// Four independent things are checked, and none of them is the transport: the document
/// says it is this origin, the digest it is addressed by is the digest of the bytes that
/// were actually served, the served `ETag` is that same digest, and the detached Ed25519
/// signature over that digest verifies against `key` -- whose thumbprint is the
/// `signature_key_id` the document names.
pub(super) fn verify(
    document: &serde_json::Value,
    etag: Option<&str>,
    origin: &str,
    key: &DiscoveryKey,
) -> Result<Trust, ReadError> {
    let object = document
        .as_object()
        .ok_or(ReadError::EndpointTrustUnverified)?;
    if text(document, "schema")? != SCHEMA || document.get("schema_revision").is_none() {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let content_hash = text(document, "content_hash")?.to_owned();
    if !lowercase_hex(&content_hash, 64) {
        return Err(ReadError::EndpointTrustUnverified);
    }
    // The served validator and the document's own address cannot disagree.
    if text(document, "etag")? != content_hash
        || etag.is_some_and(|served| served != format!("\"{content_hash}\""))
    {
        return Err(ReadError::EndpointTrustUnverified);
    }
    // Recompute the address over exactly the bytes that were content-addressed. Both sides
    // serialize a JSON object in one canonical key order, so this is a byte comparison and
    // not a structural guess.
    let mut addressed = object.clone();
    for field in APPENDED {
        if addressed.remove(field).is_none() {
            return Err(ReadError::EndpointTrustUnverified);
        }
    }
    let bytes = serde_json::to_vec(&serde_json::Value::Object(addressed))
        .map_err(|_| ReadError::EndpointTrustUnverified)?;
    if hex_of(&Sha256::digest(&bytes)) != content_hash {
        return Err(ReadError::EndpointTrustUnverified);
    }

    // The detached signature: Ed25519 over the 32 digest bytes, under the named key.
    let signature = text(document, "signature")?.to_owned();
    if !lowercase_hex(&signature, 128)
        || text(document, "signature_algorithm")? != SIGNATURE_ALGORITHM
        || text(document, "signature_trust_root")? != TRUST_ROOT
        || text(document, "signature_key_id")? != key.kid
        || thumbprint(&key.x) != key.kid
        || text(document, "jwks_uri")? != format!("{origin}{KEYS_PATH}")
    {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let public = ed25519_public(&key.x)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
        .verify(&bytes_of_hex(&content_hash), &bytes_of_hex(&signature))
        .map_err(|_| ReadError::EndpointTrustUnverified)?;

    if text(document, "issuer")? != origin {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let endpoints = document
        .get("endpoints")
        .ok_or(ReadError::EndpointTrustUnverified)?;
    if text(endpoints, "canonical_origin")? != origin {
        return Err(ReadError::EndpointTrustUnverified);
    }
    // Every derived endpoint must be on the pinned origin. A published endpoint set that
    // points somewhere else is drift, not a redirect this client may follow.
    let derived = |name: &str| -> Result<String, ReadError> {
        let value = text(endpoints, name)?;
        if !value.starts_with(&format!("{origin}/")) {
            return Err(ReadError::EndpointTrustUnverified);
        }
        Ok(value.to_owned())
    };
    // The bootstrap constraints have to describe the request this client actually makes.
    let spa = document
        .pointer("/public_clients/Spa/public_bootstrap_constraints")
        .ok_or(ReadError::EndpointTrustUnverified)?;
    if text(spa, "csrf_header")? != contract::CSRF_HEADER {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let device = device_trust(document, &derived)?;
    Ok(Trust {
        content_hash,
        signature,
        signature_trust_root: TRUST_ROOT.to_owned(),
        signature_key_id: key.kid.clone(),
        signature_key: key.x.clone(),
        canonical_origin: origin.to_owned(),
        api: derived("api")?,
        session: derived("session")?,
        session_factor: derived("session_factor")?,
        session_revoke: derived("session_revoke")?,
        run_stream: derived("run_stream")?,
        session_refresh: derived("session_refresh")?,
        device,
    })
}

/// The document's RFC 8628 discovery, checked against this release's TUI registration.
///
/// §7.2: a client validates "their exact client-kind/transport/audience profile and treat[s]
/// missing optional device support explicitly". So an absent or non-`Supported` facade is
/// `None`, while a `Supported` facade whose registration disagrees with what this release
/// expects refuses the whole document: that is confusion, not absence.
fn device_trust(
    document: &serde_json::Value,
    derived: &dyn Fn(&str) -> Result<String, ReadError>,
) -> Result<Option<DeviceTrust>, ReadError> {
    let Some(facade) = document.get("device_authorization") else {
        return Ok(None);
    };
    if text(facade, "state")? != "Supported" {
        return Ok(None);
    }
    let tui = document
        .pointer("/public_clients/Tui")
        .ok_or(ReadError::EndpointTrustUnverified)?;
    let listed = |field: &str, wanted: &str| {
        tui.get(field)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(wanted)))
    };
    if text(tui, "kind")? != "Tui"
        || text(tui, "public_client_id")? != TUI_CLIENT_ID
        || text(tui, "public_transport_kind")? != TUI_TRANSPORT
        || text(facade, "client")? != TUI_CLIENT_ID
        || !listed("allowed_public_audiences", AUDIENCE)
        || !listed("public_permissions", "device_authorization.begin")
        || !listed("public_permissions", "device_authorization.poll")
    {
        return Err(ReadError::EndpointTrustUnverified);
    }
    // The facade's two endpoints and the endpoint set must name the same URLs: two
    // spellings of one endpoint in one signed document is exactly what may not be guessed
    // between.
    let authorization = derived("device_authorization")?;
    let token = derived("device_authorization_token")?;
    if text(facade, "authorization_endpoint")? != authorization
        || text(facade, "token_endpoint")? != token
    {
        return Err(ReadError::EndpointTrustUnverified);
    }
    Ok(Some(DeviceTrust {
        authorization,
        token,
        verification: derived("device_verification")?,
        client_id: TUI_CLIENT_ID.to_owned(),
    }))
}

/// Fetches and verifies the instance's published endpoint set. Credential-free by design.
///
/// With `pinned_key` -- the key an earlier invocation verified this origin's discovery
/// against -- a document naming that key is verified against it without fetching the key
/// set again. Otherwise the key set is fetched from the one same-origin URL the document
/// must name; a document naming another key then no longer equals the pinned trust.
pub(super) async fn discover(
    http: &reqwest::Client,
    origin: &reqwest::Url,
    pinned_key: Option<&DiscoveryKey>,
) -> Result<Trust, ReadError> {
    let mut url = origin.clone();
    url.set_path(WELL_KNOWN_PATH);
    let response = http
        .get(url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| transport(&error))?;
    if response.status().as_u16() != 200 || !is_json(&response) {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let etag = response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = bounded(response, MAX_DOCUMENT_BYTES).await?;
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ReadError::EndpointTrustUnverified)?;
    // A document that does not name this origin's key set is refused before anything is
    // fetched for it; the full check follows in `verify`.
    if text(&document, "jwks_uri")? != format!("{}{KEYS_PATH}", pinned(origin)) {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let kid = text(&document, "signature_key_id")?;
    let key = match pinned_key {
        Some(key) if key.kid == kid => key.clone(),
        _ => published_key(http, origin, kid).await?,
    };
    verify(&document, etag.as_deref(), &pinned(origin), &key)
}

/// Fetches the published key set from the pinned origin and selects the key `kid`.
async fn published_key(
    http: &reqwest::Client,
    origin: &reqwest::Url,
    kid: &str,
) -> Result<DiscoveryKey, ReadError> {
    let mut url = origin.clone();
    url.set_path(KEYS_PATH);
    let response = http
        .get(url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| transport(&error))?;
    if response.status().as_u16() != 200 || !is_json(&response) {
        return Err(ReadError::EndpointTrustUnverified);
    }
    let bytes = bounded(response, MAX_KEY_SET_BYTES).await?;
    let keys: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ReadError::EndpointTrustUnverified)?;
    select_key(&keys, kid)
}

/// Where the one stored session lives. `PA_RUST_CLIENT_HOME` selects an explicit directory;
/// otherwise it is this user's own configuration directory. Never `/etc`, never the legacy
/// TUI config file, and never a path derived from the server argument.
pub(super) fn store_path() -> Result<PathBuf, ReadError> {
    let directory = match std::env::var("PA_RUST_CLIENT_HOME") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(ReadError::SessionStoreUnusable);
            }
            path
        }
        _ => dirs::config_dir()
            .ok_or(ReadError::SessionStoreUnusable)?
            .join("personal-agent")
            .join("rust-client"),
    };
    Ok(directory.join("session.toml"))
}

/// Writes the session under this user's exclusive 0600 file, replacing any predecessor.
///
/// The bytes go to a fresh sibling created exclusively with mode 0600 and are renamed over
/// the store, so a reader sees the old file or the new one and never a partial write, and a
/// pre-existing symlink or foreign file at either path never receives the credential.
#[cfg(unix)]
pub(super) fn save_at(path: &Path, stored: &Stored) -> Result<(), ReadError> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let directory = path.parent().ok_or(ReadError::SessionStoreUnusable)?;
    std::fs::create_dir_all(directory).map_err(|_| ReadError::SessionStoreUnusable)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| ReadError::SessionStoreUnusable)?;
    let text =
        Zeroizing::new(toml::to_string(stored).map_err(|_| ReadError::SessionStoreUnusable)?);
    let staging = path.with_extension("toml.new");
    let _ = std::fs::remove_file(&staging);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staging)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&staging, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&staging);
        return Err(ReadError::SessionStoreUnusable);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn save_at(_: &Path, _: &Stored) -> Result<(), ReadError> {
    Err(ReadError::SessionStoreUnusable)
}

fn save(stored: &Stored) -> Result<PathBuf, ReadError> {
    let path = store_path()?;
    save_at(&path, stored)?;
    Ok(path)
}

/// Reads the stored session, refusing a file anyone else can read or follow.
#[cfg(unix)]
pub(super) fn load_at(path: &Path) -> Result<Stored, ReadError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path).map_err(|_| ReadError::NoStoredSession)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o177 != 0
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(ReadError::SessionStoreUnusable);
    }
    let text =
        Zeroizing::new(std::fs::read_to_string(path).map_err(|_| ReadError::SessionStoreUnusable)?);
    toml::from_str(&text).map_err(|_| ReadError::SessionStoreUnusable)
}

#[cfg(not(unix))]
pub(super) fn load_at(_: &Path) -> Result<Stored, ReadError> {
    Err(ReadError::SessionStoreUnusable)
}

/// The origin the stored session belongs to, for commands whose `--server` was omitted.
pub fn stored_origin() -> Result<String, ReadError> {
    Ok(load_at(&store_path()?)?.origin.clone())
}

/// The stored session for this exact origin, behind a re-verified endpoint-trust pin.
///
/// The discovery document is verified afresh on every invocation -- digest, validator and
/// the Ed25519 signature, against the key pinned when the session was opened -- and must
/// equal the pinned trust byte for byte. A changed document, a changed key or a changed
/// signature fences the session before it is sent anywhere.
pub(super) async fn verified_session(
    origin: &reqwest::Url,
) -> Result<(SessionToken, Trust), ReadError> {
    present_at(&client()?, origin, &store_path()?, now_unix(), true).await
}

/// [`verified_session`] against an explicit store and clock.
///
/// With `rotate`, a session past its refresh point first rotates the family at the derived
/// `RefreshSession` endpoint (§5.2), and the session it answers with is the one presented.
/// The rotation never blocks presenting a session: whatever it answers, the instance still
/// decides whether the cookie is valid.
pub(super) async fn present_at(
    http: &reqwest::Client,
    origin: &reqwest::Url,
    path: &Path,
    now: u64,
    rotate: bool,
) -> Result<(SessionToken, Trust), ReadError> {
    let mut stored = load_at(path)?;
    if stored.origin != pinned(origin) {
        return Err(ReadError::NoStoredSession);
    }
    let live = discover(http, origin, stored.trust.discovery_key().as_ref()).await?;
    if live != stored.trust {
        return Err(ReadError::EndpointTrustChanged);
    }
    if rotate && rotation_due(&stored, now) {
        if let Some(notice) = rotate_refresh(http, &live, path, &mut stored, now).await? {
            eprintln!("{notice}");
        }
    }
    let token = SessionToken::from_bytes(Zeroizing::new(stored.session_token.as_bytes().to_vec()))?;
    Ok((token, live))
}

/// A rotation is due when an earlier presentation still awaits its outcome, or the current
/// credential has reached its refresh point.
fn rotation_due(stored: &Stored, now: u64) -> bool {
    stored.refresh_in_flight.is_some()
        || (stored.refresh_token.is_some()
            && stored.refresh_after_unix.is_some_and(|due| now >= due))
}

/// The instance keeps a lost refresh answer recoverable for this long after the first
/// presentation (§7.2 recovery window).
const RECOVERY_WINDOW_SECONDS: u64 = 300;
/// The one recovery is not attempted this close to the window's end: a late recovery is a
/// replay, and a replay revokes the family.
const RECOVERY_MARGIN_SECONDS: u64 = 30;
/// The header the recovery key travels in.
const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// How a rotation ended, for a notice that never carries a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rotation {
    /// The request provably never left this machine.
    NotSent,
    /// No answer that settles it: a timeout, a lost connection or a transient status. The
    /// one recovery under the same key and body may settle it.
    OutcomeUnknown,
    /// The instance refused the credential: the family ended (30 days absolute, 7 idle), was
    /// revoked, or saw a replay. It can no longer be refreshed.
    Refused,
    /// `422`: the key names another request. Nothing was rotated by this one, and no
    /// further presentation is attempted.
    Conflict,
    /// A settled answer that is not the published shape; recovering it would only answer the
    /// same bytes again.
    Invalid,
}

/// A committed rotation: the family's next session and refresh credential.
pub(super) struct Adopted {
    session: Zeroizing<String>,
    refresh: Zeroizing<String>,
    family_id: String,
    /// The issued session's life, the smaller of the body's and the cookie's `Max-Age`.
    expires_in_seconds: u64,
    family_expires_in_seconds: u64,
    must_change_password: bool,
}

/// Rotates the family's refresh credential under a fresh `Idempotency-Key`, recovering a
/// lost answer at most once under the same key and body.
///
/// The store is the ledger of that protocol, and every write is one atomic replace: the
/// credential moves out of `refresh_token` into [`Stored::refresh_in_flight`] together with
/// its key *before* it is sent, the attempt count is written before each presentation, and
/// the answer replaces both. So a crash at any point leaves either an unsent credential or a
/// sent one with its key and count -- never a credential that could be sent without its key,
/// and never a second recovery.
pub(super) async fn rotate_refresh(
    http: &reqwest::Client,
    trust: &Trust,
    path: &Path,
    stored: &mut Stored,
    now: u64,
) -> Result<Option<&'static str>, ReadError> {
    // One rotating process per store: a second one presenting the same credential under
    // another key would be a replay. A held lock means someone else is rotating right now.
    let Some(_lock) = lock_store(path)? else {
        return Ok(None);
    };
    // Re-read under the lock: another process may have rotated since this one loaded.
    *stored = load_at(path)?;
    if !rotation_due(stored, now) {
        return Ok(None);
    }
    if stored.family_expires_at_unix.is_some_and(|end| now >= end) {
        retire(stored);
        save_at(path, stored)?;
        return Ok(Some(
            "Session family ended; run `pa login` when the session is refused.",
        ));
    }
    let mut pending = match stored.refresh_in_flight.take() {
        // An earlier command presented this credential and never learned the outcome. Its
        // one recovery is still available only inside the window.
        Some(pending) => {
            let elapsed = now.saturating_sub(pending.first_sent_unix);
            if pending.attempts >= 2 || elapsed + RECOVERY_MARGIN_SECONDS >= RECOVERY_WINDOW_SECONDS
            {
                retire(stored);
                save_at(path, stored)?;
                return Ok(Some(notice(Rotation::OutcomeUnknown)));
            }
            pending
        }
        None => {
            let Some(mut refresh) = stored.refresh_token.take() else {
                return Ok(None);
            };
            let pending = InFlight {
                refresh_token: std::mem::take(&mut refresh),
                idempotency_key: new_idempotency_key()?,
                first_sent_unix: now,
                attempts: 0,
            };
            refresh.zeroize();
            pending
        }
    };
    loop {
        pending.attempts += 1;
        stored.refresh_in_flight = Some(pending);
        save_at(path, stored)?;
        let sent = stored.refresh_in_flight.as_ref().expect("just written");
        let outcome = refresh_once(http, trust, &sent.refresh_token, &sent.idempotency_key).await;
        pending = stored.refresh_in_flight.take().expect("just written");
        match outcome {
            Ok(adopted)
                if stored
                    .family_id
                    .as_deref()
                    .is_none_or(|id| id == adopted.family_id) =>
            {
                adopt(stored, adopted, now);
                save_at(path, stored)?;
                return Ok(stored.must_change_password.then_some(
                    "Session refreshed; the account must change its password before anything else.",
                ));
            }
            // Committed, but for a family this store does not hold: not adopted.
            Ok(_) => {
                retire(stored);
                save_at(path, stored)?;
                return Ok(Some(notice(Rotation::Invalid)));
            }
            Err(Rotation::NotSent) => {
                pending.attempts -= 1;
                if pending.attempts == 0 {
                    // Never presented: it stays the family's unsent credential, and the next
                    // attempt gets a key of its own.
                    stored.refresh_token = Some(std::mem::take(&mut pending.refresh_token));
                } else {
                    // The recovery never left: it stays available to a later command, inside
                    // the same window.
                    stored.refresh_in_flight = Some(pending);
                }
                save_at(path, stored)?;
                return Ok(Some(notice(Rotation::NotSent)));
            }
            Err(Rotation::OutcomeUnknown)
                if pending.attempts < 2
                    && now.saturating_sub(pending.first_sent_unix) + RECOVERY_MARGIN_SECONDS
                        < RECOVERY_WINDOW_SECONDS => {}
            Err(rotation) => {
                retire(stored);
                save_at(path, stored)?;
                return Ok(Some(notice(rotation)));
            }
        }
    }
}

/// Nothing of the family's refresh state survives: the session is used until it ends.
fn retire(stored: &mut Stored) {
    if let Some(mut refresh) = stored.refresh_token.take() {
        refresh.zeroize();
    }
    stored.refresh_in_flight = None;
    stored.refresh_after_unix = None;
}

/// Adopts a committed rotation: the new session cookie and its expiry, the next credential,
/// and the next refresh point -- half the new session's life. A session that already lives
/// to the family's end has none: no refresh can extend it, so the credential is retired.
fn adopt(stored: &mut Stored, adopted: Adopted, now: u64) {
    let family_end = now + adopted.family_expires_in_seconds;
    let due = now + adopted.expires_in_seconds / 2;
    let extendable = adopted.expires_in_seconds < adopted.family_expires_in_seconds;
    stored.session_token = adopted.session.as_str().to_owned();
    stored.family_id = Some(adopted.family_id.clone());
    stored.issued_at_unix = Some(now);
    stored.expires_at_unix = Some(now + adopted.expires_in_seconds);
    stored.family_expires_at_unix = Some(family_end);
    stored.must_change_password = adopted.must_change_password;
    stored.refresh_in_flight = None;
    if extendable {
        stored.refresh_token = Some(adopted.refresh.as_str().to_owned());
        stored.refresh_after_unix = Some(due);
    } else {
        retire(stored);
    }
}

fn notice(rotation: Rotation) -> &'static str {
    match rotation {
        Rotation::NotSent => "Session refresh not sent; will retry on the next command.",
        Rotation::OutcomeUnknown => {
            "Session refresh outcome unknown after its one recovery; the refresh credential \
             was retired, run `pa login` when the session ends."
        }
        Rotation::Refused => {
            "Session refresh refused (the session family ended or was revoked); \
             run `pa login` when the session is refused."
        }
        Rotation::Conflict => {
            "Session refresh conflicted with another request under its key; the refresh \
             credential was retired, run `pa login` when the session ends."
        }
        Rotation::Invalid => {
            "Session refresh answer was not the published shape; the refresh credential \
             was retired, run `pa login` when the session ends."
        }
    }
}

/// A fresh recovery key: 1..=128 visible ASCII bytes, unguessable, never reused.
fn new_idempotency_key() -> Result<String, ReadError> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ReadError::SessionStoreUnusable)?;
    Ok(format!("pa-tui-refresh-{}", hex_of(&bytes)))
}

/// An exclusive advisory lock beside the store, released when dropped.
#[cfg(unix)]
pub(super) struct StoreLock(#[allow(dead_code)] std::fs::File);

#[cfg(unix)]
pub(super) fn lock_store(path: &Path) -> Result<Option<StoreLock>, ReadError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path.with_extension("lock"))
        .map_err(|_| ReadError::SessionStoreUnusable)?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(StoreLock(file))),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
        Err(_) => Err(ReadError::SessionStoreUnusable),
    }
}

#[cfg(not(unix))]
pub(super) struct StoreLock;

#[cfg(not(unix))]
pub(super) fn lock_store(_: &Path) -> Result<Option<StoreLock>, ReadError> {
    Err(ReadError::SessionStoreUnusable)
}

/// One presentation of `presented` under `key`, classified.
pub(super) async fn refresh_once(
    http: &reqwest::Client,
    trust: &Trust,
    presented: &str,
    key: &str,
) -> Result<Adopted, Rotation> {
    let response = http
        .post(&trust.session_refresh)
        .header(ACCEPT, "application/json")
        .header(IDEMPOTENCY_KEY_HEADER, key)
        .json(&serde_json::json!({ "refresh_token": presented }))
        .send()
        .await
        .map_err(|error| {
            if error.is_connect() || error.is_builder() {
                Rotation::NotSent
            } else {
                Rotation::OutcomeUnknown
            }
        })?;
    match response.status().as_u16() {
        200 => {}
        400 | 401 | 403 => return Err(Rotation::Refused),
        422 => return Err(Rotation::Conflict),
        // A timeout, a transient or an unexpected status settles nothing.
        _ => return Err(Rotation::OutcomeUnknown),
    }
    if !is_json(&response) || !no_store(&response) {
        return Err(Rotation::Invalid);
    }
    let (session, max_age) = issued_session(&response).map_err(|_| Rotation::Invalid)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RotatedRefresh {
        family_id: String,
        refresh_token: String,
        expires_in_seconds: i64,
        family_expires_in_seconds: i64,
        must_change_password: bool,
    }
    impl Drop for RotatedRefresh {
        fn drop(&mut self) {
            self.refresh_token.zeroize();
        }
    }
    // A body cut short is a lost answer, which the recovery replays whole.
    let bytes =
        Zeroizing::new(bounded(response, MAX_RECEIPT_BYTES).await.map_err(
            |error| match error {
                ReadError::InvalidResponse => Rotation::Invalid,
                _ => Rotation::OutcomeUnknown,
            },
        )?);
    let mut rotated: RotatedRefresh =
        serde_json::from_slice(&bytes).map_err(|_| Rotation::Invalid)?;
    let refresh = Zeroizing::new(std::mem::take(&mut rotated.refresh_token));
    let (Ok(expires), Ok(family_expires)) = (
        u64::try_from(rotated.expires_in_seconds),
        u64::try_from(rotated.family_expires_in_seconds),
    ) else {
        return Err(Rotation::Invalid);
    };
    if !lowercase_hex(&refresh, 64)
        || !contract::canonical_uuid(&rotated.family_id)
        || !(1..=3_600).contains(&expires)
        || family_expires == 0
        || max_age == 0
    {
        return Err(Rotation::Invalid);
    }
    Ok(Adopted {
        session,
        refresh,
        family_id: std::mem::take(&mut rotated.family_id),
        expires_in_seconds: expires.min(max_age),
        family_expires_in_seconds: family_expires,
        must_change_password: rotated.must_change_password,
    })
}

/// The session cookie an authentication response committed, and nothing else.
fn opened_session(response: &reqwest::Response) -> Result<Zeroizing<String>, ReadError> {
    session_cookie(response).map(|(token, _)| token)
}

/// The session a refresh issued, with the `Max-Age` it must carry.
fn issued_session(response: &reqwest::Response) -> Result<(Zeroizing<String>, u64), ReadError> {
    match session_cookie(response)? {
        (token, Some(max_age)) => Ok((token, max_age)),
        _ => Err(ReadError::InvalidResponse),
    }
}

/// The one `pa_session` cookie of a response, checked, and its `Max-Age` when it has one.
fn session_cookie(
    response: &reqwest::Response,
) -> Result<(Zeroizing<String>, Option<u64>), ReadError> {
    let mut opened = None;
    for value in response.headers().get_all(SET_COOKIE) {
        let Ok(value) = value.to_str() else {
            return Err(ReadError::InvalidResponse);
        };
        let mut parts = value.split(';').map(str::trim);
        let Some((name, token)) = parts.next().and_then(|pair| pair.split_once('=')) else {
            continue;
        };
        if name != contract::SESSION_COOKIE {
            continue;
        }
        if !lowercase_hex(token, 64) {
            return Err(ReadError::InvalidResponse);
        }
        // §19.2: the session cookie is Secure, HttpOnly and SameSite. A response that
        // dropped one of those attributes is not the session contract this client accepts.
        let attributes: Vec<&str> = parts.collect();
        let has = |name: &str| {
            attributes
                .iter()
                .any(|attribute| attribute.eq_ignore_ascii_case(name))
        };
        if !has("Secure")
            || !has("HttpOnly")
            || !attributes.iter().any(|a| a.starts_with("SameSite="))
        {
            return Err(ReadError::InvalidResponse);
        }
        if opened.is_some() {
            return Err(ReadError::InvalidResponse);
        }
        let max_age = match attributes.iter().find_map(|attribute| {
            let (name, value) = attribute.split_once('=')?;
            name.eq_ignore_ascii_case("Max-Age").then_some(value)
        }) {
            None => None,
            Some(value) => Some(
                value
                    .parse::<u64>()
                    .map_err(|_| ReadError::InvalidResponse)?,
            ),
        };
        opened = Some((Zeroizing::new(token.to_owned()), max_age));
    }
    opened.ok_or(ReadError::InvalidResponse)
}

/// One primary credential and, when the instance asks for it, one TOTP code.
struct Presented {
    password: Zeroizing<String>,
    code: Option<Zeroizing<String>>,
}

/// Reads the password and the optional one-time code from one explicitly selected private
/// pipe, one per line. Neither ever reaches `argv`, the environment or a file.
#[cfg(unix)]
async fn presented_from_stdin() -> Result<Presented, ReadError> {
    use std::os::fd::AsFd;

    let fd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| ReadError::InvalidCredentialHandoff)?;
    let bytes = handoff::read_private(fd, Duration::from_secs(30), MAX_CREDENTIAL_BYTES)
        .await
        .map_err(|_| ReadError::InvalidCredentialHandoff)?;
    let text = Zeroizing::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| ReadError::InvalidCredentialHandoff)?
            .to_owned(),
    );
    let mut lines = text.lines();
    let password = Zeroizing::new(
        lines
            .next()
            .filter(|line| !line.is_empty())
            .ok_or(ReadError::InvalidCredentialHandoff)?
            .to_owned(),
    );
    let code = lines.next().map(|line| Zeroizing::new(line.to_owned()));
    if lines.next().is_some() {
        return Err(ReadError::InvalidCredentialHandoff);
    }
    if code.as_ref().is_some_and(|code| {
        !(6..=8).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit())
    }) {
        return Err(ReadError::InvalidCredentialHandoff);
    }
    Ok(Presented { password, code })
}

#[cfg(not(unix))]
async fn presented_from_stdin() -> Result<Presented, ReadError> {
    Err(ReadError::UnsupportedSessionHandoff)
}

/// Posts one authentication body and returns the response, without retrying it.
async fn post(
    http: &reqwest::Client,
    endpoint: &str,
    body: &serde_json::Value,
) -> Result<reqwest::Response, ReadError> {
    http.post(endpoint)
        .header(ACCEPT, "application/json")
        .json(body)
        .send()
        .await
        .map_err(|_| ReadError::Transport)
}

/// Opens one session with the local primary credential and, when required, TOTP (§5.2).
///
/// The credentials arrive on a private pipe; the endpoints come from the verified
/// discovery document; the resulting cookie is stored for this exact origin. No refresh
/// credential is retained, so the session simply expires rather than being silently renewed.
pub async fn login(
    server: String,
    login: String,
    method: Option<String>,
    allow_loopback_http: bool,
) -> Result<(), ReadError> {
    let origin = origin(&server, allow_loopback_http)?;
    if login.is_empty() || login.len() > 320 {
        return Err(ReadError::InvalidSelector);
    }
    if method
        .as_deref()
        .is_some_and(|id| !contract::canonical_uuid(id))
    {
        return Err(ReadError::InvalidSelector);
    }
    let presented = presented_from_stdin().await?;
    let http = client()?;
    // §19.2: endpoint trust is established before the first credential leaves this process.
    let trust = discover(&http, &origin, None).await?;

    let response = post(
        &http,
        &trust.session,
        &serde_json::json!({"login": login, "password": presented.password.as_str()}),
    )
    .await?;
    let opened = match response.status().as_u16() {
        201 => {
            if !no_store(&response) || !is_json(&response) {
                return Err(ReadError::InvalidResponse);
            }
            opened_session(&response)?
        }
        202 => {
            // The pre-authentication continuation is not a session and confers no authority.
            if !no_store(&response) || !is_json(&response) {
                return Err(ReadError::InvalidResponse);
            }
            if response.headers().get(SET_COOKIE).is_some() {
                return Err(ReadError::InvalidResponse);
            }
            let bytes = bounded(response, MAX_RECEIPT_BYTES).await?;
            let pending: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| ReadError::InvalidResponse)?;
            step_up(&http, &trust, &pending, method.as_deref(), &presented).await?
        }
        401 | 403 => return Err(ReadError::AuthenticationRequired),
        _ => return Err(ReadError::Transport),
    };

    let path = save(&Stored {
        origin: pinned(&origin),
        session_token: opened.as_str().to_owned(),
        trust,
        transport: PASSWORD_TRANSPORT.to_owned(),
        refresh_token: None,
        family_id: None,
        issued_at_unix: Some(now_unix()),
        expires_at_unix: None,
        refresh_after_unix: None,
        family_expires_at_unix: None,
        must_change_password: false,
        refresh_in_flight: None,
    })?;
    println!(
        "Session stored for {} at {}",
        pinned(&origin),
        path.display()
    );
    println!(
        "Endpoint trust: canonical origin pinned, published digest and Ed25519 signature verified."
    );
    Ok(())
}

/// Completes the pre-authentication challenge with one TOTP code.
async fn step_up(
    http: &reqwest::Client,
    trust: &Trust,
    pending: &serde_json::Value,
    method: Option<&str>,
    presented: &Presented,
) -> Result<Zeroizing<String>, ReadError> {
    let field = |name: &str| {
        pending
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or(ReadError::InvalidResponse)
    };
    if field("state")? != "mfa_required" {
        return Err(ReadError::InvalidResponse);
    }
    let challenge = Zeroizing::new(field("challenge_token")?.to_owned());
    if !lowercase_hex(&challenge, 64) {
        return Err(ReadError::InvalidResponse);
    }
    let methods: Vec<&str> = pending
        .get("totp_method_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or(ReadError::InvalidResponse)?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    // One answerable method, chosen explicitly when the Principal has several. This client
    // does not enrol a first factor and does not complete a challenge with a recovery code.
    let chosen = match (method, methods.as_slice()) {
        (Some(asked), all) if all.contains(&asked) => asked,
        (None, [only]) => *only,
        _ => return Err(ReadError::NoAnswerableFactor),
    };
    let code = presented
        .code
        .as_ref()
        .ok_or(ReadError::SecondFactorRequired)?;
    let response = post(
        http,
        &trust.session_factor,
        &serde_json::json!({
            "challenge_token": challenge.as_str(),
            "method_id": chosen,
            "code": code.as_str(),
        }),
    )
    .await?;
    if !no_store(&response) {
        return Err(ReadError::InvalidResponse);
    }
    match response.status().as_u16() {
        201 => opened_session(&response),
        401 | 403 => Err(ReadError::AuthenticationRequired),
        _ => Err(ReadError::Transport),
    }
}

/// Ends the session family at the instance and removes the local credential.
///
/// The local file goes whatever the instance answers: a token this client can no longer
/// vouch for must not stay on disk. The refusal is still reported.
pub async fn logout(server: String, allow_loopback_http: bool) -> Result<(), ReadError> {
    let origin = origin(&server, allow_loopback_http)?;
    logout_at(&client()?, &origin, &store_path()?).await?;
    println!("Session family revoked; stored credential removed.");
    Ok(())
}

/// `RevokeCurrentSession` with the stored session, then the store is removed.
///
/// A drifted endpoint set fences the session (§19.2): nothing is sent to the drifted
/// instance, but the local credential is removed all the same.
pub(super) async fn logout_at(
    http: &reqwest::Client,
    origin: &reqwest::Url,
    path: &Path,
) -> Result<(), ReadError> {
    let (session, trust) = match present_at(http, origin, path, now_unix(), false).await {
        Ok(presented) => presented,
        Err(ReadError::EndpointTrustChanged) => {
            let _ = std::fs::remove_file(path);
            return Err(ReadError::EndpointTrustChanged);
        }
        Err(error) => return Err(error),
    };
    let answered = http
        .post(&trust.session_revoke)
        .header(ACCEPT, "application/json")
        .header(COOKIE, session.header()?)
        .header(contract::CSRF_HEADER, "1")
        .send()
        .await;
    let _ = std::fs::remove_file(path);
    match answered.map(|response| response.status().as_u16()) {
        Ok(204) => Ok(()),
        Ok(401) => Err(ReadError::AuthenticationRequired),
        Ok(_) => Err(ReadError::Transport),
        Err(error) => Err(transport(&error)),
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
