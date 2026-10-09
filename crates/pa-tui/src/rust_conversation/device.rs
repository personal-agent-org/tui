//! `pa login`: the RFC 8628 device authorization this client kind is registered for (§7.2).
//!
//! §7.2 (line 2561): "TUI uses `DeviceAuthorizationSecureStore`." The flow is the instance's
//! own facade, and every URL comes from the verified `/.well-known/personal-agent` document:
//!
//! 1. `BeginDeviceAuthorization` -- standard form input (`client_id=pa.tui`), answered with
//!    `DeviceAuthorizationBeginResultDataV1` under `Cache-Control: no-store`.
//! 2. The Human is shown the user code and the verification page. Its URI must be exactly the
//!    published verification endpoint, and the prefilled variant may carry the user code and
//!    nothing else (§7.2).
//! 3. `PollDeviceAuthorization` every `interval_seconds`; `slow_down` moves the interval to the
//!    one the instance names (at least five seconds more), and every terminal error code is a
//!    closed local error rather than a retry.
//! 4. The one-time delivery -- the session credential, its presentation metadata and the
//!    family's first refresh credential -- goes straight into the store and is never printed.
//!
//! The session is then presented as the `pa_session` cookie plus the `pa-csrf` header (the
//! instance has no bearer path) and rotated through `RefreshSession` (`session.rs`).

use super::session::{self, DeviceTrust, Stored, Trust};
use super::*;
use reqwest::header::ACCEPT;
use serde::Deserialize;
use std::future::Future;
use std::path::{Path, PathBuf};

const BEGIN_SCHEMA: &str = "personal-agent.auth.device-authorization.begin.v1";
const POLL_SCHEMA: &str = "personal-agent.auth.device-authorization.poll.v1";
/// RFC 8628 §3.4's grant type.
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Begin, poll and delivery bodies carry a handful of bounded fields.
const MAX_BODY_BYTES: usize = 8_192;
/// The longest interval this client will accept from the instance; beyond it the ceremony is
/// not one a Human can finish in the device code's lifetime.
const MAX_INTERVAL_SECONDS: u64 = 300;
/// §7.2 (line 2595): "`slow_down` adds five seconds".
const SLOW_DOWN_STEP_SECONDS: u64 = 5;
/// Consecutive transport failures tolerated while polling before the login gives up.
const MAX_TRANSPORT_FAILURES: u32 = 3;

/// `DeviceAuthorizationBeginResultDataV1`, exactly.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Begun {
    schema: String,
    device_code: String,
    pub(super) user_code: String,
    pub(super) verification_uri: String,
    pub(super) verification_uri_complete: Option<String>,
    pub(super) expires_in_seconds: u64,
    pub(super) interval_seconds: u64,
}

impl Drop for Begun {
    fn drop(&mut self) {
        self.device_code.zeroize();
    }
}

/// `DeviceAuthorizationPollResultDataV1::Granted`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Granted {
    schema: String,
    result: String,
    native_session_family_adoption: String,
    access: Access,
    refresh_adoption: Option<String>,
}

impl Drop for Granted {
    fn drop(&mut self) {
        self.native_session_family_adoption.zeroize();
        if let Some(refresh) = self.refresh_adoption.as_mut() {
            refresh.zeroize();
        }
    }
}

/// §7.2 `ShortLivedAccessCredentialMetadata`: how the delivered session is presented.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    audience: String,
    expires_in_seconds: u64,
    session_cookie: String,
    csrf_header: String,
    family_id: String,
}

/// The fixed RFC 8628 error projection (§5.3 line 1791).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PollError {
    schema: String,
    error: String,
    #[serde(default)]
    retry_after_seconds: Option<u64>,
    #[serde(default)]
    next_interval_seconds: Option<u64>,
}

/// A user code is shown to a Human: short, and only characters that cannot steer a terminal.
fn displayable_code(code: &str) -> bool {
    (1..=32).contains(&code.len())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

impl Begun {
    /// Checks the begin result against the verified facade before anything is shown.
    fn check(&self, device: &DeviceTrust) -> Result<(), ReadError> {
        let secret_shaped = (1..=128).contains(&self.device_code.len())
            && self
                .device_code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric());
        if self.schema != BEGIN_SCHEMA
            || !secret_shaped
            || !displayable_code(&self.user_code)
            || self.expires_in_seconds == 0
            || !(1..=MAX_INTERVAL_SECONDS).contains(&self.interval_seconds)
            // The page a Human approves on is the published one, never a URL the begin
            // response gets to choose.
            || self.verification_uri != device.verification
        {
            return Err(ReadError::InvalidResponse);
        }
        if let Some(complete) = &self.verification_uri_complete {
            // §7.2: same canonical origin and verification path, prefilling only the
            // non-authorizing user code. No device code, token, redirect or extra parameter.
            let published = reqwest::Url::parse(&device.verification)
                .map_err(|_| ReadError::InvalidResponse)?;
            let url = reqwest::Url::parse(complete).map_err(|_| ReadError::InvalidResponse)?;
            let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
            if url.origin() != published.origin()
                || url.path() != published.path()
                || url.fragment().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
                || pairs != [("user_code".to_owned(), self.user_code.clone())]
            {
                return Err(ReadError::InvalidResponse);
            }
        }
        Ok(())
    }
}

/// `BeginDeviceAuthorization` with the standard form input.
pub(super) async fn begin(
    http: &reqwest::Client,
    device: &DeviceTrust,
) -> Result<Begun, ReadError> {
    let response = http
        .post(&device.authorization)
        .header(ACCEPT, "application/json")
        .form(&[("client_id", device.client_id.as_str())])
        .send()
        .await
        .map_err(|error| session::transport(&error))?;
    match response.status().as_u16() {
        200 => {}
        400..=428 | 430..=499 => return Err(ReadError::DeviceAuthorizationRefused),
        _ => return Err(ReadError::Transport),
    }
    if !session::no_store(&response) || !session::is_json(&response) {
        return Err(ReadError::InvalidResponse);
    }
    let bytes = Zeroizing::new(session::bounded(response, MAX_BODY_BYTES).await?);
    let begun: Begun = serde_json::from_slice(&bytes).map_err(|_| ReadError::InvalidResponse)?;
    begun.check(device)?;
    Ok(begun)
}

/// One poll's classified answer.
enum Polled {
    Granted(Box<Granted>),
    /// Poll again after this many seconds.
    Again(u64),
    /// A transport failure or a transient server answer; poll again at the same interval.
    Transient(ReadError),
}

async fn poll_once(
    http: &reqwest::Client,
    device: &DeviceTrust,
    begun: &Begun,
    interval: u64,
) -> Result<Polled, ReadError> {
    let sent = http
        .post(&device.token)
        .header(ACCEPT, "application/json")
        .form(&[
            ("grant_type", DEVICE_CODE_GRANT),
            ("device_code", begun.device_code.as_str()),
            ("client_id", device.client_id.as_str()),
        ])
        .send()
        .await;
    let response = match sent {
        Ok(response) => response,
        Err(error) => {
            return match session::transport(&error) {
                ReadError::TlsUntrusted => Err(ReadError::TlsUntrusted),
                other => Ok(Polled::Transient(other)),
            }
        }
    };
    let status = response.status().as_u16();
    if matches!(status, 429 | 500..=599) {
        return Ok(Polled::Transient(ReadError::Transport));
    }
    if !matches!(status, 200 | 400) {
        return Err(ReadError::DeviceAuthorizationRefused);
    }
    // Both the delivery and the error projection are `no-store` JSON (§7.2 line 2595).
    if !session::no_store(&response) || !session::is_json(&response) {
        return Err(ReadError::InvalidResponse);
    }
    let bytes = Zeroizing::new(session::bounded(response, MAX_BODY_BYTES).await?);
    if status == 200 {
        let granted: Granted =
            serde_json::from_slice(&bytes).map_err(|_| ReadError::InvalidResponse)?;
        return Ok(Polled::Granted(Box::new(granted)));
    }
    let refused: PollError =
        serde_json::from_slice(&bytes).map_err(|_| ReadError::InvalidResponse)?;
    if refused.schema != POLL_SCHEMA {
        return Err(ReadError::InvalidResponse);
    }
    match refused.error.as_str() {
        "authorization_pending" => Ok(Polled::Again(
            refused
                .retry_after_seconds
                .unwrap_or(interval)
                .max(interval),
        )),
        // RFC 8628 §3.5: the interval grows by five seconds and stays grown. The instance
        // names the interval now in force; a smaller or absent value still adds the step.
        "slow_down" => Ok(Polled::Again(
            refused
                .next_interval_seconds
                .unwrap_or(0)
                .max(interval + SLOW_DOWN_STEP_SECONDS),
        )),
        "access_denied" => Err(ReadError::DeviceAuthorizationDenied),
        "expired_token" => Err(ReadError::DeviceAuthorizationExpired),
        "invalid_grant" => Err(ReadError::DeviceAuthorizationInvalidGrant),
        "unsupported_grant_type" => Err(ReadError::DeviceAuthorizationRefused),
        _ => Err(ReadError::InvalidResponse),
    }
}

/// Polls until the ceremony settles, sleeping through `sleep` so tests need no real time.
///
/// The device code's lifetime is budgeted against the intervals actually waited: once the
/// next wait would outlive it, the ceremony is expired locally rather than polled again.
pub(super) async fn poll<S, F>(
    http: &reqwest::Client,
    device: &DeviceTrust,
    begun: &Begun,
    mut sleep: S,
) -> Result<Box<Granted>, ReadError>
where
    S: FnMut(Duration) -> F,
    F: Future<Output = ()>,
{
    let mut interval = begun.interval_seconds;
    let mut remaining = begun.expires_in_seconds;
    let mut failures = 0;
    loop {
        if interval > remaining || interval > MAX_INTERVAL_SECONDS {
            return Err(ReadError::DeviceAuthorizationExpired);
        }
        sleep(Duration::from_secs(interval)).await;
        remaining -= interval;
        match poll_once(http, device, begun, interval).await? {
            Polled::Granted(granted) => return Ok(granted),
            Polled::Again(next) => {
                failures = 0;
                interval = next;
            }
            Polled::Transient(error) => {
                failures += 1;
                if failures > MAX_TRANSPORT_FAILURES {
                    return Err(error);
                }
            }
        }
    }
}

impl Granted {
    /// Checks the delivery is the session contract this client presents, and nothing else.
    fn check(&self) -> Result<(), ReadError> {
        let valid = self.schema == POLL_SCHEMA
            && self.result == "granted"
            && session::lowercase_hex(&self.native_session_family_adoption, 64)
            && self
                .refresh_adoption
                .as_deref()
                .is_none_or(|refresh| session::lowercase_hex(refresh, 64))
            && self.access.audience == session::AUDIENCE
            && self.access.session_cookie == contract::SESSION_COOKIE
            && self.access.csrf_header == contract::CSRF_HEADER
            && self.access.expires_in_seconds > 0
            && contract::canonical_uuid(&self.access.family_id);
        if valid {
            Ok(())
        } else {
            Err(ReadError::InvalidResponse)
        }
    }

    fn into_stored(self, origin: String, trust: Trust, now: u64) -> Stored {
        let lifetime = self.access.expires_in_seconds;
        Stored {
            origin,
            session_token: self.native_session_family_adoption.clone(),
            trust,
            transport: session::TUI_TRANSPORT.to_owned(),
            refresh_token: self.refresh_adoption.clone(),
            family_id: Some(self.access.family_id.clone()),
            issued_at_unix: Some(now),
            expires_at_unix: Some(now + lifetime),
            // Rotate from half the session's life on, as the instance's own metadata says
            // the refresh credential must rotate it.
            refresh_after_unix: self
                .refresh_adoption
                .is_some()
                .then_some(now + lifetime / 2),
            family_expires_at_unix: None,
            must_change_password: false,
            refresh_in_flight: None,
        }
    }
}

/// Tells the Human where to approve. Every instance-supplied byte is sanitized, and the
/// device code -- the poll authenticator -- is never shown.
fn prompt(output: &mut dyn std::io::Write, begun: &Begun) -> Result<(), ReadError> {
    use crate::i18n::{t, Msg};
    let mut shown = String::new();
    push_sanitized(
        &mut shown,
        begun
            .verification_uri_complete
            .as_deref()
            .unwrap_or(&begun.verification_uri),
    );
    let mut page = String::new();
    push_sanitized(&mut page, &begun.verification_uri);
    let mut text = format!(
        "{}\n    {shown}\n{}",
        t(Msg::OidcOpen),
        t(Msg::OidcCode(&begun.user_code))
    );
    if begun.verification_uri_complete.is_some() {
        text.push_str(&format!("  ({page})\n"));
    }
    text.push_str(&t(Msg::OidcWaiting));
    text.push('\n');
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| ReadError::Output)
}

/// The whole login against an explicit client, store, prompt sink and sleeper.
pub(super) async fn login_at<S, F>(
    http: &reqwest::Client,
    origin: &reqwest::Url,
    path: &Path,
    output: &mut dyn std::io::Write,
    sleep: S,
) -> Result<(), ReadError>
where
    S: FnMut(Duration) -> F,
    F: Future<Output = ()>,
{
    // §19.2: endpoint trust is established before anything else is sent.
    let trust = session::discover(http, origin, None).await?;
    let device = trust
        .device
        .clone()
        .ok_or(ReadError::DeviceAuthorizationUnsupported)?;
    let begun = begin(http, &device).await?;
    prompt(output, &begun)?;
    let granted = poll(http, &device, &begun, sleep).await?;
    granted.check()?;
    let stored = granted.into_stored(session::pinned(origin), trust, session::now_unix());
    session::save_at(path, &stored)
}

/// `pa login`: the device flow against `server`, storing the delivered session family.
pub async fn login(server: String, allow_loopback_http: bool) -> Result<PathBuf, ReadError> {
    let origin = origin(&server, allow_loopback_http)?;
    let path = session::store_path()?;
    let mut prompt = std::io::stderr();
    login_at(
        &session::client()?,
        &origin,
        &path,
        &mut prompt,
        tokio::time::sleep,
    )
    .await?;
    Ok(path)
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
