//! Explicitly selected Rust backend Conversation client. Not the legacy Python chat API,
//! not a login implementation, and not an AG-UI/Run stream or terminal Run proof.

use std::io::Write;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE};
use zeroize::{Zeroize, Zeroizing};

use crate::generated::rust_conversation as contract;

#[cfg(unix)]
#[path = "rust_conversation/handoff.rs"]
mod handoff;

#[path = "rust_conversation/write.rs"]
pub mod write;

#[path = "rust_conversation/session.rs"]
pub mod session;

#[path = "rust_conversation/stream.rs"]
pub mod stream;

#[path = "rust_conversation/device.rs"]
pub mod device;

#[path = "rust_conversation/conversations.rs"]
pub mod conversations;

/// Safe local error families. Neither a credential, response body nor request URL is
/// retained as an error source; Debug is deliberately restricted to these closed codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    InvalidOrigin,
    InvalidSelector,
    InvalidSessionHandoff,
    UnsupportedSessionHandoff,
    AuthenticationRequired,
    NotAuthorized,
    Transport,
    InvalidResponse,
    InvalidTextFile,
    Conflict,
    CommitUnconfirmed,
    Output,
    /// The published endpoint-trust document is absent, malformed, or not this origin's.
    EndpointTrustUnverified,
    /// A previously pinned endpoint-trust document changed; §19.2 fences before use.
    EndpointTrustChanged,
    /// The private pipe did not carry exactly the declared credential lines.
    InvalidCredentialHandoff,
    /// No session has been stored for this exact origin.
    NoStoredSession,
    /// The stored session file exists but is not privately owned and readable.
    SessionStoreUnusable,
    /// The instance asked for a second factor the invocation did not supply.
    SecondFactorRequired,
    /// The pre-authentication continuation named no TOTP method this client can answer.
    NoAnswerableFactor,
    /// A delivery frame was absent, out of order, or not the published frame shape.
    InvalidFrame,
    /// The instance no longer retains the frames after this client's cursor: §19.3 forbids
    /// applying across a gap, so the client must re-read state rather than resume.
    ResumeExpired,
    /// The verified document names no RFC 8628 facade, or none for this client's profile.
    DeviceAuthorizationUnsupported,
    /// The Human denied the device authorization.
    DeviceAuthorizationDenied,
    /// The device code expired before a Human approved it.
    DeviceAuthorizationExpired,
    /// The device code is unknown, already collected, or no longer grants anything.
    DeviceAuthorizationInvalidGrant,
    /// The instance refused this client's request shape (`unsupported_grant_type`, begin).
    DeviceAuthorizationRefused,
    /// The server certificate is not signed by a CA this invocation trusts.
    TlsUntrusted,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidOrigin => "rust_conversation.invalid_origin",
            Self::InvalidSelector => "rust_conversation.invalid_selector",
            Self::InvalidSessionHandoff => "rust_conversation.invalid_session_stdin",
            Self::UnsupportedSessionHandoff => "rust_conversation.session_stdin_requires_unix_pipe",
            Self::AuthenticationRequired => "rust_conversation.authentication_required",
            Self::NotAuthorized => "rust_conversation.not_authorized",
            Self::Transport => "rust_conversation.transport_unavailable",
            Self::InvalidResponse => "rust_conversation.invalid_response",
            Self::InvalidTextFile => "rust_conversation.invalid_text_file",
            Self::Conflict => "rust_conversation.write_conflict",
            Self::CommitUnconfirmed => "rust_conversation.commit_unconfirmed_no_automatic_retry",
            Self::Output => "rust_conversation.output_unavailable",
            Self::EndpointTrustUnverified => "rust_session.endpoint_trust_unverified",
            Self::EndpointTrustChanged => "rust_session.endpoint_trust_changed",
            Self::InvalidCredentialHandoff => "rust_session.invalid_credential_stdin",
            Self::NoStoredSession => "rust_session.no_stored_session_for_this_origin",
            Self::SessionStoreUnusable => "rust_session.session_store_unusable",
            Self::SecondFactorRequired => "rust_session.second_factor_required",
            Self::NoAnswerableFactor => "rust_session.no_answerable_totp_method",
            Self::InvalidFrame => "rust_stream.invalid_frame",
            Self::ResumeExpired => "rust_stream.resume_expired",
            Self::DeviceAuthorizationUnsupported => "rust_device.unsupported_by_instance",
            Self::DeviceAuthorizationDenied => "rust_device.access_denied",
            Self::DeviceAuthorizationExpired => "rust_device.expired_token",
            Self::DeviceAuthorizationInvalidGrant => "rust_device.invalid_grant",
            Self::DeviceAuthorizationRefused => "rust_device.request_refused",
            Self::TlsUntrusted => {
                "rust_session.tls_certificate_untrusted (install the CA in the system store \
                 or point SSL_CERT_FILE at it for this invocation)"
            }
        })
    }
}

impl std::error::Error for ReadError {}

struct SessionToken(Zeroizing<Vec<u8>>);

impl SessionToken {
    fn from_bytes(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, ReadError> {
        if bytes.ends_with(b"\r\n") {
            let length = bytes.len() - 2;
            bytes.truncate(length);
        } else if bytes.ends_with(b"\n") {
            let length = bytes.len() - 1;
            bytes.truncate(length);
        }
        if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(ReadError::InvalidSessionHandoff);
        }
        Ok(Self(bytes))
    }

    fn header(&self) -> Result<HeaderValue, ReadError> {
        self.header_for(contract::SESSION_COOKIE)
    }

    fn header_for(&self, name: &str) -> Result<HeaderValue, ReadError> {
        let mut cookie = Zeroizing::new(Vec::with_capacity(name.len() + 65));
        cookie.extend_from_slice(name.as_bytes());
        cookie.push(b'=');
        cookie.extend_from_slice(&self.0);
        let mut header =
            HeaderValue::from_bytes(&cookie).map_err(|_| ReadError::InvalidSessionHandoff)?;
        header.set_sensitive(true);
        Ok(header)
    }
}

fn origin(server: &str, allow_loopback_http: bool) -> Result<reqwest::Url, ReadError> {
    let url = reqwest::Url::parse(server).map_err(|_| ReadError::InvalidOrigin)?;
    let loopback = url
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|address| address.is_loopback());
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.host_str().is_none()
        || !(url.scheme() == "https" || (allow_loopback_http && loopback && url.scheme() == "http"))
    {
        return Err(ReadError::InvalidOrigin);
    }
    Ok(url)
}

struct Client {
    origin: reqwest::Url,
    http: reqwest::Client,
    session: SessionToken,
}

impl Client {
    fn new(origin: reqwest::Url, session: SessionToken) -> Result<Self, ReadError> {
        let http = pa_oidc::tls::http_client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| ReadError::Transport)?;
        Ok(Self {
            origin,
            http,
            session,
        })
    }

    async fn read(&self, branch: &str, after: i64, limit: i64) -> Result<Snapshot, ReadError> {
        let response = contract::read_branch_messages(
            &self.http,
            &self.origin,
            branch,
            after,
            limit,
            self.session.header()?,
        )
        .map_err(|_| ReadError::InvalidSelector)?
        .send()
        .await
        .map_err(|_| ReadError::Transport)?;
        match response.status().as_u16() {
            200 => {}
            401 => return Err(ReadError::AuthenticationRequired),
            403 | 404 => return Err(ReadError::NotAuthorized),
            _ => return Err(ReadError::Transport),
        }
        let json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
            });
        let no_store = response
            .headers()
            .get_all(CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| {
                value
                    .split(',')
                    .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
            });
        if !json || !no_store {
            return Err(ReadError::InvalidResponse);
        }
        // JSON escaping may expand each plaintext byte to six bytes; fixed fields are
        // separately bounded by the generated maximum number of messages.
        const MAX_JSON_BYTES: usize =
            contract::MAX_PLAINTEXT_BYTES * 6 + contract::MAX_LIMIT as usize * 256 + 4096;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JSON_BYTES as u64)
        {
            return Err(ReadError::InvalidResponse);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|_| ReadError::Transport)?;
            if chunk.len() > MAX_JSON_BYTES - bytes.len() {
                return Err(ReadError::InvalidResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        Snapshot::decode(&bytes, after, limit)
    }
}

struct Snapshot(contract::MessagePage);

impl Drop for Snapshot {
    fn drop(&mut self) {
        for message in &mut self.0.messages {
            message.text.zeroize();
            for part in &mut message.parts {
                part.text.zeroize();
                // The shown arguments of an action part are disclosed content like any other
                // part text, so they leave the snapshot with it instead of outliving it.
                if let Some(action) = &mut part.action {
                    action.arguments.json.zeroize();
                }
            }
        }
    }
}

impl Snapshot {
    fn decode(bytes: &[u8], after: i64, limit: i64) -> Result<Self, ReadError> {
        let snapshot = Self(serde_json::from_slice(bytes).map_err(|_| ReadError::InvalidResponse)?);
        snapshot
            .0
            .validate()
            .map_err(|()| ReadError::InvalidResponse)?;
        if snapshot.0.messages.len() > limit as usize {
            return Err(ReadError::InvalidResponse);
        }
        let mut last = after;
        let mut text_bytes = 0usize;
        for message in &snapshot.0.messages {
            if message.turn_sequence <= last {
                return Err(ReadError::InvalidResponse);
            }
            last = message.turn_sequence;
            text_bytes = text_bytes
                .checked_add(message.text.len())
                .ok_or(ReadError::InvalidResponse)?;
        }
        if text_bytes > contract::MAX_PLAINTEXT_BYTES {
            return Err(ReadError::InvalidResponse);
        }
        let valid_next = match snapshot.0.next_after_turn {
            contract::NextAfterTurn::Value(next) => {
                snapshot.0.messages.len() == limit as usize && next == last
            }
            contract::NextAfterTurn::Null(()) => snapshot.0.messages.len() < limit as usize,
        };
        if !valid_next {
            return Err(ReadError::InvalidResponse);
        }
        Ok(snapshot)
    }

    fn render(&self) -> Zeroizing<String> {
        use std::fmt::Write as _;
        let mut rendered = Zeroizing::new(String::from("Rust Conversation · read-only\n"));
        for message in &self.0.messages {
            let role = match message.role {
                contract::Role::Human => "Human",
                contract::Role::Agent => "Assistant",
                contract::Role::ToolResult => "Tool result",
            };
            // The instance's own RFC 3339 instant, copied out as received: this client does
            // not convert it to a local zone, re-format it, or turn it into a duration.
            let mut created_at = Zeroizing::new(String::new());
            push_sanitized(&mut created_at, &message.created_at);
            let _ = writeln!(
                rendered,
                "\n{role} · {} · {}",
                message.turn_sequence, *created_at
            );
            if message.parts.is_empty() {
                // A page without parts is still readable: the flat text is the body.
                push_body(&mut rendered, None, &message.text);
            } else {
                for part in &message.parts {
                    match part.kind {
                        contract::Kind::Text => push_body(&mut rendered, None, &part.text),
                        kind => push_body(&mut rendered, Some(kind_label(kind)), &part.text),
                    }
                }
            }
        }
        match self.0.next_after_turn {
            contract::NextAfterTurn::Value(next) => {
                let _ = writeln!(rendered, "\nNext page: --after-turn {next}");
            }
            contract::NextAfterTurn::Null(()) => rendered.push_str("\nEnd of this message page.\n"),
        }
        rendered.push_str("Run status is not determined by this read.\n");
        rendered
    }
}

/// The published wire name of a non-text part kind. A closed set of literals, so a label
/// can never carry instance-supplied bytes into the terminal.
fn kind_label(kind: contract::Kind) -> &'static str {
    match kind {
        contract::Kind::Text => "text",
        contract::Kind::ReasoningStatus => "reasoning_status",
        contract::Kind::Refusal => "refusal",
        contract::Kind::StructuredData => "structured_data",
        contract::Kind::ActionCall => "action_call",
        contract::Kind::ActionResult => "action_result",
        contract::Kind::Media => "media",
    }
}

/// One part's or message's text, indented and line by line. A labelled kind prefixes every
/// one of its lines, so no line of a non-text part can pass itself off as message prose.
fn push_body(rendered: &mut String, label: Option<&str>, text: &str) {
    let mut lines = text.lines().peekable();
    if lines.peek().is_none() {
        // An empty labelled part is still reported; it is not silently dropped.
        if let Some(label) = label {
            rendered.push_str("  [");
            rendered.push_str(label);
            rendered.push_str("]\n");
        }
        return;
    }
    for line in lines {
        rendered.push_str("  ");
        if let Some(label) = label {
            rendered.push('[');
            rendered.push_str(label);
            rendered.push_str("] ");
        }
        push_sanitized(rendered, line);
        rendered.push('\n');
    }
}

/// Instance-supplied bytes, stripped of everything a terminal would act on: control
/// characters (escape introducers included) and bidirectional overrides.
fn push_sanitized(rendered: &mut String, value: &str) {
    for character in value.chars() {
        if character == '\t' {
            rendered.push_str("    ");
        } else if !character.is_control()
            && !matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            rendered.push(character);
        }
    }
}

#[derive(Default)]
struct View {
    snapshot: Option<Snapshot>,
}

impl View {
    async fn reload(
        &mut self,
        client: &Client,
        branch: &str,
        after: i64,
        limit: i64,
    ) -> Result<(), ReadError> {
        // A denied or failed reload leaves no stale classified page masquerading as a
        // current authorized result. A valid reload replaces, never appends to, the view.
        self.snapshot = None;
        self.snapshot = Some(client.read(branch, after, limit).await?);
        Ok(())
    }
}

/// Where one invocation's session credential comes from. Never both, never ambient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// One 64-hex token handed over an explicitly selected private pipe.
    PrivateStdin,
    /// The session `rust-login` stored for this exact origin, behind its pinned trust.
    StoredSession,
}

impl Credential {
    async fn present(self, origin: &reqwest::Url) -> Result<SessionToken, ReadError> {
        match self {
            Self::PrivateStdin => session_from_stdin().await,
            // §19.2: endpoint drift fences the client before any credential leaves it, so
            // the pinned document is re-verified here rather than only at login.
            Self::StoredSession => Ok(session::verified_session(origin).await?.0),
        }
    }
}

/// Fetch and render one bounded page using an explicitly selected private stdin pipe.
/// Does not read legacy config, env credentials, refresh tokens, or any credential file.
pub async fn read_from_stdin(
    server: String,
    branch: String,
    after_turn: Option<i64>,
    limit: Option<i64>,
    allow_loopback_http: bool,
) -> Result<(), ReadError> {
    read_page(
        server,
        branch,
        after_turn,
        limit,
        allow_loopback_http,
        Credential::PrivateStdin,
    )
    .await
}

/// The same bounded page, from the explicitly selected credential source.
pub async fn read_page(
    server: String,
    branch: String,
    after_turn: Option<i64>,
    limit: Option<i64>,
    allow_loopback_http: bool,
    credential: Credential,
) -> Result<(), ReadError> {
    let origin = origin(&server, allow_loopback_http)?;
    let after = after_turn.unwrap_or(contract::DEFAULT_AFTER_TURN);
    let limit = limit.unwrap_or(contract::DEFAULT_LIMIT);
    if !contract::canonical_uuid(&branch)
        || after < 0
        || !(1..=contract::MAX_LIMIT).contains(&limit)
    {
        return Err(ReadError::InvalidSelector);
    }
    let session = credential.present(&origin).await?;
    let client = Client::new(origin, session)?;
    let mut view = View::default();
    view.reload(&client, &branch, after, limit).await?;
    let rendered = view
        .snapshot
        .as_ref()
        .ok_or(ReadError::InvalidResponse)?
        .render();
    let mut output = std::io::stdout().lock();
    output
        .write_all(rendered.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| ReadError::Output)
}

#[cfg(unix)]
async fn session_from_stdin() -> Result<SessionToken, ReadError> {
    use std::os::fd::AsFd;
    // This command exclusively owns stdin during handoff. The cloned descriptor is
    // CLOEXEC; the shared open-file-description flags are restored on every exit.
    let fd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| ReadError::InvalidSessionHandoff)?;
    handoff::read_pipe(fd, Duration::from_secs(5)).await
}

#[cfg(not(unix))]
async fn session_from_stdin() -> Result<SessionToken, ReadError> {
    Err(ReadError::UnsupportedSessionHandoff)
}

#[cfg(test)]
#[path = "rust_conversation/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "rust_conversation/test_support.rs"]
mod test_support;
