//! The workspace's TLS trust decision (`tls`) and the legacy OAuth refresh grant.
//!
//! Discovery no longer lives here. The server a client talks to is discovered and verified
//! through `/.well-known/personal-agent` (§19.2) in `pa-tui`'s `rust_conversation::session`,
//! and the terminal's sign-in is the Rust backend's own RFC 8628 facade
//! (`rust_conversation::device`). The old Python backend's `/api/v1/public/client-config`
//! is not called anywhere any more.
//!
//! What remains is [`refresh`]: the legacy chat UI still holds OAuth tokens in its
//! `config.toml`, and renewing them is the only thing it needs from this crate.

pub mod tls;

use anyhow::Result;
use serde::Deserialize;

/// A legacy OAuth access/refresh token pair.
#[derive(Deserialize, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

/// Exchange a legacy refresh token for a fresh access (+ refresh) token.
pub async fn refresh(token_endpoint: &str, client_id: &str, refresh_token: &str) -> Result<Tokens> {
    let resp = tls::http_client()
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ])
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json::<Tokens>().await?)
}
