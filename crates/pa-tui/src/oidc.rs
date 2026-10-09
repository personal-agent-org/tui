//! The legacy chat UI's OAuth refresh. Its tokens come from a legacy `config.toml`; new
//! sign-ins go through the Rust backend's device authorization (`rust_conversation::device`)
//! and never produce such tokens.

use anyhow::Result;
use pa_oidc::Tokens;

/// Exchange a refresh token at the endpoint persisted in the legacy config.
pub async fn refresh(token_endpoint: &str, client_id: &str, refresh_token: &str) -> Result<Tokens> {
    pa_oidc::refresh(token_endpoint, client_id, refresh_token).await
}
