//! `pa_tui` — the Personal Agent terminal chat client as a library. `login` runs the Rust
//! backend's RFC 8628 device authorization, discovered and verified through
//! `/.well-known/personal-agent` (§7.2, §19.2), and stores the delivered session family;
//! `rust_conversation` presents it as the `pa_session` cookie plus `pa-csrf`. `run` opens the
//! legacy `/api/v1` chat UI when a legacy config exists.

mod agui;
mod api;
mod app;
mod composer;
mod computer_service;
mod config;
mod generated;
mod i18n;
mod oidc;
mod picker;
pub mod rust_conversation;
mod scrollback;
mod sse;
mod terminal;
mod ui;
mod ws;

use std::sync::Arc;

use anyhow::Result;

use api::ApiClient;
use i18n::{t, Msg};

/// Pick the UI language from an explicit value / `PA_LANG` / the system locale.
pub fn init_i18n(lang: Option<&str>) {
    i18n::init_from(lang);
}

/// Open the chat UI (default when no subcommand is given).
///
/// The full-screen chat UI still speaks the legacy `/api/v1` and starts only from a legacy
/// `config.toml`. Without one, a session `pa login` stored for the Rust backend is used to
/// list that instance's conversations instead.
pub async fn run() -> Result<()> {
    if !config::config_path().exists() {
        if let Ok(origin) = rust_conversation::session::stored_origin() {
            eprintln!("{}", t(Msg::RustBackendNoChatUi));
            rust_conversation::conversations::list(Some(origin), None, None, false, false).await?;
            return Ok(());
        }
    }
    let cfg = config::load()?;
    i18n::init_from(cfg.lang.as_deref());
    let client = Arc::new(ApiClient::new(&cfg)?);
    if let Some(name) = app::run(client.clone()).await? {
        computer_service::install(client.as_ref(), &name).await?;
    }
    Ok(())
}

/// The alternative ceremony `pa login --password` selects.
pub struct PasswordLogin {
    /// The presented login identifier. Not a credential.
    pub login: String,
    /// Which enrolled TOTP method answers the challenge; required only with several.
    pub method: Option<String>,
}

/// Log in and store the session for the Rust backend at `server`.
///
/// The default is the RFC 8628 device authorization the instance's verified
/// `/.well-known/personal-agent` document names for this client (§7.2). `password` selects
/// the local-password ceremony instead; its secrets arrive on a private stdin pipe.
pub async fn login(
    server: String,
    lang: Option<String>,
    password: Option<PasswordLogin>,
    allow_loopback_http: bool,
) -> Result<()> {
    i18n::init_from(lang.as_deref());
    match password {
        Some(PasswordLogin { login, method }) => {
            rust_conversation::session::login(server, login, method, allow_loopback_http)
                .await
                .map_err(|error| anyhow::anyhow!("{}", t(Msg::OidcFailed(&error.to_string()))))?;
        }
        None => {
            let path = rust_conversation::device::login(server, allow_loopback_http)
                .await
                .map_err(|error| anyhow::anyhow!("{}", t(Msg::OidcFailed(&error.to_string()))))?;
            println!("{}", t(Msg::LoginSuccess(&path.display().to_string())));
        }
    }
    println!("{}", t(Msg::LoginStartHint));
    Ok(())
}

/// Revoke the stored session family (`RevokeCurrentSession`) and remove every stored
/// credential, the legacy `config.toml` included.
pub async fn logout(server: Option<String>, allow_loopback_http: bool) -> Result<()> {
    let mut done = false;
    let server = server.or_else(|| rust_conversation::session::stored_origin().ok());
    if let Some(server) = server {
        match rust_conversation::session::logout(server, allow_loopback_http).await {
            Ok(()) => done = true,
            Err(rust_conversation::ReadError::NoStoredSession) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let path = config::config_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
        println!("{}", t(Msg::LogoutDone(&path.display().to_string())));
        done = true;
    }
    if !done {
        println!("{}", t(Msg::LogoutNone));
    }
    Ok(())
}
