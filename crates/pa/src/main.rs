//! `pa`, Personal Agent's terminal chat client. It consumes the chat API and never exposes
//! tools or host capabilities to the backend. Those belong exclusively to the separate `pacs`
//! Computer Service.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pa", version, about = "Personal Agent terminal chat client")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create one Rust-backend Conversation; does not start a Run or retry on uncertainty.
    RustConversationCreate {
        #[arg(long)]
        server: String,
        #[arg(long, required = true)]
        session_stdin: bool,
        #[arg(long)]
        main: bool,
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Submit a Human turn with its stable key and expected head; never reads a Run.
    RustConversationSubmit {
        #[arg(long)]
        server: String,
        #[arg(long)]
        branch: String,
        #[arg(long)]
        expected_turn: i64,
        /// Stable command key, not a credential; reuse only with identical command bytes.
        #[arg(long)]
        idempotency_key: String,
        /// Explicit regular UTF-8 file, at most 65536 bytes; text is not exposed in argv.
        #[arg(long)]
        text_file: std::path::PathBuf,
        #[arg(long, required = true)]
        session_stdin: bool,
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Open one Rust-backend session: local password and, when required, one TOTP code.
    ///
    /// Both secrets arrive on a private stdin pipe, one per line, and never in argv.
    RustLogin {
        /// Exact instance origin, normally HTTPS (no path, query, or embedded credentials).
        #[arg(long)]
        server: String,
        /// The presented login identifier. Not a credential.
        #[arg(long)]
        login: String,
        /// Which enrolled TOTP method answers the challenge; required only with several.
        #[arg(long)]
        method: Option<String>,
        /// Development only: allow cleartext HTTP to an explicitly selected loopback IP.
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Revoke the stored Rust-backend session family and remove the local credential.
    RustLogout {
        #[arg(long)]
        server: String,
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Follow one Run's delivery stream, resuming after the last frame actually applied.
    RustStream {
        #[arg(long)]
        server: String,
        /// Existing canonical Run UUID.
        #[arg(long)]
        run: String,
        /// The last applied sequence; omitted starts at the beginning of this subscription.
        #[arg(long)]
        after: Option<i64>,
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Read one existing Rust-backend Conversation page; no login or Run is started.
    RustConversation {
        /// Exact instance origin, normally HTTPS (no path, query, or embedded credentials).
        #[arg(long)]
        server: String,
        /// Existing canonical branch UUID; this command does not discover private branches.
        #[arg(long)]
        branch: String,
        /// Explicitly receive one 64-hex session token from a private stdin pipe, never a TTY.
        #[arg(long)]
        session_stdin: bool,
        /// Present the session `rust-login` stored for this exact origin instead.
        #[arg(long, conflicts_with = "session_stdin")]
        session_store: bool,
        /// Exclusive canonical turn position; omitted starts at the beginning.
        #[arg(long)]
        after_turn: Option<i64>,
        /// One bounded page (1 to 200 messages).
        #[arg(long)]
        limit: Option<i64>,
        /// Development only: allow cleartext HTTP to an explicitly selected loopback IP.
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Sign in to the instance at --server and store its session for this user.
    ///
    /// Default: the RFC 8628 device authorization named by the instance's verified
    /// /.well-known/personal-agent document; approve the printed code in a browser.
    Login {
        /// Exact instance origin, normally HTTPS (no path, query, or embedded credentials).
        #[arg(long)]
        server: String,
        /// UI language (de or en); omit to use the system locale.
        #[arg(long)]
        lang: Option<String>,
        /// Use the local password (and TOTP) ceremony instead; secrets arrive on stdin.
        #[arg(long, requires = "login")]
        password: bool,
        /// The login identifier for --password. Not a credential.
        #[arg(long, requires = "password")]
        login: Option<String>,
        /// Which enrolled TOTP method answers the challenge, for --password.
        #[arg(long, requires = "password")]
        method: Option<String>,
        /// Development only: allow cleartext HTTP to an explicitly selected loopback IP.
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// List the signed-in Human's conversations with the stored session.
    Conversations {
        /// Instance origin; omitted uses the one the stored session belongs to.
        #[arg(long)]
        server: Option<String>,
        /// One bounded page (1 to 200 conversations; default 50).
        #[arg(long)]
        limit: Option<i64>,
        /// The next_cursor a previous page printed.
        #[arg(long)]
        cursor: Option<String>,
        /// Also list conversations hidden from general lists.
        #[arg(long)]
        include_hidden: bool,
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Revoke the stored session at the instance and remove every stored credential.
    Logout {
        /// Instance origin; omitted uses the one the stored session belongs to.
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        allow_loopback_http: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    pa_tui::init_i18n(None);

    match cli.cmd {
        Some(Cmd::RustConversationCreate {
            server,
            session_stdin: true,
            main,
            allow_loopback_http,
        }) => {
            pa_tui::rust_conversation::write::create_from_stdin(server, main, allow_loopback_http)
                .await?;
            Ok(())
        }
        Some(Cmd::RustConversationSubmit {
            server,
            branch,
            expected_turn,
            idempotency_key,
            text_file,
            session_stdin: true,
            allow_loopback_http,
        }) => {
            pa_tui::rust_conversation::write::submit_from_stdin(
                server,
                branch,
                expected_turn,
                idempotency_key,
                text_file,
                allow_loopback_http,
            )
            .await?;
            Ok(())
        }
        Some(
            Cmd::RustConversationCreate {
                session_stdin: false,
                ..
            }
            | Cmd::RustConversationSubmit {
                session_stdin: false,
                ..
            },
        ) => {
            anyhow::bail!("rust_conversation.explicit_session_stdin_required")
        }
        Some(Cmd::RustConversation {
            server,
            branch,
            session_stdin,
            session_store,
            after_turn,
            limit,
            allow_loopback_http,
        }) => {
            // Exactly one explicitly selected credential source. Never both, never ambient.
            let credential = match (session_stdin, session_store) {
                (true, false) => pa_tui::rust_conversation::Credential::PrivateStdin,
                (false, true) => pa_tui::rust_conversation::Credential::StoredSession,
                _ => anyhow::bail!("rust_conversation.explicit_session_stdin_required"),
            };
            pa_tui::rust_conversation::read_page(
                server,
                branch,
                after_turn,
                limit,
                allow_loopback_http,
                credential,
            )
            .await?;
            Ok(())
        }
        Some(Cmd::RustLogin {
            server,
            login,
            method,
            allow_loopback_http,
        }) => {
            pa_tui::rust_conversation::session::login(server, login, method, allow_loopback_http)
                .await?;
            Ok(())
        }
        Some(Cmd::RustLogout {
            server,
            allow_loopback_http,
        }) => {
            pa_tui::rust_conversation::session::logout(server, allow_loopback_http).await?;
            Ok(())
        }
        Some(Cmd::RustStream {
            server,
            run,
            after,
            allow_loopback_http,
        }) => {
            pa_tui::rust_conversation::stream::follow(server, run, after, allow_loopback_http)
                .await?;
            Ok(())
        }
        None => pa_tui::run().await,
        Some(Cmd::Login {
            server,
            lang,
            password,
            login,
            method,
            allow_loopback_http,
        }) => {
            let password = match (password, login) {
                (true, Some(login)) => Some(pa_tui::PasswordLogin { login, method }),
                _ => None,
            };
            pa_tui::login(server, lang, password, allow_loopback_http).await
        }
        Some(Cmd::Conversations {
            server,
            limit,
            cursor,
            include_hidden,
            allow_loopback_http,
        }) => {
            pa_tui::rust_conversation::conversations::list(
                server,
                limit,
                cursor,
                include_hidden,
                allow_loopback_http,
            )
            .await?;
            Ok(())
        }
        Some(Cmd::Logout {
            server,
            allow_loopback_http,
        }) => pa_tui::logout(server, allow_loopback_http).await,
    }
}
