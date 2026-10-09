# Personal Agent TUI

`pa` is the terminal chat client for Personal Agent.

```bash
pa login --server https://pa.example.com   # RFC 8628 device authorization; approve the code in a browser
pa conversations                           # list your conversations with the stored session
pa logout                                  # revoke the session at the instance and remove it locally
```

`pa login` first verifies the instance's `/.well-known/personal-agent` document (canonical
origin, content address, its Ed25519 signature against the key published at
`/.well-known/personal-agent/jwks`, the `Tui` client registration) and refuses an instance
that names another origin. The key is pinned with the session: a later command verifies
against it and fences the session if the document, its signature or its key changes. `pa login --password --login NAME` uses the local password (and TOTP)
ceremony instead; the secrets are read from a private stdin pipe.

The session is stored only for the current user in
`~/.config/personal-agent/rust-client/session.toml` (directory 0700, file 0600; override the
directory with `PA_RUST_CLIENT_HOME`). It is presented as the `pa_session` cookie plus the
`pa-csrf` header. From half the session's lifetime on, the family is refreshed and the
session cookie the instance issues with it replaces the stored one; refreshing stops at the
family's own end. Each refresh carries a fresh `Idempotency-Key`; an unknown outcome (timeout,
lost answer, 5xx) is recovered exactly once with the same key and body, after which the
refresh credential is retired rather than ever presented again.
Nothing is loaded from `/etc` or shared with the desktop app or Computer Service.

TLS uses the system trust store (`SSL_CERT_FILE`/`SSL_CERT_DIR` are honoured). A
self-signed development certificate that cannot act as a trust anchor can be pinned exactly
with `PA_TLS_PINNED_CERT_FILE=/path/to/cert.pem`; verification is never switched off.

The TUI consumes the chat API and does not expose tools, sensors, filesystem access, or other
host capabilities. Those are provided exclusively by the separate
[`computer-service`](https://github.com/personal-agent-org/computer-service), which uses its own
device-bound credential. The `/computer-service` command can install that service without giving
it access to the TUI's chat token.

## Build

```bash
cargo build --release
```

The `pa` binary is written to `target/release/pa`.

## Layout

- `crates/pa`: CLI entry point
- `crates/pa-tui`: terminal chat client
- `crates/pa-oidc`: TLS trust (system roots, exact pins) and the legacy OAuth refresh
