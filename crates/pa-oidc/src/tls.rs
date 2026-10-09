//! One TLS trust decision, shared by every client in the workspace.
//!
//! Every crate here used to build its own TLS stack from `webpki-roots` alone — the Mozilla
//! root set compiled into the binary. That is the right default for talking to the public
//! internet and the wrong one for talking to your own server: a Personal Agent behind an
//! internal CA is unreachable no matter what the operating system trusts, and
//! `SSL_CERT_FILE` does nothing, because a compiled-in root list has no reason to read it.
//!
//! The failure was also badly disguised. The handshake fails, `reqwest` returns a transport
//! error, and the caller reports "client-config unreachable" — so an internal-CA deployment
//! looks like a networking or schema problem rather than a trust problem.
//!
//! Order of preference:
//!
//! 1. The system trust store (`rustls-native-certs`), which also honours `SSL_CERT_FILE` and
//!    `SSL_CERT_DIR`. Installing a CA the usual way (`update-ca-trust`, `update-ca-certificates`)
//!    is then enough, which is what an operator expects.
//! 2. `webpki-roots` as a FALLBACK, only when the system store yields nothing — a scratch
//!    container often has no store at all, and falling back keeps public endpoints working
//!    there instead of failing everything.
//!
//! Both roots sets are merged rather than either/or when the system store exists but is
//! sparse: a machine that trusts an internal CA still has to reach public IdPs.
//!
//! 3. An explicitly pinned end-entity certificate (`PA_TLS_PINNED_CERT_FILE`, PEM). §7.2 lets
//!    the TUI's native verifier support "System roots, scoped imported CA and SPKI pins". The
//!    pin is additive and exact: it is consulted only when ordinary verification refused,
//!    accepts only a presented leaf byte-equal to a pinned certificate that is also valid for
//!    the requested name, and every handshake signature is still verified against that
//!    leaf's key. It exists for a self-signed development certificate that webpki cannot
//!    use as a trust anchor (`CaUsedAsEndEntity`); there is no switch that skips verification.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

/// ALPN for ordinary HTTP clients: only what they speak. `reqwest` is built without its
/// `http2` feature, so offering `h2` let a server that prefers it (the Quasar dev server
/// does) select a protocol hyper then refuses with a panic.
const ALPN_HTTP: &[&[u8]] = &[b"http/1.1"];
/// ALPN for the control WebSocket: the upgrade must not be offered h2.
const ALPN_WS: &[&[u8]] = &[b"http/1.1"];

/// Roots to validate server certificates against: the system store, plus the compiled-in
/// Mozilla set, plus anything `SSL_CERT_FILE` / `SSL_CERT_DIR` point at.
pub fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();

    // `load_native_certs` reports per-certificate errors instead of failing outright, so a
    // single unparseable file in the system store cannot take the whole trust set down with it.
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        // A root we cannot parse is skipped, not fatal: the rest of the store is still good.
        let _ = roots.add(cert);
    }

    // Only as a fallback. Merging unconditionally would be harmless but slower, and on a
    // machine WITH a store the operator's decisions should be the ones that count.
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    roots
}

/// The environment variable naming a PEM file of explicitly pinned end-entity certificates.
pub const PINNED_CERT_ENV: &str = "PA_TLS_PINNED_CERT_FILE";

/// The certificates `PA_TLS_PINNED_CERT_FILE` pins, if it is set. An unreadable or empty file
/// pins nothing (and so widens nothing).
fn pinned_certificates() -> Vec<CertificateDer<'static>> {
    let Some(path) = std::env::var_os(PINNED_CERT_ENV).filter(|path| !path.is_empty()) else {
        return Vec::new();
    };
    CertificateDer::pem_file_iter(path)
        .map(|certificates| certificates.filter_map(Result::ok).collect())
        .unwrap_or_default()
}

/// Ordinary webpki verification, plus exact end-entity pins as a strictly additive fallback.
#[derive(Debug)]
struct PinnedOrWebPki {
    webpki: Arc<rustls::client::WebPkiServerVerifier>,
    pins: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedOrWebPki {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let refused = match self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => return Ok(verified),
            Err(refused) => refused,
        };
        if !self
            .pins
            .iter()
            .any(|pin| pin.as_ref() == end_entity.as_ref())
        {
            return Err(refused);
        }
        // The pin names one certificate for the names it carries, not for any host.
        let certificate =
            webpki::EndEntityCert::try_from(end_entity).map_err(|_| refused.clone())?;
        certificate
            .verify_is_valid_for_subject_name(server_name)
            .map_err(|_| refused)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn config_with(alpn: &[&[u8]], pins: Vec<CertificateDer<'static>>) -> rustls::ClientConfig {
    // The provider is named explicitly rather than taken from the process default: this crate
    // is used by binaries that may not have installed one, and a missing default provider
    // panics at handshake time — a long way from where the mistake was made.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions");
    let mut cfg = if pins.is_empty() {
        builder
            .with_root_certificates(root_store())
            .with_no_client_auth()
    } else {
        let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store()),
            provider.clone(),
        )
        .build()
        .expect("a non-empty root store builds a verifier");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedOrWebPki {
                webpki,
                pins,
                provider,
            }))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

fn config(alpn: &[&[u8]]) -> rustls::ClientConfig {
    config_with(alpn, pinned_certificates())
}

/// TLS config for HTTP clients.
pub fn http_tls_config() -> rustls::ClientConfig {
    config(ALPN_HTTP)
}

/// TLS config for the control WebSocket (ALPN pinned to http/1.1 for the upgrade).
pub fn ws_tls_config() -> rustls::ClientConfig {
    config(ALPN_WS)
}

/// A `reqwest` builder that trusts the same roots as everything else here.
///
/// Use this instead of `reqwest::Client::new()` / `Client::builder()`: those pick up the
/// compiled-in roots only, which is exactly the bug this module exists to fix.
pub fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().use_preconfigured_tls(http_tls_config())
}

/// A ready `reqwest` client with the shared trust store.
pub fn http_client() -> reqwest::Client {
    // A default-configuration client cannot fail to build; the fallback keeps the signature
    // infallible so call sites do not each grow error handling for an impossible case.
    http_client_builder()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trust_store_is_never_empty() {
        // Whatever the machine looks like -- system store, no system store, CI container --
        // there must be roots, or every HTTPS call fails with UnknownIssuer.
        assert!(!root_store().is_empty());
    }

    #[test]
    fn the_websocket_does_not_offer_h2() {
        // Offering h2 on the upgrade is how a WS connect ends up negotiating the wrong protocol.
        assert_eq!(ws_tls_config().alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// A test-only self-signed `localhost` certificate with `CA:TRUE`, shaped exactly like
    /// the development certificate webpki refuses as an end entity. Not used outside tests.
    const SELF_SIGNED_CA_LEAF: &str = "-----BEGIN CERTIFICATE-----\nMIIBmjCCAUGgAwIBAgIUYxKGcBBzx1+wsSwJSM6Zw7hpp50wCgYIKoZIzj0EAwIw\nFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkyNjIwNTYyNFoYDzIxMjYwOTAy\nMjA1NjI0WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\nPQMBBwNCAARWzXVS3lYL0aD1WQfVAnXoMBe58APciIh/SMw/hXaMnZApV9lb0GUE\nf9KEGG6HjIpugZxUTThnsvOwXEa2FBnEo28wbTAdBgNVHQ4EFgQUb8vHP9Z75y8o\nzY7SziAd0mMG+S0wHwYDVR0jBBgwFoAUb8vHP9Z75y8ozY7SziAd0mMG+S0wGgYD\nVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI\nzj0EAwIDRwAwRAIgTrrEI0ulBNlpKFhIvQPP47t/lXTlM+M77Wr/26vmCGcCIEyl\nj1ZOPhayUIoH/qMkbilcX0oS17LjO6Of+5A26Ual\n-----END CERTIFICATE-----";
    const SELF_SIGNED_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYhHnM9ZvcCHE2dal\n3vDBud3p2/+MupznatDHYh7ESEWhRANCAARWzXVS3lYL0aD1WQfVAnXoMBe58APc\niIh/SMw/hXaMnZApV9lb0GUEf9KEGG6HjIpugZxUTThnsvOwXEa2FBnE\n-----END PRIVATE KEY-----";

    /// One in-process TLS handshake against a server presenting [`SELF_SIGNED_CA_LEAF`].
    fn handshake(pins: Vec<CertificateDer<'static>>, name: &str) -> Result<(), rustls::Error> {
        use std::io::{Read, Write};
        let certificate = CertificateDer::from_pem_slice(SELF_SIGNED_CA_LEAF.as_bytes()).unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(SELF_SIGNED_KEY.as_bytes()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], key)
                .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let serving = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let connection = rustls::ServerConnection::new(server).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut byte = [0];
            if stream.read_exact(&mut byte).is_ok() {
                let _ = stream.write_all(&byte);
            }
        });
        let client = rustls::ClientConnection::new(
            Arc::new(config_with(ALPN_HTTP, pins)),
            ServerName::try_from(name.to_owned()).unwrap(),
        )
        .unwrap();
        let socket = std::net::TcpStream::connect(address).unwrap();
        let mut stream = rustls::StreamOwned::new(client, socket);
        let outcome = stream
            .write_all(b"x")
            .and_then(|()| stream.read_exact(&mut [0]));
        drop(stream);
        let _ = serving.join();
        outcome.map_err(|error| {
            error
                .into_inner()
                .and_then(|inner| inner.downcast::<rustls::Error>().ok())
                .map_or(rustls::Error::General("io".into()), |error| *error)
        })
    }

    #[test]
    fn a_ca_shaped_self_signed_leaf_is_refused_without_a_pin() {
        let refused = handshake(Vec::new(), "localhost").unwrap_err();
        assert!(
            matches!(refused, rustls::Error::InvalidCertificate(_)),
            "{refused:?}"
        );
    }

    #[test]
    fn exactly_the_pinned_leaf_is_accepted_and_only_for_its_own_names() {
        let pinned = CertificateDer::from_pem_slice(SELF_SIGNED_CA_LEAF.as_bytes()).unwrap();
        handshake(vec![pinned.clone()], "localhost").expect("the pinned leaf is accepted");
        assert!(handshake(vec![pinned], "elsewhere.test").is_err());

        // A different certificate pinned is no pin for this one.
        let mut other = SELF_SIGNED_CA_LEAF.as_bytes().to_vec();
        let flip = other.len() / 2;
        other[flip] = if other[flip] == b'A' { b'B' } else { b'A' };
        let other = CertificateDer::from_pem_slice(&other)
            .map(|der| der.into_owned())
            .unwrap_or_else(|_| CertificateDer::from(vec![0x30, 0x00]));
        assert!(handshake(vec![other], "localhost").is_err());
    }

    #[test]
    fn http_offers_only_the_protocol_the_client_speaks() {
        assert_eq!(http_tls_config().alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
