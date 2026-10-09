//! Endpoint trust is verified against the served bytes, not asserted by the transport.
use super::*;

const ORIGIN: &str = "https://instance.test";

use crate::rust_conversation::test_support::{
    etag_of, key, key_of, key_set, other_pair, pair, published, readdress, readdress_with,
    server_with, Reply,
};

#[test]
fn a_published_document_yields_exactly_its_own_endpoint_set() {
    let document = published(ORIGIN);
    let trust = verify(&document, Some(&etag_of(&document)), ORIGIN, &key()).expect("verified");
    assert_eq!(trust.canonical_origin, ORIGIN);
    assert_eq!(trust.session, format!("{ORIGIN}/v1/sessions"));
    assert_eq!(
        trust.session_factor,
        format!("{ORIGIN}/v1/sessions/factors")
    );
    assert_eq!(
        trust.session_revoke,
        format!("{ORIGIN}/v1/sessions/current/revoke")
    );
    assert_eq!(
        trust.run_stream,
        format!("{ORIGIN}/v1/runs/{{run_id}}/stream")
    );
    assert_eq!(trust.signature_trust_root, TRUST_ROOT);
    assert_eq!(
        trust.session_refresh,
        format!("{ORIGIN}/v1/sessions/refresh")
    );
    assert_eq!(
        trust.device,
        Some(DeviceTrust {
            authorization: format!("{ORIGIN}/v1/device-authorizations"),
            token: format!("{ORIGIN}/v1/device-authorizations/tokens"),
            verification: format!("{ORIGIN}/activate"),
            client_id: "pa.tui".into(),
        })
    );
    // The pin is over the published address, the verified signature and the key it verified
    // against, which is what a later invocation compares.
    assert_eq!(trust.signature_key_id, key().kid);
    assert_eq!(trust.signature_key, key().x);
    assert_eq!(trust.signature, document["signature"].as_str().unwrap());
    assert_eq!(
        trust.content_hash,
        document["content_hash"].as_str().unwrap()
    );
}

#[test]
fn an_edited_document_fails_its_own_recomputed_address() {
    let mut document = published(ORIGIN);
    // A changed byte with the original address: exactly the substitution a pinned digest
    // exists to catch.
    document["endpoints"]["session"] = serde_json::json!(format!("{ORIGIN}/v1/elsewhere"));
    assert_eq!(
        verify(&document, Some(&etag_of(&document)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
}

#[test]
fn a_served_validator_that_disagrees_with_the_document_is_refused() {
    let document = published(ORIGIN);
    assert_eq!(
        verify(
            &document,
            Some(&format!("\"{}\"", "0".repeat(64))),
            ORIGIN,
            &key()
        ),
        Err(ReadError::EndpointTrustUnverified)
    );
}

#[test]
fn another_origin_is_never_derived_and_never_answers_for_this_one() {
    let document = published("https://elsewhere.test");
    assert_eq!(
        verify(&document, Some(&etag_of(&document)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );

    // The same document, but one endpoint moved off the origin it claims to be.
    let mut moved = published(ORIGIN);
    moved["endpoints"]["run_stream"] =
        serde_json::json!("https://elsewhere.test/v1/runs/{run_id}/stream");
    let moved = readdress(moved);
    assert_eq!(
        verify(&moved, Some(&etag_of(&moved)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
}

#[test]
fn a_document_without_the_bootstrap_constraints_this_client_obeys_is_refused() {
    let mut document = published(ORIGIN);
    document["public_clients"]["Spa"]["public_bootstrap_constraints"]["csrf_header"] =
        serde_json::json!("x-other");
    let document = readdress(document);
    assert_eq!(
        verify(&document, Some(&etag_of(&document)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
}

#[test]
fn only_a_lowercase_fixed_length_hex_value_is_a_published_digest() {
    assert!(lowercase_hex(&"a".repeat(64), 64));
    assert!(!lowercase_hex(&"A".repeat(64), 64));
    assert!(!lowercase_hex(&"a".repeat(63), 64));
    assert!(!lowercase_hex("", 64));
}

#[test]
fn missing_or_unavailable_device_support_is_explicit_absence_not_a_guess() {
    let mut absent = published(ORIGIN);
    absent
        .as_object_mut()
        .unwrap()
        .remove("device_authorization");
    let absent = readdress(absent);
    let trust = verify(&absent, Some(&etag_of(&absent)), ORIGIN, &key()).expect("still verified");
    assert_eq!(trust.device, None);

    for state in ["UnsupportedByConfiguredProvider", "TemporarilyUnavailable"] {
        let mut unavailable = published(ORIGIN);
        unavailable["device_authorization"]["state"] = serde_json::json!(state);
        let unavailable = readdress(unavailable);
        let trust = verify(&unavailable, Some(&etag_of(&unavailable)), ORIGIN, &key()).unwrap();
        assert_eq!(trust.device, None);
    }
}

#[test]
fn a_supported_facade_for_another_client_profile_refuses_the_document() {
    let edits: [(&str, serde_json::Value); 8] = [
        (
            "/public_clients/Tui/public_transport_kind",
            "NativeBrokeredHumanSession".into(),
        ),
        ("/public_clients/Tui/public_client_id", "pa.other".into()),
        ("/public_clients/Tui/kind", "Desktop".into()),
        (
            "/public_clients/Tui/allowed_public_audiences",
            serde_json::json!(["admin"]),
        ),
        (
            "/public_clients/Tui/public_permissions",
            serde_json::json!(["session.refresh"]),
        ),
        ("/device_authorization/client", "pa.api".into()),
        // The facade and the endpoint set must name one URL, and it must be on the origin.
        (
            "/device_authorization/token_endpoint",
            format!("{ORIGIN}/v1/other").into(),
        ),
        (
            "/endpoints/device_authorization",
            "https://elsewhere.test/v1/device-authorizations".into(),
        ),
    ];
    for (pointer, value) in edits {
        let mut document = published(ORIGIN);
        *document.pointer_mut(pointer).unwrap() = value;
        let document = readdress(document);
        assert_eq!(
            verify(&document, Some(&etag_of(&document)), ORIGIN, &key()),
            Err(ReadError::EndpointTrustUnverified),
            "{pointer}"
        );
    }
    let mut without_tui = published(ORIGIN);
    without_tui["public_clients"]
        .as_object_mut()
        .unwrap()
        .remove("Tui");
    let without_tui = readdress(without_tui);
    assert_eq!(
        verify(&without_tui, Some(&etag_of(&without_tui)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
}

#[test]
fn a_document_for_another_canonical_origin_is_refused_even_when_self_consistent() {
    // What a substituted instance would serve: internally consistent, addressed and tagged,
    // and naming itself -- which is not the origin this client was configured with.
    let document = published("https://localhost:9001");
    assert_eq!(
        verify(
            &document,
            Some(&etag_of(&document)),
            "https://localhost:9000",
            &key()
        ),
        Err(ReadError::EndpointTrustUnverified)
    );
    let mut issuer = published(ORIGIN);
    issuer["issuer"] = serde_json::json!("https://elsewhere.test");
    let issuer = readdress(issuer);
    assert_eq!(
        verify(&issuer, Some(&etag_of(&issuer)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
}

#[test]
fn a_document_signed_by_another_key_is_refused_even_under_the_same_key_id() {
    // Signed by another key, but naming the fixture's key id: the signature fails.
    let mut forged = readdress_with(published(ORIGIN), &other_pair());
    forged["signature_key_id"] = serde_json::json!(key().kid);
    assert_eq!(
        verify(&forged, Some(&etag_of(&forged)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
    // Consistently signed by the other key: verifying it takes the other key, which is not
    // the one this origin's trust was pinned to.
    let other = readdress_with(published(ORIGIN), &other_pair());
    assert_eq!(
        verify(&other, Some(&etag_of(&other)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
    let trust = verify(
        &other,
        Some(&etag_of(&other)),
        ORIGIN,
        &key_of(&other_pair()),
    )
    .unwrap();
    assert_ne!(
        trust,
        verify(&published(ORIGIN), None, ORIGIN, &key()).unwrap()
    );
}

#[test]
fn a_signature_over_another_digest_or_in_another_form_is_refused() {
    // A valid signature, but over some other content.
    let mut replayed = published(ORIGIN);
    let foreign = pair().sign(&[0; 32]);
    replayed["signature"] = serde_json::json!(hex_of(foreign.as_ref()));
    // The signature is outside the content address, so the digest still matches.
    assert_eq!(
        verify(&replayed, Some(&etag_of(&replayed)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
    let edits: [(&str, serde_json::Value); 5] = [
        ("signature_algorithm", "HS256".into()),
        ("signature_trust_root", "deployment_auth_signing.v1".into()),
        ("signature_key_id", key_of(&other_pair()).kid.into()),
        ("signature", "AB".repeat(64).into()),
        ("signature", "ab".repeat(32).into()),
    ];
    for (field, value) in edits {
        let mut document = published(ORIGIN);
        document[field] = value;
        assert_eq!(
            verify(&document, Some(&etag_of(&document)), ORIGIN, &key()),
            Err(ReadError::EndpointTrustUnverified),
            "{field}"
        );
    }
    // A key set published anywhere but the one same-origin URL is not this instance's.
    let mut moved = published(ORIGIN);
    moved["jwks_uri"] = serde_json::json!("https://elsewhere.test/.well-known/personal-agent/jwks");
    let moved = readdress(moved);
    assert_eq!(
        verify(&moved, Some(&etag_of(&moved)), ORIGIN, &key()),
        Err(ReadError::EndpointTrustUnverified)
    );
}

#[test]
fn a_published_key_is_selected_only_when_it_is_its_own_thumbprint() {
    let good = key();
    assert_eq!(select_key(&key_set(&good), &good.kid), Ok(good.clone()));
    // Another key's material under this key's id.
    let mut swapped = key_set(&good);
    swapped["keys"][0]["x"] = serde_json::json!(key_of(&other_pair()).x);
    assert!(select_key(&swapped, &good.kid).is_err());
    // An id the set does not publish.
    assert!(select_key(&key_set(&good), &key_of(&other_pair()).kid).is_err());
    // The same id twice is ambiguous.
    let mut twice = key_set(&good);
    let member = twice["keys"][0].clone();
    twice["keys"].as_array_mut().unwrap().push(member);
    assert!(select_key(&twice, &good.kid).is_err());
    for (field, value) in [
        ("kty", "EC"),
        ("crv", "X25519"),
        ("alg", "ES256"),
        ("use", "enc"),
        ("trust_root", "deployment_auth_signing.v1"),
    ] {
        let mut set = key_set(&good);
        set["keys"][0][field] = serde_json::json!(value);
        assert!(select_key(&set, &good.kid).is_err(), "{field}");
    }
    let mut padded = key_set(&good);
    padded["keys"][0]["x"] = serde_json::json!(format!("{}=", good.x));
    assert!(select_key(&padded, &good.kid).is_err());
}

#[tokio::test]
async fn discovery_fetches_the_published_key_and_verifies_the_served_signature() {
    let (url, task) =
        server_with(|origin| vec![Reply::document(&published(origin)), Reply::fixture_keys()]);
    let origin = super::super::origin(url.as_str(), true).unwrap();
    let trust = discover(&client().unwrap(), &origin, None).await.unwrap();
    assert_eq!(trust.signature_key_id, key().kid);
    let seen = task.join().unwrap();
    assert!(seen[1]
        .head
        .starts_with("GET /.well-known/personal-agent/jwks HTTP/1.1\r\n"));
    assert!(!seen[1].head.to_ascii_lowercase().contains("\r\ncookie:"));

    // With the key pinned, the key set is not fetched again.
    let (url, task) = server_with(|origin| vec![Reply::document(&published(origin))]);
    let origin = super::super::origin(url.as_str(), true).unwrap();
    discover(&client().unwrap(), &origin, Some(&key()))
        .await
        .unwrap();
    assert_eq!(task.join().unwrap().len(), 1);
}

#[tokio::test]
async fn discovery_refuses_a_document_the_published_key_does_not_verify() {
    // The instance serves a document signed by one key and publishes another under its id.
    let (url, task) = server_with(|origin| {
        let forged = readdress_with(published(origin), &other_pair());
        let mut set = key_set(&key());
        set["keys"][0]["kid"] = serde_json::json!(key_of(&other_pair()).kid);
        vec![Reply::document(&forged), Reply::keys(&set)]
    });
    let origin = super::super::origin(url.as_str(), true).unwrap();
    assert_eq!(
        discover(&client().unwrap(), &origin, None).await.err(),
        Some(ReadError::EndpointTrustUnverified)
    );
    task.join().unwrap();

    // A pinned key never yields to a document naming a different one: the new key is
    // fetched, verified, and the result is not the pinned trust.
    let (url, task) = server_with(|origin| {
        vec![
            Reply::document(&readdress_with(published(origin), &other_pair())),
            Reply::keys(&key_set(&key_of(&other_pair()))),
        ]
    });
    let origin = super::super::origin(url.as_str(), true).unwrap();
    let trust = discover(&client().unwrap(), &origin, Some(&key()))
        .await
        .unwrap();
    assert_ne!(trust.signature_key_id, key().kid);
    task.join().unwrap();
}
