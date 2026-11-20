//! Firma, versión y formato del manifiesto.

mod common;

use blocklists::{ListError, Manifest};
use common::{content, key, public, release, sign};
use ed25519_dalek::SigningKey;

#[test]
fn a_signed_newer_manifest_is_accepted() {
    let r = release(2026112001, &content("a"), &[], &key());
    let m = Manifest::verify(
        &r.manifest,
        &r.signature,
        &[public(&key())],
        Some(2026111901),
    )
    .unwrap();
    assert_eq!(m.version, 2026112001);
    // Sin listas instaladas también.
    Manifest::verify(&r.manifest, &r.signature, &[public(&key())], None).unwrap();
}

#[test]
fn another_key_is_rejected() {
    let impostor = SigningKey::from_bytes(&[0x22; 32]);
    let r = release(2026112001, &content("a"), &[], &impostor);
    assert_eq!(
        Manifest::verify(&r.manifest, &r.signature, &[public(&key())], None),
        Err(ListError::BadSignature)
    );
}

#[test]
fn any_altered_byte_is_rejected() {
    let r = release(2026112001, &content("a"), &[], &key());
    for position in (0..r.manifest.len()).step_by(7) {
        let mut altered = r.manifest.clone();
        altered[position] ^= 0x01;
        assert_eq!(
            Manifest::verify(&altered, &r.signature, &[public(&key())], None),
            Err(ListError::BadSignature),
            "byte {position}"
        );
    }
}

#[test]
fn same_or_older_versions_are_rejected() {
    let r = release(2026112001, &content("a"), &[], &key());
    for installed in [2026112001, 2026112002, 2027010101] {
        assert_eq!(
            Manifest::verify(
                &r.manifest,
                &r.signature,
                &[public(&key())],
                Some(installed)
            ),
            Err(ListError::NotNewer {
                installed,
                offered: 2026112001
            })
        );
    }
}

#[test]
fn rotated_keys_are_both_trusted() {
    let new_key = SigningKey::from_bytes(&[0x33; 32]);
    let keys = [public(&key()), public(&new_key)];
    for signer in [key(), new_key] {
        let r = release(2026112001, &content("a"), &[], &signer);
        Manifest::verify(&r.manifest, &r.signature, &keys, None).unwrap();
    }
    // Sin ninguna clave de confianza, nada pasa.
    let r = release(2026112001, &content("a"), &[], &key());
    assert_eq!(
        Manifest::verify(&r.manifest, &r.signature, &[], None),
        Err(ListError::BadSignature)
    );
}

#[test]
fn signed_but_malformed_manifests_are_rejected() {
    let cases: [(&str, &[u8]); 4] = [
        ("no es json", b"esto no es un manifiesto"),
        (
            "formato futuro",
            br#"{"format":2,"version":1,"created":"x","lists":{}}"#,
        ),
        (
            "faltan categorías",
            br#"{"format":1,"version":1,"created":"x","lists":{}}"#,
        ),
        (
            "categoría desconocida",
            br#"{"format":1,"version":1,"created":"x","lists":{
              "porn":{"domains":0,"size":0,"sha256":""},
              "gambling":{"domains":0,"size":0,"sha256":""},
              "dating":{"domains":0,"size":0,"sha256":""},
              "bypass":{"domains":0,"size":0,"sha256":""},
              "social":{"domains":0,"size":0,"sha256":""}}}"#,
        ),
    ];
    for (label, manifest) in cases {
        let signature = sign(manifest, &key());
        assert!(
            matches!(
                Manifest::verify(manifest, &signature, &[public(&key())], None),
                Err(ListError::BadManifest(_))
            ),
            "{label}"
        );
    }
}

#[test]
fn signature_file_tolerates_a_trailing_newline_only() {
    let r = release(2026112001, &content("a"), &[], &key());
    let mut with_newline = r.signature.clone();
    with_newline.push(b'\n');
    Manifest::verify(&r.manifest, &with_newline, &[public(&key())], None).unwrap();
    for bad in [&b""[..], b"zz", &r.signature[..64]] {
        assert_eq!(
            Manifest::verify(&r.manifest, bad, &[public(&key())], None),
            Err(ListError::BadSignature)
        );
    }
}
