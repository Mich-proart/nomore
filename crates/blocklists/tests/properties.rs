//! Propiedades: diferencias exactas y ningún pánico con datos basura.

mod common;

use std::collections::BTreeMap;

use blocklists::{Delta, Installed, Manifest};
use common::{content, key, public, release, sign};
use filter_core::{Category, CategoryList};
use proptest::prelude::*;

fn list(mut hashes: Vec<u64>) -> CategoryList {
    hashes.sort_unstable();
    hashes.dedup();
    CategoryList::from_hashes(Category::Porn, hashes).unwrap()
}

proptest! {
    #[test]
    fn delta_from_a_to_b_turns_a_into_b(
        a in proptest::collection::vec(any::<u64>(), 0..300),
        b in proptest::collection::vec(any::<u64>(), 0..300),
        shared in proptest::collection::vec(any::<u64>(), 0..300),
    ) {
        let old = list(a.iter().chain(&shared).copied().collect());
        let new = list(b.iter().chain(&shared).copied().collect());
        let delta = Delta::between(&old, &new, 1, 2).unwrap();
        let parsed = Delta::parse(&delta.to_bytes()).unwrap();
        prop_assert_eq!(parsed.apply(&old).unwrap(), new);
    }

    #[test]
    fn parsing_random_deltas_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        if let Ok(delta) = Delta::parse(&bytes) {
            let _ = delta.apply(&list(vec![1, 2, 3]));
        }
    }

    #[test]
    fn random_manifests_and_signatures_never_pass(
        manifest in proptest::collection::vec(any::<u8>(), 0..600),
        signature in proptest::collection::vec(any::<u8>(), 0..200),
    ) {
        prop_assert!(Manifest::verify(&manifest, &signature, &[public(&key())], None).is_err());
    }

    #[test]
    fn random_files_never_produce_lists(
        porn in proptest::collection::vec(any::<u8>(), 0..300),
        delta in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let r = release(2, &content("a"), &[(1, &content("z"))], &key());
        let m = Manifest::verify(&r.manifest, &r.signature, &[public(&key())], None).unwrap();
        let installed = Installed {
            version: 1,
            lists: content("z").iter().map(|(c, l)| (*c, l.to_bytes())).collect(),
        };
        let mut files: BTreeMap<String, Vec<u8>> = r.files.clone();
        files.insert("porn.nmbl".into(), porn);
        prop_assert!(m.apply(None, &files).is_err());
        let mut files: BTreeMap<String, Vec<u8>> = r.files.clone();
        files.retain(|name, _| name.ends_with(".delta"));
        files.insert("porn.1.delta".into(), delta);
        prop_assert!(m.apply(Some(&installed), &files).is_err());
    }

    #[test]
    fn a_validly_signed_manifest_with_random_hashes_never_produces_lists(
        hash in "[0-9a-f]{64}",
        size in any::<u64>(),
    ) {
        // Aun firmado, un manifiesto que no describe los ficheros servidos
        // no da listas.
        let r = release(1, &content("a"), &[], &key());
        let mut m: serde_json::Value = serde_json::from_slice(&r.manifest).unwrap();
        m["lists"]["porn"]["sha256"] = hash.into();
        m["lists"]["porn"]["size"] = size.into();
        let manifest = serde_json::to_vec(&m).unwrap();
        let signature = sign(&manifest, &key());
        let verified = Manifest::verify(&manifest, &signature, &[public(&key())], None).unwrap();
        prop_assert!(verified.apply(None, &r.files).is_err());
    }
}
