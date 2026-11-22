//! Publicaciones de prueba firmadas.
#![allow(dead_code)]

use std::collections::BTreeMap;

use blocklists::{
    category_name, delta_file_name, full_file_name, signing_bytes, Delta, DeltaRef, FileRef,
    ListEntry, Manifest,
};
use ed25519_dalek::{Signer, SigningKey};
use filter_core::{Category, CategoryList};

pub fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

pub fn public(key: &SigningKey) -> [u8; 32] {
    *key.verifying_key().as_bytes()
}

/// Contenido de las cuatro categorías en una versión.
pub type Content = BTreeMap<Category, CategoryList>;

pub fn content(seed: &str) -> Content {
    Category::ALL
        .into_iter()
        .map(|category| {
            let domains: Vec<String> = (0..20)
                .map(|i| format!("{}{i}.{seed}.com", category_name(category)))
                .collect();
            let bytes = CategoryList::build(category, &domains).unwrap();
            (category, CategoryList::parse(&bytes).unwrap())
        })
        .collect()
}

/// `content` con algunos dominios cambiados en cada categoría.
pub fn evolve(base: &Content, seed: &str) -> Content {
    base.iter()
        .map(|(category, list)| {
            let mut hashes: Vec<u64> = list.hashes().iter().skip(3).copied().collect();
            let extra = CategoryList::parse(
                &CategoryList::build(
                    *category,
                    [format!("nuevo.{seed}.com"), format!("otro.{seed}.com")],
                )
                .unwrap(),
            )
            .unwrap();
            hashes.extend_from_slice(extra.hashes());
            hashes.sort_unstable();
            hashes.dedup();
            (
                *category,
                CategoryList::from_hashes(*category, hashes).unwrap(),
            )
        })
        .collect()
}

pub struct Release {
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Publicación de `version` con `content`, y diferencias desde `previous`.
pub fn release(
    version: u64,
    content: &Content,
    previous: &[(u64, &Content)],
    key: &SigningKey,
) -> Release {
    let mut files = BTreeMap::new();
    let mut lists = BTreeMap::new();
    for (category, list) in content {
        let full = list.to_bytes();
        let mut deltas = Vec::new();
        for (from, old) in previous {
            let delta = Delta::between(&old[category], list, *from, version)
                .unwrap()
                .to_bytes();
            deltas.push(DeltaRef {
                from: *from,
                file: FileRef::of(&delta),
            });
            files.insert(delta_file_name(*category, *from), delta);
        }
        lists.insert(
            category_name(*category).to_owned(),
            ListEntry {
                domains: list.len() as u64,
                file: FileRef::of(&full),
                deltas,
            },
        );
        files.insert(full_file_name(*category), full);
    }
    let manifest = Manifest {
        format: 1,
        version,
        created: "2026-11-20".into(),
        lists,
    }
    .to_json();
    let signature = sign(&manifest, key);
    Release {
        manifest,
        signature,
        files,
    }
}

pub fn sign(manifest: &[u8], key: &SigningKey) -> Vec<u8> {
    key.sign(&signing_bytes(manifest))
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into_bytes()
}

/// Solo los ficheros que pide un plan.
pub fn fetch(release: &Release, plan: &[blocklists::Fetch]) -> BTreeMap<String, Vec<u8>> {
    plan.iter()
        .map(|f| (f.name.clone(), release.files[&f.name].clone()))
        .collect()
}
