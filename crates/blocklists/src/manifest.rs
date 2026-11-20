//! Manifiesto de una publicación: qué contiene y con qué huellas, firmado.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use filter_core::Category;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ListError;

/// Formato de manifiesto que entiende esta versión.
pub const MANIFEST_FORMAT: u32 = 1;
/// Prefijo de lo que se firma, para que la firma no valga en otro contexto.
const SIGNING_TAG: &[u8] = b"nomore-lists-v1\n";
/// Un manifiesto real ocupa unos pocos KB.
const MAX_MANIFEST_BYTES: usize = 1 << 20;

/// Nombre de una categoría en el manifiesto y en los ficheros.
pub fn category_name(category: Category) -> &'static str {
    match category {
        Category::Porn => "porn",
        Category::Gambling => "gambling",
        Category::Dating => "dating",
        Category::Bypass => "bypass",
    }
}

fn category_from_name(name: &str) -> Option<Category> {
    Category::ALL
        .into_iter()
        .find(|category| category_name(*category) == name)
}

/// Huella y tamaño de un fichero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// Tamaño en bytes.
    pub size: u64,
    /// SHA-256 en hexadecimal.
    pub sha256: String,
}

impl FileRef {
    /// Describe `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            size: bytes.len() as u64,
            sha256: sha256_hex(bytes),
        }
    }

    /// `true` si `bytes` es exactamente este fichero.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() as u64 == self.size && sha256_hex(bytes) == self.sha256
    }
}

/// Diferencia disponible desde una versión anterior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaRef {
    /// Versión de origen.
    pub from: u64,
    /// El fichero.
    #[serde(flatten)]
    pub file: FileRef,
}

/// Una categoría en la publicación.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListEntry {
    /// Número de dominios.
    pub domains: u64,
    /// El binario completo.
    #[serde(flatten)]
    pub file: FileRef,
    /// Diferencias desde versiones anteriores.
    #[serde(default)]
    pub deltas: Vec<DeltaRef>,
}

/// El manifiesto tal como se escribe en `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Formato del manifiesto.
    pub format: u32,
    /// Versión de la publicación, `AAAAMMDDnn`.
    pub version: u64,
    /// Fecha de generación, `AAAA-MM-DD`.
    pub created: String,
    /// Una entrada por categoría, por nombre.
    pub lists: BTreeMap<String, ListEntry>,
}

impl Manifest {
    /// Comprueba firma, formato y versión, y devuelve el manifiesto.
    ///
    /// `signature` es el contenido de `manifest.sig`: la firma Ed25519 en
    /// hexadecimal. `keys` son las claves públicas de confianza. Con
    /// `installed`, solo se acepta una versión estrictamente mayor.
    pub fn verify(
        manifest: &[u8],
        signature: &[u8],
        keys: &[[u8; 32]],
        installed: Option<u64>,
    ) -> Result<Self, ListError> {
        if manifest.len() > MAX_MANIFEST_BYTES {
            return Err(ListError::BadManifest("demasiado grande"));
        }
        if !signed_by_any(manifest, signature, keys) {
            return Err(ListError::BadSignature);
        }
        let parsed: Self = serde_json::from_slice(manifest)
            .map_err(|_| ListError::BadManifest("no es un manifiesto"))?;
        if parsed.format != MANIFEST_FORMAT {
            return Err(ListError::BadManifest("formato desconocido"));
        }
        for category in Category::ALL {
            if !parsed.lists.contains_key(category_name(category)) {
                return Err(ListError::BadManifest("falta una categoría"));
            }
        }
        if parsed
            .lists
            .keys()
            .any(|name| category_from_name(name).is_none())
        {
            return Err(ListError::BadManifest("categoría desconocida"));
        }
        if let Some(installed) = installed {
            if parsed.version <= installed {
                return Err(ListError::NotNewer {
                    installed,
                    offered: parsed.version,
                });
            }
        }
        Ok(parsed)
    }

    /// Entrada de una categoría. Tras [`Manifest::verify`] siempre existe.
    pub fn entry(&self, category: Category) -> Option<&ListEntry> {
        self.lists.get(category_name(category))
    }

    /// Bytes exactos de `manifest.json`.
    pub fn to_json(&self) -> Vec<u8> {
        // Serializar estos tipos no falla.
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }
}

/// Nombre del binario completo de una categoría.
pub fn full_file_name(category: Category) -> String {
    format!("{}.nmbl", category_name(category))
}

/// Nombre de la diferencia de una categoría desde `from`.
pub fn delta_file_name(category: Category, from: u64) -> String {
    format!("{}.{from}.delta", category_name(category))
}

/// Bytes que se firman para `manifest`.
pub fn signing_bytes(manifest: &[u8]) -> Vec<u8> {
    let mut bytes = SIGNING_TAG.to_vec();
    bytes.extend_from_slice(manifest);
    bytes
}

fn signed_by_any(manifest: &[u8], signature: &[u8], keys: &[[u8; 32]]) -> bool {
    let Some(signature) = std::str::from_utf8(signature)
        .ok()
        .and_then(|text| decode_hex::<64>(text.trim()))
    else {
        return false;
    };
    let signature = Signature::from_bytes(&signature);
    let message = signing_bytes(manifest);
    keys.iter().any(|key| {
        VerifyingKey::from_bytes(key)
            .is_ok_and(|key| key.verify_strict(&message, &signature).is_ok())
    })
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn decode_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let bytes = hex.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        *byte = (high * 16 + low) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_roundtrip() {
        for category in Category::ALL {
            assert_eq!(category_from_name(category_name(category)), Some(category));
        }
        assert_eq!(category_from_name("social"), None);
        assert_eq!(full_file_name(Category::Porn), "porn.nmbl");
        assert_eq!(
            delta_file_name(Category::Dating, 2026111901),
            "dating.2026111901.delta"
        );
    }

    #[test]
    fn file_ref_checks_size_and_hash() {
        let file = FileRef::of(b"abc");
        assert_eq!(
            file.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(file.matches(b"abc"));
        assert!(!file.matches(b"abd"));
        assert!(!file.matches(b"abcd"));
    }
}
