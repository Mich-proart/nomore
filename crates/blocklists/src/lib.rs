//! Verificador de las listas de NoMore.
//!
//! Acepta solo publicaciones firmadas por una clave de confianza y más
//! nuevas que las instaladas, decide qué descargar (diferencia o binario
//! completo) y construye las listas nuevas comprobando cada byte. No abre
//! sockets: descargar es trabajo del agente.
//!
//! ```text
//! let manifest = Manifest::verify(&json, &sig, TRUSTED_LIST_KEYS, Some(installed.version))?;
//! let wanted = manifest.plan(Some(&installed));   // descargar estos ficheros
//! let updated = manifest.apply(Some(&installed), &downloaded)?;
//! // guardar `updated` de forma atómica y reconstruir el filtro
//! ```

mod delta;
mod error;
mod keys;
mod manifest;
mod verify;

pub use delta::Delta;
pub use error::ListError;
pub use keys::TRUSTED_LIST_KEYS;
pub use manifest::{
    category_name, delta_file_name, full_file_name, signing_bytes, DeltaRef, FileRef, ListEntry,
    Manifest, MANIFEST_FORMAT,
};
pub use verify::{Fetch, Installed};
