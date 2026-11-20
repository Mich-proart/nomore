//! Estado guardado: sellado con HMAC-SHA256 y una clave del dispositivo.
//!
//! ```text
//! bytes 0..4      marca "NMGS"
//! byte  4         versión de formato (1)
//! bytes 5..n-32   estado en JSON
//! bytes n-32..n   HMAC-SHA256 de todo lo anterior
//! ```
//!
//! La clave la aporta el agente y vive fuera del alcance del protegido
//! (DPAPI en Windows, Keystore en Android). Sin ella no se puede fabricar un
//! estado que pase la comprobación.

use hmac::{Hmac, Mac};
use sha2::Sha256;

const MAGIC: &[u8; 4] = b"NMGS";
const FORMAT_VERSION: u8 = 1;
const TAG_LEN: usize = 32;
const HEADER_LEN: usize = 5;

/// Por qué no se ha podido abrir un estado guardado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// No es un estado de NoMore, está truncado o es de otra versión.
    Malformed,
    /// La firma no cuadra: alterado, o sellado con otra clave.
    BadTag,
}

fn mac(key: &[u8]) -> Hmac<Sha256> {
    // HMAC acepta claves de cualquier longitud: esto no puede fallar.
    <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!())
}

/// Sella `payload` con la clave del dispositivo.
pub(crate) fn seal(payload: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(payload);
    let mut mac = mac(key);
    mac.update(&out);
    out.extend_from_slice(&mac.finalize().into_bytes());
    out
}

/// Comprueba el sello y devuelve el contenido.
pub(crate) fn open<'a>(sealed: &'a [u8], key: &[u8]) -> Result<&'a [u8], OpenError> {
    if sealed.len() < HEADER_LEN + TAG_LEN || &sealed[..4] != MAGIC || sealed[4] != FORMAT_VERSION {
        return Err(OpenError::Malformed);
    }
    let (signed, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let mut mac = mac(key);
    mac.update(signed);
    // `verify_slice` compara en tiempo constante.
    mac.verify_slice(tag).map_err(|_| OpenError::BadTag)?;
    Ok(&signed[HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let sealed = seal(b"{\"a\":1}", b"clave");
        assert_eq!(open(&sealed, b"clave"), Ok(&b"{\"a\":1}"[..]));
    }

    #[test]
    fn any_flipped_bit_is_detected() {
        let sealed = seal(b"contenido del estado", b"clave");
        for byte in 0..sealed.len() {
            for bit in 0..8 {
                let mut altered = sealed.clone();
                altered[byte] ^= 1 << bit;
                assert!(open(&altered, b"clave").is_err(), "byte {byte} bit {bit}");
            }
        }
    }

    #[test]
    fn another_key_does_not_open_it() {
        let sealed = seal(b"x", b"clave-de-este-dispositivo");
        assert_eq!(open(&sealed, b"clave-de-otro"), Err(OpenError::BadTag));
    }

    #[test]
    fn short_or_foreign_input_is_malformed() {
        assert_eq!(open(b"", b"k"), Err(OpenError::Malformed));
        assert_eq!(open(&[0; 36], b"k"), Err(OpenError::Malformed));
        let mut other_version = seal(b"x", b"k");
        other_version[4] = 2;
        assert_eq!(open(&other_version, b"k"), Err(OpenError::Malformed));
    }
}
