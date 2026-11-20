//! Aprobaciones a distancia firmadas por el servidor.
//!
//! El guardián aprueba una solicitud desde el aviso que recibe. El servidor
//! firma con Ed25519 qué se aprueba, para qué dispositivo y hasta cuándo, y
//! el dispositivo solo acepta firmas de la clave fijada al vincularlo.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::GuardError;
use crate::mode::Action;
use crate::secret::GuardianId;

/// Prefijo de lo que se firma, para que la firma no sirva en otro contexto.
const DOMAIN_TAG: &[u8] = b"nomore-approval-v1\n";

/// Lo que el servidor firma.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalBody {
    /// Dispositivo al que va dirigida, en hexadecimal.
    pub device: String,
    /// Número de la solicitud que aprueba.
    pub request: u64,
    /// Acción aprobada; debe ser exactamente la de la solicitud.
    pub action: Action,
    /// Guardián que la aprobó.
    pub guardian: GuardianId,
    /// Hora (segundos Unix) a partir de la cual deja de valer.
    pub expires_at: u64,
}

impl ApprovalBody {
    /// Bytes exactos que se firman. El servidor debe usar esta misma función.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = DOMAIN_TAG.to_vec();
        // Serializar estos tipos no falla; si fallara, nada verificaría.
        bytes.extend(serde_json::to_vec(self).unwrap_or_default());
        bytes
    }
}

/// Una aprobación tal como llega del servidor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// Lo aprobado.
    pub body: ApprovalBody,
    /// Firma Ed25519 de `body.signing_bytes()`, 128 caracteres hexadecimales.
    pub signature: String,
}

/// Comprueba la firma con la clave pública del servidor.
pub(crate) fn signature_is_valid(approval: &Approval, server_key: &[u8; 32]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(server_key) else {
        return false;
    };
    let Some(signature) = decode_hex::<64>(&approval.signature) else {
        return false;
    };
    // `verify_strict` rechaza además firmas maleables y claves débiles.
    key.verify_strict(
        &approval.body.signing_bytes(),
        &Signature::from_bytes(&signature),
    )
    .is_ok()
}

/// Clave pública del servidor a partir de su forma hexadecimal ya validada.
pub(crate) fn parse_server_key(hex: &str) -> Result<[u8; 32], GuardError> {
    let key = decode_hex::<32>(hex).ok_or(GuardError::InvalidAction("clave de servidor"))?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| GuardError::InvalidAction("la clave del servidor no es una clave Ed25519"))?;
    Ok(key)
}

pub(crate) fn decode_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
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
    fn hex_decoding() {
        assert_eq!(decode_hex::<2>("0aFf"), Some([0x0a, 0xff]));
        assert_eq!(decode_hex::<2>("0a"), None);
        assert_eq!(decode_hex::<2>("0aFg"), None);
        assert_eq!(decode_hex::<1>("ñ"), None);
    }

    #[test]
    fn signing_bytes_are_tagged_and_stable() {
        let body = ApprovalBody {
            device: "00".repeat(16),
            request: 7,
            action: Action::Uninstall,
            guardian: GuardianId::Second,
            expires_at: 1_800_000_600,
        };
        let bytes = body.signing_bytes();
        assert!(bytes.starts_with(b"nomore-approval-v1\n"));
        // Si este texto cambia, las aprobaciones de un servidor ya desplegado
        // dejan de verificar: es parte del contrato con `guardian-link`.
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "nomore-approval-v1\n{\"device\":\"00000000000000000000000000000000\",\
             \"request\":7,\"action\":{\"action\":\"uninstall\"},\"guardian\":\"second\",\
             \"expires_at\":1800000600}"
        );
    }
}
