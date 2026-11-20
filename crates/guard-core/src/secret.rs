//! Guardianes: claves, códigos de recuperación y espera entre fallos.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::GuardError;

/// Nunca hay más de dos guardianes.
pub const MAX_GUARDIANS: usize = 2;
/// Bytes aleatorios que el agente debe aportar para dar de alta un guardián
/// o cambiar una clave.
pub const ENTROPY_LEN: usize = 48;
/// Longitud mínima de una clave.
pub const MIN_SECRET_CHARS: usize = 8;

/// Argon2id: 19 MiB y 2 pasadas, el mínimo que recomienda OWASP.
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_PASSES: u32 = 2;
/// La espera entre fallos se duplica hasta llegar a una hora.
const MAX_LOCK_SECS: u64 = 3_600;
/// A partir de este número de fallos seguidos se avisa al guardián.
pub(crate) const FAILURES_BEFORE_ALERT: u32 = 3;

/// Cuál de los dos guardianes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianId {
    /// El que emparejó el dispositivo, o el que ocupa ese puesto.
    First,
    /// El segundo.
    Second,
}

/// Datos para dar de alta a un guardián.
#[derive(Clone)]
pub struct NewGuardian {
    /// Nombre con el que se le identifica en la interfaz y en los eventos.
    pub name: String,
    /// Clave que escribirá para autorizar.
    pub secret: String,
    /// Bytes aleatorios del sistema.
    pub entropy: [u8; ENTROPY_LEN],
}

/// Lo que se puede saber de un guardián sin su clave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianInfo {
    /// Cuál de los dos.
    pub id: GuardianId,
    /// Su nombre.
    pub name: String,
}

/// Código de recuperación recién generado. Se muestra una sola vez.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode(String);

impl RecoveryCode {
    /// El código, con el formato `XXXX-XXXX-XXXX-XXXX`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryCode {
    /// No se vuelca en registros ni trazas.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(…)")
    }
}

/// Un guardián tal como se guarda: nunca su clave, solo las huellas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GuardianRecord {
    pub(crate) id: GuardianId,
    pub(crate) name: String,
    salt: [u8; 16],
    secret_hash: [u8; 32],
    recovery_salt: [u8; 16],
    /// `None` cuando el código ya se ha usado.
    recovery_hash: Option<[u8; 32]>,
}

impl GuardianRecord {
    /// Crea el registro y el código de recuperación que hay que enseñar.
    pub(crate) fn create(
        id: GuardianId,
        guardian: &NewGuardian,
    ) -> Result<(Self, RecoveryCode), GuardError> {
        let name = guardian.name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(GuardError::InvalidAction(
                "el nombre debe tener de 1 a 64 caracteres",
            ));
        }
        let mut record = Self {
            id,
            name: name.to_owned(),
            salt: [0; 16],
            secret_hash: [0; 32],
            recovery_salt: [0; 16],
            recovery_hash: None,
        };
        let code = record.set_secret(&guardian.secret, &guardian.entropy)?;
        Ok((record, code))
    }

    /// Cambia la clave y renueva el código de recuperación.
    pub(crate) fn set_secret(
        &mut self,
        secret: &str,
        entropy: &[u8; ENTROPY_LEN],
    ) -> Result<RecoveryCode, GuardError> {
        if secret.chars().count() < MIN_SECRET_CHARS {
            return Err(GuardError::WeakSecret);
        }
        let (salt, rest) = entropy.split_at(16);
        let (recovery_salt, rest) = rest.split_at(16);
        let code = encode_recovery_code(&rest[..10]);

        self.salt.copy_from_slice(salt);
        self.recovery_salt.copy_from_slice(recovery_salt);
        self.secret_hash = derive(secret, &self.salt)?;
        self.recovery_hash = Some(hash_recovery_code(&code.0, &self.recovery_salt));
        Ok(code)
    }

    pub(crate) fn secret_matches(&self, secret: &str) -> bool {
        derive(secret, &self.salt).is_ok_and(|hash| constant_time_eq(&hash, &self.secret_hash))
    }

    /// Comprueba el código de recuperación y, si es el bueno, lo gasta.
    pub(crate) fn redeem_recovery_code(&mut self, code: &str) -> bool {
        let Some(expected) = self.recovery_hash else {
            return false;
        };
        let normalized: String = code
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let formatted = format_recovery_code(&normalized);
        let matches = constant_time_eq(
            &hash_recovery_code(&formatted, &self.recovery_salt),
            &expected,
        );
        if matches {
            self.recovery_hash = None;
        }
        matches
    }

    pub(crate) fn info(&self) -> GuardianInfo {
        GuardianInfo {
            id: self.id,
            name: self.name.clone(),
        }
    }
}

fn derive(secret: &str, salt: &[u8; 16]) -> Result<[u8; 32], GuardError> {
    let failed = GuardError::InvalidAction("no se pudo procesar la clave");
    let params =
        Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, 1, Some(32)).map_err(|_| failed.clone())?;
    let mut hash = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret.as_bytes(), salt, &mut hash)
        .map_err(|_| failed)?;
    Ok(hash)
}

fn hash_recovery_code(formatted: &str, salt: &[u8; 16]) -> [u8; 32] {
    // El código son 80 bits aleatorios: no necesita una función lenta.
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(formatted.as_bytes());
    hasher.finalize().into()
}

/// Diez bytes en base 32, en cuatro grupos de cuatro.
fn encode_recovery_code(bytes: &[u8]) -> RecoveryCode {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut symbols = String::with_capacity(16);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            symbols.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    RecoveryCode(format_recovery_code(&symbols))
}

fn format_recovery_code(symbols: &str) -> String {
    let mut out = String::with_capacity(symbols.len() + symbols.len() / 4);
    for (index, symbol) in symbols.chars().enumerate() {
        if index > 0 && index % 4 == 0 {
            out.push('-');
        }
        out.push(symbol);
    }
    out
}

/// Compara sin que el tiempo dependa de dónde está la primera diferencia.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Fallos seguidos al escribir una clave o un código, comunes a los dos
/// guardianes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Failures {
    count: u32,
    locked_until: u64,
}

impl Failures {
    pub(crate) fn ensure_unlocked(&self, now_secs: u64) -> Result<(), GuardError> {
        if now_secs < self.locked_until {
            return Err(GuardError::TooManyAttempts {
                retry_at_secs: self.locked_until,
            });
        }
        Ok(())
    }

    /// Anota un fallo y devuelve cuántos van seguidos. La espera es de 1 s,
    /// 2 s, 4 s… hasta una hora.
    pub(crate) fn register(&mut self, now_secs: u64) -> u32 {
        self.count = self.count.saturating_add(1);
        let wait = 1u64
            .checked_shl(self.count - 1)
            .map_or(MAX_LOCK_SECS, |secs| secs.min(MAX_LOCK_SECS));
        self.locked_until = now_secs.saturating_add(wait);
        self.count
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_guardian(secret: &str) -> NewGuardian {
        let mut entropy = [0u8; ENTROPY_LEN];
        for (i, byte) in entropy.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        NewGuardian {
            name: "  Guardián  ".into(),
            secret: secret.into(),
            entropy,
        }
    }

    #[test]
    fn secret_is_checked_and_never_stored() {
        let (record, _) =
            GuardianRecord::create(GuardianId::First, &new_guardian("clave-larga-1")).unwrap();
        assert!(record.secret_matches("clave-larga-1"));
        assert!(!record.secret_matches("clave-larga-2"));
        assert!(!record.secret_matches(""));
        let stored = serde_json::to_string(&record).unwrap();
        assert!(!stored.contains("clave-larga-1"));
        assert_eq!(record.name, "Guardián");
    }

    #[test]
    fn short_secrets_and_bad_names_are_rejected() {
        assert_eq!(
            GuardianRecord::create(GuardianId::First, &new_guardian("1234567")).unwrap_err(),
            GuardError::WeakSecret
        );
        // Ocho caracteres bastan aunque no sean ASCII.
        assert!(GuardianRecord::create(GuardianId::First, &new_guardian("ñandúñañ")).is_ok());
        let mut nameless = new_guardian("clave-larga-1");
        nameless.name = "   ".into();
        assert!(GuardianRecord::create(GuardianId::First, &nameless).is_err());
    }

    #[test]
    fn recovery_code_has_the_expected_shape() {
        let (_, code) =
            GuardianRecord::create(GuardianId::First, &new_guardian("clave-larga-1")).unwrap();
        let groups: Vec<_> = code.as_str().split('-').collect();
        assert_eq!(groups.len(), 4);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(code
            .as_str()
            .chars()
            .all(|c| c == '-' || c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert_eq!(format!("{code:?}"), "RecoveryCode(…)");
    }

    #[test]
    fn recovery_code_works_once_and_tolerates_formatting() {
        let (mut record, code) =
            GuardianRecord::create(GuardianId::First, &new_guardian("clave-larga-1")).unwrap();
        assert!(!record.redeem_recovery_code("AAAA-AAAA-AAAA-AAAA"));
        let sloppy = code.as_str().to_lowercase().replace('-', " ");
        assert!(record.redeem_recovery_code(&sloppy));
        assert!(
            !record.redeem_recovery_code(code.as_str()),
            "ya está gastado"
        );
    }

    #[test]
    fn changing_the_secret_renews_the_recovery_code() {
        let (mut record, old_code) =
            GuardianRecord::create(GuardianId::First, &new_guardian("clave-larga-1")).unwrap();
        let new_code = record
            .set_secret("otra-clave-99", &[7u8; ENTROPY_LEN])
            .unwrap();
        assert!(record.secret_matches("otra-clave-99"));
        assert!(!record.secret_matches("clave-larga-1"));
        assert_ne!(old_code, new_code);
        assert!(!record.redeem_recovery_code(old_code.as_str()));
        assert!(record.redeem_recovery_code(new_code.as_str()));
    }

    #[test]
    fn base32_matches_a_known_vector() {
        // RFC 4648: "fooba" → "MZXW6YTB"; diez bytes dan dieciséis símbolos.
        assert_eq!(
            encode_recovery_code(b"foobafooba").as_str(),
            "MZXW-6YTB-MZXW-6YTB"
        );
    }

    #[test]
    fn lock_doubles_up_to_an_hour() {
        let mut failures = Failures::default();
        failures.ensure_unlocked(0).unwrap();
        let mut waits = Vec::new();
        for _ in 0..14 {
            failures.register(1_000);
            waits.push(failures.locked_until - 1_000);
        }
        assert_eq!(&waits[..5], [1, 2, 4, 8, 16]);
        assert_eq!(waits[11], 2_048);
        assert_eq!(waits[12], 3_600);
        assert_eq!(waits[13], 3_600);
        assert_eq!(
            failures.ensure_unlocked(1_000),
            Err(GuardError::TooManyAttempts {
                retry_at_secs: 4_600
            })
        );
        failures.ensure_unlocked(4_600).unwrap();
        failures.reset();
        failures.ensure_unlocked(0).unwrap();
    }

    #[test]
    fn many_failures_do_not_overflow() {
        let mut failures = Failures::default();
        for _ in 0..200 {
            failures.register(u64::MAX - 10);
        }
        assert_eq!(failures.count, 200);
    }
}
