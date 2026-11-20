//! Claves públicas de confianza para las listas.
//!
//! Se fijan aquí y viajan dentro de la app: nunca se descargan. Hay sitio
//! para varias, para poder cambiar de clave con una actualización de la app
//! sin dejar a ningún dispositivo sin listas.

/// Claves Ed25519 con las que se firman las publicaciones de
/// `Mich-proart/nomore-lists`.
pub const TRUSTED_LIST_KEYS: &[[u8; 32]] = &[
    // Clave 1, creada el 20-11-2026. Pública: 52377313687909f06fe9276459294b15d5d77b31c5d951fc2a3aae3ea4e1e3bb
    [
        0x52, 0x37, 0x73, 0x13, 0x68, 0x79, 0x09, 0xf0, 0x6f, 0xe9, 0x27, 0x64, 0x59, 0x29, 0x4b,
        0x15, 0xd5, 0xd7, 0x7b, 0x31, 0xc5, 0xd9, 0x51, 0xfc, 0x2a, 0x3a, 0xae, 0x3e, 0xa4, 0xe1,
        0xe3, 0xbb,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_valid_ed25519_points() {
        assert!(!TRUSTED_LIST_KEYS.is_empty());
        for key in TRUSTED_LIST_KEYS {
            assert!(ed25519_dalek::VerifyingKey::from_bytes(key).is_ok());
        }
    }
}
