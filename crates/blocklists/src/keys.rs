//! Claves públicas de confianza para las listas.
//!
//! Se fijan aquí y viajan dentro de la app: nunca se descargan. Hay sitio
//! para varias, para poder cambiar de clave con una actualización de la app
//! sin dejar a ningún dispositivo sin listas.

/// Claves Ed25519 con las que se firman las publicaciones de
/// `Mich-proart/nomore-lists`. Vacía hasta generar la primera (tarea 10).
pub const TRUSTED_LIST_KEYS: &[[u8; 32]] = &[];
