//! De eventos a avisos: con qué prisa hay que contarle cada cosa al guardián.

use crate::event::{Category, EventKind, Urgency};

/// Urgencia de un evento.
///
/// Manipulación y autorizaciones avisan al instante. De los intentos de
/// acceso solo la pornografía: apuestas, citas y vías de escape van al
/// resumen diario, porque una página normal puede cargarlas sin que nadie
/// las haya buscado.
pub(crate) fn urgency_of(kind: &EventKind) -> Urgency {
    match kind {
        EventKind::AccessAttempt { category, .. } => match category {
            Category::Porn => Urgency::Immediate,
            Category::Gambling | Category::Dating | Category::Bypass => Urgency::Digest,
        },
        EventKind::Overflow { other, .. } if *other == 0 => Urgency::Digest,
        EventKind::Tightened { .. } => Urgency::Digest,
        _ => Urgency::Immediate,
    }
}
