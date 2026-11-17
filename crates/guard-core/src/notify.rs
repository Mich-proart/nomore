//! De eventos a avisos: con qué prisa se cuenta cada cosa, cómo se agrupan
//! los intentos repetidos y cuándo se emite la señal de vida.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::event::{Category, EventId, EventKind, Urgency};

/// Los intentos repetidos al mismo sitio se agrupan durante 15 minutos.
pub const ACCESS_WINDOW_SECS: u64 = 900;
/// Cada cuánto se emite la señal de vida.
pub const HEARTBEAT_SECS: u64 = 900;
/// Ventanas abiertas a la vez, como mucho.
const MAX_OPEN_WINDOWS: usize = 512;

/// Urgencia de un evento.
///
/// Manipulación y autorizaciones avisan al instante. De los intentos de
/// acceso solo la pornografía: apuestas, citas y vías de escape van al
/// resumen diario, porque una página normal puede cargarlas sin que nadie
/// las haya buscado.
pub(crate) fn urgency_of(kind: &EventKind) -> Urgency {
    match kind {
        EventKind::AccessAttempt { category, .. } | EventKind::AccessRepeated { category, .. } => {
            match category {
                Category::Porn => Urgency::Immediate,
                Category::Gambling | Category::Dating | Category::Bypass => Urgency::Digest,
            }
        }
        EventKind::Overflow { other, .. } if *other == 0 => Urgency::Digest,
        EventKind::Tightened { .. } | EventKind::PauseEnded => Urgency::Digest,
        EventKind::Heartbeat { .. } => Urgency::Silent,
        _ => Urgency::Immediate,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Window {
    category: Category,
    opened_at: u64,
    extra: u64,
}

/// Ventanas de agrupación abiertas, una por sitio.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccessWindows {
    open: BTreeMap<String, Window>,
}

impl AccessWindows {
    /// Anota un intento. Devuelve los eventos a emitir: el propio intento si
    /// abre ventana, más el resumen de una ventana cerrada para hacer sitio.
    pub(crate) fn record(&mut self, site: String, category: Category, now: u64) -> Vec<EventKind> {
        let mut out = self.close_expired(now);
        if let Some(window) = self.open.get_mut(&site) {
            window.extra = window.extra.saturating_add(1);
            return out;
        }
        if self.open.len() >= MAX_OPEN_WINDOWS {
            let oldest = self
                .open
                .iter()
                .min_by_key(|(_, window)| window.opened_at)
                .map(|(site, _)| site.clone());
            if let Some(site) = oldest {
                out.extend(self.close(&site));
            }
        }
        self.open.insert(
            site.clone(),
            Window {
                category,
                opened_at: now,
                extra: 0,
            },
        );
        out.push(EventKind::AccessAttempt { site, category });
        out
    }

    /// Cierra las ventanas que han cumplido sus 15 minutos.
    pub(crate) fn close_expired(&mut self, now: u64) -> Vec<EventKind> {
        let expired: Vec<String> = self
            .open
            .iter()
            .filter(|(_, w)| now >= w.opened_at.saturating_add(ACCESS_WINDOW_SECS))
            .map(|(site, _)| site.clone())
            .collect();
        expired.iter().filter_map(|site| self.close(site)).collect()
    }

    fn close(&mut self, site: &str) -> Option<EventKind> {
        let window = self.open.remove(site)?;
        (window.extra > 0).then(|| EventKind::AccessRepeated {
            site: site.to_owned(),
            category: window.category,
            count: window.extra,
            since: window.opened_at,
        })
    }
}

/// Cuándo toca la próxima señal de vida.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Heartbeat {
    last_at: Option<u64>,
    last_id: Option<EventId>,
}

impl Heartbeat {
    /// `true` si toca emitir. Si la anterior sigue sin entregar no se emite
    /// otra: sin conexión basta con una, y así no se llena la cola.
    pub(crate) fn due(&self, now: u64, delivered: impl Fn(EventId) -> bool) -> bool {
        let interval_passed = self
            .last_at
            .is_none_or(|at| now >= at.saturating_add(HEARTBEAT_SECS));
        let previous_delivered = self.last_id.is_none_or(delivered);
        interval_passed && previous_delivered
    }

    pub(crate) fn sent(&mut self, now: u64, id: Option<EventId>) {
        self.last_at = Some(now);
        self.last_id = id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(windows: &mut AccessWindows, site: &str, now: u64) -> Vec<EventKind> {
        windows.record(site.to_owned(), Category::Porn, now)
    }

    #[test]
    fn repeats_inside_the_window_are_only_counted() {
        let mut windows = AccessWindows::default();
        assert_eq!(record(&mut windows, "a.com", 0).len(), 1);
        for second in 1..40 {
            assert!(record(&mut windows, "a.com", second).is_empty());
        }
        assert!(windows.close_expired(ACCESS_WINDOW_SECS - 1).is_empty());
        assert_eq!(
            windows.close_expired(ACCESS_WINDOW_SECS),
            [EventKind::AccessRepeated {
                site: "a.com".into(),
                category: Category::Porn,
                count: 39,
                since: 0,
            }]
        );
    }

    #[test]
    fn a_single_attempt_closes_silently() {
        let mut windows = AccessWindows::default();
        record(&mut windows, "a.com", 0);
        assert!(windows.close_expired(ACCESS_WINDOW_SECS).is_empty());
    }

    #[test]
    fn after_the_window_a_new_attempt_alerts_again() {
        let mut windows = AccessWindows::default();
        record(&mut windows, "a.com", 0);
        record(&mut windows, "a.com", 5);
        let events = record(&mut windows, "a.com", ACCESS_WINDOW_SECS + 1);
        assert_eq!(events.len(), 2, "cierra la ventana vieja y abre otra");
        assert!(matches!(
            events[0],
            EventKind::AccessRepeated { count: 1, .. }
        ));
        assert!(matches!(events[1], EventKind::AccessAttempt { .. }));
    }

    #[test]
    fn different_sites_have_their_own_windows() {
        let mut windows = AccessWindows::default();
        assert_eq!(record(&mut windows, "a.com", 0).len(), 1);
        assert_eq!(record(&mut windows, "b.com", 1).len(), 1);
    }

    #[test]
    fn open_windows_are_bounded() {
        let mut windows = AccessWindows::default();
        for i in 0..MAX_OPEN_WINDOWS {
            record(&mut windows, &format!("s{i}.com"), 0);
        }
        record(&mut windows, "s0.com", 1);
        let events = record(&mut windows, "nuevo.com", 2);
        assert_eq!(windows.open.len(), MAX_OPEN_WINDOWS);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EventKind::AccessRepeated { count: 1, .. })),
            "la ventana desalojada entrega su cuenta"
        );
    }

    #[test]
    fn heartbeat_waits_for_the_interval_and_for_delivery() {
        let mut heartbeat = Heartbeat::default();
        assert!(heartbeat.due(0, |_| false), "la primera sale enseguida");
        heartbeat.sent(0, Some(1));
        assert!(!heartbeat.due(HEARTBEAT_SECS - 1, |_| true));
        assert!(
            !heartbeat.due(HEARTBEAT_SECS, |_| false),
            "la anterior sigue en cola"
        );
        assert!(heartbeat.due(HEARTBEAT_SECS, |_| true));
    }
}
