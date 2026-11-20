//! Tiempo de confianza.
//!
//! El reloj del sistema lo puede cambiar cualquiera, así que las esperas no
//! se miden con él. La librería lleva su propia hora, que solo avanza con la
//! hora del servidor o con el reloj monótono del dispositivo.

use serde::{Deserialize, Serialize};

/// Diferencia admitida entre el reloj del sistema y el monótono antes de
/// considerarlo manipulación. Cubre los ajustes normales de sincronización.
const TOLERANCE_MS: u64 = 120_000;

/// La hora, tal como la ve el agente en el momento de una llamada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimePoint {
    /// Reloj del sistema, en segundos Unix. No es de fiar.
    pub wall_secs: u64,
    /// Reloj monótono, en milisegundos desde el arranque. Debe seguir
    /// contando durante la suspensión.
    pub monotonic_ms: u64,
    /// Identificador del arranque actual: cambia en cada reinicio.
    pub boot_id: u64,
    /// Hora del servidor en segundos Unix, si se acaba de obtener.
    pub server_secs: Option<u64>,
}

/// El reloj del sistema no está donde debería.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockJump {
    pub(crate) expected_wall_secs: u64,
    pub(crate) actual_wall_secs: u64,
}

/// Hora de confianza: nunca retrocede y no se deja adelantar desde fuera.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TrustedClock {
    trusted_ms: u64,
    last: TimePoint,
}

impl TrustedClock {
    /// Empieza a contar. La hora inicial es la del servidor si la hay y, si
    /// no, la del sistema: solo importan las diferencias a partir de aquí.
    pub(crate) fn start(at: TimePoint) -> Self {
        let initial_secs = at.server_secs.unwrap_or(at.wall_secs);
        Self {
            trusted_ms: initial_secs.saturating_mul(1000),
            last: at,
        }
    }

    /// Avanza hasta `at` y avisa si el reloj del sistema ha sido movido.
    pub(crate) fn advance(&mut self, at: TimePoint) -> Option<ClockJump> {
        let same_boot =
            at.boot_id == self.last.boot_id && at.monotonic_ms >= self.last.monotonic_ms;
        let jump = if same_boot {
            let elapsed_ms = at.monotonic_ms - self.last.monotonic_ms;
            self.trusted_ms = self.trusted_ms.saturating_add(elapsed_ms);

            let expected_ms = self
                .last
                .wall_secs
                .saturating_mul(1000)
                .saturating_add(elapsed_ms);
            let actual_ms = at.wall_secs.saturating_mul(1000);
            (expected_ms.abs_diff(actual_ms) > TOLERANCE_MS).then_some(ClockJump {
                expected_wall_secs: expected_ms / 1000,
                actual_wall_secs: at.wall_secs,
            })
        } else {
            // Reinicio: no se sabe cuánto ha estado apagado, así que la hora
            // de confianza no avanza. Que el reloj del sistema vaya hacia
            // delante es normal; que vaya hacia atrás, no.
            let went_back = at.wall_secs.saturating_add(TOLERANCE_MS / 1000) < self.last.wall_secs;
            went_back.then_some(ClockJump {
                expected_wall_secs: self.last.wall_secs,
                actual_wall_secs: at.wall_secs,
            })
        };

        if let Some(server_secs) = at.server_secs {
            self.trusted_ms = self.trusted_ms.max(server_secs.saturating_mul(1000));
        }
        self.last = at;
        jump
    }

    /// Hora de confianza en segundos Unix.
    pub(crate) fn now_secs(&self) -> u64 {
        self.trusted_ms / 1000
    }

    /// Último reloj del sistema visto, para anotarlo junto a cada evento.
    pub(crate) fn wall_secs(&self) -> u64 {
        self.last.wall_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: u64 = 1_800_000_000;

    fn at(wall_secs: u64, monotonic_ms: u64) -> TimePoint {
        TimePoint {
            wall_secs,
            monotonic_ms,
            boot_id: 1,
            server_secs: None,
        }
    }

    #[test]
    fn follows_the_monotonic_clock() {
        let mut clock = TrustedClock::start(at(START, 5_000));
        assert_eq!(clock.advance(at(START + 60, 65_000)), None);
        assert_eq!(clock.now_secs(), START + 60);
    }

    #[test]
    fn moving_the_system_clock_forward_does_not_advance_and_is_detected() {
        let mut clock = TrustedClock::start(at(START, 0));
        // Pasa un minuto real, pero el reloj del sistema salta tres días.
        let jump = clock.advance(at(START + 3 * 86_400, 60_000));
        assert_eq!(
            jump,
            Some(ClockJump {
                expected_wall_secs: START + 60,
                actual_wall_secs: START + 3 * 86_400,
            })
        );
        assert_eq!(clock.now_secs(), START + 60);
    }

    #[test]
    fn moving_the_system_clock_back_is_detected() {
        let mut clock = TrustedClock::start(at(START, 0));
        assert!(clock.advance(at(START - 3_600, 60_000)).is_some());
        assert_eq!(clock.now_secs(), START + 60);
    }

    #[test]
    fn a_jump_is_reported_once() {
        let mut clock = TrustedClock::start(at(START, 0));
        assert!(clock.advance(at(START + 86_400, 60_000)).is_some());
        // A partir del salto, el reloj del sistema vuelve a ir acompasado.
        assert_eq!(clock.advance(at(START + 86_400 + 60, 120_000)), None);
    }

    #[test]
    fn small_corrections_are_tolerated() {
        let mut clock = TrustedClock::start(at(START, 0));
        // Una sincronización horaria corrige 90 s.
        assert_eq!(clock.advance(at(START + 60 + 90, 60_000)), None);
        // …y otra más tarde lo devuelve a su sitio.
        assert_eq!(clock.advance(at(START + 120, 120_000)), None);
    }

    #[test]
    fn time_powered_off_does_not_count() {
        let mut clock = TrustedClock::start(at(START, 600_000));
        let after_reboot = TimePoint {
            wall_secs: START + 3 * 86_400,
            monotonic_ms: 2_000,
            boot_id: 2,
            server_secs: None,
        };
        assert_eq!(
            clock.advance(after_reboot),
            None,
            "avanzar apagado es normal"
        );
        assert_eq!(clock.now_secs(), START);

        // Y sigue contando desde ahí con el nuevo arranque.
        let later = TimePoint {
            monotonic_ms: 32_000,
            wall_secs: START + 3 * 86_400 + 30,
            ..after_reboot
        };
        assert_eq!(clock.advance(later), None);
        assert_eq!(clock.now_secs(), START + 30);
    }

    #[test]
    fn a_reboot_with_a_longer_uptime_is_still_a_reboot() {
        // El monótono tras reiniciar puede ser mayor que el último visto.
        let mut clock = TrustedClock::start(at(START, 10_000));
        let after_reboot = TimePoint {
            wall_secs: START + 86_400,
            monotonic_ms: 7_200_000,
            boot_id: 2,
            server_secs: None,
        };
        assert_eq!(clock.advance(after_reboot), None);
        assert_eq!(clock.now_secs(), START);
    }

    #[test]
    fn clock_set_back_across_a_reboot_is_detected() {
        let mut clock = TrustedClock::start(at(START, 600_000));
        let after_reboot = TimePoint {
            wall_secs: START - 86_400,
            monotonic_ms: 2_000,
            boot_id: 2,
            server_secs: None,
        };
        assert!(clock.advance(after_reboot).is_some());
    }

    #[test]
    fn server_time_rules_and_never_goes_back() {
        let mut clock = TrustedClock::start(at(START, 0));
        let with_server = |monotonic_ms, server| TimePoint {
            wall_secs: START + monotonic_ms / 1000,
            monotonic_ms,
            boot_id: 1,
            server_secs: Some(server),
        };
        // El servidor dice que es más tarde: se le cree.
        clock.advance(with_server(1_000, START + 500));
        assert_eq!(clock.now_secs(), START + 500);
        // Una hora de servidor anterior no hace retroceder.
        clock.advance(with_server(2_000, START + 100));
        assert_eq!(clock.now_secs(), START + 501);
    }

    #[test]
    fn server_time_recovers_time_spent_powered_off() {
        let mut clock = TrustedClock::start(at(START, 600_000));
        let after_reboot = TimePoint {
            wall_secs: START + 3 * 86_400,
            monotonic_ms: 2_000,
            boot_id: 2,
            server_secs: Some(START + 3 * 86_400),
        };
        clock.advance(after_reboot);
        assert_eq!(clock.now_secs(), START + 3 * 86_400);
    }

    #[test]
    fn starts_from_server_time_when_available() {
        let clock = TrustedClock::start(TimePoint {
            wall_secs: 12,
            monotonic_ms: 0,
            boot_id: 1,
            server_secs: Some(START),
        });
        assert_eq!(clock.now_secs(), START);
    }

    #[test]
    fn extreme_values_do_not_overflow() {
        let mut clock = TrustedClock::start(at(u64::MAX, u64::MAX - 1));
        clock.advance(at(u64::MAX, u64::MAX));
        clock.advance(TimePoint {
            wall_secs: 0,
            monotonic_ms: 0,
            boot_id: 9,
            server_secs: Some(u64::MAX),
        });
        let _ = clock.now_secs();
    }
}
