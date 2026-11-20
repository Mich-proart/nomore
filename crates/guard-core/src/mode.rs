//! Modos, ajustes protegidos y qué exige autorización.
//!
//! Regla general: endurecer la protección es libre ([`Tightening`]); aflojarla
//! exige autorización ([`Action`]).

use serde::{Deserialize, Serialize};

use crate::error::GuardError;
use crate::secret::GuardianId;

/// Espera por defecto para desbloquear sin guardián, en horas.
pub const DEFAULT_DELAY_HOURS: u32 = 72;
/// Espera máxima que se puede fijar: 30 días.
pub const MAX_DELAY_HOURS: u32 = 720;
/// Una pausa dura como mucho 24 h y se reanuda sola.
pub const MAX_PAUSE_MINUTES: u32 = 1_440;
/// Tamaño máximo de la lista de permitidos y de la de bloqueos añadidos.
pub const MAX_LIST_ENTRIES: usize = 1_000;

/// Quién instala y qué puede hacer el protegido sin el guardián.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Un adulto se lo instala a sí mismo. Puede desbloquear tras la espera.
    SelfControl,
    /// Lo instala el guardián. El protegido no puede desbloquear nada.
    Parental,
}

/// Categorías que el guardián puede apagar. Pornografía y vías de escape no
/// están porque no se pueden apagar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Toggle {
    /// Apuestas y juego.
    Gambling,
    /// Apps y webs de citas.
    Dating,
}

/// Ajustes que nadie puede aflojar sin autorización. El agente construye con
/// ellos la política de filtrado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Modo de uso.
    pub mode: Mode,
    /// Bloquear apuestas.
    pub block_gambling: bool,
    /// Bloquear citas.
    pub block_dating: bool,
    /// Dominios permitidos por un guardián aunque estén en una lista.
    pub allowlist: Vec<String>,
    /// Dominios bloqueados además de las listas.
    pub extra_blocks: Vec<String>,
    /// Si la protección está en pausa, hasta qué hora de confianza.
    pub paused_until: Option<u64>,
    /// Espera para desbloquear sin guardián, en horas.
    pub delay_hours: u32,
}

impl Settings {
    /// Protección máxima: todo bloqueado y nada permitido.
    pub(crate) fn locked_down() -> Self {
        Self {
            mode: Mode::SelfControl,
            block_gambling: true,
            block_dating: true,
            allowlist: Vec::new(),
            extra_blocks: Vec::new(),
            paused_until: None,
            delay_hours: DEFAULT_DELAY_HOURS,
        }
    }

    /// `true` si la protección está en pausa a la hora `now_secs`.
    pub fn is_paused(&self, now_secs: u64) -> bool {
        self.paused_until.is_some_and(|until| until > now_secs)
    }

    /// Aplica una acción ya autorizada que cambia ajustes.
    pub(crate) fn apply(&mut self, action: &Action, now_secs: u64) -> Result<(), GuardError> {
        match action {
            Action::AllowDomain { domain } => add_unique(&mut self.allowlist, domain)?,
            Action::UnblockDomain { domain } => self.extra_blocks.retain(|d| d != domain),
            Action::DisableCategory { category } => match category {
                Toggle::Gambling => self.block_gambling = false,
                Toggle::Dating => self.block_dating = false,
            },
            Action::Pause { minutes } => {
                self.paused_until = Some(now_secs.saturating_add(u64::from(*minutes) * 60));
            }
            Action::ShortenDelay { hours } => {
                if *hours >= self.delay_hours {
                    return Err(GuardError::InvalidAction("la espera nueva no es más corta"));
                }
                self.delay_hours = *hours;
            }
            Action::ChangeMode { mode } => self.mode = *mode,
            Action::Uninstall
            | Action::AddGuardian
            | Action::RemoveGuardian { .. }
            | Action::ChangeSecret { .. }
            | Action::LinkServer { .. } => {}
        }
        Ok(())
    }

    /// Aplica un endurecimiento. No necesita autorización.
    pub(crate) fn tighten(&mut self, change: &Tightening) -> Result<(), GuardError> {
        match change {
            Tightening::BlockDomain { domain } => {
                add_unique(&mut self.extra_blocks, domain)?;
                self.allowlist.retain(|d| d != domain);
            }
            Tightening::DisallowDomain { domain } => self.allowlist.retain(|d| d != domain),
            Tightening::EnableCategory { category } => match category {
                Toggle::Gambling => self.block_gambling = true,
                Toggle::Dating => self.block_dating = true,
            },
            Tightening::Resume => self.paused_until = None,
            Tightening::LengthenDelay { hours } => {
                if *hours <= self.delay_hours {
                    return Err(GuardError::InvalidAction("la espera nueva no es más larga"));
                }
                self.delay_hours = *hours;
            }
        }
        Ok(())
    }
}

fn add_unique(list: &mut Vec<String>, domain: &str) -> Result<(), GuardError> {
    if list.iter().any(|d| d == domain) {
        return Ok(());
    }
    if list.len() >= MAX_LIST_ENTRIES {
        return Err(GuardError::InvalidAction("la lista está llena"));
    }
    list.push(domain.to_owned());
    Ok(())
}

/// Todo lo que afloja la protección. Exige autorización.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Permitir un dominio (y sus subdominios) aunque esté en una lista.
    AllowDomain {
        /// Dominio a permitir.
        domain: String,
    },
    /// Quitar un dominio de los bloqueos añadidos.
    UnblockDomain {
        /// Dominio a dejar de bloquear.
        domain: String,
    },
    /// Dejar de bloquear apuestas o citas.
    DisableCategory {
        /// Categoría a apagar.
        category: Toggle,
    },
    /// Pausar toda la protección. Se reanuda sola.
    Pause {
        /// Duración, de 1 a 1440 minutos.
        minutes: u32,
    },
    /// Acortar la espera para desbloquear sin guardián.
    ShortenDelay {
        /// Nueva espera en horas, menor que la actual.
        hours: u32,
    },
    /// Cambiar entre autocontrol y parental.
    ChangeMode {
        /// Modo nuevo.
        mode: Mode,
    },
    /// Desinstalar NoMore.
    Uninstall,
    /// Dar de alta al segundo guardián.
    AddGuardian,
    /// Quitar a un guardián. Siempre queda al menos uno.
    RemoveGuardian {
        /// Guardián a quitar.
        guardian: GuardianId,
    },
    /// Cambiar la clave de un guardián.
    ChangeSecret {
        /// De quién es la clave.
        guardian: GuardianId,
    },
    /// Fijar o cambiar el servidor cuyas aprobaciones a distancia se aceptan.
    /// Afloja porque abre una vía de autorización.
    LinkServer {
        /// Clave pública Ed25519 del servidor, 64 caracteres hexadecimales.
        public_key: String,
    },
}

impl Action {
    /// Comprueba que la acción tiene sentido y la deja en forma canónica, para
    /// que una autorización valga exactamente para lo que se pidió.
    pub(crate) fn normalized(&self) -> Result<Self, GuardError> {
        Ok(match self {
            Self::AllowDomain { domain } => Self::AllowDomain {
                domain: normalize_domain(domain)?,
            },
            Self::UnblockDomain { domain } => Self::UnblockDomain {
                domain: normalize_domain(domain)?,
            },
            Self::Pause { minutes } if !(1..=MAX_PAUSE_MINUTES).contains(minutes) => {
                return Err(GuardError::InvalidAction(
                    "la pausa dura de 1 a 1440 minutos",
                ));
            }
            Self::LinkServer { public_key } => {
                let key = public_key.trim().to_ascii_lowercase();
                if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(GuardError::InvalidAction(
                        "la clave del servidor son 64 caracteres hexadecimales",
                    ));
                }
                Self::LinkServer { public_key: key }
            }
            Self::ShortenDelay { hours: 0 } => {
                return Err(GuardError::InvalidAction("la espera mínima es de 1 hora"));
            }
            other => other.clone(),
        })
    }
}

/// Todo lo que endurece la protección. Es libre.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum Tightening {
    /// Bloquear un dominio más.
    BlockDomain {
        /// Dominio a bloquear.
        domain: String,
    },
    /// Retirar un dominio de la lista de permitidos.
    DisallowDomain {
        /// Dominio que deja de estar permitido.
        domain: String,
    },
    /// Volver a bloquear apuestas o citas.
    EnableCategory {
        /// Categoría a encender.
        category: Toggle,
    },
    /// Terminar una pausa antes de tiempo.
    Resume,
    /// Alargar la espera para desbloquear sin guardián.
    LengthenDelay {
        /// Nueva espera en horas, mayor que la actual y de 720 como mucho.
        hours: u32,
    },
}

impl Tightening {
    pub(crate) fn normalized(&self) -> Result<Self, GuardError> {
        Ok(match self {
            Self::BlockDomain { domain } => Self::BlockDomain {
                domain: normalize_domain(domain)?,
            },
            Self::DisallowDomain { domain } => Self::DisallowDomain {
                domain: normalize_domain(domain)?,
            },
            Self::LengthenDelay { hours } if *hours > MAX_DELAY_HOURS => {
                return Err(GuardError::InvalidAction(
                    "la espera máxima es de 720 horas",
                ));
            }
            other => other.clone(),
        })
    }
}

/// Minúsculas, sin punto final y solo caracteres de nombre de dominio.
pub(crate) fn normalize_domain(input: &str) -> Result<String, GuardError> {
    let invalid = GuardError::InvalidAction("dominio no válido");
    let trimmed = input.trim();
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(invalid);
    }
    for label in trimmed.split('.') {
        let valid_chars = label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if label.is_empty() || label.len() > 63 || !valid_chars {
            return Err(invalid);
        }
    }
    Ok(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_normalized() {
        assert_eq!(
            normalize_domain(" WWW.Ejemplo.COM. ").unwrap(),
            "www.ejemplo.com"
        );
        for bad in ["", ".", "a..b", "a b.com", "españa.com", "http://x.com"] {
            assert!(normalize_domain(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn locked_down_is_the_strictest_setting() {
        let s = Settings::locked_down();
        assert!(s.block_gambling && s.block_dating);
        assert!(s.allowlist.is_empty());
        assert_eq!(s.paused_until, None);
        assert_eq!(s.delay_hours, 72);
    }

    #[test]
    fn pause_expires_on_its_own() {
        let mut s = Settings::locked_down();
        s.apply(&Action::Pause { minutes: 30 }, 1_000).unwrap();
        assert!(s.is_paused(1_000));
        assert!(s.is_paused(1_000 + 30 * 60 - 1));
        assert!(!s.is_paused(1_000 + 30 * 60));
    }

    #[test]
    fn blocking_a_domain_removes_it_from_the_allowlist() {
        let mut s = Settings::locked_down();
        let domain = "ejemplo.com".to_owned();
        s.apply(
            &Action::AllowDomain {
                domain: domain.clone(),
            },
            0,
        )
        .unwrap();
        s.tighten(&Tightening::BlockDomain {
            domain: domain.clone(),
        })
        .unwrap();
        assert!(s.allowlist.is_empty());
        assert_eq!(s.extra_blocks, [domain]);
    }

    #[test]
    fn lists_do_not_duplicate_and_are_bounded() {
        let mut s = Settings::locked_down();
        for _ in 0..3 {
            s.tighten(&Tightening::BlockDomain {
                domain: "a.com".into(),
            })
            .unwrap();
        }
        assert_eq!(s.extra_blocks.len(), 1);
        for i in 0..MAX_LIST_ENTRIES {
            let _ = s.tighten(&Tightening::BlockDomain {
                domain: format!("d{i}.com"),
            });
        }
        assert_eq!(s.extra_blocks.len(), MAX_LIST_ENTRIES);
    }

    #[test]
    fn delay_only_moves_in_the_stated_direction() {
        let mut s = Settings::locked_down();
        assert!(s.tighten(&Tightening::LengthenDelay { hours: 72 }).is_err());
        assert!(s.tighten(&Tightening::LengthenDelay { hours: 24 }).is_err());
        s.tighten(&Tightening::LengthenDelay { hours: 96 }).unwrap();
        assert!(s.apply(&Action::ShortenDelay { hours: 96 }, 0).is_err());
        assert!(s.apply(&Action::ShortenDelay { hours: 200 }, 0).is_err());
        s.apply(&Action::ShortenDelay { hours: 48 }, 0).unwrap();
        assert_eq!(s.delay_hours, 48);
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        assert!(Action::Pause { minutes: 0 }.normalized().is_err());
        assert!(Action::Pause { minutes: 1_441 }.normalized().is_err());
        assert!(Action::Pause { minutes: 1_440 }.normalized().is_ok());
        assert!(Action::ShortenDelay { hours: 0 }.normalized().is_err());
        assert!(Tightening::LengthenDelay { hours: 721 }
            .normalized()
            .is_err());
        assert!(Action::AllowDomain {
            domain: "no válido".into()
        }
        .normalized()
        .is_err());
    }
}
