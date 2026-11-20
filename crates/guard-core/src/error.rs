//! Errores de la librería.

use std::fmt;

/// Por qué no se ha podido hacer lo que se pedía.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// Todavía no hay ningún guardián emparejado.
    NotPaired,
    /// Ya hay un guardián: no se puede emparejar de nuevo.
    AlreadyPaired,
    /// La clave tiene menos de 8 caracteres.
    WeakSecret,
    /// La clave no es la de ningún guardián.
    WrongSecret,
    /// El código de recuperación no es válido.
    WrongRecoveryCode,
    /// Demasiados fallos seguidos: hay que esperar hasta esta hora de confianza.
    TooManyAttempts {
        /// Segundos Unix a partir de los cuales se admite otro intento.
        retry_at_secs: u64,
    },
    /// La acción exige una autorización que no existe o ha caducado.
    NotAuthorized,
    /// La acción no tiene sentido tal como está escrita.
    InvalidAction(&'static str),
    /// Ya hay dos guardianes, que es el máximo.
    TooManyGuardians,
    /// No se puede quitar al único guardián.
    LastGuardian,
    /// No existe ese guardián.
    UnknownGuardian,
    /// Hay demasiadas solicitudes de desbloqueo pendientes.
    TooManyRequests,
    /// No hay ninguna solicitud pendiente con ese número.
    UnknownRequest,
    /// Aún no hay servidor vinculado: no se aceptan aprobaciones a distancia.
    NoServerLinked,
    /// La aprobación a distancia no es válida.
    InvalidApproval(&'static str),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPaired => write!(f, "no hay ningún guardián emparejado"),
            Self::AlreadyPaired => write!(f, "ya hay un guardián emparejado"),
            Self::WeakSecret => write!(f, "la clave debe tener al menos 8 caracteres"),
            Self::WrongSecret => write!(f, "clave incorrecta"),
            Self::WrongRecoveryCode => write!(f, "código de recuperación incorrecto"),
            Self::TooManyAttempts { retry_at_secs } => {
                write!(
                    f,
                    "demasiados intentos; reintentar a partir de {retry_at_secs}"
                )
            }
            Self::NotAuthorized => write!(f, "la acción exige autorización"),
            Self::InvalidAction(why) => write!(f, "acción no válida: {why}"),
            Self::TooManyGuardians => write!(f, "ya hay dos guardianes"),
            Self::LastGuardian => write!(f, "no se puede quitar al único guardián"),
            Self::UnknownGuardian => write!(f, "no existe ese guardián"),
            Self::TooManyRequests => write!(f, "demasiadas solicitudes pendientes"),
            Self::UnknownRequest => write!(f, "no existe esa solicitud"),
            Self::NoServerLinked => write!(f, "no hay servidor vinculado"),
            Self::InvalidApproval(why) => write!(f, "aprobación no válida: {why}"),
        }
    }
}

impl std::error::Error for GuardError {}
