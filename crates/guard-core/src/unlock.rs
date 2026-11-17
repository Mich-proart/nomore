//! Solicitudes de desbloqueo.
//!
//! El protegido pide autorización para una acción. En autocontrol, pasada la
//! espera, la acción queda permitida durante una hora. En parental la espera
//! no vence nunca: solo un guardián puede aprobarla. En los dos modos los
//! guardianes reciben aviso en cuanto se pide.

use serde::{Deserialize, Serialize};

use crate::error::GuardError;
use crate::mode::Action;

/// Cuánto dura el permiso cuando vence la espera.
pub const DELAY_GRANT_SECS: u64 = 3_600;
/// Solicitudes pendientes a la vez, como mucho.
pub const MAX_PENDING_REQUESTS: usize = 16;

/// Una solicitud pendiente.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockRequest {
    /// Número de la solicitud. No se reutiliza nunca.
    pub id: u64,
    /// Acción pedida.
    pub action: Action,
    /// Hora de confianza a la que se pidió.
    pub created_at: u64,
    /// Hora de confianza a la que vence la espera; `None` en modo parental.
    pub ready_at: Option<u64>,
}

/// Solicitudes pendientes de un dispositivo.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Requests {
    next_id: u64,
    pending: Vec<UnlockRequest>,
}

impl Requests {
    /// Crea una solicitud, o devuelve la que ya había para la misma acción.
    /// El segundo valor es `true` si es nueva.
    pub(crate) fn open(
        &mut self,
        action: Action,
        now: u64,
        delay_secs: Option<u64>,
    ) -> Result<(UnlockRequest, bool), GuardError> {
        if let Some(existing) = self.pending.iter().find(|r| r.action == action) {
            return Ok((existing.clone(), false));
        }
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(GuardError::TooManyRequests);
        }
        self.next_id += 1;
        let request = UnlockRequest {
            id: self.next_id,
            action,
            created_at: now,
            ready_at: delay_secs.map(|delay| now.saturating_add(delay)),
        };
        self.pending.push(request.clone());
        Ok((request, true))
    }

    pub(crate) fn get(&self, id: u64) -> Option<&UnlockRequest> {
        self.pending.iter().find(|r| r.id == id)
    }

    pub(crate) fn remove(&mut self, id: u64) -> Option<UnlockRequest> {
        let position = self.pending.iter().position(|r| r.id == id)?;
        Some(self.pending.remove(position))
    }

    /// Retira las solicitudes de `action`: ya no hacen falta.
    pub(crate) fn satisfy(&mut self, action: &Action) {
        self.pending.retain(|r| r.action != *action);
    }

    /// Saca las solicitudes cuya espera ha vencido.
    pub(crate) fn take_ready(&mut self, now: u64) -> Vec<UnlockRequest> {
        let (ready, waiting) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|r| r.ready_at.is_some_and(|at| at <= now));
        self.pending = waiting;
        ready
    }

    /// En modo parental ninguna espera vence.
    pub(crate) fn stop_all_delays(&mut self) {
        for request in &mut self.pending {
            request.ready_at = None;
        }
    }

    pub(crate) fn pending(&self) -> &[UnlockRequest] {
        &self.pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(d: &str) -> Action {
        Action::AllowDomain { domain: d.into() }
    }

    #[test]
    fn ids_grow_and_are_never_reused() {
        let mut requests = Requests::default();
        let (a, new_a) = requests.open(allow("a.com"), 0, Some(10)).unwrap();
        let (b, _) = requests.open(allow("b.com"), 0, Some(10)).unwrap();
        assert!(new_a);
        assert_eq!((a.id, b.id), (1, 2));
        requests.remove(2);
        let (c, _) = requests.open(allow("c.com"), 0, Some(10)).unwrap();
        assert_eq!(c.id, 3);
    }

    #[test]
    fn asking_twice_for_the_same_action_returns_the_first_request() {
        let mut requests = Requests::default();
        let (first, _) = requests.open(allow("a.com"), 0, Some(100)).unwrap();
        let (again, is_new) = requests.open(allow("a.com"), 50, Some(100)).unwrap();
        assert!(!is_new);
        assert_eq!(
            again, first,
            "pedir otra vez no reinicia ni adelanta la espera"
        );
    }

    #[test]
    fn pending_requests_are_bounded() {
        let mut requests = Requests::default();
        for i in 0..MAX_PENDING_REQUESTS {
            requests
                .open(allow(&format!("d{i}.com")), 0, Some(10))
                .unwrap();
        }
        assert_eq!(
            requests.open(allow("otro.com"), 0, Some(10)).unwrap_err(),
            GuardError::TooManyRequests
        );
    }

    #[test]
    fn only_due_requests_are_taken() {
        let mut requests = Requests::default();
        requests.open(allow("pronto.com"), 0, Some(10)).unwrap();
        requests.open(allow("tarde.com"), 0, Some(20)).unwrap();
        requests.open(allow("nunca.com"), 0, None).unwrap();
        assert!(requests.take_ready(9).is_empty());
        let ready = requests.take_ready(10);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].action, allow("pronto.com"));
        assert_eq!(requests.pending().len(), 2);
        assert_eq!(
            requests.take_ready(u64::MAX).len(),
            1,
            "la de parental no vence"
        );
    }
}
