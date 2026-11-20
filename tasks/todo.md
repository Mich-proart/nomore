# Tareas: `guard-core`

Plan: [plan.md](plan.md). Comprobación común a todas las tareas:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Fase 1: Base

- [x] **Tarea 1: Crate y tiempo de confianza** (S)
  - Crear `crates/guard-core` y `clock.rs`: `TimePoint` y la hora de confianza que avanza con el servidor o con el reloj monótono.
  - Aceptación: adelantar el reloj del sistema no adelanta la hora de confianza y se detecta; tras un reinicio sin conexión la hora no avanza; con hora de servidor nunca retrocede.
  - Verificación: comprobación común.
  - Dependencias: ninguna.
  - Ficheros: `crates/guard-core/Cargo.toml`, `src/lib.rs`, `src/clock.rs`, `src/error.rs`.

- [x] **Tarea 2: Eventos, cadena y cola de salida** (M)
  - `event.rs`: tipos de evento, numeración, cadena SHA-256, cola con confirmación y contadores de desbordamiento.
  - Aceptación: una cadena íntegra verifica y una con un evento quitado o alterado no; `acknowledge` vacía la cola hasta el evento indicado; con la cola llena los accesos se cuentan y los de manipulación se conservan.
  - Verificación: comprobación común.
  - Dependencias: 1.
  - Ficheros: `src/event.rs`, `src/lib.rs`, `Cargo.toml` del crate.

- [x] **Tarea 3: Ajustes, acciones y `check`** (S)
  - `mode.rs`: ajustes protegidos, modos, lista de acciones y la regla «endurecer es libre, aflojar exige autorización».
  - Aceptación: cada fila de «Qué exige autorización» tiene prueba; sin permiso, toda acción que afloja se deniega; endurecer se aplica y se anota.
  - Verificación: comprobación común.
  - Dependencias: 2.
  - Ficheros: `src/mode.rs`, `src/lib.rs`, `tests/actions.rs`.

- [x] **Tarea 4: Emparejar y autorizar con la clave del guardián** (M)
  - `secret.rs`: `setup`, huella Argon2id, código de recuperación, espera creciente entre fallos, permiso de un solo uso y `perform`.
  - Aceptación: la clave correcta permite una sola acción, una sola vez; tres fallos generan aviso y la espera crece hasta 1 h; el código de recuperación permite cambiar la clave; se admiten dos guardianes y nunca un tercero, cualquiera de los dos autoriza, y no se puede quitar al último.
  - Verificación: comprobación común.
  - Dependencias: 3.
  - Ficheros: `src/secret.rs`, `src/guard.rs`, `src/lib.rs`, `tests/secret.rs`, `Cargo.toml` del crate.

### Punto de control A
- [x] Comprobación común en verde.
- [x] Escenario completo: emparejar, autorizar con clave «permitir un dominio», aplicarlo y ver los eventos en la cola.
- [x] Revisión con Michell antes de seguir.

## Fase 2: Autorización y avisos

- [x] **Tarea 5: Desbloqueo con espera y pausa** (M)
  - `unlock.rs`: solicitud, cancelación, vencimiento en hora de confianza, ventana de 1 h, denegación en modo parental, pausa de 24 h como máximo que se reanuda sola, y `tick`.
  - Aceptación: en autocontrol la acción queda permitida a las 72 h y deja de estarlo 1 h después; en parental se deniega; alargar la espera es libre y acortarla exige autorización; adelantar el reloj no la acorta.
  - Verificación: comprobación común.
  - Dependencias: 4.
  - Ficheros: `src/unlock.rs`, `src/guard.rs`, `src/lib.rs`, `tests/unlock.rs`.

- [x] **Tarea 6: Aprobación a distancia firmada** (S)
  - Verificar aprobaciones Ed25519 ligadas a dispositivo, solicitud, acción y caducidad.
  - Aceptación: una aprobación válida concede el permiso; se rechazan las de firma incorrecta, otra solicitud, otra acción, caducadas o ya usadas.
  - Verificación: comprobación común.
  - Dependencias: 5.
  - Ficheros: `src/approval.rs`, `src/lib.rs`, `tests/approval.rs`, `Cargo.toml` del crate.

- [x] **Tarea 7: Intentos de acceso, urgencia y señal de vida** (M)
  - `notify.rs`: agrupación de 15 min por sitio, evento de repetidos, urgencia de cada evento y señal de vida cada 15 min desde `tick`.
  - Aceptación: 40 intentos al mismo sitio en un minuto dan un evento inmediato y, al cerrar la ventana, uno de «39 más»; pornografía es inmediata y apuestas y citas van a resumen; toda manipulación es inmediata.
  - Verificación: comprobación común.
  - Dependencias: 2 y 3.
  - Ficheros: `src/notify.rs`, `src/event.rs`, `src/lib.rs`, `tests/notify.rs`.

### Punto de control B
- [x] Comprobación común en verde.
- [x] Cada fila de «Qué exige autorización» y de «Avisos» tiene prueba (criterio 1).
- [x] Revisión con Michell antes de seguir.

## Fase 3: Garantías

- [x] **Tarea 8: Estado autenticado y fallo cerrado** (M)
  - `state.rs`: `save` y `load` con versión y HMAC; arranque sin emparejar si falta, está corrupto o es de otro dispositivo.
  - Aceptación: guardar y cargar conserva todo (ajustes, solicitudes, hora de confianza, cola); cualquier byte alterado u otra clave de dispositivo dan arranque cerrado con evento de manipulación (criterio 4).
  - Verificación: comprobación común.
  - Dependencias: 5, 6 y 7.
  - Ficheros: `src/state.rs`, `src/lib.rs`, `tests/state.rs`, `Cargo.toml` del crate.

- [x] **Tarea 9: Pruebas de propiedades** (M)
  - Secuencias aleatorias de órdenes y saltos de reloj; bytes aleatorios en `load` y en aprobaciones.
  - Aceptación: en 100 000 secuencias sin clave, sin aprobación válida y sin que venza la espera, los ajustes nunca se aflojan (criterio 2); el reloj del sistema nunca acorta una espera (criterio 3); ningún pánico.
  - Verificación: `cargo test -p guard-core --release -- --ignored`.
  - Dependencias: 8.
  - Ficheros: `tests/properties.rs`, `Cargo.toml` del crate.

- [x] **Tarea 10: `filter-core` devuelve la regla que coincidió** (S)
  - Nueva función pública `Filter::blocked_rule(domain)` que devuelve la categoría y la entrada de la lista (`pornhub.com` para `cdn.es.pornhub.com`), para usarla como clave de agrupación.
  - Aceptación: devuelve la entrada exacta de la lista; `None` si el dominio no está bloqueado; no cambia ningún comportamiento existente.
  - Verificación: comprobación común.
  - Dependencias: ninguna.
  - Ficheros: `crates/filter-core/src/blocklist.rs`, `src/policy.rs`, `tests/policy.rs`, `SPEC-filter-core.md`.

- [x] **Tarea 11: CI y medición de Argon2id** (S)
  - Extender los trabajos de garantías y destinos a todo el workspace; prueba que mide la comprobación de clave.
  - Aceptación: los cuatro destinos compilan sin avisos con los dos crates (criterio 6); la comprobación de clave tarda menos de 1 s en CI (criterio 5, parte medible aquí).
  - Verificación: el CI pasa en la rama.
  - Dependencias: 9.
  - Ficheros: `.github/workflows/ci.yml`, `crates/guard-core/tests/guarantees.rs`.

### Punto de control final
- [x] Los seis criterios de éxito de la especificación se cumplen.
- [ ] Revisión con Michell y fusión en `development`.
