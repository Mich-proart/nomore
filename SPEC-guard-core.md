# Spec: `guard-core`

Módulo del [mapa de capacidades](CAPABILITY-MAP.md). Estado: **aprobada el 16-11-2026 e implementada**. Plan en [tasks/plan.md](tasks/plan.md).

## Objetivo

Librería Rust que contiene las reglas del anti-manipulación, iguales en Windows y Android. Responde a tres preguntas:

1. **¿Puede hacerse esto ahora?** Cambiar la política, pausar la protección o desinstalar exigen autorización.
2. **¿Qué ha pasado?** Lleva el registro de intentos de acceso y de manipulación.
3. **¿Qué hay que contarle al guardián?** Convierte ese registro en avisos, agrupados para no inundarle.

Como `filter-core`, no abre sockets ni lee ficheros: quien la usa (`windows-agent`, `android-app`) le pasa la hora, guarda su estado y envía los avisos a `guardian-link`.

## Roles y modos

- **Protegido**: quien usa el dispositivo. **Guardián**: quien tiene la clave y recibe los avisos.
- **Uno o dos guardianes, nunca más.** Cada uno tiene su propia clave y su propio código de recuperación, y los dos tienen acceso total: cualquiera de ellos puede autorizar cualquier acción por sí solo, incluido añadir o quitar al otro. Siempre queda al menos uno.
- Todos los avisos llegan a los dos, también cuando es el otro guardián quien autoriza algo.
- El modo se elige al instalar y solo el guardián puede cambiarlo.

| | Autocontrol | Parental |
|---|---|---|
| Quién instala | El protegido | El guardián |
| Desbloqueo sin guardián | Sí, tras la espera y con aviso | No |
| El protegido ve la configuración | Sí | No |
| El protegido ve que NoMore está instalado y quién es su guardián | Sí | Sí |

## Qué exige autorización

| Acción | Sin autorización | Con autorización |
|---|---|---|
| Añadir un dominio a bloquear, activar una categoría | Permitido | — |
| Ver el estado y el registro propio | Permitido (en parental, solo el estado) | — |
| Cancelar una solicitud de desbloqueo | Permitido | — |
| Permitir un dominio, desactivar apuestas o citas | Denegado | Permitido |
| Pausar la protección (máximo 24 h, se reactiva sola) | Denegado | Permitido |
| Desinstalar, cambiar de modo, vincular otro servidor | Denegado | Permitido |
| Añadir el segundo guardián, quitar un guardián, cambiar una clave | Denegado | Permitido |

Regla general: endurecer es libre, aflojar exige autorización.

## Cómo se autoriza

Tres vías, todas dejan evento y aviso al guardián:

1. **Clave de un guardián** escrita en el dispositivo. Efecto inmediato (el permiso dura 10 min). Funciona sin conexión.
2. **Aprobación a distancia**: el protegido pide, el guardián aprueba desde el aviso que recibe. El servidor firma con Ed25519 dispositivo, solicitud, acción, guardián y caducidad; el dispositivo solo acepta la clave pública fijada con la acción «vincular servidor», que exige autorización. Funciona en los dos modos.
3. **Espera** (solo autocontrol): el protegido pide, el guardián recibe aviso al instante, y pasada la espera la acción queda permitida durante 1 h. Cualquiera puede cancelarla antes.

Detalles:

- Espera por defecto: **72 h**. El protegido puede alargarla; acortarla exige autorización.
- Una autorización vale para una sola acción concreta, no es un «modo desbloqueado».
- Clave errónea: espera creciente entre intentos (1 s, 2 s, 4 s… hasta 1 h) y aviso al guardián al tercer fallo.
- **Clave perdida**: cada guardián recibe un código de recuperación al darse de alta, que sirve una vez para cambiar su clave. Si hay dos guardianes, el otro también puede cambiársela. Sin clave ni código, en autocontrol queda la vía de la espera; en parental, reinstalar el dispositivo.

### El reloj

Adelantar el reloj del sistema no acorta la espera:

- Con conexión, manda la hora de `guardian-link`.
- Sin conexión, solo cuenta el tiempo con el dispositivo encendido, medido con el reloj monótono.
- Un salto del reloj del sistema que no cuadre con el monótono genera un evento de manipulación.

## Eventos

Todo lo relevante se anota como evento con hora, tipo y datos.

| Familia | Eventos |
|---|---|
| Acceso | Intento de conexión a un dominio bloqueado (dominio y categoría) |
| Manipulación | Servicio detenido o desinstalación intentada; DNS, hosts o VPN del sistema cambiados; VPN o proxy ajeno activo; reloj alterado; estado de NoMore corrupto o borrado; clave errónea repetida |
| Autorización | Desbloqueo pedido, aprobado, cancelado, cumplido; protección pausada y reanudada; política cambiada |
| Vida | Señal periódica de «sigo aquí y protegido» |

- **Detectar** la manipulación es trabajo de cada agente; `guard-core` define los tipos, los anota y decide el aviso.
- **Registro encadenado**: cada evento lleva la huella del anterior. Si alguien borra o altera eventos, el servidor lo nota al recibir el siguiente.
- **Cola de salida**: los eventos se guardan hasta que el servidor confirma su recepción. Sin conexión se acumulan (máximo 10 000; al llenarse se resumen los de acceso, nunca se descartan los de manipulación).
- **Señal de vida**: si el dispositivo deja de dar señal (apagado prolongado, red cortada, NoMore eliminado), es el servidor quien avisa al guardián. Aquí solo se define la señal y cada cuánto se emite (cada 15 min con conexión).

## Avisos

| Qué | Cuándo se avisa |
|---|---|
| Manipulación | Al instante, siempre |
| Solicitud de desbloqueo, pausa, cambio de política | Al instante |
| Intento de acceso a pornografía | Al instante el primero; los siguientes al mismo sitio se agrupan durante 15 min |
| Intento de acceso a apuestas o citas | Resumen diario |
| Resumen | Diario, aunque no haya nada («sin incidencias»), para que el silencio también informe. Lo compone y envía el servidor |
| Señal de vida | Nunca se avisa: solo la usa el servidor para detectar silencios |

Límite conocido: el DNS no distingue entre escribir una dirección y que una página normal cargue un anuncio de una casa de apuestas. Por eso los avisos dicen «intento de conexión a», no «visitó», y apuestas y citas van al resumen diario en vez de avisar al instante.

## Estado y arranque

- El estado (modo, huella Argon2id de la clave del guardián, solicitudes pendientes, tiempo acumulado, cola de eventos) se serializa a bytes. El agente lo guarda donde el protegido no pueda escribir.
- Va autenticado con una clave del dispositivo que aporta el agente (DPAPI en Windows, Keystore en Android).
- **Fallo cerrado**: si el estado falta, está corrupto o no autentica, se arranca con protección máxima, sin solicitudes pendientes, y se emite un evento de manipulación.

## Tecnología

- Rust estable, edición 2021, mismos destinos que `filter-core`. Sin `unsafe`, sin red, sin disco, sin reloj propio.
- Dependencias previstas (se confirman en el plan): `argon2`, `hmac`, `sha2`, `ed25519-dalek`, `serde`, `serde_json`.

## Comandos

```
Compilar:  cargo build -p guard-core
Probar:    cargo test -p guard-core
Garantías: cargo test -p guard-core --release -- --ignored --nocapture
Lint:      cargo clippy -p guard-core --all-targets -- -D warnings
Formato:   cargo fmt --all -- --check
```

## Estructura

```
crates/guard-core/
  src/lib.rs          → API pública
  src/guard.rs        → la máquina de estados que une todo lo demás
  src/mode.rs         → modos, ajustes protegidos, acciones y qué exige autorización
  src/secret.rs       → clave del guardián, código de recuperación, espera entre fallos
  src/unlock.rs       → solicitudes de desbloqueo y su máquina de estados
  src/clock.rs        → tiempo de confianza a partir de reloj del sistema, monótono y servidor
  src/event.rs        → tipos de evento, registro encadenado, cola de salida
  src/notify.rs       → de eventos a avisos: urgencia, agrupación y señal de vida
  src/approval.rs     → aprobaciones a distancia firmadas
  src/state.rs        → serialización autenticada y fallo cerrado
  tests/              → pruebas de integración por escenario
```

## API y estilo

Mismas convenciones que `filter-core`. La librería es una máquina de estados: entra una orden con la hora, sale el resultado y los eventos generados.

```rust
pub struct Guard { /* estado */ }

impl Guard {
    /// Dispositivo sin emparejar: protección máxima. `device` son 16 bytes
    /// aleatorios generados al instalar.
    pub fn unpaired(device: DeviceId, now: TimePoint) -> Guard;
    /// Primer guardián y modo. Devuelve su código de recuperación.
    pub fn setup(&mut self, mode: Mode, guardian: NewGuardian, now: TimePoint)
        -> Result<RecoveryCode, GuardError>;

    /// ¿Puede hacerse `action` ahora mismo?
    pub fn check(&mut self, action: &Action, now: TimePoint) -> Decision;

    /// Las tres vías de autorización.
    pub fn authorize_with_secret(&mut self, action: &Action, secret: &str, now: TimePoint)
        -> Result<GuardianId, GuardError>;
    pub fn request(&mut self, action: &Action, now: TimePoint) -> Result<UnlockRequest, GuardError>;
    pub fn approve_remotely(&mut self, approval: &Approval, now: TimePoint)
        -> Result<GuardianId, GuardError>;

    /// Aplicar lo autorizado (gasta el permiso) y endurecer (libre).
    pub fn perform(&mut self, action: &Action, now: TimePoint) -> Result<(), GuardError>;
    pub fn tighten(&mut self, change: &Tightening, now: TimePoint) -> Result<(), GuardError>;

    /// Lo que detecta el agente, y su llamada de cada minuto.
    pub fn record_access(&mut self, site: &str, category: Category, now: TimePoint);
    pub fn record_tamper(&mut self, tamper: Tamper, now: TimePoint);
    pub fn tick(&mut self, now: TimePoint);

    /// Avisos listos para enviar, y confirmación de los ya recibidos.
    pub fn outbox(&self) -> Vec<Envelope>;
    pub fn acknowledge(&mut self, up_to: EventId, now: TimePoint);
}
```

Además: `add_guardian`, `change_secret`, `authorize_with_recovery_code`, `cancel_request`, y consultas (`settings`, `guardians`, `pending_requests`, `protection_active`…).

`TimePoint` agrupa reloj del sistema, reloj monótono, identificador de arranque y, si la hay, hora del servidor.

## Pruebas

- **Unitarias** por fichero.
- **Por escenario**: «pide desbloqueo, adelanta el reloj, sigue denegado», «borra el estado, arranca cerrado y avisa», «tres claves erróneas, aviso», «40 consultas al mismo sitio en un minuto, un solo aviso».
- **De propiedades**: ninguna secuencia de órdenes sin clave, sin aprobación firmada y sin que pase la espera consigue aflojar la protección; `load` no entra en pánico con bytes aleatorios; un registro con un evento quitado o alterado no verifica.

## Límites

- **Siempre**: toda acción que afloja pasa por `check`; todo cambio de estado genera evento; fallo cerrado.
- **Preguntar antes**: dependencias nuevas, formato del estado guardado, formato de los eventos (es el contrato con `guardian-link`).
- **Nunca**: más de dos guardianes; modo oculto; registrar o enviar dominios permitidos; guardar la clave del guardián en claro; una puerta trasera o clave maestra.

## Criterios de éxito

1. Cada fila de «Qué exige autorización» y de «Avisos» tiene al menos una prueba.
2. La prueba de propiedades de «no se puede aflojar sin autorización» pasa con 100 000 secuencias aleatorias.
3. Adelantar el reloj del sistema no acorta ninguna espera, y queda anotado.
4. Estado ausente, corrupto o con otra clave de dispositivo: arranque cerrado y evento de manipulación.
5. Comprobar la clave del guardián tarda entre 0,1 y 1 s en un móvil de gama media (Argon2id ajustado), y un registro alterado no verifica.
6. Compila sin avisos para Windows y las tres arquitecturas de Android; clippy y formato en verde.

## Resultados medidos

En Linux x86-64 (20-11-2026):

| Criterio | Objetivo | Resultado |
|---|---|---|
| 1. Cada fila de «Qué exige autorización» y de «Avisos» con prueba | Todas | Todas (`tests/actions.rs`, `tests/notify.rs`, `tests/unlock.rs`) |
| 2. Secuencias aleatorias sin autorización que aflojan algo | 0 de 100 000 | 0 de 100 000 (2 048 054 pasos, 24 s). La prueba detecta los errores introducidos a propósito |
| 3. El reloj del sistema acorta una espera | Nunca | Nunca, y queda anotado |
| 4. Estado ausente, alterado, de otra clave o de otro dispositivo | Arranque cerrado y aviso | Sí, con cualquier byte alterado |
| 5. Comprobar la clave del guardián | < 1 s; 0,1–1 s en móvil | 20 ms aquí, igual con clave buena o errónea. Se mide en un móvil real en `android-app` |
| 6. Compila para Windows y Android sin avisos | 4 destinos | 4 destinos, en CI |

## Decisiones

- **Guardianes**: dos como máximo, los dos con acceso total.
- **Canal de los avisos**: de momento solo correo. WhatsApp y SMS quedan para más adelante.
- **Intentos de acceso**: pornografía al instante (agrupando 15 min por sitio); apuestas y citas en el resumen diario.
- **Espera en autocontrol**: 72 h.
- **Contenido del aviso**: incluye el nombre del sitio.
