# Spec: `guard-core`

Módulo del [mapa de capacidades](CAPABILITY-MAP.md). Estado: **aprobada el 16-11-2026**. Plan en [tasks/plan.md](tasks/plan.md).

## Objetivo

Librería Rust que contiene las reglas del anti-manipulación, iguales en Windows y Android. Responde a tres preguntas:

1. **¿Puede hacerse esto ahora?** Cambiar la política, pausar la protección o desinstalar exigen autorización.
2. **¿Qué ha pasado?** Lleva el registro de intentos de acceso y de manipulación.
3. **¿Qué hay que contarle al guardián?** Convierte ese registro en avisos, agrupados para no inundarle.

Como `filter-core`, no abre sockets ni lee ficheros: quien la usa (`windows-agent`, `android-app`) le pasa la hora, guarda su estado y envía los avisos a `guardian-link`.

## Roles y modos

- **Protegido**: quien usa el dispositivo. **Guardián**: quien tiene la clave y recibe los avisos.
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
| Desinstalar, cambiar de guardián o de modo | Denegado | Permitido |

Regla general: endurecer es libre, aflojar exige autorización.

## Cómo se autoriza

Tres vías, todas dejan evento y aviso al guardián:

1. **Clave del guardián** escrita en el dispositivo. Efecto inmediato. Funciona sin conexión.
2. **Aprobación a distancia**: el protegido pide, el guardián aprueba desde el aviso que recibe. Llega con `guardian-link`; aquí solo se define y se verifica la aprobación firmada.
3. **Espera** (solo autocontrol): el protegido pide, el guardián recibe aviso al instante, y pasada la espera la acción queda permitida durante 1 h. Cualquiera puede cancelarla antes.

Detalles:

- Espera por defecto: **72 h**. El protegido puede alargarla; acortarla exige autorización.
- Una autorización vale para una sola acción concreta, no es un «modo desbloqueado».
- Clave errónea: espera creciente entre intentos (1 s, 2 s, 4 s… hasta 1 h) y aviso al guardián al tercer fallo.
- **Clave perdida**: al emparejar se genera un código de recuperación para el guardián. Sin clave ni código, en autocontrol queda la vía de la espera; en parental, reinstalar el dispositivo.

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
| Resumen | Diario, aunque no haya nada («sin incidencias»), para que el silencio también informe |

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
Lint:      cargo clippy -p guard-core --all-targets -- -D warnings
Formato:   cargo fmt --all -- --check
```

## Estructura

```
crates/guard-core/
  src/lib.rs          → API pública
  src/mode.rs         → modos, acciones y qué exige autorización
  src/secret.rs       → clave del guardián, código de recuperación, espera entre fallos
  src/unlock.rs       → solicitudes de desbloqueo y su máquina de estados
  src/clock.rs        → tiempo de confianza a partir de reloj del sistema, monótono y servidor
  src/event.rs        → tipos de evento, registro encadenado, cola de salida
  src/notify.rs       → de eventos a avisos: urgencia y agrupación
  src/state.rs        → serialización autenticada y fallo cerrado
  tests/              → pruebas de integración por escenario
```

## API y estilo

Mismas convenciones que `filter-core`. La librería es una máquina de estados: entra una orden con la hora, sale el resultado y los eventos generados.

```rust
pub struct Guard { /* estado */ }

impl Guard {
    /// Arranca desde el estado guardado. Si no es válido, falla cerrado.
    pub fn load(saved: Option<&[u8]>, device_key: &[u8], now: Instant) -> Guard;

    /// ¿Puede hacerse `action` ahora mismo?
    pub fn check(&self, action: &Action, now: Instant) -> Decision;

    /// El protegido pide autorización; devuelve cuándo quedará permitida.
    pub fn request(&mut self, action: Action, now: Instant) -> Result<Request, GuardError>;

    /// El guardián autoriza con su clave.
    pub fn authorize_with_secret(&mut self, action: &Action, secret: &str, now: Instant)
        -> Result<(), GuardError>;

    /// Anota algo que ha detectado el agente.
    pub fn record(&mut self, event: EventKind, now: Instant);

    /// Avisos listos para enviar, y confirmación de los ya recibidos.
    pub fn outbox(&self) -> Vec<Envelope>;
    pub fn acknowledge(&mut self, up_to: EventId);

    /// Estado para guardar en disco.
    pub fn save(&self) -> Vec<u8>;
}
```

`Instant` agrupa reloj del sistema, reloj monótono y, si la hay, hora del servidor.

## Pruebas

- **Unitarias** por fichero.
- **Por escenario**: «pide desbloqueo, adelanta el reloj, sigue denegado», «borra el estado, arranca cerrado y avisa», «tres claves erróneas, aviso», «40 consultas al mismo sitio en un minuto, un solo aviso».
- **De propiedades**: ninguna secuencia de órdenes sin clave, sin aprobación firmada y sin que pase la espera consigue aflojar la protección; `load` no entra en pánico con bytes aleatorios; un registro con un evento quitado o alterado no verifica.

## Límites

- **Siempre**: toda acción que afloja pasa por `check`; todo cambio de estado genera evento; fallo cerrado.
- **Preguntar antes**: dependencias nuevas, formato del estado guardado, formato de los eventos (es el contrato con `guardian-link`).
- **Nunca**: modo oculto; registrar o enviar dominios permitidos; guardar la clave del guardián en claro; una puerta trasera o clave maestra.

## Criterios de éxito

1. Cada fila de «Qué exige autorización» y de «Avisos» tiene al menos una prueba.
2. La prueba de propiedades de «no se puede aflojar sin autorización» pasa con 100 000 secuencias aleatorias.
3. Adelantar el reloj del sistema no acorta ninguna espera, y queda anotado.
4. Estado ausente, corrupto o con otra clave de dispositivo: arranque cerrado y evento de manipulación.
5. Comprobar la clave del guardián tarda entre 0,1 y 1 s en un móvil de gama media (Argon2id ajustado), y un registro alterado no verifica.
6. Compila sin avisos para Windows y las tres arquitecturas de Android; clippy y formato en verde.

## Decisiones

- **Canal de los avisos**: de momento solo correo. WhatsApp y SMS quedan para más adelante.
- **Intentos de acceso**: pornografía al instante (agrupando 15 min por sitio); apuestas y citas en el resumen diario.
- **Espera en autocontrol**: 72 h.
- **Contenido del aviso**: incluye el nombre del sitio.
