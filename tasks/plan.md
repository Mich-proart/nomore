# Plan de implementación: `guard-core`

Especificación: [SPEC-guard-core.md](../SPEC-guard-core.md). Tareas: [todo.md](todo.md). Estado: **aprobado el 16-11-2026**.

## Resumen

Librería Rust con las reglas del anti-manipulación: qué exige autorización, cómo se autoriza, qué se anota y con qué urgencia se avisa. Es una máquina de estados sin red, sin disco y sin reloj propio. Se construye empezando por lo que todo lo demás necesita (tiempo de confianza y eventos), sigue con las tres vías de autorización y termina con el guardado seguro y las pruebas de propiedades.

## Decisiones de arquitectura

1. **Tiempo de confianza.** Cada llamada recibe un `TimePoint` con el reloj del sistema, el reloj monótono, un identificador de arranque y, si la hay, la hora del servidor. La librería mantiene su propia hora:
   - con hora de servidor, manda esa (y nunca retrocede);
   - sin ella, avanza lo que avance el reloj monótono;
   - tras un reinicio sin conexión no avanza: el tiempo apagado no cuenta.
   
   Si el reloj del sistema y el monótono se separan más de 2 minutos, se anota manipulación. Requisito para los agentes: el reloj monótono debe seguir contando durante la suspensión.

2. **Los ajustes protegidos viven aquí.** Categorías activas, lista de permitidos, bloqueos añadidos, pausa, modo y duración de la espera forman parte del estado de `guard-core`. El agente construye la política de `filter-core` a partir de ellos. Así ningún ajuste puede cambiar sin pasar por `check`, y manipular el fichero equivale a manipular el estado. `guard-core` no depende de `filter-core`: usa tipos propios y sencillos.

3. **Autorizaciones de un solo uso.** Autorizar produce un permiso para una acción concreta, con caducidad. `perform` lo consume, aplica el cambio y anota el evento.

4. **Uno o dos guardianes.** Cada uno con su clave y su código de recuperación; cualquiera autoriza cualquier acción. Al escribir una clave se comprueba contra los dos, y los fallos se cuentan en común. Cada evento de autorización dice qué guardián fue.

   **Clave del guardián.** Se guarda su huella Argon2id (19 MiB, 2 pasadas), nunca la clave. El código de recuperación se genera al emparejar y se guarda igual. La librería no genera azar: el agente le pasa los bytes aleatorios.

5. **Aprobación a distancia.** El servidor firma con Ed25519 «apruebo la solicitud N del dispositivo D para la acción A, válido hasta T». La clave pública del servidor se fija al emparejar. Cada número de solicitud sirve una sola vez.

6. **Eventos.** JSON con versión, numerados y encadenados con SHA-256: cada uno incluye la huella del anterior. El servidor detecta huecos, alteraciones y también la restauración de una copia antigua del estado, porque la cadena se bifurca.

7. **Cola de salida acotada, sin reescribir.** Con la cola llena, los intentos de acceso se cuentan en vez de anotarse uno a uno y se emite un único resumen cuando hay sitio. Los eventos de manipulación tienen reserva propia.

8. **Agrupación de intentos.** El primer intento a un sitio genera evento. Los repetidos en los 15 minutos siguientes solo se cuentan, y al cerrar la ventana sale un evento «N intentos más». La clave de agrupación es la regla de la lista que coincidió (`pornhub.com`), no el subdominio consultado; para eso `filter-core` necesita una función nueva (tarea 10).

9. **Cada evento lleva su urgencia** (inmediata, resumen o silenciosa). El correo del resumen diario, incluido el de «sin incidencias», lo compone el servidor: es quien conoce la zona horaria del guardián y quien debe enviarlo aunque el dispositivo esté apagado.

10. **`tick`.** El agente llama a `tick(now)` cada minuto. Ahí se cierran ventanas de agrupación, caducan permisos, se reanuda la protección tras una pausa y se emite la señal de vida.

11. **Estado guardado.** JSON con versión más HMAC-SHA256 con la clave del dispositivo. Si falta o no autentica, se arranca **sin emparejar**: protección máxima, lista de permitidos vacía y evento de manipulación.

12. **Dependencias**: `argon2`, `hmac`, `sha2`, `ed25519-dalek`, `serde`, `serde_json`. En desarrollo, `proptest`.

## Ajustes respecto a la especificación

- La API usa `TimePoint` en vez de `Instant` y añade `setup` (emparejar), `perform` y `tick`.
- «Resumen diario» pasa a ser responsabilidad de `guardian-link`; aquí se etiqueta la urgencia.
- Criterio 5 (clave entre 0,1 y 1 s en un móvil): aquí se fijan los parámetros y se mide en CI; la medición en un móvil real se hace en `android-app`.
- Se añade una función a `filter-core` (tarea 10). Es un cambio de su API pública, solo aditivo.

## Dependencias entre piezas

```
clock ──→ event ──→ mode ──→ secret ──→ unlock ──→ approval
                     │                               │
                     └──→ access/notify              └──→ state ──→ propiedades
```

## Fases

1. **Base**: tareas 1 a 4. Al terminar, el guardián empareja, autoriza una acción con su clave, se aplica y queda anotada.
2. **Autorización y avisos**: tareas 5 a 7. Al terminar, funcionan la espera de 72 h, la aprobación firmada y la agrupación de intentos.
3. **Garantías**: tareas 8 a 11. Al terminar, se cumplen los criterios de éxito.

## Riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Quien tiene permisos de administrador puede, con esfuerzo, leer la clave del dispositivo y falsificar el estado | Alto | No se puede impedir desde una librería. Se detecta desde fuera: cadena bifurcada o falta de señal en el servidor, y aviso al guardián |
| Borrar el estado permite emparejar de nuevo con otro guardián | Medio | Arranca con protección máxima y el guardián anterior recibe el aviso de «sin señal». El agente guardará el estado por duplicado |
| El reloj monótono se detiene en suspensión en alguna plataforma y da falsos avisos de reloj alterado | Medio | Requisito escrito para los agentes; tolerancia de 2 min; prueba de escenario |
| Argon2id demasiado lento o pesado en móviles modestos | Bajo | Parámetros en una constante; se mide en `android-app` |
| Con uso sin conexión, 72 h de espera son 72 h de dispositivo encendido | Bajo | Es deliberado; con conexión cuenta el tiempo real. Se explica en la interfaz |

## Fuera de este plan

Detectar la manipulación en cada sistema y guardar el estado (`windows-agent`, `android-app`); recibir eventos, enviar correos, detectar falta de señal y firmar aprobaciones (`guardian-link`).
