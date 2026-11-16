# Mapa de capacidades: NoMore

Estado: **aprobado el 16-11-2026** (revisión 2, con avisos al guardián). Cada módulo tiene su especificación en `SPEC-<id>.md`.

## Objetivo

App de escritorio y móvil que bloquea pornografía y desnudos por todas las vías posibles, y que la persona protegida no puede desactivar por sí sola.

## Roles

Un único modelo sirve para autocontrol y para control parental:

- **Protegido**: quien usa el dispositivo (el adulto que se lo instala, o el hijo).
- **Guardián**: quien tiene la llave (compañero de rendición de cuentas, esposa, padre o madre).

La diferencia entre los dos casos es solo de configuración:

| | Autocontrol | Padres e hijos |
|---|---|---|
| Quién instala | El protegido | El guardián |
| Desbloqueo sin guardián | Sí, tras una espera larga (p. ej. 72 h) y con aviso | No |
| El protegido ve la configuración | Sí | No |

## Módulos

| Id | Responsabilidad | Depende de |
|---|---|---|
| `filter-core` | Decide si un dominio se bloquea: listas, subdominios, SafeSearch forzado, bloqueo de DoH, VPN y proxies conocidos. Librería Rust compartida por todas las plataformas | — |
| `guard-core` | Anti-manipulación común: roles, clave del guardián, solicitudes de desbloqueo con espera, registro de eventos (intentos de acceso y de manipulación) y cola de avisos. Librería Rust | — |
| `blocklists` | Genera y publica las listas de dominios (firmadas y versionadas) y define cómo se actualizan los clientes | `filter-core` |
| `guardian-link` | Servidor: recibe los eventos de los dispositivos y avisa al guardián por correo (WhatsApp, SMS o notificación en el móvil, más adelante), detecta dispositivos que dejan de dar señal y permite aprobar desbloqueos a distancia | `guard-core` |
| `windows-agent` | Servicio de Windows (SYSTEM): proxy DNS local, DNS forzado en todos los adaptadores, DoH de navegadores desactivado por política, autorreparación, protección contra desinstalación y envío de eventos | `filter-core`, `guard-core`, `blocklists`, `guardian-link` |
| `windows-ui` | Interfaz (Tauri): instalación, emparejar guardián, estado, pedir desbloqueo | `windows-agent` |
| `android-app` | App Kotlin: VPN local con filtrado DNS, administrador de dispositivo contra desinstalación, envío de eventos, interfaz propia | `filter-core`, `guard-core`, `blocklists`, `guardian-link` |
| `screen-ai` | Detección local de desnudos en pantalla, para lo que el DNS no ve (redes sociales, mensajería) | `windows-agent`, `android-app` |

Orden de construcción:

```
filter-core ✔ → guard-core → blocklists → guardian-link → windows-agent → windows-ui → android-app → screen-ai
```

Fuera de este mapa por ahora: macOS, Linux, iOS.

## Supuestos

1. Se reescribe desde cero. El código actual (Python, `.bat`) se mueve a `legacy/` y se quitan `build/` y `dist/` del repositorio.
2. Rust para el núcleo y el servicio de Windows, Tauri para la interfaz de escritorio, Kotlin nativo para Android (el núcleo Rust se enlaza por JNI).
3. El bloqueo funciona siempre sin servidor. El servidor (`guardian-link`) solo hace falta para avisar al guardián y para aprobar desbloqueos a distancia; sin conexión, el guardián desbloquea con su clave en el propio dispositivo.
4. Windows 10 y 11; Android 8 o superior.
5. Gratuito y con donaciones, como el prototipo. Código en este mismo repositorio (monorepo).
6. El filtrado DNS lo hace NoMore en local, con listas propias; un DNS filtrado externo queda solo como respaldo.

## Decisiones

- **Categorías bloqueadas**: pornografía, apuestas y apps y webs de citas.
- **Android**: se distribuye como APK directo, fuera de Google Play.
- **Visibilidad del código**: indiferente. Se escribe como si fuera público: ningún secreto ni clave de firma en el repositorio.
- **Avisos al guardián** (revisión 2): el guardián recibe aviso de los intentos de acceso a sitios bloqueados y de cualquier intento de manipulación. Por eso `guardian-link` pasa a construirse antes que los agentes.
- **Transparencia**: NoMore nunca funciona oculto. El protegido ve siempre que está instalado, quién es su guardián y qué se le comunica. Solo se comunican intentos sobre categorías bloqueadas, nunca la navegación permitida.
