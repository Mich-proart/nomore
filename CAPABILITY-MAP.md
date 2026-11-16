# Mapa de capacidades: NoMore

Estado: **aprobado el 16-11-2026**. Cada módulo tiene su especificación en `SPEC-<id>.md`.

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
| `guard-core` | Anti-manipulación común: roles, clave del guardián, solicitudes de desbloqueo con espera, registro de intentos de manipulación, configuración firmada. Librería Rust | — |
| `blocklists` | Genera y publica las listas de dominios (firmadas y versionadas) y define cómo se actualizan los clientes | `filter-core` |
| `windows-agent` | Servicio de Windows (SYSTEM): proxy DNS local, DNS forzado en todos los adaptadores, DoH de navegadores desactivado por política, autorreparación y protección contra desinstalación | `filter-core`, `guard-core`, `blocklists` |
| `windows-ui` | Interfaz (Tauri): instalación, emparejar guardián, estado, pedir desbloqueo | `windows-agent` |
| `android-app` | App Kotlin: VPN local con filtrado DNS, administrador de dispositivo contra desinstalación, interfaz propia | `filter-core`, `guard-core`, `blocklists` |
| `guardian-link` | Servidor mínimo: avisos al guardián (correo o push) y aprobación remota de desbloqueos | `guard-core` |
| `screen-ai` | Detección local de desnudos en pantalla, para lo que el DNS no ve (redes sociales, mensajería) | `windows-agent`, `android-app` |

Orden de construcción:

```
filter-core, guard-core → blocklists → windows-agent → windows-ui → android-app → guardian-link → screen-ai
```

Fuera de este mapa por ahora: macOS, Linux, iOS.

## Supuestos

1. Se reescribe desde cero. El código actual (Python, `.bat`) se mueve a `legacy/` y se quitan `build/` y `dist/` del repositorio.
2. Rust para el núcleo y el servicio de Windows, Tauri para la interfaz de escritorio, Kotlin nativo para Android (el núcleo Rust se enlaza por JNI).
3. La primera versión funciona sin servidor: clave del guardián guardada en el dispositivo y espera para desbloquear. Los avisos remotos llegan con `guardian-link`.
4. Windows 10 y 11; Android 8 o superior.
5. Gratuito y con donaciones, como el prototipo. Código en este mismo repositorio (monorepo).
6. El filtrado DNS lo hace NoMore en local, con listas propias; un DNS filtrado externo queda solo como respaldo.

## Decisiones

- **Categorías bloqueadas**: pornografía, apuestas y apps y webs de citas.
- **Android**: se distribuye como APK directo, fuera de Google Play.
- **Visibilidad del código**: indiferente. Se escribe como si fuera público: ningún secreto ni clave de firma en el repositorio.
