# Plan de implementación: `blocklists`

Especificación: [SPEC-blocklists.md](../SPEC-blocklists.md). Tareas: [todo.md](todo.md). Estado: **pendiente de aprobación**.

## Resumen

Dos crates nuevos en el workspace. Primero el **verificador** (`crates/blocklists`), porque define el contrato que el generador tiene que cumplir y es lo que irá dentro de las apps. Después el **generador** (`crates/blocklists-build`), probado con fuentes de ejemplo sin red. Por último, la puesta en producción: fuentes reales, repositorio `nomore-lists`, ejecución diaria y primera publicación medida contra los criterios.

## Decisiones de arquitectura

1. **Manifiesto en JSON, firmado tal cual.** `manifest.json` lleva formato, versión, fecha y, por categoría, número de dominios, tamaño y SHA-256 del binario completo y de cada diferencia. La firma Ed25519 cubre los bytes exactos del fichero, con un prefijo de dominio (`nomore-lists-v1\n`) como en las aprobaciones de `guard-core`.

2. **Versión = `AAAAMMDDnn`** (fecha y contador, p. ej. `2026112001`). Es creciente y legible. El verificador rechaza cualquier versión menor o igual que la instalada.

3. **Diferencias en binario propio** (`NMDL`): categoría, versión de origen y de destino, y dos listas ordenadas de huellas (añadidas y quitadas). Aplicarla es una mezcla de listas ordenadas. Tras aplicarla, el SHA-256 del binario resultante debe coincidir con el del manifiesto: si no, se descarta y se pide el completo.

4. **El verificador no descarga, planifica.** API en tres pasos:
   - `Manifest::verify(bytes, firma, clave, versión_instalada)` comprueba firma y versión;
   - `manifest.plan(&instaladas)` dice qué ficheros hacen falta (diferencia si la hay desde la versión instalada; completo si no);
   - `apply(manifest, instaladas, ficheros)` devuelve las listas nuevas o un error, sin tocar las anteriores.
   
   El agente descarga lo que diga el plan y guarda el resultado de forma atómica.

5. **Categorías de `filter-core`.** Se reutiliza `filter_core::Category`; en el manifiesto van como texto (`porn`, `gambling`, `dating`, `bypass`).

6. **Generador modular y reproducible.**
   - `parse` convierte cada formato en dominios.
   - `clean` normaliza, une, colapsa subdominios y aplica protegidos y alarmas.
   - `publish` escribe binarios, diferencias, manifiesto, `SOURCES.md` e informe, y firma.
   - Mismas entradas, mismos bytes: nada depende del orden de descarga ni de la hora salvo la fecha de versión, que se pasa como argumento.

7. **Estado entre ejecuciones = la publicación anterior.** El generador descarga la última publicación de `nomore-lists` para calcular diferencias, comparar tamaños por fuente y detectar dominios populares nuevos. La última versión buena de cada fuente se guarda como fichero en la publicación (`sources/<fuente>.txt.zst`), para poder reutilizarla si la fuente falla.

8. **Alarma de populares con Tranco.** Se descarga el top 10 000 de Tranco en cada ejecución. Un dominio de ese top que entra nuevo en una categoría queda en cuarentena (`quarantine.txt` en el repositorio de listas) hasta que se revise; la ejecución abre un aviso (issue) en GitHub.

9. **Dependencias.**
   - Verificador: `ed25519-dalek`, `sha2`, `serde`, `serde_json` y `filter-core`.
   - Generador: además `ureq` (descargas), `idna` (punycode), `toml` (configuración), `zstd` (copias de fuentes) y `clap` (línea de órdenes).
   - En desarrollo: `proptest`.

10. **Clave de firma.** El generador tiene un subcomando `keygen` que crea el par de claves en ficheros locales. Tú guardas la privada como secreto `NOMORE_LISTS_SIGNING_KEY` del repositorio de listas y una copia fuera de línea; la pública se fija en `crates/blocklists/src/keys.rs`.

## Lo que necesito de ti, y cuándo

| Cuándo | Qué |
|---|---|
| Tarea 10 | Crear el repositorio público vacío `Mich-proart/nomore-lists` (no puedo crear repositorios desde aquí) |
| Tarea 10 | Ejecutar `keygen` en tu ordenador, guardar la clave privada como secreto del repositorio y una copia fuera de línea |
| Antes de la primera publicación | Escribir al mantenedor de UT1 para confirmar la versión de la licencia (te preparo el correo) |

## Fases

1. **Verificador**: tareas 1 a 4. Al terminar, la librería acepta solo publicaciones firmadas y más nuevas, y actualiza con diferencias.
2. **Generador**: tareas 5 a 8. Al terminar, `blocklists-build` produce una publicación completa a partir de fuentes de ejemplo, y el verificador la acepta.
3. **Producción**: tareas 9 a 11. Al terminar, hay publicación diaria real y se cumplen los criterios.

## Riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| La lista de pornografía combinada supera 32 MB | Medio | Medir en la tarea 11; si pasa, quitar dominios sin DNS (plan de la especificación) o dejar oisd/HaGeZi como complemento solo en escritorio |
| Una fuente cambia de formato sin avisar | Medio | Tamaño mínimo por fuente y caída máxima del 30 %: se usa la versión anterior y el informe lo señala |
| Falsos positivos graves (un sitio legítimo bloqueado en todos los dispositivos) | Alto | Protegidos, cuarentena de populares, control del top 1 000 en cada ejecución, y lista de permitidos de cada guardián |
| Se filtra la clave de firma | Alto | Copia fuera de línea; el verificador admite una lista de claves públicas para poder rotarla con una actualización de la app |
| El entorno de desarrollo no puede descargar de la mayoría de sitios | Bajo | Todo se prueba con ficheros de ejemplo; la primera ejecución real es en GitHub Actions |
| Tiempo de ejecución en Actions | Bajo | Millones de dominios se procesan en segundos; el límite de 6 h no es un problema |

## Fuera de este plan

Guardar las listas y lanzar la actualización periódica en el dispositivo (`windows-agent`, `android-app`); listas de partida incluidas en el instalador (se generan aquí, se empaquetan allí); bloqueos propios de cada guardián (`extra_blocks` de `guard-core`), que el agente añade como lista aparte.
