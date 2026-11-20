# Spec: `blocklists`

Módulo del [mapa de capacidades](CAPABILITY-MAP.md). Estado: **aprobada el 20-11-2026**. Plan en [tasks/plan.md](tasks/plan.md).

## Objetivo

Que cada dispositivo tenga siempre listas buenas, recientes y auténticas de las cuatro categorías: pornografía, apuestas, citas y vías de escape. Tiene dos partes:

1. **Generador** (se ejecuta en GitHub Actions cada día): descarga listas públicas, las limpia, las combina, comprueba que no bloquean sitios legítimos importantes, genera los binarios de `filter-core`, calcula las diferencias con la versión anterior y lo firma todo.
2. **Verificador** (librería que usan `windows-agent` y `android-app`): comprueba la firma, aplica las diferencias y rechaza cualquier lista alterada o más antigua que la que ya tiene. Como las otras librerías, no abre sockets: la descarga la hace el agente.

## Fuentes

Solo listas públicas, mantenidas y con licencia que permita redistribuir.

| Categoría | Fuente | Licencia | Tamaño aproximado |
|---|---|---|---|
| Pornografía | The Block List Project, `porn` | Unlicense | ~950 000 |
| | Steven Black, extensión `porn` | MIT | ~77 000 |
| | HaGeZi, `nsfw` | GPL-3.0 | |
| | oisd, `nsfw` | GPL-3.0 | |
| Apuestas | The Block List Project, `gambling` | Unlicense | ~340 000 |
| | HaGeZi, `gambling` | GPL-3.0 | |
| | Steven Black, extensión `gambling` | MIT | ~6 000 |
| Citas | UT1 (Universidad Toulouse Capitole), `dating` | Creative Commons (versión por confirmar) | ~3 500 |
| | ShadowWhisperer, `dating` | por confirmar | |
| Vías de escape | HaGeZi, `doh-vpn-proxy-bypass` | GPL-3.0 | |
| | HaGeZi, «buscadores sin SafeSearch» | GPL-3.0 | |
| | Lista propia de NoMore (p. ej. `html.duckduckgo.com`, `lite.duckduckgo.com`) | la del proyecto | decenas |

Más una **lista propia por categoría** para añadir lo que falte, mantenida en el repositorio de listas.

Cada fuente se declara en un fichero de configuración (URL, formato, categoría, licencia, tamaño mínimo esperado). Formatos admitidos: hosts (`0.0.0.0 dominio`), un dominio por línea, comodín (`*.dominio`) y Adblock básico (`||dominio^`). Lo demás se ignora y se cuenta.

## Limpieza y combinación

1. **Normalizar**: minúsculas, sin punto final, IDN a punycode; se descarta lo que no sea un dominio válido (IP, `localhost`, comentarios).
2. **Unir y quitar duplicados** por categoría.
3. **Colapsar subdominios**: si está `pornhub.com`, sobra `es.pornhub.com`. `filter-core` ya bloquea los subdominios.
4. **Lista de protegidos**: dominios que nunca se bloquean por categoría aunque una fuente los incluya. Contiene buscadores (para que SafeSearch funcione), servicios del sistema (Microsoft, Apple, Google, actualizaciones), bancos y administración pública, y las redes sociales generalistas (decisión ya tomada: las cubre `screen-ai`). Si un protegido aparece en una fuente, se descarta y se anota en el informe.
5. **Alarma de falsos positivos**: si una fuente mete en una lista un dominio del top 10 000 de Tranco que no estaba antes, ese dominio queda fuera hasta revisarlo a mano, y la ejecución abre un aviso en el repositorio.
6. **Fuente caída o sospechosa**: si una fuente no responde, o su tamaño cae más de un 30 % respecto a la vez anterior, se usa su última versión buena. Nunca se publica una lista mucho más pequeña por un fallo de descarga.

## Lo que se publica

Un repositorio público aparte, `Mich-proart/nomore-lists`, con una publicación (GitHub Release) por versión:

```
manifest.json            versión, fecha, y por categoría: número de dominios y SHA-256 del binario
manifest.sig             firma Ed25519 de manifest.json
porn.nmbl                binarios de filter-core, completos
gambling.nmbl
dating.nmbl
bypass.nmbl
porn.<desde>.delta       diferencias respecto a las 7 versiones anteriores
…
SOURCES.md               fuentes, licencias y atribuciones
report.md                qué entró, qué salió, qué se descartó y por qué
```

- **Versión**: número creciente, la fecha en formato `AAAAMMDD` más un contador.
- **Diferencias**: dos listas ordenadas de huellas, añadidas y quitadas. Como las listas sobre todo crecen, la actualización diaria es pequeña; si el dispositivo lleva más de 7 versiones sin actualizar, descarga los binarios completos.
- **Licencia de lo publicado**: GPL-3.0, porque incluye fuentes GPL-3.0. Eso obliga a que las listas sean públicas y a citar las fuentes, cosa que encaja con un proyecto gratuito.

## Verificación en el dispositivo

- La clave pública de las listas va **dentro de la app**; no se descarga.
- El agente pasa al verificador el manifiesto, la firma y los ficheros. El verificador comprueba firma, versión y huella de cada fichero, y devuelve las listas listas para `filter-core`.
- **Nunca hacia atrás**: una versión menor o igual que la instalada se rechaza, aunque esté bien firmada. Así nadie puede servir una lista antigua y más corta.
- **Nunca sin listas**: si algo falla, el dispositivo se queda con las que tenía. La app incluye unas listas de partida, para que NoMore proteja desde el primer minuto aunque no haya conexión.
- Un manifiesto con firma inválida se anota como evento de manipulación (`guard-core`).

## Tecnología

- Rust, en el mismo workspace: `crates/blocklists` (verificador, librería sin red) y `crates/blocklists-build` (generador, binario con red).
- Reutiliza `CategoryList::build` de `filter-core` y Ed25519 como en `guard-core`.
- Generador: `ureq` o `reqwest` para descargar, `idna` para punycode.
- Ejecución diaria con GitHub Actions en el repositorio de listas. La clave privada de firma vive solo como secreto de ese repositorio, con una copia de seguridad fuera de línea.

## Comandos

```
Probar:     cargo test -p blocklists -p blocklists-build
Generar:    cargo run -p blocklists-build --release -- --config lists.toml --out dist/
Verificar:  cargo run -p blocklists-build --release -- verify dist/
```

## Estructura

```
crates/blocklists/
  src/manifest.rs     → formato del manifiesto, firma y versión
  src/delta.rs        → diferencias: generar y aplicar
  src/verify.rs       → del material descargado a listas de confianza
crates/blocklists-build/
  src/sources.rs      → configuración de fuentes y descarga
  src/parse.rs        → formatos hosts, dominios, comodín y Adblock
  src/clean.rs        → normalizar, unir, colapsar, protegidos, alarmas
  src/publish.rs      → binarios, diferencias, manifiesto, informe
  lists.toml          → fuentes
  protected.txt       → dominios que nunca se bloquean
  tests/fixtures/     → fuentes de ejemplo para las pruebas
```

## Pruebas

- **Unitarias**: cada formato de entrada, normalización, colapso de subdominios, protegidos, diferencias.
- **Verificador**: manifiesto alterado, firma de otra clave, versión antigua, fichero que no cuadra con su huella, diferencia mal aplicada: todo se rechaza y se conservan las listas anteriores.
- **Propiedades**: aplicar la diferencia de A a B sobre A da exactamente B; el verificador no entra en pánico con bytes aleatorios.
- **Calidad, en cada ejecución diaria**:
  - un conjunto de control de ~300 sitios conocidos (porno, apuestas, citas, DoH y VPN) debe quedar bloqueado entero;
  - el top 1 000 de Tranco, menos los que sean de verdad de estas categorías, no debe tener ningún bloqueo.

## Límites

- **Siempre**: generación reproducible (mismas fuentes, mismo resultado); informe de cada ejecución; atribución de cada fuente.
- **Preguntar antes**: añadir o quitar fuentes; cambiar la lista de protegidos; cambiar el formato del manifiesto (contrato con los agentes).
- **Nunca**: publicar sin firma; bajar de versión; meter en el repositorio principal las listas generadas; usar fuentes cuya licencia no permita redistribuir.

## Criterios de éxito

1. El conjunto de control queda bloqueado al 100 % y el top 1 000 legítimo al 0 %.
2. El verificador rechaza los cinco tipos de material alterado de «Pruebas» y conserva las listas anteriores.
3. Una actualización diaria normal pesa menos de 1 MB.
4. La lista de pornografía cabe en menos de 32 MB de memoria en el móvil.
5. Si una fuente falla o encoge más de un 30 %, la publicación sigue con su última versión buena.
6. Dos ejecuciones con las mismas fuentes producen binarios idénticos.

## Decisiones

- **Licencia de las listas publicadas**: GPL-3.0, con atribución de cada fuente.
- **Dónde publicar**: repositorio público aparte `Mich-proart/nomore-lists`, con GitHub Releases.
- **Clave de firma**: la genera Michell con un script del proyecto y guarda una copia fuera de línea.
- **UT1**: solo su lista de citas, citando la fuente; se confirma la versión de la licencia con el mantenedor antes de publicar. Sus listas de redirectores quedan fuera.
- **Tamaño**: si la lista de pornografía pasa de 32 MB en memoria, se quitan primero los dominios que ya no existen.
