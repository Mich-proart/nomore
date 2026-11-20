//! Lectura de los formatos de las fuentes. Devuelve los candidatos tal cual
//! (sin normalizar) y cuántas líneas con contenido se han ignorado.

use std::net::IpAddr;

use serde::Deserialize;

/// Formato de una fuente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// `0.0.0.0 dominio [dominio…]`
    Hosts,
    /// Un dominio por línea.
    Domains,
    /// Un dominio por línea, con `*.` delante opcional.
    Wildcard,
    /// Reglas Adblock: solo `||dominio^`.
    Adblock,
}

/// Resultado de leer una fuente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Candidatos, en el orden de la fuente.
    pub candidates: Vec<String>,
    /// Líneas con contenido que no se han entendido o no aplican.
    pub ignored: usize,
}

/// Lee `text` en el formato indicado.
pub fn parse(text: &str, format: Format) -> Parsed {
    let mut out = Parsed::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let found = match format {
            Format::Hosts => hosts_line(line, &mut out.candidates),
            Format::Domains | Format::Wildcard => plain_line(line, format, &mut out.candidates),
            Format::Adblock => adblock_line(line, &mut out.candidates),
        };
        match found {
            Line::Comment => {}
            Line::Used => {}
            Line::Ignored => out.ignored += 1,
        }
    }
    out
}

enum Line {
    Comment,
    Used,
    Ignored,
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

fn hosts_line(line: &str, out: &mut Vec<String>) -> Line {
    let content = strip_comment(line);
    if content.is_empty() {
        return Line::Comment;
    }
    let mut tokens = content.split_whitespace();
    let Some(address) = tokens.next() else {
        return Line::Comment;
    };
    if address != "0" && address.parse::<IpAddr>().is_err() {
        return Line::Ignored;
    }
    let before = out.len();
    out.extend(tokens.map(str::to_owned));
    if out.len() == before {
        Line::Ignored
    } else {
        Line::Used
    }
}

fn plain_line(line: &str, format: Format, out: &mut Vec<String>) -> Line {
    if line.starts_with('!') {
        return Line::Comment;
    }
    let content = strip_comment(line);
    let Some(token) = content.split_whitespace().next() else {
        return Line::Comment;
    };
    let token = match format {
        Format::Wildcard => token.strip_prefix("*.").unwrap_or(token),
        _ => token,
    };
    if token.contains(['*', '/', ':', '|', '^', '$', '@']) {
        return Line::Ignored;
    }
    out.push(token.to_owned());
    Line::Used
}

fn adblock_line(line: &str, out: &mut Vec<String>) -> Line {
    if line.starts_with('!') || line.starts_with('[') || line.starts_with('#') {
        return Line::Comment;
    }
    let rule = line
        .strip_suffix("$important")
        .unwrap_or(line)
        .strip_prefix("||")
        .and_then(|rest| rest.strip_suffix('^'));
    match rule {
        Some(domain) if !domain.contains(['*', '/', '^', '$', '|']) && !domain.is_empty() => {
            out.push(domain.to_owned());
            Line::Used
        }
        _ => Line::Ignored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        let text = "\
# Título
127.0.0.1 localhost
0.0.0.0 uno.com
0.0.0.0 dos.com tres.com # comentario
::1 ip6-localhost
0 cero.com
uno.com
0.0.0.0
";
        let parsed = parse(text, Format::Hosts);
        assert_eq!(
            parsed.candidates,
            [
                "localhost",
                "uno.com",
                "dos.com",
                "tres.com",
                "ip6-localhost",
                "cero.com"
            ]
        );
        assert_eq!(parsed.ignored, 2, "una línea sin IP y una IP sin dominio");
    }

    #[test]
    fn domains() {
        let text =
            "! cabecera adblock\n# comentario\nuno.com\n  dos.com  # nota\nhttp://tres.com/x\n";
        let parsed = parse(text, Format::Domains);
        assert_eq!(parsed.candidates, ["uno.com", "dos.com"]);
        assert_eq!(parsed.ignored, 1);
    }

    #[test]
    fn wildcard() {
        let parsed = parse("*.uno.com\ndos.com\n*.*.tres.com\n", Format::Wildcard);
        assert_eq!(parsed.candidates, ["uno.com", "dos.com"]);
        assert_eq!(parsed.ignored, 1);
    }

    #[test]
    fn adblock() {
        let text = "\
[Adblock Plus 2.0]
! Title: lista
||uno.com^
||dos.com^$important
@@||permitido.com^
||tres.com/ruta^
##.anuncio
||cuatro.com^$third-party
/regex/
";
        let parsed = parse(text, Format::Adblock);
        assert_eq!(parsed.candidates, ["uno.com", "dos.com"]);
        assert_eq!(parsed.ignored, 4);
    }

    #[test]
    fn windows_line_endings() {
        let parsed = parse("uno.com\r\ndos.com\r\n", Format::Domains);
        assert_eq!(parsed.candidates, ["uno.com", "dos.com"]);
    }
}
