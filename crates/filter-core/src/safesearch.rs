//! SafeSearch forzado y YouTube restringido.
//!
//! Cada buscador publica un nombre "seguro"; si el DNS responde con las
//! direcciones de ese nombre, el buscador aplica el filtro sin que el usuario
//! pueda quitarlo.

/// Nombre seguro de Google.
const GOOGLE: &str = "forcesafesearch.google.com";
/// Nombre seguro de Bing.
const BING: &str = "strict.bing.com";
/// Nombre seguro de DuckDuckGo.
const DUCKDUCKGO: &str = "safe.duckduckgo.com";
/// YouTube en modo restringido estricto.
const YOUTUBE: &str = "restrict.youtube.com";

/// Terminaciones de `www.google.*`, según <https://www.google.com/supported_domains>
/// (consultado el 16-11-2026). Ordenadas, para búsqueda binaria.
const GOOGLE_SUFFIXES: &[&str] = &[
    "ad", "ae", "al", "am", "as", "at", "az", "ba", "be", "bf", "bg", "bi", "bj", "bs", "bt", "by",
    "ca", "cat", "cd", "cf", "cg", "ch", "ci", "cl", "cm", "cn", "co.ao", "co.bw", "co.ck",
    "co.cr", "co.id", "co.il", "co.in", "co.jp", "co.ke", "co.kr", "co.ls", "co.ma", "co.mz",
    "co.nz", "co.th", "co.tz", "co.ug", "co.uk", "co.uz", "co.ve", "co.vi", "co.za", "co.zm",
    "co.zw", "com", "com.af", "com.ag", "com.ar", "com.au", "com.bd", "com.bh", "com.bn", "com.bo",
    "com.br", "com.bz", "com.co", "com.cu", "com.cy", "com.do", "com.ec", "com.eg", "com.et",
    "com.fj", "com.gh", "com.gi", "com.gt", "com.hk", "com.jm", "com.kh", "com.kw", "com.lb",
    "com.ly", "com.mm", "com.mt", "com.mx", "com.my", "com.na", "com.ng", "com.ni", "com.np",
    "com.om", "com.pa", "com.pe", "com.pg", "com.ph", "com.pk", "com.pr", "com.py", "com.qa",
    "com.sa", "com.sb", "com.sg", "com.sl", "com.sv", "com.tj", "com.tr", "com.tw", "com.ua",
    "com.uy", "com.vc", "com.vn", "cv", "cz", "de", "dj", "dk", "dm", "dz", "ee", "es", "fi", "fm",
    "fr", "ga", "ge", "gg", "gl", "gm", "gr", "gy", "hn", "hr", "ht", "hu", "ie", "im", "iq", "is",
    "it", "je", "jo", "kg", "ki", "kz", "la", "li", "lk", "lt", "lu", "lv", "md", "me", "mg", "mk",
    "ml", "mn", "mu", "mv", "mw", "ne", "nl", "no", "nr", "nu", "pl", "pn", "ps", "pt", "ro", "rs",
    "ru", "rw", "sc", "se", "sh", "si", "sk", "sm", "sn", "so", "sr", "st", "td", "tg", "tl", "tm",
    "tn", "to", "tt", "vu", "ws",
];

/// Nombre seguro al que hay que redirigir `name` (ya normalizado), si lo hay.
///
/// La coincidencia es exacta: `maps.google.com` o `mail.google.com` no se tocan.
pub(crate) fn target_for(name: &str) -> Option<&'static str> {
    match name {
        "www.bing.com" => Some(BING),
        "duckduckgo.com" | "www.duckduckgo.com" => Some(DUCKDUCKGO),
        "www.youtube.com"
        | "m.youtube.com"
        | "youtubei.googleapis.com"
        | "youtube.googleapis.com"
        | "www.youtube-nocookie.com" => Some(YOUTUBE),
        _ => {
            let suffix = name.strip_prefix("www.google.")?;
            GOOGLE_SUFFIXES.binary_search(&suffix).ok().map(|_| GOOGLE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_table_is_sorted_and_unique() {
        assert!(GOOGLE_SUFFIXES.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(GOOGLE_SUFFIXES.len(), 187);
    }

    #[test]
    fn google_country_domains_are_redirected() {
        for name in [
            "www.google.com",
            "www.google.es",
            "www.google.co.uk",
            "www.google.com.mx",
            "www.google.co.ve",
            "www.google.cat",
        ] {
            assert_eq!(target_for(name), Some(GOOGLE), "{name}");
        }
    }

    #[test]
    fn other_engines_and_youtube_are_redirected() {
        assert_eq!(target_for("www.bing.com"), Some(BING));
        assert_eq!(target_for("duckduckgo.com"), Some(DUCKDUCKGO));
        assert_eq!(target_for("www.duckduckgo.com"), Some(DUCKDUCKGO));
        assert_eq!(target_for("www.youtube.com"), Some(YOUTUBE));
        assert_eq!(target_for("m.youtube.com"), Some(YOUTUBE));
        assert_eq!(target_for("youtubei.googleapis.com"), Some(YOUTUBE));
        assert_eq!(target_for("www.youtube-nocookie.com"), Some(YOUTUBE));
    }

    #[test]
    fn unrelated_names_are_left_alone() {
        for name in [
            "google.com",
            "maps.google.com",
            "mail.google.com",
            "www.google.invalido",
            "www.google.com.evil.net",
            "www.googlex.com",
            "forcesafesearch.google.com",
            "strict.bing.com",
            "wikipedia.org",
        ] {
            assert_eq!(target_for(name), None, "{name}");
        }
    }
}
