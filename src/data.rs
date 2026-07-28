//! Global constants and embedded wordlists.

macro_rules! wordlist {
    ($name:ident, $file:literal) => {
        pub fn $name() -> Vec<&'static str> {
            include_str!($file)
                .lines()
                .map(str::trim_end)
                .filter(|l| !l.is_empty())
                .collect()
        }
    };
}

wordlist!(agents, "../assets/wordlists/agents.txt");
wordlist!(bxss, "../assets/wordlists/bxss.txt");
wordlist!(js_func, "../assets/wordlists/js_func.txt");
wordlist!(js_value, "../assets/wordlists/js_value.txt");
wordlist!(ssrf_parameters, "../assets/wordlists/ssrf_parameters.txt");
wordlist!(ssti, "../assets/wordlists/ssti.txt");
wordlist!(tld, "../assets/wordlists/tld.txt");
wordlist!(xss_tags, "../assets/wordlists/xss.txt");
wordlist!(xss_attr, "../assets/wordlists/xss_attr.txt");

pub const LOGO: &str = include_str!("../assets/logo.txt");

/// interact.sh public servers
pub const INTERACT_SERVERS: [&str; 6] = [
    "interact.sh",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.me",
];

/// Enabled modules when using `-m all`
pub const ENABLED_MODS: [&str; 4] = ["ssti", "firebase", "req_callback", "xss"];

pub const FIREBASE_URL: &str = "https://%s.firebaseio.com";

pub const LOGGING_FORMAT: &str = "%(name)-12s: %(levelname)-8s %(message)s";

pub fn logging_file() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".scant3r.log")
}

pub const CSP_LIST: &[&str] = &[
    ".doubleclick.net",
    ".googleadservices.com",
    "cse.google.com",
    "accounts.google.com",
    "*.google.com",
    "www.blogger.com",
    "*.blogger.com",
    "translate.yandex.net",
    "api-metrika.yandex.ru",
    "api.vk.comm",
    "*.vk.com",
    "*.yandex.ru",
    "*.yandex.net",
    "app-sjint.marketo.com",
    "app-e.marketo.com",
    "*.marketo.com",
    "detector.alicdn.com",
    "suggest.taobao.com",
    "ount.tbcdn.cn",
    "bebezoo.1688.com",
    "wb.amap.com",
    "a.sm.cn",
    "api.m.sm.cn",
    "*.taobao.com",
    "*.tbcdn.cn",
    "*.1688.com",
    "*.amap.com",
    "*.sm.cn",
    "mkto.uber.com",
    "*.uber.com",
    "ads.yap.yahoo.com",
    "mempf.yahoo.co.jp",
    "suggest-shop.yahooapis.jp",
    "www.aol.com",
    "df-webservices.comet.aol.com",
    "api.cmi.aol.com",
    "ui.comet.aol.com",
    "portal.pf.aol.com",
    "*.yahoo.com",
    "*.yahoo.jp",
    "*.yahooapis.jp",
    "*.aol.com",
    "search.twitter.com",
    "*.twitter.com",
    "twitter.com",
    "ajax.googleapis.com",
    "*.googleapis.com",
    "google.com",
    "*.yandex.com",
];
pub const BLOCK_CONTENT_TYPE: [&str; 10] = [
    "application/json",
    "application/javascript",
    "text/javascript",
    "text/plain",
    "text/css",
    "image/jpeg",
    "image/png",
    "image/bmp",
    "image/gif",
    "application/rss+xml",
];
