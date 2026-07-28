use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::Parser;

/// Colored `--help` / error output.
const CLAP_STYLING: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default())
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD));

pub const AFTER_HELP: &str =
    "for Questions/suggestions/Bugs : https://github.com/knassar702/scant3r/issues\nwiki: https://scant3r.knas.me";

/// ScanT3r - module-based web automation & vulnerability scanner
#[derive(Parser, Debug, Clone)]
#[command(name = "scant3r", version, about, after_help = AFTER_HELP, styles = CLAP_STYLING)]
pub struct Cli {
    /// Your target URL
    #[arg(short = 'u', long = "url", default_value = "")]
    pub url: String,

    /// Exit after get this number of errors
    #[arg(short = 'e', long = "exit-after", default_value_t = 500)]
    pub exit_after: usize,

    /// Callback timeout
    #[arg(long = "callback-time", default_value_t = 0.5)]
    pub callback_time: f64,

    /// Change the url parameters into request body ( in non-GET methods )
    #[arg(short = 'c', long = "convert-body")]
    pub convert_body: bool,

    /// The output json file location
    #[arg(short = 'o', long = "output", default_value = "")]
    pub output: String,

    /// add custom header (ex:-H='Cookie: test=1; PHPSESSID=test')
    #[arg(short = 'H', long = "header", default_value = "")]
    pub headers: String,

    /// add cookie to the header (ex: 'cookie1=1; cookie2=2')
    #[arg(short = 'C', long = "cookie", default_value = "")]
    pub cookies: String,

    /// change debug messages mode (1: info 2: debug 3: warning 4: error)
    #[arg(short = 'v', long = "logger-mode", default_value_t = 2)]
    pub log_mode: u8,

    /// number of seconds to hold between each HTTP(S) requests.
    #[arg(short = 's', long = "sleep", default_value_t = 0)]
    pub delay: u64,

    /// Methods Allowed on your target
    #[arg(short = 'M', long = "method", default_value = "GET")]
    pub methods: String,

    /// run scant3r module (ex: -m=example)
    #[arg(short = 'm', long = "module", default_value = "")]
    pub modules: String,

    /// add targets list
    #[arg(short = 'l', long = "list", default_value = "")]
    pub targetlist: String,

    /// JSON Request Body
    #[arg(short = 'j', long = "json")]
    pub json: bool,

    /// Forward all requests to proxy
    #[arg(short = 'p', long = "proxy", default_value = "")]
    pub proxy: String,

    /// Follow redirects
    #[arg(short = 'r', long = "follow-redirects")]
    pub allow_redirects: bool,

    /// use random user agent
    #[arg(short = 'R', long = "random-agents")]
    pub random_agents: bool,

    /// Number of workers (default: 50)
    #[arg(short = 'w', long = "workers", default_value_t = 50)]
    pub threads: usize,

    /// set connection timeout (default: 10)
    #[arg(short = 't', long = "timeout", default_value_t = 10)]
    pub timeout: u64,
}

impl Cli {
    /// Parse argv, translating the legacy multi-char short flag `-ct`
    /// (accepted by the Python argparse version) into `--callback-time`.
    pub fn parse_cli() -> Self {
        let args: Vec<std::ffi::OsString> = std::env::args_os()
            .map(|a| {
                if a == "-ct" {
                    std::ffi::OsString::from("--callback-time")
                } else if let Some(rest) = a.to_str().and_then(|s| s.strip_prefix("-ct=")) {
                    std::ffi::OsString::from(format!("--callback-time={rest}"))
                } else {
                    a
                }
            })
            .collect();
        Self::parse_from(args)
    }
}
