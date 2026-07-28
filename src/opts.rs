use std::collections::HashMap;

use crate::cli::Cli;
use crate::data::ENABLED_MODS;
use crate::utils::{extract_cookie, extract_headers};

/// Fully-resolved scan options, equivalent to the dict produced by
/// the Python `Args.get_args()` + the `exec` snippets in opts.yaml.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub urls: Vec<String>,
    pub url: String,
    pub exit_after: usize,
    pub callback_time: f64,
    pub convert_body: bool,
    pub output: String,
    pub headers: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub log_mode: u8,
    pub delay: u64,
    pub methods: Vec<String>,
    pub modules: Vec<String>,
    pub json: bool,
    pub proxy: Option<String>,
    pub allow_redirects: bool,
    pub random_agents: bool,
    pub threads: usize,
    pub timeout: u64,
}

impl ScanOptions {
    pub fn from_cli(cli: &Cli) -> Self {
        let mut urls: Vec<String> = Vec::new();

        // -l/--list : read targets from a file (opts.yaml `exec` behavior)
        if !cli.targetlist.is_empty() {
            match std::fs::read_to_string(&cli.targetlist) {
                Ok(content) => {
                    for line in content.lines() {
                        let line = line.trim_end();
                        if !line.is_empty() {
                            urls.push(line.to_string());
                        }
                    }
                }
                Err(_) => std::process::exit(1),
            }
        }

        let modules = if cli.modules == "all" {
            ENABLED_MODS.iter().map(|s| s.to_string()).collect()
        } else if cli.modules.is_empty() {
            Vec::new()
        } else {
            cli.modules.split(',').map(|s| s.to_string()).collect()
        };

        let proxy = if cli.proxy.is_empty() {
            None
        } else {
            Some(cli.proxy.clone())
        };

        ScanOptions {
            urls,
            url: cli.url.clone(),
            exit_after: cli.exit_after,
            callback_time: cli.callback_time,
            convert_body: cli.convert_body,
            output: cli.output.clone(),
            headers: extract_headers(&cli.headers),
            cookies: extract_cookie(&cli.cookies),
            log_mode: cli.log_mode,
            delay: cli.delay,
            methods: cli.methods.split(',').map(|s| s.to_string()).collect(),
            modules,
            json: cli.json,
            proxy,
            allow_redirects: cli.allow_redirects,
            random_agents: cli.random_agents,
            threads: cli.threads,
            timeout: cli.timeout,
        }
    }
}
