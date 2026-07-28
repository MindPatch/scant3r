use std::io::{IsTerminal, Read};
use std::sync::Arc;

use console::style;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

use scant3r::cli::Cli;
use scant3r::data;
use scant3r::http::HttpSender;
use scant3r::modules::run_modules;
use scant3r::opts::ScanOptions;

fn display_banner() {
    // same color scheme as the classic logo: red, red, yellow, green
    for (i, line) in data::LOGO.lines().enumerate() {
        let styled = style(line);
        match i {
            0 | 1 => println!("{}", styled.red().bold()),
            2 => println!("{}", styled.yellow()),
            3 => println!("{}", styled.green()),
            _ => println!("{line}"),
        }
    }
    println!(
        "{} Fast & flexible {} CLI tool",
        style("[*]").cyan().bold(),
        style("DAST").magenta().bold()
    );
    println!(
        "{} Coded by: {} @knassar702",
        style("[+]").green().bold(),
        style("Khaled Nassar").bold()
    );
    println!(
        "{} Version: {}",
        style("[+]").green().bold(),
        style(env!("CARGO_PKG_VERSION")).yellow()
    );
    println!();
}

/// One-line scan setup summary before the progress bar starts.
fn display_scan_info(opts: &ScanOptions) {
    println!(
        "{} Targets: {} | Modules: {} | Workers: {} | Timeout: {}s",
        style("[>]").blue().bold(),
        style(opts.urls.len()).yellow().bold(),
        style(opts.modules.join(",")).cyan(),
        style(opts.threads).yellow().bold(),
        style(opts.timeout).yellow(),
    );
}

/// Final colored summary line.
fn display_summary(findings: usize, requests: usize, elapsed: std::time::Duration, output: &str) {
    let findings_style = if findings > 0 {
        style(findings).red().bold()
    } else {
        style(findings).green().bold()
    };
    println!(
        "\n{} Done in {} | Requests: {} | Findings: {}",
        style("[✔]").green().bold(),
        style(format!("{:.2?}", elapsed)).yellow(),
        style(requests).cyan(),
        findings_style,
    );
    if !output.is_empty() {
        println!(
            "{} Report saved to {}",
            style("[+]").green().bold(),
            style(output).underlined()
        );
    }
}

fn init_logging(log_mode: u8) {
    let level = match log_mode {
        1 => "info",
        3 => "warn",
        4 => "error",
        _ => "debug",
    };
    let log_file = data::logging_file();
    if log_file.exists() {
        let _ = std::fs::remove_file(&log_file);
    }
    let file = std::fs::File::create(&log_file)
        .unwrap_or_else(|_| std::fs::File::create("/dev/null").unwrap());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(format!("scant3r={level}")))
        .with_writer(file.with_max_level(tracing::Level::TRACE))
        .with_ansi(false)
        .init();
}

fn get_urls(opts: &mut ScanOptions) {
    if !opts.urls.is_empty() {
        return;
    }
    if !opts.url.is_empty() {
        opts.urls.push(opts.url.clone());
        return;
    }
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprintln!(
            "{} PIPE is empty, you need to use {} option",
            style("[-]").red().bold(),
            style("-l").yellow().bold()
        );
        eprintln!("{} Exit ...", style("[!]").cyan().bold());
        std::process::exit(1);
    }
    let mut buf = String::new();
    if stdin.lock().read_to_string(&mut buf).is_ok() {
        for line in buf.lines() {
            let line = line.trim_end();
            if !line.is_empty() {
                opts.urls.push(line.to_string());
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse_cli();
    let mut opts = ScanOptions::from_cli(&cli);
    init_logging(opts.log_mode);

    display_banner();
    get_urls(&mut opts);

    let http = Arc::new(HttpSender::new(
        opts.timeout,
        opts.headers.clone(),
        opts.cookies.clone(),
        opts.random_agents,
        opts.proxy.clone(),
        opts.allow_redirects,
        opts.json,
        opts.delay,
    ));

    let opts = Arc::new(opts);
    if opts.modules.is_empty() {
        eprintln!(
            "{} no module selected, use {} (ex: -m all or -m xss,ssti)",
            style("[!]").yellow().bold(),
            style("-m").yellow().bold()
        );
        std::process::exit(1);
    }
    display_scan_info(&opts);

    let started = std::time::Instant::now();
    let output = run_modules(opts.clone(), http.clone()).await;
    let elapsed = started.elapsed();

    // count real findings: entries with a `found` array contribute its length
    let findings = output
        .iter()
        .map(|r| r["found"].as_array().map(|f| f.len()).unwrap_or(1))
        .sum();
    let requests = http.count.load(std::sync::atomic::Ordering::Relaxed);

    if !opts.output.is_empty() {
        match std::fs::File::create(&opts.output) {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(serde_json::to_string(&output).unwrap().as_bytes()) {
                    eprintln!("{} failed to write output: {e}", style("[-]").red().bold());
                }
            }
            Err(_) => {
                eprintln!(
                    "{} File is not writable, please check your permission, Exit ..",
                    style("[-]").red().bold()
                );
                std::process::exit(1);
            }
        }
    }

    display_summary(findings, requests, elapsed, &opts.output);
}
