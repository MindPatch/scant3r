pub mod firebase;
pub mod req_callback;
pub mod ssti;
pub mod xss;
pub mod xss_payloads;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};

use crate::http::{Body, HttpResponse, HttpSender};
use crate::opts::ScanOptions;
use crate::utils::post_data;

pub type ModuleResult = Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Scanner,
    Recon,
}

/// Shared state handed to every module run.
pub struct ScanContext {
    pub http: Arc<HttpSender>,
    pub opts: Arc<ScanOptions>,
    pub progress: ProgressBar,
}

impl ScanContext {
    /// Print a finding without breaking the progress bar.
    pub fn println(&self, msg: impl AsRef<str>) {
        if self.progress.is_hidden() {
            println!("{}", msg.as_ref());
        } else {
            self.progress.println(msg);
        }
    }
}

#[async_trait]
pub trait Module: Send + Sync {
    fn tag(&self) -> Tag;
    /// Scan one url (scanner modules) or one host root (recon modules).
    /// Returns an empty JSON object when nothing was found.
    async fn run(&self, ctx: &ScanContext, url: &str) -> ModuleResult;
}

type ModuleFactory = fn() -> Arc<dyn Module>;

/// Static module registry (replaces the Python importlib loader).
pub fn registry() -> Vec<(&'static str, ModuleFactory)> {
    vec![
        ("xss", || Arc::new(xss::Xss)),
        ("ssti", || Arc::new(ssti::Ssti)),
        ("firebase", || Arc::new(firebase::Firebase)),
        ("req_callback", || Arc::new(req_callback::ReqCallback)),
    ]
}

fn create_module(name: &str) -> Option<Arc<dyn Module>> {
    registry()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| f())
}

/// The base-class request helper from the Python `modules/scan.py`.
pub async fn send_request(
    ctx: &ScanContext,
    method: &str,
    url: &str,
    second_url: Option<&str>,
) -> Result<HttpResponse, reqwest::Error> {
    let convert_body = ctx.opts.convert_body;
    if method.eq_ignore_ascii_case("GET") {
        return ctx.http.send_simple(url, method, convert_body).await;
    }
    let (url, body) = if convert_body {
        let params = post_data(url);
        let base = url.split('?').next().unwrap_or(url).to_string();
        (base, Body::Pairs(params))
    } else {
        (url.to_string(), Body::None)
    };
    let target = match second_url {
        Some(u) if convert_body => u.split('?').next().unwrap_or(u).to_string(),
        _ => url,
    };
    ctx.http
        .send(&target, method, body, HashMap::new(), convert_body, None, None)
        .await
}

/// Strip fragments from the url (Python `Scan.transform_url`).
pub fn transform_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let mut out = format!("{}://{}{}", u.scheme(), u.host_str().unwrap_or(""), u.path());
            if let Some(q) = u.query() {
                out += &format!("?{q}");
            }
            out
        }
        Err(_) => url.to_string(),
    }
}

/// Run all enabled modules over all urls. Mirrors `ModuleLoader.run`.
pub async fn run_modules(opts: Arc<ScanOptions>, http: Arc<HttpSender>) -> Vec<serde_json::Value> {
    let mut modules: Vec<Arc<dyn Module>> = Vec::new();
    for name in &opts.modules {
        match create_module(name) {
            Some(m) => modules.push(m),
            None => tracing::error!("module not found: {name}"),
        }
    }
    if modules.is_empty() {
        return Vec::new();
    }

    // unique host roots, in first-seen order (urljoin(url, "/"))
    let mut hosts: Vec<String> = Vec::new();
    for url in &opts.urls {
        if let Ok(u) = url::Url::parse(url) {
            let root = format!("{}://{}/", u.scheme(), u.host_str().unwrap_or(""));
            if !hosts.contains(&root) {
                hosts.push(root);
            }
        }
    }

    let n_scanner = modules.iter().filter(|m| m.tag() == Tag::Scanner).count();
    let n_recon = modules.len() - n_scanner;
    let total = (opts.urls.len() * n_scanner + hosts.len() * n_recon) as u64;

    let progress = ProgressBar::new(total);
    progress.set_style(
        ProgressStyle::with_template(
            " Scanning {pos}/{len} | {percent:>3}% [{wide_bar:.green}] {spinner}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "),
    );
    progress.enable_steady_tick(std::time::Duration::from_millis(100));

    let ctx = Arc::new(ScanContext {
        http,
        opts: opts.clone(),
        progress: progress.clone(),
    });

    let mut tasks: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = ModuleResult> + Send>>,
    > = Vec::new();
    for url in &opts.urls {
        for module in modules.iter().filter(|m| m.tag() == Tag::Scanner) {
            let ctx = ctx.clone();
            let url = url.clone();
            let module = module.clone();
            tasks.push(Box::pin(async move { module.run(&ctx, &url).await }));
        }
    }
    for host in &hosts {
        for module in modules.iter().filter(|m| m.tag() == Tag::Recon) {
            let ctx = ctx.clone();
            let host = host.clone();
            let module = module.clone();
            tasks.push(Box::pin(async move { module.run(&ctx, &host).await }));
        }
    }

    let exit_after = opts.exit_after;
    let mut errs = 0usize;
    let mut reports: Vec<serde_json::Value> = Vec::new();
    let mut stream = stream::iter(tasks).buffer_unordered(opts.threads.max(1));
    while let Some(result) = stream.next().await {
        progress.inc(1);
        match result {
            Ok(report) => {
                let non_empty = report
                    .as_object()
                    .map(|o| !o.is_empty())
                    .unwrap_or(false);
                if non_empty {
                    reports.push(report);
                }
            }
            Err(e) => {
                errs += 1;
                tracing::error!("module task failed: {e}");
                if errs >= exit_after {
                    tracing::error!("exit because of errors counter: {errs}");
                    progress.abandon_with_message(format!("aborted after {errs} errors"));
                    return reports;
                }
            }
        }
    }

    progress.finish_and_clear();
    reports
}
