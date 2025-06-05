mod core;
mod plugin;
mod cve;

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::{info, error, debug};
use std::time::Duration;

use crate::core::crawler::{Crawler, DiscoveredUrl, Parameter, Form, CrawlerConfig, CrawlStrategy};
use crate::plugin::{PluginManager, Target, TargetType};
use crate::plugin::scanners::{HttpScanner, XssScanner};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Target to scan (URL, IP, or file path)
    #[arg(short, long)]
    target: String,

    /// Configuration file path
    #[arg(short, long)]
    config: Option<String>,

    /// Verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Maximum crawl depth
    #[arg(short, long, default_value = "3")]
    depth: usize,

    /// Maximum number of pages to crawl
    #[arg(long)]
    max_pages: Option<usize>,

    /// Crawling strategy (BFS or DFS)
    #[arg(long, default_value = "BFS")]
    strategy: String,

    /// Delay between requests in milliseconds
    #[arg(long, default_value = "100")]
    delay: u64,

    /// Number of concurrent threads for crawling (default: 8). Controls how many pages are fetched in parallel.
    #[arg(long = "crawler-threads", default_value = "8", help = "Number of concurrent threads for crawling (default: 8). Controls how many pages are fetched in parallel.")]
    crawler_threads: usize,

    /// Number of concurrent worker tasks for vulnerability scanning (default: 4). Controls how many scan jobs run in parallel.
    #[arg(long = "scanner-workers", default_value = "4", help = "Number of concurrent worker tasks for vulnerability scanning (default: 4). Controls how many scan jobs run in parallel.")]
    scanner_workers: usize,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Respect robots.txt
    #[arg(long)]
    respect_robots: bool,

    /// Comma-separated list of allowed domains
    #[arg(long)]
    allowed_domains: Option<String>,

    /// Comma-separated list of excluded paths
    #[arg(long)]
    excluded_paths: Option<String>,

    /// Comma-separated list of excluded file extensions
    #[arg(long)]
    excluded_extensions: Option<String>,

    /// Comma-separated list of plugins to use
    #[arg(short, long, default_value = "xss_scanner,http_scanner")]
    plugins: String,

    /// Show site tree after crawling
    #[arg(long)]
    show_sitetree: bool,

    /// Crawler-only mode (skip vulnerability scanning)
    #[arg(long)]
    crawler_only: bool,

    /// Export sitemap to file (supports json, xml, txt)
    #[arg(long)]
    export_sitemap: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging based on verbosity
    let cli = Cli::parse();
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    std::env::set_var("RUST_LOG", log_level);
    tracing_subscriber::fmt::init();

    // Create progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );

    // Configure crawler
    let mut config = CrawlerConfig::default();
    config.max_depth = cli.depth;
    config.max_pages = cli.max_pages;
    config.strategy = match cli.strategy.to_uppercase().as_str() {
        "DFS" => CrawlStrategy::DFS,
        _ => CrawlStrategy::BFS,
    };
    config.delay = Duration::from_millis(cli.delay);
    config.concurrency = cli.crawler_threads;
    config.timeout = Duration::from_secs(cli.timeout);
    config.respect_robots = cli.respect_robots;

    // Parse allowed domains
    if let Some(domains) = cli.allowed_domains {
        config.allowed_domains = domains.split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }

    // Parse excluded paths
    if let Some(paths) = cli.excluded_paths {
        config.excluded_paths = paths.split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }

    // Parse excluded extensions
    if let Some(exts) = cli.excluded_extensions {
        config.excluded_extensions = exts.split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }

    // Crawl the target
    pb.set_message("Crawling target...");
    let mut crawler = Crawler::new(&cli.target, config)?;
    let discovered_urls = crawler.crawl().await?;
    
    info!("Discovered {} URLs", discovered_urls.len());

    // Export sitemap if requested
    if let Some(export_path) = cli.export_sitemap {
        pb.set_message("Exporting sitemap...");
        export_sitemap(&discovered_urls, &export_path)?;
        info!("Sitemap exported to {}", export_path);
    }

    // Show site tree if requested
    if cli.show_sitetree {
        info!("Building site tree...");
        let tree = build_site_tree(&discovered_urls);
        info!("Site Tree:");
        info!("==========");
        log_site_tree(&tree, 0);
    }

    // Skip vulnerability scanning if in crawler-only mode
    if !cli.crawler_only {
        // Initialize plugin manager
        let plugin_manager = PluginManager::new();

        // Register plugins
        pb.set_message("Registering plugins...");
        plugin_manager.register_plugin(Box::new(XssScanner::new())).await?;
        plugin_manager.register_plugin(Box::new(HttpScanner::new())).await?;

        // Create target
        let target = Target {
            raw: cli.target.clone(),
            target_type: TargetType::Url,
            metadata: serde_json::json!({
                "discovered_urls": discovered_urls,
            }),
        };

        // Run selected plugins with concurrency control
        pb.set_message("Running scanners...");
        use tokio::sync::Semaphore;
        use std::sync::Arc;
        let semaphore = Arc::new(Semaphore::new(cli.scanner_workers));
        let mut handles = Vec::new();
        let results = plugin_manager.list_plugins().await;
        for plugin in results {
            let permit = semaphore.clone().acquire_owned().await?;
            let target = target.clone();
            let plugin_name = plugin.name().to_string();
            let pb = pb.clone();
            handles.push(tokio::spawn(async move {
                let res = plugin.scan(&target).await;
                drop(permit);
                (plugin_name, res)
            }));
        }
        let results = futures::future::join_all(handles).await;
        pb.finish_with_message("Scan complete!");
        info!("Scan Results:");
        info!("=============");
        for result in results {
            let (plugin_name, result) = match result {
                Ok(pair) => pair,
                Err(e) => {
                    error!("Plugin task join error: {}", e);
                    continue;
                }
            };
            match result {
                Ok(scan_result) => {
                    info!("Plugin: {}", plugin_name);
                    info!("Found {} vulnerabilities:", scan_result.vulnerabilities.len());
                    for vuln in scan_result.vulnerabilities {
                        info!("");
                        info!("  Severity: {:?}", vuln.severity);
                        info!("  Name: {}", vuln.name);
                        info!("  Description: {}", vuln.description);
                        if let Some(cve_id) = vuln.cve_id {
                            info!("  CVE: {}", cve_id);
                        }
                        if let Some(metadata) = vuln.metadata.as_object() {
                            info!("  Details:");
                            for (key, value) in metadata {
                                info!("    {}: {}", key, value);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Plugin {} failed: {}", plugin_name, e);
                }
            }
        }
    } else {
        pb.finish_with_message("Crawl complete!");
    }

    Ok(())
}

/// Export sitemap to file
fn export_sitemap(urls: &[DiscoveredUrl], path: &str) -> Result<()> {
    let extension = path.split('.').last().unwrap_or("json").to_lowercase();
    
    match extension.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(urls)?;
            std::fs::write(path, json)?;
        }
        "xml" => {
            let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<sitemap>\n");
            for url in urls {
                xml.push_str(&format!("  <url>\n"));
                xml.push_str(&format!("    <loc>{}</loc>\n", url.url));
                xml.push_str(&format!("    <method>{}</method>\n", url.method));
                xml.push_str(&format!("    <depth>{}</depth>\n", url.depth));
                if let Some(status) = url.status_code {
                    xml.push_str(&format!("    <status>{}</status>\n", status));
                }
                if let Some(content_type) = &url.content_type {
                    xml.push_str(&format!("    <content-type>{}</content-type>\n", content_type));
                }
                if let Some(content_length) = url.content_length {
                    xml.push_str(&format!("    <content-length>{}</content-length>\n", content_length));
                }
                if !url.parameters.is_empty() {
                    xml.push_str("    <parameters>\n");
                    for param in &url.parameters {
                        xml.push_str(&format!("      <parameter>\n"));
                        xml.push_str(&format!("        <name>{}</name>\n", param.name));
                        xml.push_str(&format!("        <value>{}</value>\n", param.value));
                        xml.push_str(&format!("        <type>{:?}</type>\n", param.param_type));
                        xml.push_str("      </parameter>\n");
                    }
                    xml.push_str("    </parameters>\n");
                }
                if !url.forms.is_empty() {
                    xml.push_str("    <forms>\n");
                    for form in &url.forms {
                        xml.push_str(&format!("      <form>\n"));
                        xml.push_str(&format!("        <action>{}</action>\n", form.action));
                        xml.push_str(&format!("        <method>{}</method>\n", form.method));
                        if let Some(enctype) = &form.enctype {
                            xml.push_str(&format!("        <enctype>{}</enctype>\n", enctype));
                        }
                        if !form.parameters.is_empty() {
                            xml.push_str("        <parameters>\n");
                            for param in &form.parameters {
                                xml.push_str(&format!("          <parameter>\n"));
                                xml.push_str(&format!("            <name>{}</name>\n", param.name));
                                xml.push_str(&format!("            <value>{}</value>\n", param.value));
                                xml.push_str(&format!("            <type>{:?}</type>\n", param.param_type));
                                xml.push_str("          </parameter>\n");
                            }
                            xml.push_str("        </parameters>\n");
                        }
                        xml.push_str("      </form>\n");
                    }
                    xml.push_str("    </forms>\n");
                }
                xml.push_str("  </url>\n");
            }
            xml.push_str("</sitemap>");
            std::fs::write(path, xml)?;
        }
        "txt" => {
            let mut txt = String::new();
            for url in urls {
                txt.push_str(&format!("URL: {}\n", url.url));
                txt.push_str(&format!("Method: {}\n", url.method));
                txt.push_str(&format!("Depth: {}\n", url.depth));
                if let Some(status) = url.status_code {
                    txt.push_str(&format!("Status: {}\n", status));
                }
                if let Some(content_type) = &url.content_type {
                    txt.push_str(&format!("Content-Type: {}\n", content_type));
                }
                if let Some(content_length) = url.content_length {
                    txt.push_str(&format!("Content-Length: {}\n", content_length));
                }
                if !url.parameters.is_empty() {
                    txt.push_str("Parameters:\n");
                    for param in &url.parameters {
                        txt.push_str(&format!("  {}: {} ({:?})\n", param.name, param.value, param.param_type));
                    }
                }
                if !url.forms.is_empty() {
                    txt.push_str("Forms:\n");
                    for form in &url.forms {
                        txt.push_str(&format!("  Action: {}\n", form.action));
                        txt.push_str(&format!("  Method: {}\n", form.method));
                        if let Some(enctype) = &form.enctype {
                            txt.push_str(&format!("  Enctype: {}\n", enctype));
                        }
                        if !form.parameters.is_empty() {
                            txt.push_str("  Parameters:\n");
                            for param in &form.parameters {
                                txt.push_str(&format!("    {}: {} ({:?})\n", param.name, param.value, param.param_type));
                            }
                        }
                    }
                }
                txt.push_str("\n");
            }
            std::fs::write(path, txt)?;
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported export format: {}", extension));
        }
    }

    Ok(())
}

/// Represents a node in the site tree
#[derive(Clone)]
struct SiteNode {
    path: String,
    children: Vec<SiteNode>,
    params: Vec<Parameter>,
    forms: Vec<Form>,
}

/// Build a tree structure from discovered URLs
fn build_site_tree(urls: &[DiscoveredUrl]) -> SiteNode {
    debug!("Building site tree from {} discovered URLs", urls.len());
    
    let mut root = SiteNode {
        path: "/".to_string(),
        children: Vec::new(),
        params: Vec::new(),
        forms: Vec::new(),
    };

    // Sort URLs by path length to ensure parent paths are created before children
    let mut sorted_urls: Vec<_> = urls.iter().collect();
    sorted_urls.sort_by_key(|url| url.url.path().len());

    for url in sorted_urls {
        debug!("Processing URL: {}", url.url);
        let path = url.url.path();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        debug!("Path segments: {:?}", segments);
        
        // Build the path segments
        for (i, _segment) in segments.iter().enumerate() {
            let current_path = format!("/{}", segments[..=i].join("/"));
            let is_last = i == segments.len() - 1;
            debug!("Current path: {}, is_last: {}", current_path, is_last);
            
            // Find or create the node for this path
            let node = find_or_create_node(&mut root, &current_path);
            
            // If this is the last segment, add parameters and forms
            if is_last {
                debug!("Adding parameters: {:?} and forms: {:?}", url.parameters, url.forms);
                node.params = url.parameters.clone();
                node.forms = url.forms.clone();
            }
        }
    }
    root
}

/// Helper function to find or create a node in the tree
fn find_or_create_node<'a>(root: &'a mut SiteNode, path: &str) -> &'a mut SiteNode {
    if path == "/" {
        return root;
    }

    // First check if the node exists
    let exists = root.children.iter().any(|child| child.path == path);
    debug!("Node {} exists: {}", path, exists);
    
    if !exists {
        // If it doesn't exist, create it
        debug!("Creating new node for path: {}", path);
        let new_node = SiteNode {
            path: path.to_string(),
            children: Vec::new(),
            params: Vec::new(),
            forms: Vec::new(),
        };
        root.children.push(new_node);
    }
    
    // Now we can safely get a mutable reference
    root.children.iter_mut().find(|child| child.path == path).unwrap()
}

/// Print the site tree with proper indentation using logging
fn log_site_tree(node: &SiteNode, depth: usize) {
    let indent = "  ".repeat(depth);
    info!("{}├─ {}", indent, node.path);
    
    if !node.params.is_empty() {
        let param_indent = "  ".repeat(depth + 1);
        info!("{}├─ Parameters:", param_indent);
        for param in &node.params {
            info!("{}│  ├─ {}: {}", param_indent, param.name, param.value);
        }
    }
    
    if !node.forms.is_empty() {
        let form_indent = "  ".repeat(depth + 1);
        info!("{}├─ Forms:", form_indent);
        for form in &node.forms {
            info!("{}│  ├─ {} ({})", form_indent, form.action, form.method);
            for param in &form.parameters {
                info!("{}│  │  ├─ {}: {}", form_indent, param.name, param.value);
            }
        }
    }
    
    // Sort children by path for consistent output
    let mut children = node.children.clone();
    children.sort_by_key(|c| c.path.clone());
    
    for child in &children {
        log_site_tree(child, depth + 1);
    }
}
