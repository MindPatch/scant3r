mod core;
mod plugin;
mod cve;

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::{info, error, debug};
use std::time::Duration;
use std::collections::HashMap;
use reqwest::header::HeaderMap;

use crate::core::crawler::{Crawler, DiscoveredUrl, Parameter, Form, CrawlerConfig, CrawlStrategy};
use crate::plugin::{PluginManager, Target, TargetType};
use crate::plugin::scanners::{HttpScanner, XssScanner};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Target URL to scan
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

    /// HTTP proxy to use (e.g., http://127.0.0.1:8080)
    #[arg(long)]
    proxy: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let cli = Cli::parse();

    // Create crawler configuration
    let crawler_config = crate::core::crawler::CrawlerConfig {
        max_depth: cli.depth,
        max_pages: cli.max_pages,
        strategy: match cli.strategy.to_uppercase().as_str() {
            "DFS" => CrawlStrategy::DFS,
            _ => CrawlStrategy::BFS,
        },
        delay: Duration::from_millis(cli.delay),
        concurrency: cli.crawler_threads,
        timeout: Duration::from_secs(cli.timeout),
        respect_robots: cli.respect_robots,
        allowed_domains: cli.allowed_domains.map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
        excluded_paths: cli.excluded_paths.map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
        excluded_extensions: cli.excluded_extensions.map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
        proxy: cli.proxy.clone(),
        custom_headers: Some(HeaderMap::new()),
        max_retries: 3,
        user_agent: "scant3r/0.1.0".to_string(),
    };

    // Create crawler
    let mut crawler = Crawler::new(&cli.target, crawler_config)?;

    // Create plugin manager
    let mut manager = PluginManager::new();

    // Register plugins with proxy configuration
    manager.register_plugin(Box::new(HttpScanner::new().with_proxy(cli.proxy.clone()))).await?;
    manager.register_plugin(Box::new(XssScanner::new().with_proxy(cli.proxy.clone()))).await?;

    // Run crawler
    let discovered_urls = crawler.crawl().await?;

    // Export sitemap if requested
    if let Some(path) = &cli.export_sitemap {
        export_sitemap(&discovered_urls, path)?;
    }

    // Show site tree if requested
    if cli.show_sitetree {
        let tree = build_site_tree(&discovered_urls);
        log_site_tree(&tree, 0);
    }

    // Skip vulnerability scanning if crawler_only is set
    if !cli.crawler_only {
        // Create target with discovered URLs
        let target = Target {
            raw: cli.target,
            target_type: TargetType::Url,
            metadata: serde_json::json!({
                "discovered_urls": discovered_urls,
            }),
        };

        // Run plugins
        let results = manager.run_scan(&target).await?;

        // Print results
        for result in results {
            println!("Plugin: {}", result.plugin_name);
            println!("Success: {}", result.success);
            println!("Vulnerabilities:");
            for vuln in result.vulnerabilities {
                println!("  - {} (Severity: {:?})", vuln.name, vuln.severity);
                println!("    Description: {}", vuln.description);
                if let Some(cve) = vuln.cve_id {
                    println!("    CVE: {}", cve);
                }
                println!("    Metadata: {}", serde_json::to_string_pretty(&vuln.metadata)?);
            }
            println!();
        }
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
