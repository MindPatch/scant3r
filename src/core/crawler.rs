use std::collections::{HashSet, VecDeque, HashMap};
use url::{Url, Position};
use reqwest::{Client, header::HeaderMap};
use anyhow::Result;
use tracing::{trace, warn, info, debug};
use tracing::instrument;
use std::sync::Arc;
use tokio::sync::{Semaphore, Mutex};
use serde::{Serialize, Deserialize};
use futures::future::join_all;
use std::time::Duration;
use scraper::{Html, Selector};
use robotstxt;
use robotstxt::DefaultMatcher;

/// Crawling strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlStrategy {
    BFS,  // Breadth-First Search
    DFS,  // Depth-First Search
}

/// Crawler configuration
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    pub max_depth: usize,
    pub concurrency: usize,
    pub delay: Duration,
    pub respect_robots: bool,
    pub strategy: CrawlStrategy,
    pub max_retries: usize,
    pub timeout: Duration,
    pub custom_headers: Option<HeaderMap>,
    pub allowed_domains: HashSet<String>,
    pub excluded_paths: HashSet<String>,
    pub excluded_extensions: HashSet<String>,
    pub max_pages: Option<usize>,
    pub user_agent: String,
    pub proxy: Option<String>,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            concurrency: 8,
            delay: Duration::from_millis(100),
            respect_robots: true,
            strategy: CrawlStrategy::BFS,
            max_retries: 3,
            timeout: Duration::from_secs(30),
            custom_headers: None,
            allowed_domains: HashSet::new(),
            excluded_paths: HashSet::new(),
            excluded_extensions: HashSet::new(),
            max_pages: None,
            user_agent: "scant3r".to_string(),
            proxy: None,
        }
    }
}

/// Represents a discovered URL with its parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredUrl {
    pub url: Url,
    pub method: String,
    pub parameters: Vec<Parameter>,
    pub forms: Vec<Form>,
    pub depth: usize,
    pub parent_url: Option<Url>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub value: String,
    pub param_type: ParameterType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterType {
    Query,
    Post,
    Path,
    Header,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub parameters: Vec<Parameter>,
    pub enctype: Option<String>,
}

/// Crawler for discovering URLs and parameters
pub struct Crawler {
    target: String,
    config: CrawlerConfig,
    client: Client,
    visited_urls: HashSet<String>,
    discovered_urls: Vec<DiscoveredUrl>,
    base_url: Url,
    queue: VecDeque<(Url, usize, Option<Url>)>,
    robots_txt_cache: Arc<Mutex<HashMap<String, String>>>,
}

impl Clone for Crawler {
    fn clone(&self) -> Self {
        Self {
            target: self.target.clone(),
            config: self.config.clone(),
            client: self.client.clone(),
            visited_urls: self.visited_urls.clone(),
            discovered_urls: self.discovered_urls.clone(),
            base_url: self.base_url.clone(),
            queue: self.queue.clone(),
            robots_txt_cache: self.robots_txt_cache.clone(),
        }
    }
}

impl Crawler {
    pub fn new(target: &str, config: CrawlerConfig) -> Result<Self> {
        let client = if let Some(proxy_url) = &config.proxy {
            Client::builder()
                .proxy(reqwest::Proxy::http(proxy_url).unwrap_or_else(|_| {
                    tracing::warn!("Failed to set HTTP proxy, falling back to direct connection");
                    reqwest::Proxy::all("").unwrap_or_else(|_| {
                        tracing::warn!("Failed to create direct proxy, using default client");
                        reqwest::Proxy::custom(|_| None::<String>)
                    })
                }))
                .build()
                .unwrap_or_else(|_| {
                    tracing::warn!("Failed to build client with proxy, falling back to default client");
                    Client::new()
                })
        } else {
            Client::new()
        };

        let base_url = Url::parse(target)?;
        let domain = base_url.host_str().unwrap_or("").to_string();
        
        // Add base domain to allowed domains if empty
        let mut config = config;
        if config.allowed_domains.is_empty() {
            config.allowed_domains.insert(domain);
        }

        Ok(Self {
            target: target.to_string(),
            config,
            client,
            visited_urls: HashSet::new(),
            discovered_urls: Vec::new(),
            base_url,
            queue: VecDeque::new(),
            robots_txt_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Main crawl entry point
    pub async fn crawl(&mut self) -> Result<Vec<DiscoveredUrl>> {
        let discovered_urls = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let visited = Arc::new(Mutex::new(HashSet::new()));
        let page_count = Arc::new(Mutex::new(0));
        let self_arc = Arc::new(self.clone());
        
        // Initialize queue with base URL
        let base_url = self.base_url.clone();
        debug!("Starting crawl from base URL: {}", base_url);
        queue.lock().await.push_back((base_url.clone(), 0, None));
        
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut handles = Vec::new();

        info!("Starting crawl from {} with strategy {:?}", self.base_url, self.config.strategy);

        // Process URLs until queue is empty and all tasks are complete
        loop {
            // Check if we have any URLs to process
            let next_url = {
                let mut q = queue.lock().await;
                match self.config.strategy {
                    CrawlStrategy::BFS => q.pop_front(),
                    CrawlStrategy::DFS => q.pop_back(),
                }
            };

            // If no more URLs and no active tasks, we're done
            if next_url.is_none() && handles.is_empty() {
                break;
            }

            // If we have a URL to process
            if let Some((url, depth, parent_url)) = next_url {
                // Check if we've reached the maximum number of pages
                if let Some(max_pages) = self.config.max_pages {
                    let count = *page_count.lock().await;
                    if count >= max_pages {
                        debug!("Reached maximum page limit of {}", max_pages);
                        break;
                    }
                }

                if depth > self.config.max_depth {
                    debug!("Skipping {} - max depth reached", url);
                    continue;
                }

                let url_str = Self::normalize_url(&url);
                if visited.lock().await.contains(&url_str) {
                    debug!("Skipping {} - already visited", url);
                    continue;
                }

                // Check if URL should be crawled
                if !Self::should_crawl(
                    &self.config.allowed_domains,
                    &self.config.excluded_paths,
                    &self.config.excluded_extensions,
                    &url
                ) {
                    debug!("Skipping {} - not allowed by rules", url);
                    continue;
                }

                visited.lock().await.insert(url_str.clone());
                debug!("Processing URL: {} (depth: {})", url, depth);

                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let client = self.client.clone();
                let config = self.config.clone();
                let url_clone = url.clone();
                let discovered_urls = discovered_urls.clone();
                let queue = queue.clone();
                let visited = visited.clone();
                let page_count = page_count.clone();
                let self_arc = self_arc.clone();

                let handle = tokio::spawn(async move {
                    // Respect delay between requests
                    tokio::time::sleep(config.delay).await;

                    trace!("Crawling: {}", url_clone);
                    if config.respect_robots && !self_arc.allowed_by_robots(&url_clone).await {
                        trace!("Blocked by robots.txt: {}", url_clone);
                        drop(permit);
                        return;
                    }

                    let mut req = client.get(url_clone.as_str());
                    if let Some(headers) = &config.custom_headers {
                        req = req.headers(headers.clone());
                    }

                    let resp = Self::fetch_with_retries(req, config.max_retries).await;
                    match resp {
                        Ok(response) => {
                            let status = response.status();
                            let headers = response.headers().clone();
                            let content_type = headers
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());
                            let content_length = headers
                                .get("content-length")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|s| s.parse().ok());

                            let body = match response.text().await {
                                Ok(b) => b,
                                Err(_) => { drop(permit); return; },
                            };

                            trace!("HTTP Response: status={:?}, headers={:#?}, body=\n{}", status, headers, body);
                            
                            // Extract and process URLs
                            let urls = Self::extract_urls(&body, &url_clone);
                            debug!("Found {} URLs on {}", urls.len(), url_clone);
                            
                            for new_url in urls {
                                let new_url_str = Self::normalize_url(&new_url);
                                if !visited.lock().await.contains(&new_url_str) 
                                    && Self::should_crawl(
                                        &config.allowed_domains,
                                        &config.excluded_paths,
                                        &config.excluded_extensions,
                                        &new_url
                                    ) {
                                    debug!("Adding new URL to queue: {}", new_url);
                                    queue.lock().await.push_back((new_url, depth + 1, Some(url_clone.clone())));
                                } else {
                                    debug!("Skipping URL: {} (visited or not allowed)", new_url);
                                }
                            }

                            // Extract parameters and forms
                            let parameters = Self::extract_parameters(&body, &url_clone);
                            let forms = Self::extract_forms(&body);
                            debug!("Found {} parameters and {} forms on {}", 
                                parameters.len(), forms.len(), url_clone);
                            
                            discovered_urls.lock().await.push(DiscoveredUrl {
                                url: url_clone.clone(),
                                method: "GET".to_string(),
                                parameters,
                                forms,
                                depth,
                                parent_url,
                                status_code: Some(status.as_u16()),
                                content_type,
                                content_length,
                            });

                            // Increment page count
                            *page_count.lock().await += 1;
                        }
                        Err(e) => {
                            warn!("Failed to crawl {}: {}", url_clone, e);
                        }
                    }
                    drop(permit);
                });
                handles.push(handle);
            }

            // Clean up completed tasks
            handles.retain(|handle| !handle.is_finished());
        }

        // Wait for any remaining tasks to complete
        join_all(handles).await;
        
        let result = Arc::try_unwrap(discovered_urls).unwrap().into_inner();
        info!("Crawl complete. Found {} URLs", result.len());
        Ok(result)
    }

    /// Check if a URL should be crawled based on configuration rules
    fn should_crawl(
        allowed_domains: &HashSet<String>,
        excluded_paths: &HashSet<String>,
        excluded_extensions: &HashSet<String>,
        url: &Url
    ) -> bool {
        // Check domain
        if let Some(host) = url.host_str() {
            if !allowed_domains.contains(host) {
                return false;
            }
        }

        // Check excluded paths
        let path = url.path();
        if excluded_paths.iter().any(|p| path.contains(p)) {
            return false;
        }

        // Check excluded extensions
        if let Some(ext) = url.path().split('.').last() {
            if excluded_extensions.contains(ext) {
                return false;
            }
        }

        true
    }

    /// Normalize a URL for deduplication
    fn normalize_url(url: &Url) -> String {
        let mut url = url.clone();
        
        // Remove fragment
        url.set_fragment(None);
        
        // Normalize path
        let path = url.path();
        let normalized_path = if path.is_empty() {
            "/".to_string()
        } else if !path.starts_with('/') {
            format!("/{}", path)
        } else {
            path.to_string()
        };
        url.set_path(&normalized_path);
        
        // Sort query parameters
        let mut pairs: Vec<_> = url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        pairs.sort();
        let query = if !pairs.is_empty() {
            let qs: Vec<String> = pairs.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            Some(qs.join("&"))
        } else {
            None
        };
        url.set_query(query.as_deref());
        
        // Convert to string
        let mut s = url[..Position::AfterPath].to_string();
        if let Some(q) = url.query() {
            s.push('?');
            s.push_str(q);
        }
        
        debug!("Normalized URL: {} -> {}", url, s);
        s
    }

    /// Extract URLs from HTML using proper HTML parsing
    fn extract_urls(html: &str, base_url: &Url) -> Vec<Url> {
        let mut urls = Vec::new();
        let document = Html::parse_document(html);

        // Helper function to safely join URLs
        let join_url = |href: &str| -> Option<Url> {
            // Skip empty, javascript:, mailto:, tel:, etc.
            if href.is_empty() || href.starts_with("javascript:") || href.starts_with("mailto:") || href.starts_with("tel:") {
                return None;
            }
            
            // Handle absolute URLs
            if href.starts_with("http://") || href.starts_with("https://") {
                return Url::parse(href).ok();
            }
            
            // Handle relative URLs
            base_url.join(href).ok()
        };

        // Extract links
        if let Ok(selector) = Selector::parse("a[href]") {
            for element in document.select(&selector) {
                if let Some(href) = element.value().attr("href") {
                    if let Some(url) = join_url(href) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract images
        if let Ok(selector) = Selector::parse("img[src]") {
            for element in document.select(&selector) {
                if let Some(src) = element.value().attr("src") {
                    if let Some(url) = join_url(src) {
                        urls.push(url);
                    }
                }
                // Also check data-src
                if let Some(data_src) = element.value().attr("data-src") {
                    if let Some(url) = join_url(data_src) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract scripts
        if let Ok(selector) = Selector::parse("script[src]") {
            for element in document.select(&selector) {
                if let Some(src) = element.value().attr("src") {
                    if let Some(url) = join_url(src) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract stylesheets
        if let Ok(selector) = Selector::parse("link[href]") {
            for element in document.select(&selector) {
                if let Some(href) = element.value().attr("href") {
                    if let Some(url) = join_url(href) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract iframes
        if let Ok(selector) = Selector::parse("iframe[src]") {
            for element in document.select(&selector) {
                if let Some(src) = element.value().attr("src") {
                    if let Some(url) = join_url(src) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract forms
        if let Ok(selector) = Selector::parse("form[action]") {
            for element in document.select(&selector) {
                if let Some(action) = element.value().attr("action") {
                    if let Some(url) = join_url(action) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract video sources
        if let Ok(selector) = Selector::parse("video source[src]") {
            for element in document.select(&selector) {
                if let Some(src) = element.value().attr("src") {
                    if let Some(url) = join_url(src) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract audio sources
        if let Ok(selector) = Selector::parse("audio source[src]") {
            for element in document.select(&selector) {
                if let Some(src) = element.value().attr("src") {
                    if let Some(url) = join_url(src) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract meta refresh URLs
        if let Ok(selector) = Selector::parse("meta[http-equiv='refresh']") {
            for element in document.select(&selector) {
                if let Some(content) = element.value().attr("content") {
                    if let Some(url_str) = content.split(';').nth(1) {
                        if let Some(url) = join_url(url_str.trim()) {
                            urls.push(url);
                        }
                    }
                }
            }
        }

        // Extract Open Graph URLs
        if let Ok(selector) = Selector::parse("meta[property^='og:']") {
            for element in document.select(&selector) {
                if let Some(content) = element.value().attr("content") {
                    if let Some(url) = join_url(content) {
                        urls.push(url);
                    }
                }
            }
        }

        // Deduplicate URLs
        urls.sort();
        urls.dedup();
        
        debug!("Extracted {} unique URLs from HTML", urls.len());
        for url in &urls {
            debug!("Found URL: {}", url);
        }
        urls
    }

    /// Extract parameters from URL and HTML
    fn extract_parameters(_html: &str, url: &Url) -> Vec<Parameter> {
        let mut parameters = Vec::new();
        
        // Query parameters
        for (name, value) in url.query_pairs() {
            parameters.push(Parameter {
                name: name.to_string(),
                value: value.to_string(),
                param_type: ParameterType::Query,
            });
        }

        // Path parameters (basic)
        if let Some(segments) = url.path_segments() {
            for segment in segments {
                if segment.contains('=') {
                    if let Some((name, value)) = segment.split_once('=') {
                        parameters.push(Parameter {
                            name: name.to_string(),
                            value: value.to_string(),
                            param_type: ParameterType::Path,
                        });
                    }
                }
            }
        }

        // Fragment parameters
        if let Some(fragment) = url.fragment() {
            for pair in fragment.split('&') {
                if let Some((name, value)) = pair.split_once('=') {
                    parameters.push(Parameter {
                        name: name.to_string(),
                        value: value.to_string(),
                        param_type: ParameterType::Query,
                    });
                }
            }
        }

        parameters
    }

    /// Extract forms and their parameters using proper HTML parsing
    fn extract_forms(html: &str) -> Vec<Form> {
        let mut forms = Vec::new();
        let document = Html::parse_document(html);

        if let Ok(selector) = Selector::parse("form") {
            for form_element in document.select(&selector) {
                let action = form_element.value().attr("action").unwrap_or("").to_string();
                let method = form_element.value().attr("method").unwrap_or("GET").to_uppercase();
                let enctype = form_element.value().attr("enctype").map(|s| s.to_string());

                let mut parameters = Vec::new();

                // Extract input fields
                if let Ok(input_selector) = Selector::parse("input") {
                    for input in form_element.select(&input_selector) {
                        if let Some(name) = input.value().attr("name") {
                            let value = input.value().attr("value").unwrap_or("");
                            let param_type = if method == "POST" { ParameterType::Post } else { ParameterType::Query };
                            
                            parameters.push(Parameter {
                                name: name.to_string(),
                                value: value.to_string(),
                                param_type,
                            });
                        }
                    }
                }

                // Extract textareas
                if let Ok(textarea_selector) = Selector::parse("textarea") {
                    for textarea in form_element.select(&textarea_selector) {
                        if let Some(name) = textarea.value().attr("name") {
                            let value = textarea.text().collect::<Vec<_>>().join("");
                            let param_type = if method == "POST" { ParameterType::Post } else { ParameterType::Query };
                            
                            parameters.push(Parameter {
                                name: name.to_string(),
                                value,
                                param_type,
                            });
                        }
                    }
                }

                // Extract select options
                if let Ok(select_selector) = Selector::parse("select") {
                    for select in form_element.select(&select_selector) {
                        if let Some(name) = select.value().attr("name") {
                            if let Ok(option_selector) = Selector::parse("option[selected]") {
                                for option in select.select(&option_selector) {
                                    let value = option.value().attr("value").unwrap_or("");
                                    let param_type = if method == "POST" { ParameterType::Post } else { ParameterType::Query };
                                    
                                    parameters.push(Parameter {
                                        name: name.to_string(),
                                        value: value.to_string(),
                                        param_type,
                                    });
                                }
                            }
                        }
                    }
                }

                forms.push(Form {
                    action,
                    method,
                    parameters,
                    enctype,
                });
            }
        }

        forms
    }

    /// Fetch with retries and exponential backoff
    async fn fetch_with_retries(req: reqwest::RequestBuilder, retries: usize) -> Result<reqwest::Response> {
        let mut attempt = 0;
        loop {
            match req.try_clone().unwrap().send().await {
                Ok(resp) => return Ok(resp),
                Err(e) if attempt < retries => {
                    let wait = 2u64.pow(attempt as u32);
                    warn!("Request failed (attempt {}): {}. Retrying in {}s...", attempt + 1, e, wait);
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    attempt += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Check if a URL is allowed by robots.txt
    #[instrument(skip(self, url), fields(url = %url))]
    async fn allowed_by_robots(&self, url: &Url) -> bool {
        if !self.config.respect_robots {
            debug!("Robots.txt is not respected, allowing {}", url);
            return true;
        }

        let origin = match url.origin().ascii_serialization() {
            origin if origin.is_empty() => {
                warn!("Could not get origin for URL: {}", url);
                return true; // Allow by default if we can't get origin
            },
            origin => origin,
        };

        // First, check cache (async lock)
        {
            let cache = self.robots_txt_cache.lock().await;
            if let Some(content) = cache.get(&origin) {
                debug!("Using cached robots.txt for {}", origin);
                let mut matcher = DefaultMatcher::default();
                let user_agent = &self.config.user_agent;
                let url_string = url.as_str();
                let allowed = matcher.one_agent_allowed_by_robots(content, user_agent, url_string);
                if !allowed {
                    debug!("URL {} disallowed by robots.txt for user agent {}", url, user_agent);
                }
                return allowed;
            }
        }

        // Not in cache, fetch robots.txt
        let robots_url = match Url::parse(&origin) {
            Ok(mut u) => {
                 u.set_path("/robots.txt");
                 u
            }
            Err(e) => {
                warn!("Failed to construct robots.txt URL for {}: {}", origin, e);
                return true; // Allow by default if we can't construct the URL
            }
        };

        debug!("Fetching robots.txt from {}", robots_url);
        let robots_content = match self.client.get(robots_url.as_str()).send().await {
            Ok(resp) => match resp.text().await {
                Ok(text) => text,
                Err(e) => {
                    warn!("Failed to read robots.txt content from {}: {}", robots_url, e);
                    return true; // Allow by default if we can't read the content
                }
            },
            Err(e) => {
                debug!("Failed to fetch robots.txt from {}: {}", robots_url, e);
                return true; // Allow by default if we can't fetch robots.txt
            }
        };

        // Insert into cache
        {
            let mut cache = self.robots_txt_cache.lock().await;
            cache.insert(origin.clone(), robots_content.clone());
        }

        // Now check permission
        let mut matcher = DefaultMatcher::default();
        let user_agent = &self.config.user_agent;
        let url_string = url.as_str();
        let allowed = matcher.one_agent_allowed_by_robots(&robots_content, user_agent, url_string);
        if !allowed {
            debug!("URL {} disallowed by robots.txt for user agent {}", url, user_agent);
        }
        allowed
    }
} 