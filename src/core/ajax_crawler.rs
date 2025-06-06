use anyhow::Result;
use fantoccini::{Client, ClientBuilder, Locator};
use std::time::Duration;
use std::collections::HashSet;
use url::Url;
use tracing::debug;
use rand::Rng;
use sha2::{Sha256, Digest};
use crate::core::crawler::{DiscoveredUrl, Parameter, Form, ParameterType};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct AppState {
    url: String,
    dom_hash: String,
    form_state: String,
}

#[derive(Debug, Clone)]
pub struct AjaxCrawler {
    client: Client,
    visited_urls: HashSet<String>,
    visited_states: HashSet<AppState>,
    max_depth: usize,
    max_pages: Option<usize>,
    allowed_domains: Vec<String>,
    excluded_paths: Vec<String>,
    excluded_extensions: Vec<String>,
    delay: Duration,
    base_domain: String,
    state_history: Vec<AppState>,
}

#[derive(Debug, Clone)]
pub struct AjaxCrawlerConfig {
    pub max_depth: usize,
    pub max_pages: Option<usize>,
    pub allowed_domains: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub excluded_extensions: Vec<String>,
    pub delay: Duration,
    pub proxy: Option<String>,
    pub headless: bool,
}

impl AjaxCrawler {
    pub async fn new(url: &str, config: AjaxCrawlerConfig) -> Result<Self> {
        let mut caps = serde_json::map::Map::new();
        let mut chrome_opts = serde_json::map::Map::new();
        
        // Base Chrome options
        let mut args = vec![
            "--disable-gpu".to_string(),
            "--no-sandbox".to_string(),
            "--disable-dev-shm-usage".to_string(),
            "--disable-web-security".to_string(),
            "--ignore-certificate-errors".to_string()
        ];

        // Add headless mode if enabled
        if config.headless {
            args.push("--headless".to_string());
        }

        // Add proxy if configured
        if let Some(proxy) = &config.proxy {
            args.push(format!("--proxy-server={}", proxy));
        }

        chrome_opts.insert("args".to_string(), serde_json::json!(args));
        caps.insert("goog:chromeOptions".to_string(), serde_json::Value::Object(chrome_opts));

        // Build the client with capabilities
        let client = ClientBuilder::native()
            .capabilities(caps)
            .connect("http://localhost:4444")
            .await?;

        // Extract base domain from the start URL
        let base_url = Url::parse(url)?;
        let base_domain = base_url.host_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid URL: no host found"))?
            .to_string();

        Ok(Self {
            client,
            visited_urls: HashSet::new(),
            visited_states: HashSet::new(),
            max_depth: config.max_depth,
            max_pages: config.max_pages,
            allowed_domains: config.allowed_domains,
            excluded_paths: config.excluded_paths,
            excluded_extensions: config.excluded_extensions,
            delay: config.delay,
            base_domain,
            state_history: Vec::new(),
        })
    }

    pub async fn crawl(&mut self, start_url: &str) -> Result<Vec<DiscoveredUrl>> {
        let mut discovered_urls = Vec::new();
        let mut urls_to_visit = vec![(start_url.to_string(), 0)]; // (url, depth)

        while let Some((url, depth)) = urls_to_visit.pop() {
            if depth > self.max_depth {
                continue;
            }

            if self.visited_urls.contains(&url) {
                continue;
            }

            if let Some(max_pages) = self.max_pages {
                if self.visited_urls.len() >= max_pages {
                    break;
                }
            }

            // Check if URL is allowed
            if !self.is_url_allowed(&url) {
                continue;
            }

            // Visit the page
            self.client.goto(&url).await?;
            tokio::time::sleep(self.delay).await;

            // Wait for page to load
            self.client.wait().for_element(Locator::Css("body")).await?;

            // Wait for dynamic content to load
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Get current state
            let current_state = self.get_current_state().await?;
            
            // Only process if we haven't seen this state before
            if !self.visited_states.contains(&current_state) {
                self.visited_states.insert(current_state.clone());
                self.state_history.push(current_state);

                // Handle dynamic elements
                self.handle_dynamic_elements().await?;

                // Click clickable elements
                self.click_elements().await?;

                // Fill and submit forms with random data
                let forms = self.extract_forms().await?;
                for form in &forms {
                    self.fill_form_with_random_data(form).await?;
                }

                // Extract current page information
                let current_url = self.client.current_url().await?;
                let page_source = self.client.source().await?;
                
                // Extract forms and parameters
                let forms = self.extract_forms().await?;
                let parameters = self.extract_parameters().await?;

                // Create DiscoveredUrl
                let discovered_url = DiscoveredUrl {
                    url: current_url.clone(),
                    method: "GET".to_string(),
                    depth,
                    status_code: Some(200),
                    content_type: Some("text/html".to_string()),
                    content_length: Some(page_source.len() as u64),
                    parameters,
                    forms,
                    parent_url: Some(Url::parse(&url)?),
                };

                discovered_urls.push(discovered_url);
                self.visited_urls.insert(url.clone());

                // Find new links
                let new_links = self.extract_links().await?;
                for link in new_links {
                    if !self.visited_urls.contains(&link) && self.is_url_allowed(&link) {
                        urls_to_visit.push((link, depth + 1));
                    }
                }
            }
        }

        Ok(discovered_urls)
    }

    async fn get_current_state(&mut self) -> Result<AppState> {
        let current_url = self.client.current_url().await?;
        let page_source = self.client.source().await?;
        
        // Get form states
        let forms = self.extract_forms().await?;
        let form_state = serde_json::to_string(&forms)?;
        
        // Calculate DOM hash using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(page_source.as_bytes());
        let dom_hash = format!("{:x}", hasher.finalize());
        
        Ok(AppState {
            url: current_url.to_string(),
            dom_hash,
            form_state,
        })
    }

    async fn handle_dynamic_elements(&mut self) -> Result<()> {
        // Handle custom elements
        let custom_elements = self.client.find_all(Locator::Css("[data-role], [role], [data-toggle], [data-target]")).await?;
        for mut element in custom_elements {
            let element_value = serde_json::to_value(element.clone())?;
            let element_value_clone = element_value.clone();
            
            // Check for redirect attributes before interaction
            for attr in ["data-url", "data-href", "data-action", "onclick"] {
                if let Ok(value) = element.attr(attr).await {
                    if let Some(value_str) = value {
                        if let Some(url) = self.normalize_url(&value_str) {
                            if !self.is_url_allowed(&url) {
                                debug!("Skipping custom element interaction - redirects to external domain: {}", url);
                                continue;
                            }
                        }
                    }
                }
            }
            
            if let Ok(displayed) = self.client.execute("return arguments[0].offsetParent !== null", vec![element_value]).await {
                if displayed.as_bool().unwrap_or(false) {
                    // Try different interaction methods
                    if let Err(e) = element.click().await {
                        debug!("Failed to click custom element: {}", e);
                        // Try JavaScript click as fallback
                        if let Err(e) = self.client.execute("arguments[0].click()", vec![element_value_clone]).await {
                            debug!("Failed JavaScript click on custom element: {}", e);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // Handle elements with dynamic event handlers
        let dynamic_elements = self.client.find_all(Locator::Css("[onclick], [onmouseover], [onmouseout], [onfocus], [onblur]")).await?;
        for mut element in dynamic_elements {
            let element_value = serde_json::to_value(element.clone())?;
            let element_value_clone = element_value.clone();
            
            // Check onclick handler for redirects
            if let Ok(onclick) = element.attr("onclick").await {
                if let Some(onclick_str) = onclick {
                    if let Some(url) = self.extract_url_from_onclick(&onclick_str) {
                        if !self.is_url_allowed(&url) {
                            debug!("Skipping dynamic element interaction - redirects to external domain: {}", url);
                            continue;
                        }
                    }
                }
            }
            
            if let Ok(displayed) = self.client.execute("return arguments[0].offsetParent !== null", vec![element_value]).await {
                if displayed.as_bool().unwrap_or(false) {
                    // Trigger multiple events
                    let events = ["click", "mouseover", "focus"];
                    for event in events {
                        if let Err(e) = self.client.execute(
                            format!("arguments[0].dispatchEvent(new Event('{}'))", event).as_str(),
                            vec![element_value_clone.clone()]
                        ).await {
                            debug!("Failed to trigger {} event: {}", event, e);
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        }

        Ok(())
    }

    fn generate_random_input(&self, field_type: &str) -> String {
        let mut rng = rand::thread_rng();
        match field_type {
            "text" | "search" => {
                let len = rng.gen_range(5..20);
                (0..len)
                    .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                    .collect()
            },
            "email" => {
                let username: String = (0..8)
                    .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                    .collect();
                format!("{}@example.com", username)
            },
            "number" => {
                rng.gen_range(1..1000).to_string()
            },
            "tel" => {
                format!("+1{}", rng.gen_range(1000000000i64..9999999999i64))
            },
            "url" => {
                let domain: String = (0..8)
                    .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                    .collect();
                format!("https://{}.com", domain)
            },
            _ => {
                let len = rng.gen_range(5..20);
                (0..len)
                    .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                    .collect()
            }
        }
    }

    async fn fill_form_with_random_data(&mut self, form: &Form) -> Result<()> {
        for param in &form.parameters {
            let mut inputs = self.client
                .find_all(Locator::Css(&format!("input[name='{}']", param.name)))
                .await?;
            
            if let Some(input) = inputs.first_mut() {
                let input_type = input.attr("type").await?.unwrap_or_else(|| "text".to_string());
                let random_value = self.generate_random_input(&input_type);
                
                // Try to set the value using JavaScript
                let script = format!(
                    "document.querySelector('input[name=\"{}\"]').value = '{}'",
                    param.name, random_value
                );
                
                if let Err(e) = self.client.execute(&script, vec![]).await {
                    debug!("Failed to set random value for {}: {}", param.name, e);
                }
            }
        }

        // Try to submit the form
        if let Err(e) = self.client.execute("arguments[0].submit()", vec![serde_json::to_value(form)?]).await {
            debug!("Failed to submit form: {}", e);
        }

        Ok(())
    }

    async fn click_elements(&mut self) -> Result<()> {
        // Click buttons
        let buttons = self.client.find_all(Locator::Css("button")).await?;
        for mut button in buttons {
            let button_value = serde_json::to_value(button.clone())?;
            if let Ok(displayed) = self.client.execute("return arguments[0].offsetParent !== null", vec![button_value]).await {
                if displayed.as_bool().unwrap_or(false) {
                    // Check if button has onclick or form action that redirects
                    if let Ok(onclick) = button.attr("onclick").await {
                        if let Some(onclick_str) = onclick {
                            if let Some(url) = self.extract_url_from_onclick(&onclick_str) {
                                if !self.is_url_allowed(&url) {
                                    debug!("Skipping button click - redirects to external domain: {}", url);
                                    continue;
                                }
                            }
                        }
                    }
                    if let Err(e) = button.click().await {
                        debug!("Failed to click button: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // Click links
        let links = self.client.find_all(Locator::Css("a")).await?;
        for mut link in links {
            let link_value = serde_json::to_value(link.clone())?;
            if let Ok(displayed) = self.client.execute("return arguments[0].offsetParent !== null", vec![link_value]).await {
                if displayed.as_bool().unwrap_or(false) {
                    // Check href before clicking
                    if let Ok(href) = link.attr("href").await {
                        if let Some(href_str) = href {
                            if let Some(url) = self.normalize_url(&href_str) {
                                if !self.is_url_allowed(&url) {
                                    debug!("Skipping link click - external domain: {}", url);
                                    continue;
                                }
                            }
                        }
                    }
                    if let Err(e) = link.click().await {
                        debug!("Failed to click link: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // Click elements with onclick handlers
        let onclick_elements = self.client.find_all(Locator::Css("[onclick]")).await?;
        for mut element in onclick_elements {
            let element_value = serde_json::to_value(element.clone())?;
            if let Ok(displayed) = self.client.execute("return arguments[0].offsetParent !== null", vec![element_value]).await {
                if displayed.as_bool().unwrap_or(false) {
                    // Check onclick handler before clicking
                    if let Ok(onclick) = element.attr("onclick").await {
                        if let Some(onclick_str) = onclick {
                            if let Some(url) = self.extract_url_from_onclick(&onclick_str) {
                                if !self.is_url_allowed(&url) {
                                    debug!("Skipping element click - redirects to external domain: {}", url);
                                    continue;
                                }
                            }
                        }
                    }
                    if let Err(e) = element.click().await {
                        debug!("Failed to click element with onclick: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // Click elements with role="button"
        let role_buttons = self.client.find_all(Locator::Css("[role='button']")).await?;
        for mut button in role_buttons {
            let button_value = serde_json::to_value(button.clone())?;
            if let Ok(displayed) = self.client.execute("return arguments[0].offsetParent !== null", vec![button_value]).await {
                if displayed.as_bool().unwrap_or(false) {
                    // Check for any redirect attributes
                    for attr in ["onclick", "data-url", "data-href", "data-action"] {
                        if let Ok(value) = button.attr(attr).await {
                            if let Some(value_str) = value {
                                if let Some(url) = self.normalize_url(&value_str) {
                                    if !self.is_url_allowed(&url) {
                                        debug!("Skipping role button click - redirects to external domain: {}", url);
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    if let Err(e) = button.click().await {
                        debug!("Failed to click role button: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Ok(())
    }

    async fn extract_links(&mut self) -> Result<Vec<String>> {
        let mut urls = Vec::new();

        // Extract links from <a> tags
        let links = self.client.find_all(Locator::Css("a[href]")).await?;
        for mut link in links {
            if let Ok(href) = link.attr("href").await {
                if let Some(href_str) = href {
                    if let Some(url) = self.normalize_url(&href_str) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract links from onclick handlers
        let onclick_elements = self.client.find_all(Locator::Css("[onclick]")).await?;
        for mut element in onclick_elements {
            if let Ok(onclick) = element.attr("onclick").await {
                if let Some(onclick_str) = onclick {
                    // Extract URLs from onclick handlers
                    if let Some(url) = self.extract_url_from_onclick(&onclick_str) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract links from data attributes
        let data_elements = self.client.find_all(Locator::Css("[data-url], [data-href], [data-src], [data-action]")).await?;
        for mut element in data_elements {
            for attr in ["data-url", "data-href", "data-src", "data-action"] {
                if let Ok(data_url) = element.attr(attr).await {
                    if let Some(url_str) = data_url {
                        if let Some(url) = self.normalize_url(&url_str) {
                            urls.push(url);
                        }
                    }
                }
            }
        }

        // Extract links from src attributes
        let src_elements = self.client.find_all(Locator::Css("[src]")).await?;
        for mut element in src_elements {
            if let Ok(src) = element.attr("src").await {
                if let Some(src_str) = src {
                    if let Some(url) = self.normalize_url(&src_str) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract links from background images
        let style_elements = self.client.find_all(Locator::Css("[style*='background']")).await?;
        for mut element in style_elements {
            if let Ok(style) = element.attr("style").await {
                if let Some(style_str) = style {
                    if let Some(url) = self.extract_url_from_style(&style_str) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract links from meta refresh
        let meta_refresh = self.client.find_all(Locator::Css("meta[http-equiv='refresh']")).await?;
        for mut meta in meta_refresh {
            if let Ok(content) = meta.attr("content").await {
                if let Some(content_str) = content {
                    if let Some(url) = self.extract_url_from_meta_refresh(&content_str) {
                        urls.push(url);
                    }
                }
            }
        }

        // Extract links from JavaScript variables
        let scripts = self.client.find_all(Locator::Css("script")).await?;
        for mut script in scripts {
            if let Ok(script_content) = script.text().await {
                if let Some(urls_from_js) = self.extract_urls_from_js(&script_content) {
                    urls.extend(urls_from_js);
                }
            }
        }

        Ok(urls)
    }

    fn extract_url_from_onclick(&self, onclick: &str) -> Option<String> {
        // Common patterns in onclick handlers
        let patterns = [
            r#"window\.location\.href\s*=\s*['"]([^'"]+)['"]"#,
            r#"window\.open\(['"]([^'"]+)['"]"#,
            r#"location\.href\s*=\s*['"]([^'"]+)['"]"#,
            r#"window\.location\s*=\s*['"]([^'"]+)['"]"#,
        ];

        for pattern in patterns {
            if let Some(captures) = regex::Regex::new(pattern).ok().and_then(|re| re.captures(onclick)) {
                if let Some(url) = captures.get(1) {
                    return self.normalize_url(url.as_str());
                }
            }
        }

        None
    }

    fn extract_url_from_style(&self, style: &str) -> Option<String> {
        // Extract URLs from background-image: url() patterns
        let re = regex::Regex::new(r#"url\(["']?([^"']+)["']?\)"#).ok()?;
        if let Some(captures) = re.captures(style) {
            if let Some(url) = captures.get(1) {
                return self.normalize_url(url.as_str());
            }
        }
        None
    }

    fn extract_url_from_meta_refresh(&self, content: &str) -> Option<String> {
        // Extract URL from meta refresh content (e.g., "0;url=http://example.com")
        let re = regex::Regex::new(r#"url=["']?([^"']+)["']?"#).ok()?;
        if let Some(captures) = re.captures(content) {
            if let Some(url) = captures.get(1) {
                return self.normalize_url(url.as_str());
            }
        }
        None
    }

    fn extract_urls_from_js(&self, script: &str) -> Option<Vec<String>> {
        let mut urls = Vec::new();
        
        // Common patterns for URLs in JavaScript
        let patterns = [
            r#"["'](https?://[^"']+)["']"#,
            r#"url:\s*["']([^"']+)["']"#,
            r#"href:\s*["']([^"']+)["']"#,
            r#"src:\s*["']([^"']+)["']"#,
            r#"location\.href\s*=\s*["']([^"']+)["']"#,
            r#"window\.location\s*=\s*["']([^"']+)["']"#,
            r#"window\.open\(["']([^"']+)["']"#,
        ];

        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for captures in re.captures_iter(script) {
                    if let Some(url_match) = captures.get(1) {
                        if let Some(url) = self.normalize_url(url_match.as_str()) {
                            urls.push(url);
                        }
                    }
                }
            }
        }

        if urls.is_empty() {
            None
        } else {
            Some(urls)
        }
    }

    async fn extract_forms(&mut self) -> Result<Vec<Form>> {
        let forms = self.client.find_all(Locator::Css("form")).await?;
        let mut discovered_forms = Vec::new();

        for mut form in forms {
            let action = form.attr("action").await?.unwrap_or_default();
            let method = form.attr("method").await?.unwrap_or_else(|| "GET".to_string());
            let enctype = form.attr("enctype").await?;

            let inputs = form.find_all(Locator::Css("input")).await?;
            let mut parameters = Vec::new();

            for mut input in inputs {
                let name = input.attr("name").await?;
                let value = input.attr("value").await?;
                
                if let Some(name) = name {
                    parameters.push(Parameter {
                        name,
                        value: value.unwrap_or_default(),
                        param_type: ParameterType::Query,
                    });
                }
            }

            discovered_forms.push(Form {
                action,
                method,
                enctype,
                parameters,
            });
        }

        Ok(discovered_forms)
    }

    async fn extract_parameters(&mut self) -> Result<Vec<Parameter>> {
        let inputs = self.client.find_all(Locator::Css("input")).await?;
        let mut parameters = Vec::new();

        for mut input in inputs {
            let name = input.attr("name").await?;
            let value = input.attr("value").await?;
            
            if let Some(name) = name {
                parameters.push(Parameter {
                    name,
                    value: value.unwrap_or_default(),
                    param_type: ParameterType::Query,
                });
            }
        }

        Ok(parameters)
    }

    fn is_url_allowed(&self, url: &str) -> bool {
        if let Ok(parsed_url) = Url::parse(url) {
            // Check if URL is from the same domain
            if let Some(host) = parsed_url.host_str() {
                if !host.ends_with(&self.base_domain) {
                    return false;
                }
            } else {
                return false;
            }

            // Check excluded paths
            let path = parsed_url.path();
            if self.excluded_paths.iter().any(|p| path.contains(p)) {
                return false;
            }

            // Check excluded extensions
            if let Some(ext) = path.split('.').last() {
                if self.excluded_extensions.iter().any(|e| e == ext) {
                    return false;
                }
            }

            true
        } else {
            false
        }
    }

    fn normalize_url(&self, href: &str) -> Option<String> {
        if href.starts_with("javascript:") || href.starts_with("#") {
            return None;
        }

        // Handle relative URLs
        if href.starts_with("//") {
            if let Ok(url) = Url::parse(&format!("https:{}", href)) {
                if let Some(host) = url.host_str() {
                    if host.ends_with(&self.base_domain) {
                        return Some(url.to_string());
                    }
                }
            }
            return None;
        }

        // Handle absolute URLs
        if let Ok(url) = Url::parse(href) {
            if let Some(host) = url.host_str() {
                if host.ends_with(&self.base_domain) {
                    return Some(url.to_string());
                }
            }
            return None;
        }

        // Handle relative URLs
        if let Ok(absolute_url) = Url::parse(&format!("https://{}{}", self.base_domain, href)) {
            return Some(absolute_url.to_string());
        }

        None
    }
} 