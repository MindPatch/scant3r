use crate::plugin::{ScannerPlugin, Target, ScanResult, Vulnerability, Severity};
use async_trait::async_trait;
use std::fmt::Debug;
use anyhow::Result;
use reqwest::Client;
use url::Url;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use regex::Regex;
use std::sync::atomic::{AtomicBool, Ordering};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct XssPayload {
    payload: String,
    context: InjectionContext,
    encoding: PayloadEncoding,
    description: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum InjectionContext {
    HtmlAttribute,
    HtmlTag,
    JavaScript,
    Url,
    Css,
    Unknown,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum PayloadEncoding {
    None,
    HtmlEntity,
    Url,
    DoubleUrl,
    JavaScript,
    Mixed,
}

/// XSS scanner plugin that tests for reflected XSS vulnerabilities
#[derive(Debug)]
pub struct XssScanner {
    client: Client,
    payloads: Vec<XssPayload>,
    delete_all_params: bool,
    custom_input: Option<String>,
    safe_mode: bool,
    waf_detected: AtomicBool,
    context_patterns: HashMap<InjectionContext, Vec<Regex>>,
}

impl XssScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            client: Client::new(),
            payloads: Vec::new(),
            delete_all_params: false,
            custom_input: None,
            safe_mode: true,
            waf_detected: AtomicBool::new(false),
            context_patterns: HashMap::new(),
        };
        
        scanner.init_payloads();
        scanner.init_context_patterns();
        scanner
    }

    fn init_payloads(&mut self) {
        // Basic HTML/script tags
        self.payloads.extend(vec![
            XssPayload {
                payload: "<script>alert(1)</script>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::None,
                description: "Basic script tag injection".to_string(),
            },
            XssPayload {
                payload: "<img src=x onerror=alert(1)>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::None,
                description: "Event handler injection".to_string(),
            },
        ]);

        // Event handlers
        self.payloads.extend(vec![
            XssPayload {
                payload: "<svg/onload=alert(1)>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::None,
                description: "SVG event handler".to_string(),
            },
            XssPayload {
                payload: "<body onload=alert(1)>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::None,
                description: "Body event handler".to_string(),
            },
        ]);

        // Template injection vectors
        self.payloads.extend(vec![
            XssPayload {
                payload: "${alert(1)}".to_string(),
                context: InjectionContext::JavaScript,
                encoding: PayloadEncoding::None,
                description: "Template literal injection".to_string(),
            },
            XssPayload {
                payload: "<%= alert(1) %>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::None,
                description: "ERB template injection".to_string(),
            },
        ]);

        // Polyglots and encodings
        self.payloads.extend(vec![
            XssPayload {
                payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */alert(1))//%0D%0A%0d%0a//".to_string(),
                context: InjectionContext::Url,
                encoding: PayloadEncoding::Mixed,
                description: "JavaScript protocol polyglot".to_string(),
            },
            XssPayload {
                payload: "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;alert(1)&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::HtmlEntity,
                description: "HTML entity encoded script".to_string(),
            },
        ]);
    }

    fn init_context_patterns(&mut self) {
        self.context_patterns.insert(
            InjectionContext::HtmlAttribute,
            vec![
                // Match attributes with single or double quotes
                Regex::new(r#"<[^>]+\s+[^>]*=["'][^"']*["'][^>]*>"#).unwrap(),
                // Match unquoted attributes
                Regex::new(r#"<[^>]+\s+[^>]*=[^"'\s>]+[^>]*>"#).unwrap(),
            ],
        );

        self.context_patterns.insert(
            InjectionContext::JavaScript,
            vec![
                // Match script tags
                Regex::new(r#"<script[^>]*>.*?</script>"#).unwrap(),
                // Match javascript: protocol
                Regex::new(r#"javascript:"#).unwrap(),
                // Match event handlers
                Regex::new(r#"on\w+\s*="#).unwrap(),
            ],
        );

        self.context_patterns.insert(
            InjectionContext::Url,
            vec![
                // Match URLs
                Regex::new(r#"https?://[^\s"']+"#).unwrap(),
                // Match url() in CSS
                Regex::new(r#"url\(['"]?[^'")\s]+['"]?\)"#).unwrap(),
            ],
        );
    }

    fn detect_context(&self, html: &str, position: usize) -> InjectionContext {
        for (context, patterns) in &self.context_patterns {
            for pattern in patterns {
                if let Some(mat) = pattern.find_at(html, position) {
                    if mat.start() <= position && position <= mat.end() {
                        return context.clone();
                    }
                }
            }
        }
        InjectionContext::Unknown
    }

    fn encode_payload(&self, payload: &str, encoding: &PayloadEncoding) -> String {
        match encoding {
            PayloadEncoding::None => payload.to_string(),
            PayloadEncoding::HtmlEntity => {
                payload.chars()
                    .map(|c| format!("&#x{:X};", c as u32))
                    .collect()
            },
            PayloadEncoding::Url => {
                utf8_percent_encode(payload, NON_ALPHANUMERIC).to_string()
            },
            PayloadEncoding::DoubleUrl => {
                let first_encode = utf8_percent_encode(payload, NON_ALPHANUMERIC).to_string();
                utf8_percent_encode(&first_encode, NON_ALPHANUMERIC).to_string()
            },
            PayloadEncoding::JavaScript => {
                payload.chars()
                    .map(|c| format!("\\u{:04x}", c as u32))
                    .collect()
            },
            PayloadEncoding::Mixed => {
                // Mix different encodings
                let mut result = String::new();
                for (i, c) in payload.chars().enumerate() {
                    match i % 3 {
                        0 => result.push_str(&format!("&#x{:X};", c as u32)),
                        1 => result.push_str(&utf8_percent_encode(&c.to_string(), NON_ALPHANUMERIC).to_string()),
                        _ => result.push(c),
                    }
                }
                result
            },
        }
    }

    async fn test_parameter(&self, url: &Url, param_name: &str, payload: &XssPayload) -> Result<Option<Vulnerability>> {
        let mut test_url = url.clone();
        {
            let mut query_pairs = test_url.query_pairs_mut();
            query_pairs.clear();
            if !self.delete_all_params {
                let encoded_payload = self.encode_payload(&payload.payload, &payload.encoding);
                query_pairs.append_pair(param_name, &encoded_payload);
            }
        }

        match self.client.get(test_url.as_str()).send().await {
            Ok(response) => {
                // Get content type before consuming the response
                let content_type = response.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();

                // Check content type to ensure it's HTML or similar
                if !content_type.contains("text/html") 
                    && !content_type.contains("application/xhtml+xml")
                    && !content_type.contains("text/xml")
                    && !content_type.contains("application/xml") {
                    return Ok(None);
                }

                if let Ok(text) = response.text().await {
                    // Check for WAF detection
                    if self.detect_waf(&text) {
                        self.waf_detected.store(true, Ordering::SeqCst);
                        return Ok(None);
                    }

                    // Verify payload reflection
                    if self.verify_reflection(&text, &payload) {
                        return Ok(Some(Vulnerability {
                            name: "Reflected XSS".to_string(),
                            description: format!(
                                "Parameter '{}' appears to be vulnerable to reflected XSS ({})",
                                param_name,
                                payload.description
                            ),
                            severity: Severity::High,
                            cve_id: None,
                            metadata: json!({
                                "url": test_url.to_string(),
                                "parameter": param_name,
                                "payload": payload.payload,
                                "context": format!("{:?}", payload.context),
                                "encoding": format!("{:?}", payload.encoding),
                                "content_type": content_type,
                            }),
                        }));
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to test URL {}: {}", test_url, e);
            }
        }
        Ok(None)
    }

    fn detect_waf(&self, response: &str) -> bool {
        // Common WAF detection patterns
        let waf_patterns = vec![
            "blocked by security policy",
            "security violation",
            "forbidden",
            "mod_security",
            "cloudflare",
            "akamai",
            "incapsula",
        ];

        waf_patterns.iter().any(|pattern| response.to_lowercase().contains(pattern))
    }

    fn verify_reflection(&self, response: &str, payload: &XssPayload) -> bool {
        // Basic reflection check
        if response.contains(&payload.payload) {
            return true;
        }

        // Check for encoded reflection
        let encoded = self.encode_payload(&payload.payload, &payload.encoding);
        if response.contains(&encoded) {
            return true;
        }

        // Check for partial reflection
        let words: Vec<&str> = payload.payload.split_whitespace().collect();
        if words.iter().all(|word| response.contains(word)) {
            return true;
        }

        false
    }

    pub fn with_delete_all_params(mut self, delete_all_params: bool) -> Self {
        self.delete_all_params = delete_all_params;
        self
    }

    pub fn with_custom_input(mut self, custom_input: Option<String>) -> Self {
        self.custom_input = custom_input;
        self
    }

    pub fn with_safe_mode(mut self, safe_mode: bool) -> Self {
        self.safe_mode = safe_mode;
        self
    }
}

#[async_trait]
impl ScannerPlugin for XssScanner {
    fn name(&self) -> &'static str {
        "xss_scanner"
    }

    fn description(&self) -> &'static str {
        "Advanced XSS scanner with context-aware payloads and WAF detection"
    }

    fn version(&self) -> &'static str {
        "0.2.0"
    }

    async fn validate(&self, target: &Target) -> Result<bool> {
        match target.target_type {
            crate::plugin::TargetType::Url => Ok(true),
            _ => Ok(false),
        }
    }

    async fn scan(&self, target: &Target) -> Result<ScanResult> {
        let url = Url::parse(&target.raw)?;
        let mut vulnerabilities = Vec::new();
        let mut seen_vulns = HashSet::new();

        if let Some(discovered_urls) = target.metadata.get("discovered_urls") {
            if let Some(urls) = discovered_urls.as_array() {
                for url_data in urls {
                    if let Ok(discovered_url) = serde_json::from_value::<crate::core::crawler::DiscoveredUrl>(url_data.clone()) {
                        for param in &discovered_url.parameters {
                            // Create a unique key for this parameter and endpoint
                            let vuln_key = format!("{}:{}", discovered_url.url, param.name);
                            
                            // Skip if we've already found a vulnerability for this parameter
                            if seen_vulns.contains(&vuln_key) {
                                continue;
                            }

                            let payloads = if let Some(input) = &self.custom_input {
                                vec![XssPayload {
                                    payload: input.clone(),
                                    context: InjectionContext::Unknown,
                                    encoding: PayloadEncoding::None,
                                    description: "Custom input".to_string(),
                                }]
                            } else {
                                self.payloads.clone()
                            };

                            for payload in &payloads {
                                if let Some(vuln) = self.test_parameter(&discovered_url.url, &param.name, payload).await? {
                                    seen_vulns.insert(vuln_key);
                                    vulnerabilities.push(vuln);
                                    break; // Stop testing this parameter once we find a vulnerability
                                }
                            }
                        }
                    }
                }
            }
        } else {
            let response = self.client.get(url.as_str()).send().await?;
            let _text = response.text().await?;
            
            for (name, _value) in url.query_pairs() {
                // Create a unique key for this parameter and endpoint
                let vuln_key = format!("{}:{}", url, name);
                
                // Skip if we've already found a vulnerability for this parameter
                if seen_vulns.contains(&vuln_key) {
                    continue;
                }

                let payloads = if let Some(input) = &self.custom_input {
                    vec![XssPayload {
                        payload: input.clone(),
                        context: InjectionContext::Unknown,
                        encoding: PayloadEncoding::None,
                        description: "Custom input".to_string(),
                    }]
                } else {
                    self.payloads.clone()
                };

                for payload in &payloads {
                    if let Some(vuln) = self.test_parameter(&url, &name, payload).await? {
                        seen_vulns.insert(vuln_key);
                        vulnerabilities.push(vuln);
                        break; // Stop testing this parameter once we find a vulnerability
                    }
                }
            }
        }

        Ok(ScanResult {
            plugin_name: self.name().to_string(),
            success: true,
            vulnerabilities,
            metadata: json!({
                "scanned_urls": target.metadata.get("discovered_urls").cloned(),
                "waf_detected": self.waf_detected.load(Ordering::SeqCst),
                "safe_mode": self.safe_mode,
                "unique_vulnerabilities": seen_vulns.len(),
            }),
        })
    }

    fn box_clone(&self) -> Box<dyn ScannerPlugin + Send + Sync> {
        Box::new(Self::new())
    }
} 