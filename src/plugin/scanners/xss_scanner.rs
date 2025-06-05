use crate::plugin::{ScannerPlugin, Target, ScanResult, Vulnerability, Severity};
use async_trait::async_trait;
use std::fmt::Debug;
use anyhow::Result;
use reqwest::Client;
use url::Url;

/// XSS scanner plugin that tests for reflected XSS vulnerabilities
#[derive(Debug)]
pub struct XssScanner {
    client: Client,
    payloads: Vec<String>,
}

impl XssScanner {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            payloads: vec![
                "<script>alert(1)</script>".to_string(),
                "\"><script>alert(1)</script>".to_string(),
                "'><script>alert(1)</script>".to_string(),
                "<img src=x onerror=alert(1)>".to_string(),
                "javascript:alert(1)".to_string(),
            ],
        }
    }

    async fn test_parameter(&self, url: &Url, param_name: &str, payload: &str) -> Result<Option<Vulnerability>> {
        let mut test_url = url.clone();
        {
            let mut query_pairs = test_url.query_pairs_mut();
            query_pairs.clear();
            query_pairs.append_pair(param_name, payload);
        } // query_pairs is dropped here

        match self.client.get(test_url.as_str()).send().await {
            Ok(response) => {
                if let Ok(text) = response.text().await {
                    if text.contains(payload) {
                        return Ok(Some(Vulnerability {
                            name: "Reflected XSS".to_string(),
                            description: format!(
                                "Parameter '{}' appears to be vulnerable to reflected XSS",
                                param_name
                            ),
                            severity: Severity::High,
                            cve_id: None,
                            metadata: serde_json::json!({
                                "url": test_url.to_string(),
                                "parameter": param_name,
                                "payload": payload,
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
}

#[async_trait]
impl ScannerPlugin for XssScanner {
    fn name(&self) -> &'static str {
        "xss_scanner"
    }

    fn description(&self) -> &'static str {
        "Scans for reflected XSS vulnerabilities in web applications"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
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

        // If we have discovered URLs in the metadata, use them
        if let Some(discovered_urls) = target.metadata.get("discovered_urls") {
            if let Some(urls) = discovered_urls.as_array() {
                for url_data in urls {
                    if let Ok(discovered_url) = serde_json::from_value::<crate::core::crawler::DiscoveredUrl>(url_data.clone()) {
                        for param in &discovered_url.parameters {
                            for payload in &self.payloads {
                                if let Some(vuln) = self.test_parameter(&discovered_url.url, &param.name, payload).await? {
                                    vulnerabilities.push(vuln);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Basic scan of the target URL
            let response = self.client.get(url.as_str()).send().await?;
            let _text = response.text().await?;
            
            // Extract parameters from the URL
            for (name, _) in url.query_pairs() {
                for payload in &self.payloads {
                    if let Some(vuln) = self.test_parameter(&url, &name, payload).await? {
                        vulnerabilities.push(vuln);
                    }
                }
            }
        }

        Ok(ScanResult {
            plugin_name: self.name().to_string(),
            success: true,
            vulnerabilities,
            metadata: serde_json::json!({
                "scanned_urls": target.metadata.get("discovered_urls").cloned(),
            }),
        })
    }

    fn box_clone(&self) -> Box<dyn ScannerPlugin + Send + Sync> {
        Box::new(Self::new())
    }
} 