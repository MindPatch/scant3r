use crate::plugin::{ScannerPlugin, Target, ScanResult, Vulnerability, Severity};
use async_trait::async_trait;
use std::fmt::Debug;
use anyhow::Result;
use reqwest::Client;
use url::Url;
use std::any::Any;

/// Scanner for detecting exposed Apache Impala instances
#[derive(Debug, Clone)]
pub struct ImpalaScanner {
    client: Client,
    proxy: Option<String>,
}

impl ImpalaScanner {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::limited(2))
                .build()
                .unwrap(),
            proxy: None,
        }
    }

    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        if let Some(proxy_url) = proxy {
            self.proxy = Some(proxy_url.clone());
            let mut builder = Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::limited(2));
            
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
                    .redirect(reqwest::redirect::Policy::limited(2))
                    .build()
                    .unwrap()
            });
        }
        self
    }
}

#[async_trait]
impl ScannerPlugin for ImpalaScanner {
    fn name(&self) -> &'static str {
        "impala_scanner"
    }

    fn description(&self) -> &'static str {
        "Detects exposed Apache Impala instances"
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

    async fn scan(&mut self, target: &Target) -> Result<ScanResult> {
        let url = Url::parse(&target.raw)?;
        let mut vulnerabilities = Vec::new();

        // Send GET request to the target
        match self.client.get(url.as_str()).send().await {
            Ok(response) => {
                // Check if status code is 200
                if response.status().as_u16() == 200 {
                    if let Ok(text) = response.text().await {
                        // Check for both required strings in the response
                        if text.contains("Apache Impala") && text.contains("Process Info") {
                            vulnerabilities.push(Vulnerability {
                                name: "Apache Impala Exposure".to_string(),
                                description: "Apache Impala instance is exposed and accessible".to_string(),
                                severity: Severity::Medium,
                                cve_id: None,
                                metadata: serde_json::json!({
                                    "url": url.to_string(),
                                    "vendor": "apache",
                                    "product": "impala",
                                    "shodan_query": "http.favicon.hash:587330928",
                                    "cpe": "cpe:2.3:a:apache:impala:*:*:*:*:*:*:*:*",
                                }),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to scan URL {}: {}", url, e);
            }
        }

        Ok(ScanResult {
            plugin_name: self.name().to_string(),
            success: true,
            vulnerabilities,
            metadata: serde_json::json!({
                "url": url.to_string(),
                "max_redirects": 2,
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