use crate::plugin::{ScannerPlugin, Target, ScanResult, Vulnerability, Severity};
use async_trait::async_trait;
use std::fmt::Debug;
use anyhow::Result;
use reqwest::Client;
use url::Url;
use tracing::{trace};

/// HTTP scanner plugin that checks for security headers and common misconfigurations
#[derive(Debug)]
pub struct HttpScanner {
    client: Client,
}

impl HttpScanner {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for HttpScanner {
    fn name(&self) -> &'static str {
        "http_scanner"
    }

    fn description(&self) -> &'static str {
        "Scans for HTTP security headers and common misconfigurations"
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

        // Build the request
        let request = self.client.get(url.as_str()).build()?;
        // Log the request at trace level
        trace!("HTTP Request: {:#?}", request);

        // Send the request
        let response = self.client.execute(request).await?;
        // Log the response at trace level
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;
        trace!("HTTP Response: status={:?}, headers={:#?}, body=\n{}", status, headers, body);

        // Check for security headers
        let security_headers = [
            ("X-Frame-Options", "Missing X-Frame-Options header"),
            ("X-Content-Type-Options", "Missing X-Content-Type-Options header"),
            ("X-XSS-Protection", "Missing X-XSS-Protection header"),
            ("Content-Security-Policy", "Missing Content-Security-Policy header"),
            ("Strict-Transport-Security", "Missing HSTS header"),
        ];

        for (header, message) in security_headers {
            if !headers.contains_key(header) {
                vulnerabilities.push(Vulnerability {
                    name: "Missing Security Header".to_string(),
                    description: message.to_string(),
                    severity: Severity::Medium,
                    cve_id: None,
                    metadata: serde_json::json!({
                        "url": url.to_string(),
                        "header": header,
                    }),
                });
            }
        }

        Ok(ScanResult {
            plugin_name: self.name().to_string(),
            success: true,
            vulnerabilities,
            metadata: serde_json::json!({
                "url": url.to_string(),
                "status_code": status.as_u16(),
            }),
        })
    }

    fn box_clone(&self) -> Box<dyn ScannerPlugin + Send + Sync> {
        Box::new(Self::new())
    }
} 