use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Represents a target that can be scanned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// The raw input value
    pub raw: String,
    /// The type of target (URL, IP, File, etc.)
    pub target_type: TargetType,
    /// Additional metadata about the target
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetType {
    Url,
    Ip,
    File,
    Domain,
    Other(String),
}

/// Result of a plugin's scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// The plugin that produced this result
    pub plugin_name: String,
    /// Whether the scan was successful
    pub success: bool,
    /// Any vulnerabilities found
    pub vulnerabilities: Vec<Vulnerability>,
    /// Additional metadata about the scan
    pub metadata: serde_json::Value,
}

/// Represents a vulnerability found during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// The name/title of the vulnerability
    pub name: String,
    /// Description of the vulnerability
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// CVE ID if applicable
    pub cve_id: Option<String>,
    /// Additional metadata
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// The main trait that all scanner plugins must implement
#[async_trait]
pub trait ScannerPlugin: Send + Sync + Debug {
    /// Returns the name of the plugin
    fn name(&self) -> &'static str;
    
    /// Returns a description of what the plugin does
    fn description(&self) -> &'static str;
    
    /// Returns the version of the plugin
    fn version(&self) -> &'static str;
    
    /// Validates if the plugin can handle the given target
    async fn validate(&self, target: &Target) -> anyhow::Result<bool>;
    
    /// Performs the actual scan on the target
    async fn scan(&self, target: &Target) -> anyhow::Result<ScanResult>;
    
    /// Returns any dependencies this plugin has on other plugins
    fn dependencies(&self) -> Vec<&'static str> {
        Vec::new()
    }
}

/// Configuration for a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Whether the plugin is enabled
    pub enabled: bool,
    /// Plugin-specific configuration
    pub settings: serde_json::Value,
} 