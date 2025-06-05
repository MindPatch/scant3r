use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::fmt::Debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetType {
    Url,
    Ip,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub raw: String,
    pub target_type: TargetType,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub cve_id: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub plugin_name: String,
    pub success: bool,
    pub vulnerabilities: Vec<Vulnerability>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
}

#[async_trait]
pub trait ScannerPlugin: Send + Sync + Debug {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn version(&self) -> &'static str;
    
    async fn validate(&self, target: &Target) -> anyhow::Result<bool>;
    async fn scan(&self, target: &Target) -> anyhow::Result<ScanResult>;
    
    fn box_clone(&self) -> Box<dyn ScannerPlugin + Send + Sync>;
} 