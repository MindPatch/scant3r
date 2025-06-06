use std::any::Any;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub raw: String,
    pub target_type: TargetType,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetType {
    Url,
    Host,
    Ip,
    Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub plugin_name: String,
    pub success: bool,
    pub vulnerabilities: Vec<Vulnerability>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub cve_id: Option<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
}

#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn version(&self) -> &'static str;
    async fn validate(&self, target: &Target) -> Result<bool>;
    async fn scan(&mut self, target: &Target) -> Result<ScanResult>;
    fn box_clone(&self) -> Box<dyn ScannerPlugin + Send + Sync>;
    fn as_any(&self) -> &dyn Any;
} 