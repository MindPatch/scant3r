use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use tracing::{info, warn};

use super::scanner_trait::{PluginConfig, ScannerPlugin, Target, ScanResult};

/// Manages the loading and execution of scanner plugins
pub struct PluginManager {
    plugins: Arc<RwLock<HashMap<String, Box<dyn ScannerPlugin + Send + Sync>>>>,
    configs: Arc<RwLock<HashMap<String, PluginConfig>>>,
}

impl PluginManager {
    /// Creates a new plugin manager
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a new plugin
    pub async fn register_plugin(&self, plugin: Box<dyn ScannerPlugin + Send + Sync>) -> Result<()> {
        let name = plugin.name().to_string();
        let mut plugins = self.plugins.write().await;
        plugins.insert(name.clone(), plugin);
        
        // Set default config
        let mut configs = self.configs.write().await;
        configs.insert(name, PluginConfig { enabled: true });
        
        Ok(())
    }

    /// Gets a plugin by name
    pub async fn get_plugin(&self, name: &str) -> Option<Box<dyn ScannerPlugin + Send + Sync>> {
        let plugins = self.plugins.read().await;
        plugins.get(name).map(|p| p.box_clone())
    }

    /// Returns all registered plugins
    pub async fn list_plugins(&self) -> Vec<Box<dyn ScannerPlugin + Send + Sync>> {
        let plugins = self.plugins.read().await;
        plugins.values().map(|p| p.box_clone()).collect()
    }

    /// Sets the configuration for a plugin
    pub async fn configure_plugin(&self, name: &str, config: PluginConfig) -> Result<()> {
        let mut configs = self.configs.write().await;
        configs.insert(name.to_string(), config);
        Ok(())
    }

    /// Runs all enabled plugins that can handle the target
    pub async fn run_scan(&self, target: &Target) -> Result<Vec<(String, Result<ScanResult>)>> {
        let plugins = self.plugins.read().await;
        let configs = self.configs.read().await;
        
        let mut results = Vec::new();
        
        for (name, plugin) in plugins.iter() {
            if configs.get(name).map(|c| c.enabled).unwrap_or(true) {
                info!("Running plugin: {}", name);
                let result = plugin.scan(target).await;
                results.push((name.clone(), result));
            }
        }
        
        Ok(results)
    }
} 