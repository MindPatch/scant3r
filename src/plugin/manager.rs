use anyhow::Result;
use tracing::info;

use super::scanner_trait::{PluginConfig, ScannerPlugin, Target, ScanResult};
use super::scanners::{HttpScanner, XssScanner, ImpalaScanner};

/// Manages the loading and execution of scanner plugins
pub struct PluginManager {
    plugins: Vec<Box<dyn ScannerPlugin + Send + Sync>>,
    proxy: Option<String>,
}

impl PluginManager {
    /// Creates a new plugin manager
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            proxy: None,
        }
    }

    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }

    /// Registers a new plugin
    pub async fn register_plugin(&mut self, plugin: Box<dyn ScannerPlugin + Send + Sync>) -> Result<()> {
        if let Some(proxy) = &self.proxy {
            if let Some(http_scanner) = plugin.as_any().downcast_ref::<HttpScanner>() {
                let scanner = http_scanner.clone().with_proxy(Some(proxy.clone()));
                self.plugins.push(Box::new(scanner));
                return Ok(());
            }
            if let Some(xss_scanner) = plugin.as_any().downcast_ref::<XssScanner>() {
                let scanner = xss_scanner.clone().with_proxy(Some(proxy.clone()));
                self.plugins.push(Box::new(scanner));
                return Ok(());
            }
            if let Some(impala_scanner) = plugin.as_any().downcast_ref::<ImpalaScanner>() {
                let scanner = impala_scanner.clone().with_proxy(Some(proxy.clone()));
                self.plugins.push(Box::new(scanner));
                return Ok(());
            }
        }
        self.plugins.push(plugin);
        Ok(())
    }

    /// Gets a plugin by name
    pub async fn get_plugin(&self, name: &str) -> Option<Box<dyn ScannerPlugin + Send + Sync>> {
        self.plugins.iter()
            .find(|p| p.name() == name)
            .map(|p| p.box_clone())
    }

    /// Returns all registered plugins
    pub async fn list_plugins(&self) -> Vec<Box<dyn ScannerPlugin + Send + Sync>> {
        self.plugins.iter()
            .map(|p| p.box_clone())
            .collect()
    }

    /// Sets the configuration for a plugin
    pub async fn configure_plugin(&self, _name: &str, _config: PluginConfig) -> Result<()> {
        // This method is not implemented in the new structure
        Ok(())
    }

    /// Runs all enabled plugins that can handle the target
    pub async fn run_scan(&mut self, target: &Target) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();
        
        for plugin in &mut self.plugins {
            info!("Running plugin: {}", plugin.name());
            let result = plugin.scan(target).await?;
            results.push(result);
        }
        
        Ok(results)
    }

    pub async fn scan_with_plugin(&mut self, name: &str, target: &Target) -> Result<Option<ScanResult>> {
        if let Some(plugin) = self.plugins.iter_mut().find(|p| p.name() == name) {
            if plugin.validate(target).await? {
                Ok(Some(plugin.scan(target).await?))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
} 