use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use chrono::{DateTime, Utc};
use tracing::info;

use super::parser::CVE;

/// Stores and provides access to CVE data
pub struct CVEStore {
    cves: Arc<RwLock<HashMap<String, CVE>>>,
    last_update: Arc<RwLock<DateTime<Utc>>>,
}

impl CVEStore {
    /// Creates a new CVE store
    pub fn new() -> Self {
        Self {
            cves: Arc::new(RwLock::new(HashMap::new())),
            last_update: Arc::new(RwLock::new(Utc::now())),
        }
    }

    /// Adds new CVEs to the store
    pub async fn add_cves(&self, cves: Vec<CVE>) -> Result<()> {
        let mut store = self.cves.write().await;
        
        for cve in cves {
            store.insert(cve.id.clone(), cve);
        }
        
        *self.last_update.write().await = Utc::now();
        Ok(())
    }

    /// Gets a CVE by its ID
    pub async fn get_cve(&self, id: &str) -> Option<CVE> {
        let store = self.cves.read().await;
        store.get(id).cloned()
    }

    /// Searches for CVEs by product and version
    pub async fn search_by_product(&self, vendor: &str, product: &str, version: &str) -> Vec<CVE> {
        let store = self.cves.read().await;
        
        store
            .values()
            .filter(|cve| {
                cve.affected_products.iter().any(|p| {
                    p.vendor == vendor && p.product == product && {
                        p.versions.iter().any(|v| {
                            match v.version_type {
                                super::parser::VersionType::Exact => v.version == version,
                                super::parser::VersionType::Range => {
                                    // TODO: Implement version range parsing
                                    false
                                }
                                super::parser::VersionType::LessThan => {
                                    // TODO: Implement version comparison
                                    false
                                }
                                super::parser::VersionType::LessThanOrEqual => {
                                    // TODO: Implement version comparison
                                    false
                                }
                                super::parser::VersionType::GreaterThan => {
                                    // TODO: Implement version comparison
                                    false
                                }
                                super::parser::VersionType::GreaterThanOrEqual => {
                                    // TODO: Implement version comparison
                                    false
                                }
                            }
                        })
                    }
                })
            })
            .cloned()
            .collect()
    }

    /// Gets all CVEs with a specific severity
    pub async fn get_by_severity(&self, severity: super::parser::Severity) -> Vec<CVE> {
        let store = self.cves.read().await;
        
        store
            .values()
            .filter(|cve| cve.severity == severity)
            .cloned()
            .collect()
    }

    /// Gets the total number of CVEs in the store
    pub async fn cve_count(&self) -> usize {
        let store = self.cves.read().await;
        store.len()
    }

    /// Gets the last time the store was updated
    pub async fn last_update(&self) -> DateTime<Utc> {
        *self.last_update.read().await
    }
} 