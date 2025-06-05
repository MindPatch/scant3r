use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use chrono::{DateTime, Utc};
use tracing::{info, error};

use super::feed::{CVEFeed, FeedConfig, FeedSource};
use super::parser::CVEParser;
use super::store::CVEStore;

/// Manages synchronization of multiple CVE feeds
pub struct FeedSynchronizer {
    feeds: Arc<RwLock<HashMap<FeedSource, CVEFeed>>>,
    store: Arc<CVEStore>,
}

impl FeedSynchronizer {
    /// Creates a new feed synchronizer
    pub fn new(store: Arc<CVEStore>) -> Self {
        Self {
            feeds: Arc::new(RwLock::new(HashMap::new())),
            store,
        }
    }

    /// Registers a new CVE feed
    pub async fn register_feed(&self, config: FeedConfig, parser: Box<dyn CVEParser>) -> Result<()> {
        let feed = CVEFeed::new(config, parser);
        let source = feed.source().clone();
        
        let mut feeds = self.feeds.write().await;
        feeds.insert(source, feed);
        
        Ok(())
    }

    /// Synchronizes all feeds that need updating
    pub async fn sync_feeds(&self) -> Result<()> {
        let mut feeds = self.feeds.write().await;
        
        for (source, feed) in feeds.iter_mut() {
            if feed.needs_sync() {
                info!("Syncing feed from {:?}", source);
                
                match feed.fetch().await {
                    Ok(cves) => {
                        info!("Fetched {} CVEs from {:?}", cves.len(), source);
                        self.store.add_cves(cves).await?;
                    }
                    Err(e) => {
                        error!("Failed to sync feed from {:?}: {}", source, e);
                    }
                }
            } else {
                info!("Feed from {:?} is up to date", source);
            }
        }
        
        Ok(())
    }

    /// Gets the last sync time for a specific feed
    pub async fn get_last_sync(&self, source: &FeedSource) -> Option<DateTime<Utc>> {
        let feeds = self.feeds.read().await;
        feeds.get(source).and_then(|feed| feed.last_sync())
    }

    /// Gets the number of feeds being managed
    pub async fn feed_count(&self) -> usize {
        let feeds = self.feeds.read().await;
        feeds.len()
    }
} 