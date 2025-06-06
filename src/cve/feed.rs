use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use chrono::{DateTime, Utc};
use anyhow::Result;
use reqwest::Client;
use url::Url;
use std::hash::Hash;

use super::parser::{CVEParser, CVE};

/// Represents a CVE data feed source
#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub enum FeedSource {
    NVD,
    ExploitDB,
    GitHubAdvisories,
    Custom(String),
}

/// Represents the format of a CVE feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedFormat {
    JSON,
    XML,
    CSV,
    Custom(String),
}

/// Configuration for a CVE feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    /// The source of the feed
    pub source: FeedSource,
    /// The URL to fetch the feed from
    pub url: String,
    /// The format of the feed
    pub format: FeedFormat,
    /// How often to sync the feed (in hours)
    pub sync_interval: u64,
    /// Additional configuration
    pub metadata: serde_json::Value,
}

/// Represents a CVE data feed
pub struct CVEFeed {
    config: FeedConfig,
    parser: Box<dyn CVEParser>,
    client: Client,
    last_sync: Option<DateTime<Utc>>,
}

impl CVEFeed {
    /// Creates a new CVE feed
    pub fn new(config: FeedConfig, parser: Box<dyn CVEParser>) -> Self {
        Self {
            config,
            parser,
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            last_sync: None,
        }
    }

    /// Fetches and parses the CVE feed
    pub async fn fetch(&mut self) -> Result<Vec<CVE>> {
        let url = Url::parse(&self.config.url)?;
        let response = self.client.get(url).send().await?;
        let data = response.bytes().await?;
        
        let cves = self.parser.parse(&data)?;
        self.last_sync = Some(Utc::now());
        
        Ok(cves)
    }

    /// Checks if the feed needs to be synced
    pub fn needs_sync(&self) -> bool {
        match self.last_sync {
            None => true,
            Some(last) => {
                let now = Utc::now();
                let hours_since_last_sync = (now - last).num_hours() as u32;
                hours_since_last_sync >= self.config.sync_interval as u32
            }
        }
    }

    /// Gets the source of this feed
    pub fn source(&self) -> &FeedSource {
        &self.config.source
    }

    /// Gets the format of this feed
    pub fn format(&self) -> &FeedFormat {
        &self.config.format
    }

    /// Gets the last sync time
    pub fn last_sync(&self) -> Option<DateTime<Utc>> {
        self.last_sync
    }
} 