use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use chrono::{DateTime, Utc};

/// Represents a CVE entry with its metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVE {
    /// The CVE ID (e.g., "CVE-2023-1234")
    pub id: String,
    /// The date the CVE was published
    pub published_date: DateTime<Utc>,
    /// The date the CVE was last modified
    pub modified_date: DateTime<Utc>,
    /// The CVE description
    pub description: String,
    /// The severity of the vulnerability
    pub severity: Severity,
    /// The CVSS score if available
    pub cvss_score: Option<f32>,
    /// The CVSS vector if available
    pub cvss_vector: Option<String>,
    /// Affected products and versions
    pub affected_products: Vec<AffectedProduct>,
    /// References to additional information
    pub references: Vec<Reference>,
    /// Additional metadata
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProduct {
    /// The vendor name
    pub vendor: String,
    /// The product name
    pub product: String,
    /// The affected versions
    pub versions: Vec<Version>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    /// The version number or range
    pub version: String,
    /// The type of version specification
    pub version_type: VersionType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VersionType {
    Exact,
    Range,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    /// The reference URL
    pub url: String,
    /// The reference type (e.g., "Patch", "Vendor Advisory")
    pub reference_type: String,
    /// Additional metadata about the reference
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Trait for parsing CVE data from different sources
pub trait CVEParser: Send + Sync + Debug {
    /// Parse CVE data from a byte buffer
    fn parse(&self, data: &[u8]) -> anyhow::Result<Vec<CVE>>;
    
    /// Get the format this parser supports
    fn format(&self) -> super::feed::FeedFormat;
    
    /// Get the source this parser is for
    fn source(&self) -> super::feed::FeedSource;
} 