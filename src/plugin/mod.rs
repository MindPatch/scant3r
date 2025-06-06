pub mod scanner_trait;
pub mod manager;
pub mod scanners;

pub use scanner_trait::*;
pub use manager::*;
pub use scanners::*;

// Re-export commonly used types
pub use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use url::Url;
use anyhow::Result;

// Remove duplicate type definitions since they are imported from scanner_trait 