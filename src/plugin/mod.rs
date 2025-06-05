mod scanner_trait;
mod manager;
pub mod scanners;

pub use scanner_trait::{ScannerPlugin, Target, ScanResult, Vulnerability, Severity, TargetType};
pub use manager::PluginManager;
pub use scanners::{HttpScanner, XssScanner, ImpalaScanner};

// Re-export commonly used types
pub use async_trait::async_trait; 