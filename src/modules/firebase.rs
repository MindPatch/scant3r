use async_trait::async_trait;
use console::style;
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};

use super::{Module, ModuleResult, ScanContext, Tag};
use crate::data;
use crate::http::Body;

pub struct Firebase;

/// Extract the registrable domain name without TLD
/// (the Python `tldextract.extract(url).domain`).
fn domain_name(url: &str) -> Option<String> {
    let host = url::Url::parse(url).ok()?.host_str()?.to_string();
    let parsed = addr::parse_domain_name(&host).ok()?;
    let root = parsed.root()?;
    root.split('.').next().map(|s| s.to_string())
}

async fn scan_host(ctx: &ScanContext, target_host: &str) -> Value {
    let firebase = data::FIREBASE_URL.replace("%s", target_host);
    let mut report = json!({"host": firebase, "read": {}, "write": {}});
    let read_url = crate::utils::add_path(&firebase, "/.json");
    let Ok(read_response) = ctx.http.send_simple(&read_url, "GET", false).await else {
        return report;
    };
    tracing::debug!("Check for Read permission -> {firebase}");
    if read_response.status == 200 {
        report["read"] = json!({
            "url": read_url,
            "content_length": read_response.text.len(),
            "status": 200,
            "request": read_response.dump_request(),
            "response": read_response.dump_response(),
        });

        tracing::debug!("Check for Write permission -> {firebase}");
        let write_url = crate::utils::add_path(&firebase, "/firebase/security.json");
        if let Ok(write_response) = ctx
            .http
            .send(
                &write_url,
                "PUT",
                Body::Pairs(vec![("msg".to_string(), "scant3r".to_string())]),
                Default::default(),
                false,
                None,
                None,
            )
            .await
        {
            if write_response.status == 200 {
                report["write"] = json!({
                    "url": write_url,
                    "write": true,
                    "content_length": write_response.text.len(),
                    "status": 200,
                    "request": write_response.dump_request(),
                    "response": write_response.dump_response(),
                });
            }
        }
    }
    report
}

#[async_trait]
impl Module for Firebase {
    fn tag(&self) -> Tag {
        Tag::Recon
    }

    async fn run(&self, ctx: &ScanContext, url: &str) -> ModuleResult {
        let Some(host) = domain_name(url) else {
            return Ok(json!({}));
        };
        let mut all_hosts = vec![host.clone()];
        for tld in data::tld() {
            all_hosts.push(format!("{}{}", host, tld.trim_end()));
        }

        let mut found: Vec<Value> = Vec::new();
        let mut stream = stream::iter(all_hosts.into_iter().map(|target| async move {
            scan_host(ctx, &target).await
        }))
        .buffer_unordered(5);

        while let Some(result) = stream.next().await {
            let has_read = result["read"].as_object().map(|o| !o.is_empty()).unwrap_or(false);
            let has_write = result["write"].as_object().map(|o| !o.is_empty()).unwrap_or(false);
            if !has_read && !has_write {
                continue;
            }
            let mut lines = vec![format!(
                "🔓 Open Firebase on {}",
                style(result["host"].as_str().unwrap_or("")).yellow().bold()
            )];
            if has_read {
                lines.push(format!("🔍 The reading permission is {}", style("enabled").red()));
            }
            if has_write {
                lines.push(format!("✍️  The writing permission is {}", style("enabled").red()));
            }
            ctx.println(crate::report::finding_block(&lines, None));
            found.push(result);
        }

        if found.is_empty() {
            Ok(json!({}))
        } else {
            Ok(json!({"module": "firebase", "found": found}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::domain_name;

    #[test]
    fn extracts_domain_like_tldextract() {
        assert_eq!(
            domain_name("http://testphp.vulnweb.com/listproducts.php?cat=1"),
            Some("vulnweb".to_string())
        );
        assert_eq!(
            domain_name("https://www.example.co.uk/"),
            Some("example".to_string())
        );
        assert_eq!(domain_name("http://github.com"), Some("github".to_string()));
    }
}
