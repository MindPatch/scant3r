use async_trait::async_trait;
use console::style;
use serde_json::json;

use super::{send_request, Module, ModuleResult, ScanContext, Tag};
use crate::data;
use crate::report::finding_block;
use crate::utils::{insert_to_params_urls, random_str};

pub struct Ssti;

#[async_trait]
impl Module for Ssti {
    fn tag(&self) -> Tag {
        Tag::Scanner
    }

    async fn run(&self, ctx: &ScanContext, url: &str) -> ModuleResult {
        let mut report = json!({});
        for method in &ctx.opts.methods {
            // check for reflected params
            let reflect_payload = random_str(3);
            let new_urls = insert_to_params_urls(url, &format!("scan{reflect_payload}r"), false);
            tracing::debug!("SSTI: GENERATE A NEW URLS: {new_urls:?}");
            for new_url in &new_urls {
                let Ok(response) = send_request(ctx, method, new_url, None).await else {
                    continue;
                };
                let raw_response = response.dump_response();
                if !raw_response.contains(&reflect_payload) {
                    continue;
                }
                tracing::debug!("REFLECTED {reflect_payload} on {}", response.url);
                tracing::debug!("SSTI: MATCHING WITH scan10tr");

                // scan the target with the ssti payloads
                for payload in data::ssti() {
                    let new_custom_urls = insert_to_params_urls(url, payload, false);
                    for new_custom_url in &new_custom_urls {
                        let Ok(response) = send_request(ctx, method, new_custom_url, None).await
                        else {
                            continue;
                        };
                        let raw_response = response.dump_response();
                        if !raw_response.contains("scan10tr") {
                            continue;
                        }
                        tracing::debug!("SSTI: MATCHED {}", response.url);
                        report = json!({
                            "module": "ssti",
                            "name": "Server-Side template injection",
                            "url": response.url,
                            "request": response.dump_request(),
                            "response": response.dump_response(),
                            "payload": payload,
                            "matching": "scan10tr",
                        });
                        let msg = finding_block(
                            &[
                                format!("🔥 {}", style("Server-Side template injection").bold()),
                                format!("🎯 The Effected URL: {}", response.url),
                                format!(
                                    "💉 The Used Payload: {}",
                                    style(payload).red().bold()
                                ),
                                format!(
                                    "🔍 Matched with : {}",
                                    style("scan10tr").yellow().bold()
                                ),
                            ],
                            Some((raw_response.as_str(), "scan10tr")),
                        );
                        ctx.println(msg);
                    }
                }
            }
        }
        Ok(report)
    }
}
