use async_trait::async_trait;
use console::style;
use serde_json::json;

use super::xss_payloads::XssPayloads;
use super::{send_request, Module, ModuleResult, ScanContext, Tag};
use crate::htmlparser::{find_locations, xpath_matches};
use crate::report::finding_block;
use crate::utils::{insert_to_params_urls, random_str};

pub struct Xss;

#[async_trait]
impl Module for Xss {
    fn tag(&self) -> Tag {
        Tag::Scanner
    }

    async fn run(&self, ctx: &ScanContext, url: &str) -> ModuleResult {
        let mut found: Vec<serde_json::Value> = Vec::new();
        let xss = XssPayloads::new(Vec::new());
        for method in &ctx.opts.methods {
            // check for reflected params
            let rand_str = random_str(3);
            let reflect_payload = format!("scan{rand_str}r").to_lowercase();
            let new_urls = insert_to_params_urls(url, &reflect_payload, false);
            for new_url in &new_urls {
                tracing::debug!("XSS: GENERATE A NEW URL: {new_url}");
                let Ok(response) = send_request(ctx, method, new_url, None).await else {
                    continue;
                };
                let locations = find_locations(&response.text, &reflect_payload);
                if locations.is_empty() {
                    continue;
                }
                tracing::debug!(
                    "REFLECTED {reflect_payload} on {} | {locations:?}",
                    response.url
                );
                for xss_location in locations {
                    // scan the target with the xss payloads
                    for (payload, payload_search) in
                        xss.generate(&reflect_payload, xss_location)
                    {
                        let new_custom_urls = insert_to_params_urls(url, &payload, false);
                        for new_custom_url in &new_custom_urls {
                            let Ok(response) =
                                send_request(ctx, method, new_custom_url, None).await
                            else {
                                continue;
                            };
                            let raw_response = &response.text;
                            if !xpath_matches(raw_response, &payload_search) {
                                continue;
                            }
                            tracing::debug!("XSS: MATCHED {}", response.url);
                            found.push(json!({
                                "type": xss_location.value(),
                                "url": response.url,
                                "request": response.dump_request(),
                                "response": response.dump_response(),
                                "payload": payload,
                                "matching": payload_search,
                            }));
                            let msg = finding_block(
                                &[
                                    format!(
                                        "🔥 {}",
                                        style("Reflected Cross-site scripting").bold()
                                    ),
                                    format!("🎯 The Effected URL: {}", response.url),
                                    format!("📄 XSS Location: {}", xss_location.value()),
                                    format!(
                                        "💉 The Used Payload: {}",
                                        style(&payload).red().bold()
                                    ),
                                ],
                                Some((raw_response.as_str(), payload.as_str())),
                            );
                            ctx.println(msg);
                            break;
                        }
                    }
                }
            }
        }
        Ok(json!({
            "module": "xss",
            "name": "Reflected Cross-site scripting",
            "found": found,
        }))
    }
}
