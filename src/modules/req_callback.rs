use std::time::Duration;

use async_trait::async_trait;
use console::style;
use serde_json::json;

use super::{send_request, Module, ModuleResult, ScanContext, Tag};
use crate::oast::Interactsh;
use crate::report::finding_block;
use crate::utils::insert_to_params_urls;

const PROTOCOLS: [&str; 2] = ["http", "https"];

pub struct ReqCallback;

#[async_trait]
impl Module for ReqCallback {
    fn tag(&self) -> Tag {
        Tag::Scanner
    }

    async fn run(&self, ctx: &ScanContext, url: &str) -> ModuleResult {
        let mut report = json!({});
        for method in &ctx.opts.methods {
            let callback = Interactsh::new("", "").await?;
            for protocol in PROTOCOLS {
                let payload = format!("{protocol}://{}", callback.domain);
                let new_urls = insert_to_params_urls(url, &payload, true);
                for new_url in &new_urls {
                    let Ok(response) = send_request(ctx, method, new_url, None).await else {
                        continue;
                    };
                    tokio::time::sleep(Duration::from_secs_f64(
                        ctx.opts.callback_time.max(0.0),
                    ))
                    .await;
                    let callback_results = callback.pull_logs().await.unwrap_or_default();
                    if callback_results.is_empty() {
                        continue;
                    }
                    report = json!({
                        "module": "req_callback",
                        "name": "Out-of-band resource load",
                        "url": response.url,
                        "request": response.dump_request(),
                        "response": response.dump_response(),
                        "payload": payload,
                        "callback": callback_results,
                    });
                    let msg = finding_block(
                        &[
                            format!("🛰 {}", style("Out-of-band resource load").bold()),
                            format!("🎯 The Effected URL: {}", response.url),
                            format!(
                                "💉 The Used Payload: {}",
                                style(&payload).red().bold()
                            ),
                            format!(
                                "🔍 Callback log: {}",
                                style(format!("{callback_results:?}")).yellow().bold()
                            ),
                        ],
                        None,
                    );
                    ctx.println(msg);
                }
            }
        }
        Ok(report)
    }
}
