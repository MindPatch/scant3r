use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rand::seq::SliceRandom;
use reqwest::redirect::Policy;

use crate::data;
use crate::utils::post_data;

const DEFAULT_UA: &str =
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0";

/// Request body for [`HttpSender::send`].
#[derive(Debug, Clone, Default)]
pub enum Body {
    #[default]
    None,
    /// application/x-www-form-urlencoded pairs
    Pairs(Vec<(String, String)>),
    /// raw body string
    Raw(String),
    /// JSON value
    Json(serde_json::Value),
}

/// A completed HTTP exchange (request + response), carrying everything
/// needed for `dump_request` / `dump_response` report output.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub method: String,
    pub url: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Option<String>,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub text: String,
}

impl HttpResponse {
    /// Render the request part, same format as the Python `dump_request`.
    pub fn dump_request(&self) -> String {
        let mut body = String::new();
        body += &self.method;
        body += " ";
        body += &format!("{} HTTP/1.1", self.url);
        body += "\n";
        for (header, value) in &self.request_headers {
            body += &format!("{header}: {value}\n");
        }
        if let Some(req_body) = &self.request_body {
            body += &format!("\n{req_body}");
        }
        body
    }

    /// Render the response part, same format as the Python `dump_response`.
    pub fn dump_response(&self) -> String {
        let mut body = String::from("HTTP /1.1 ");
        body += &self.status.to_string();
        body += " \n";
        for (header, value) in &self.headers {
            body += &format!("{header}: {value}\n");
        }
        body += "\n\n";
        body += &self.text;
        body
    }
}

/// Shared HTTP client, equivalent to the Python `httpSender`.
pub struct HttpSender {
    client: reqwest::Client,
    timeout: u64,
    headers: HashMap<String, String>,
    cookies: HashMap<String, String>,
    random_agents: bool,
    allow_redirects: bool,
    json_mode: bool,
    delay: u64,
    pub count: AtomicUsize,
    agents: Vec<&'static str>,
}

impl HttpSender {
    #[allow(clippy::too_many_arguments)] // mirrors the Python httpSender options
    pub fn new(
        timeout: u64,
        headers: HashMap<String, String>,
        cookies: HashMap<String, String>,
        random_agents: bool,
        proxy: Option<String>,
        allow_redirects: bool,
        json_mode: bool,
        delay: u64,
    ) -> Self {
        let client = build_client(proxy.as_deref(), allow_redirects, timeout);
        HttpSender {
            client,
            timeout,
            headers,
            cookies,
            random_agents,
            allow_redirects,
            json_mode,
            delay,
            count: AtomicUsize::new(0),
            agents: data::agents(),
        }
    }

    fn user_agent(&self) -> &str {
        if self.random_agents {
            self.agents
                .choose(&mut rand::thread_rng())
                .map(|s| s as &str)
                .unwrap_or(DEFAULT_UA)
        } else {
            DEFAULT_UA
        }
    }

    /// Send a request using the user options. Equivalent to `httpSender.send`.
    #[allow(clippy::too_many_arguments)] // mirrors the Python httpSender.send
    pub async fn send(
        &self,
        url: &str,
        method: &str,
        body: Body,
        extra_headers: HashMap<String, String>,
        org: bool,
        timeout: Option<u64>,
        json: Option<serde_json::Value>,
    ) -> Result<HttpResponse, reqwest::Error> {
        let mut headers = extra_headers;
        if !headers.keys().any(|h| h.eq_ignore_ascii_case("user-agent")) {
            headers.insert("User-agent".to_string(), self.user_agent().to_string());
        }
        for (h, v) in &self.headers {
            // Intended behavior of the Python quirk: a `Cookie` header passed
            // via -H is ignored when -C cookies are set.
            if h.eq_ignore_ascii_case("cookie") && !self.cookies.is_empty() {
                continue;
            }
            headers.entry(h.clone()).or_insert_with(|| v.clone());
        }

        let timeout = match timeout {
            Some(10) | None => self.timeout,
            Some(t) => t,
        };

        let mut url = url.to_string();
        let mut body = body;

        // convert body to parameters (the `org` option)
        if org {
            let empty = matches!(&body, Body::None)
                || matches!(&body, Body::Raw(s) if s.is_empty())
                || matches!(&body, Body::Pairs(p) if p.is_empty());
            if method.eq_ignore_ascii_case("GET") {
                if !empty {
                    let pairs = match std::mem::take(&mut body) {
                        Body::Raw(s) => post_data(&s),
                        Body::Pairs(p) => p,
                        other => {
                            body = other;
                            Vec::new()
                        }
                    };
                    if !pairs.is_empty() {
                        if let Ok(mut u) = url::Url::parse(&url) {
                            let mut ser = url::form_urlencoded::Serializer::new(String::new());
                            for (k, v) in &pairs {
                                ser.append_pair(k, v);
                            }
                            u.set_query(Some(&ser.finish()));
                            url = u.to_string();
                        }
                        body = Body::None;
                    }
                }
            } else if empty {
                let pairs = post_data(&url);
                if !pairs.is_empty() {
                    body = Body::Pairs(pairs);
                    if let Ok(mut u) = url::Url::parse(&url) {
                        u.set_query(None);
                        url = u.to_string();
                    }
                }
            }
        }

        let mut json_body = json;
        if !method.eq_ignore_ascii_case("GET") && self.json_mode {
            let mut map = match json_body.take() {
                Some(serde_json::Value::Object(m)) => m,
                _ => serde_json::Map::new(),
            };
            match std::mem::take(&mut body) {
                Body::Pairs(p) => {
                    for (k, v) in p {
                        map.insert(k, serde_json::Value::String(v));
                    }
                }
                Body::Raw(s) => {
                    for (k, v) in post_data(&s) {
                        map.insert(k, serde_json::Value::String(v));
                    }
                }
                _ => {}
            }
            json_body = Some(serde_json::Value::Object(map));
            body = Body::None;
        }

        let method = match reqwest::Method::from_bytes(method.to_uppercase().as_bytes()) {
            Ok(m) => m,
            Err(_) => reqwest::Method::GET,
        };

        let mut builder = self.client.request(method.clone(), &url);
        builder = builder.timeout(Duration::from_secs(timeout));
        for (h, v) in &headers {
            builder = builder.header(h, v);
        }
        if !self.cookies.is_empty() {
            let cookie_header = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder = builder.header("Cookie", cookie_header);
        }

        let body_repr = match &body {
            Body::Pairs(p) => Some(
                p.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("&"),
            ),
            Body::Raw(s) => Some(s.clone()),
            _ => None,
        };
        builder = match body {
            Body::None => builder,
            Body::Pairs(p) => builder.form(&p),
            Body::Raw(s) => builder.body(s),
            Body::Json(v) => builder.json(&v),
        };
        if let Some(v) = json_body {
            builder = builder.json(&v);
        }

        let request = builder.build()?;
        let request_headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let request_body = request
            .body()
            .and_then(|b| b.as_bytes())
            .map(|b| String::from_utf8_lossy(b).to_string())
            .or(body_repr);

        let response = self.client.execute(request).await?;

        if self.delay > 0 {
            tokio::time::sleep(Duration::from_secs(self.delay)).await;
        }
        self.count.fetch_add(1, Ordering::Relaxed);

        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let text = response.text().await.unwrap_or_default();

        Ok(HttpResponse {
            method: method.to_string(),
            url,
            request_headers,
            request_body,
            status,
            headers: resp_headers,
            text,
        })
    }

    /// Convenience wrapper matching the most common module call shape.
    pub async fn send_simple(
        &self,
        url: &str,
        method: &str,
        org: bool,
    ) -> Result<HttpResponse, reqwest::Error> {
        self.send(url, method, Body::None, HashMap::new(), org, None, None)
            .await
    }

    /// Send a request with custom options (without user options).
    /// Equivalent to `httpSender.custom`.
    pub async fn custom(
        &self,
        url: &str,
        method: &str,
        headers: HashMap<String, String>,
        timeout: u64,
        json: Option<serde_json::Value>,
    ) -> Result<HttpResponse, reqwest::Error> {
        let client = build_client(None, self.allow_redirects, timeout);
        if self.delay > 0 {
            tokio::time::sleep(Duration::from_secs(self.delay)).await;
        }
        let method = reqwest::Method::from_bytes(method.to_uppercase().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let mut builder = client.request(method.clone(), url).timeout(Duration::from_secs(timeout));
        for (h, v) in &headers {
            builder = builder.header(h, v);
        }
        if let Some(v) = json {
            builder = builder.json(&v);
        }
        let request = builder.build()?;
        let request_headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let request_body = request
            .body()
            .and_then(|b| b.as_bytes())
            .map(|b| String::from_utf8_lossy(b).to_string());
        let response = client.execute(request).await?;
        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let text = response.text().await.unwrap_or_default();
        Ok(HttpResponse {
            method: method.to_string(),
            url: url.to_string(),
            request_headers,
            request_body,
            status,
            headers: resp_headers,
            text,
        })
    }
}

fn build_client(proxy: Option<&str>, allow_redirects: bool, timeout: u64) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(timeout))
        .redirect(if allow_redirects {
            Policy::default()
        } else {
            Policy::none()
        });
    if let Some(p) = proxy {
        if let Ok(proxy) = reqwest::Proxy::all(p) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}
