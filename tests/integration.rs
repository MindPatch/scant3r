use std::sync::Arc;

use indicatif::ProgressBar;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use scant3r::http::HttpSender;
use scant3r::modules::{Module, ScanContext};
use scant3r::opts::ScanOptions;

/// A deliberately vulnerable test server: reflects every query value
/// unescaped into the HTML body, and "evaluates" the SSTI template
/// expressions the scanner probes for.
async fn start_vuln_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let Ok(n) = socket.read(&mut buf).await else {
                    return;
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                let query = path.split_once('?').map(|x| x.1).unwrap_or("").to_string();
                let mut values = String::new();
                for (_, v) in url::form_urlencoded::parse(query.as_bytes()) {
                    values.push_str(&v);
                }
                // "server-side template evaluation"
                let evaluated = values
                    .replace("{{2*5}}", "10")
                    .replace("<%= 2*5%>", "10")
                    .replace("${2*5}", "10");
                let body = format!("<html><body>results for: {evaluated}</body></html>");
                let res = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(res.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

fn test_opts(url: &str) -> Arc<ScanOptions> {
    Arc::new(ScanOptions {
        urls: vec![url.to_string()],
        url: url.to_string(),
        exit_after: 500,
        callback_time: 0.0,
        convert_body: false,
        output: String::new(),
        headers: Default::default(),
        cookies: Default::default(),
        log_mode: 2,
        delay: 0,
        methods: vec!["GET".to_string()],
        modules: vec![],
        json: false,
        proxy: None,
        allow_redirects: false,
        random_agents: false,
        threads: 10,
        timeout: 10,
    })
}

fn test_ctx(opts: Arc<ScanOptions>) -> Arc<ScanContext> {
    let http = Arc::new(HttpSender::new(
        opts.timeout,
        opts.headers.clone(),
        opts.cookies.clone(),
        false,
        None,
        false,
        false,
        0,
    ));
    Arc::new(ScanContext {
        http,
        opts,
        progress: ProgressBar::hidden(),
    })
}

#[tokio::test]
async fn ssti_finds_vulnerability() {
    let base = start_vuln_server().await;
    let url = format!("{base}/?q=1");
    let opts = test_opts(&url);
    let ctx = test_ctx(opts);
    let report = scant3r::modules::ssti::Ssti
        .run(&ctx, &url)
        .await
        .expect("ssti run failed");
    assert_eq!(report["module"], "ssti");
    assert_eq!(report["matching"], "scan10tr");
}

#[tokio::test]
async fn xss_finds_reflected_vulnerability() {
    let base = start_vuln_server().await;
    let url = format!("{base}/?q=1");
    let opts = test_opts(&url);
    let ctx = test_ctx(opts);
    let report = scant3r::modules::xss::Xss
        .run(&ctx, &url)
        .await
        .expect("xss run failed");
    assert_eq!(report["module"], "xss");
    let found = report["found"].as_array().expect("found must be an array");
    assert!(!found.is_empty(), "xss module should report a finding");
    assert!(found.iter().any(|f| f["payload"].as_str().unwrap_or("").contains("onload")));
}

#[tokio::test]
async fn http_sender_sends_headers_and_cookies() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 65536];
        let n = socket.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let body = req.split("\r\n\r\n").next().unwrap_or("").to_string();
        let res = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = socket.write_all(res.as_bytes()).await;
    });

    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Test".to_string(), "yes".to_string());
    let mut cookies = std::collections::HashMap::new();
    cookies.insert("session".to_string(), "abc".to_string());
    let http = HttpSender::new(10, headers, cookies, false, None, false, false, 0);
    let res = http
        .send_simple(&format!("http://{addr}/"), "GET", false)
        .await
        .expect("request failed");
    assert_eq!(res.status, 200);
    assert!(res.text.contains("x-test: yes"), "custom header missing: {}", res.text);
    assert!(res.text.contains("cookie: session=abc"), "cookie missing: {}", res.text);
    assert!(res.text.contains("user-agent:"), "UA missing: {}", res.text);
}
