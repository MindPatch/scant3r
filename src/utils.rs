use rand::Rng;
use url::Url;

/// Generate a random uppercase string.
pub fn random_str(num: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..num).map(|_| rng.gen_range(b'A'..=b'Z') as char).collect()
}

fn url_encode_all(data: &str) -> String {
    let mut out = String::new();
    for byte in data.bytes() {
        out.push_str(&format!("%{:02x}", byte));
    }
    out
}

/// From plain text to (multi-round) url encoding.
///
/// ```
/// assert_eq!(scant3r::utils::urlencoder("<", 1), "%3c");
/// assert_eq!(scant3r::utils::urlencoder("<", 2), "%25%33%63");
/// ```
pub fn urlencoder(data: &str, many: usize) -> String {
    let mut data = data.to_string();
    for _ in 0..many {
        data = url_encode_all(&data);
    }
    data
}

/// Remove duplicate elements, keeping first-occurrence order.
pub fn remove_dups(l: &[String]) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for x in l {
        if !v.contains(x) {
            v.push(x.clone());
        }
    }
    v
}

/// Remove duplicate urls and entries without a host.
pub fn remove_dups_urls(l: &[String]) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for i in l {
        let has_host = Url::parse(i).map(|u| u.host_str().is_some()).unwrap_or(false);
        if has_host && !v.contains(i) {
            v.push(i.clone());
        }
    }
    v
}

/// Parse a query string like Python's `dict(parse_qsl(q, keep_blank_values))`:
/// first-occurrence order, last value wins, optionally dropping blank values.
fn query_to_map(query: &str, keep_blank_values: bool) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let (k, v) = (k.into_owned(), v.into_owned());
        if !keep_blank_values && v.is_empty() {
            continue;
        }
        if let Some(entry) = out.iter_mut().find(|(ek, _)| *ek == k) {
            entry.1 = v;
        } else {
            out.push((k, v));
        }
    }
    out
}

fn encode_query(pairs: &[(String, String)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

/// Append text to every parameter name.
///
/// `http://google.com/?name=` + `PAYLOAD` -> `http://google.com/?namePAYLOAD=`
pub fn insert_to_params_name(url: &str, text: &str) -> String {
    let Ok(parsed) = Url::parse(url) else {
        return url.to_string();
    };
    let pairs = query_to_map(parsed.query().unwrap_or(""), false);
    let pairs: Vec<(String, String)> =
        pairs.into_iter().map(|(k, v)| (format!("{k}{text}"), v)).collect();
    let mut new_url = parsed;
    new_url.set_query(Some(&encode_query(&pairs)));
    new_url.to_string()
}

/// Append text to parameter values (only when `parameter` exists).
/// `remove_content` replaces the values instead.
pub fn insert_to_custom_params(
    url: &str,
    parameter: &str,
    text: &str,
    remove_content: bool,
) -> String {
    let Ok(parsed) = Url::parse(url) else {
        return url.to_string();
    };
    let pairs = query_to_map(parsed.query().unwrap_or(""), false);
    if !pairs.iter().any(|(k, _)| k == parameter) {
        return url.to_string();
    }
    // Ported quirk: the Python version mutates *every* parameter value.
    let pairs: Vec<(String, String)> = pairs
        .into_iter()
        .map(|(k, v)| {
            if remove_content {
                (k, text.to_string())
            } else {
                (k, format!("{v}{text}"))
            }
        })
        .collect();
    let mut new_url = parsed;
    new_url.set_query(Some(&encode_query(&pairs)));
    new_url.to_string()
}

/// Return the query string of the url.
pub fn dump_params(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.query().map(|q| q.to_string()))
        .unwrap_or_default()
}

/// Join a path onto an url.
pub fn add_path(url: &str, path: &str) -> String {
    Url::parse(url)
        .and_then(|base| base.join(path))
        .map(|u| u.to_string())
        .unwrap_or_else(|_| url.to_string())
}

/// One URL per parameter, with `text` appended to its value
/// (or replacing it when `remove_content` is set).
///
/// Ported quirk: the Python version mutates the shared dict cumulatively,
/// so the n-th URL also carries the modifications of the previous ones.
pub fn insert_to_params_urls(url: &str, text: &str, remove_content: bool) -> Vec<String> {
    let Ok(parsed) = Url::parse(url) else {
        return Vec::new();
    };
    let mut pairs = query_to_map(parsed.query().unwrap_or(""), true);
    let originals = pairs.clone();
    let mut urls = Vec::new();
    for (param, value) in originals {
        if let Some(entry) = pairs.iter_mut().find(|(k, _)| *k == param) {
            entry.1 = if remove_content {
                text.to_string()
            } else {
                format!("{value}{text}")
            };
        }
        let mut new_url = parsed.clone();
        new_url.set_query(Some(&encode_query(&pairs)));
        urls.push(new_url.to_string());
    }
    urls
}

/// Insert text after each path segment.
pub fn insert_text_to_urlpath(url: &str, text: &str) -> Vec<String> {
    let path = Url::parse(url).map(|u| u.path().to_string()).unwrap_or_default();
    let mut new_urls = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        if let Some(idx) = url.find(segment) {
            let mut u = url.to_string();
            u.insert_str(idx + segment.len(), text);
            new_urls.push(u);
        }
    }
    new_urls
}

/// Convert url parameters (or a bare query string) into key/value pairs
/// (for cookies, request body parameters).
pub fn post_data(url: &str) -> Vec<(String, String)> {
    let query = if let Ok(parsed) = Url::parse(url) {
        parsed.query().unwrap_or("").to_string()
    } else {
        url.trim_start_matches('?').to_string()
    };
    query_to_map(&query, false)
}

/// Convert a header string into key/value pairs.
///
/// ```
/// let h = scant3r::utils::extract_headers("User-agent: YES\nHacker: 3");
/// assert_eq!(h["User-agent"], "YES");
/// assert_eq!(h["Hacker"], "3");
/// ```
pub fn extract_headers(headers: &str) -> std::collections::HashMap<String, String> {
    let re = regex::Regex::new(r"^(.*):\s(.*)$").unwrap();
    let mut out = std::collections::HashMap::new();
    for line in headers.replace("\\n", "\n").lines() {
        if let Some(cap) = re.captures(line) {
            let mut value = cap[2].to_string();
            if value.ends_with(',') {
                value.pop();
            }
            out.insert(cap[1].to_string(), value);
        }
    }
    out
}

/// Convert a cookie string into key/value pairs.
pub fn extract_cookie(cookies: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let cookies = cookies.trim();
    if cookies.is_empty() {
        return out;
    }
    for cookie in cookies.split(';') {
        let cookie = cookie.trim();
        let mut parts = cookie.split('=');
        if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
            // Ported quirk: Python takes parts[1], ignoring any further '=' segments.
            out.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    out
}

/// Insert `new_text` right after the first occurrence of `find_this`.
pub fn insert_after(text: &str, find_this: &str, new_text: &str) -> String {
    match text.find(find_this) {
        Some(i) => {
            let end = i + find_this.len();
            format!("{}{}{}", &text[..end], new_text, &text[end..])
        }
        None => text.to_string(),
    }
}
