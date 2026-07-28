use scraper::{Html, Node};

/// Where a reflected pattern was found, mirroring the Python `HTMLMatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtmlMatch {
    TagName,
    EndTag,
    AttrName,
    AttrValue,
    Comment,
    Text,
}

impl HtmlMatch {
    pub fn value(&self) -> &'static str {
        match self {
            HtmlMatch::TagName => "tagname",
            HtmlMatch::EndTag => "endtag",
            HtmlMatch::AttrName => "attrname",
            HtmlMatch::AttrValue => "attrvalue",
            HtmlMatch::Comment => "comment",
            HtmlMatch::Text => "text",
        }
    }
}

/// Find every context where `pattern` appears in the document,
/// equivalent to the Python `HTMLocation` parser.
pub fn find_locations(html: &str, pattern: &str) -> Vec<HtmlMatch> {
    let document = Html::parse_document(html);
    let mut out = Vec::new();
    for node in document.tree.root().descendants() {
        match node.value() {
            Node::Element(el) => {
                if el.name().contains(pattern) {
                    out.push(HtmlMatch::TagName);
                }
                for (name, value) in el.attrs() {
                    if name.contains(pattern) {
                        out.push(HtmlMatch::AttrName);
                    }
                    if value.contains(pattern) {
                        out.push(HtmlMatch::AttrValue);
                    }
                }
            }
            Node::Text(text) => {
                if text.text.contains(pattern) {
                    out.push(HtmlMatch::Text);
                }
            }
            Node::Comment(comment) if comment.comment.contains(pattern) => {
                out.push(HtmlMatch::Comment);
            }
            _ => {}
        }
    }
    out
}

/// Build an XPath-style match pattern (`//tag[@a="v"][@b]`) from the first
/// element found in `fragment`, mirroring the Python `HTMLForXpath` parser.
pub fn xpath_for_fragment(fragment: &str) -> String {
    let document = Html::parse_fragment(fragment);
    let mut fallback: Option<String> = None;
    for node in document.tree.root().descendants() {
        if let Node::Element(el) = node.value() {
            let build = |el: &scraper::node::Element| {
                let mut out = format!("//{}", el.name());
                for (name, value) in el.attrs() {
                    if value.is_empty() {
                        out += &format!("[@{name}]");
                    } else {
                        out += &format!("[@{name}=\"{}\"]", value.replace('"', ""));
                    }
                }
                out
            };
            // skip the implicit html/head/body wrappers html5ever inserts,
            // so the pattern targets the first tag of the payload itself
            if matches!(el.name(), "html" | "head" | "body") {
                if el.attrs().next().is_some() && fallback.is_none() {
                    fallback = Some(build(el));
                }
                continue;
            }
            return build(el);
        }
    }
    fallback.unwrap_or_else(|| "//".to_string())
}

/// Evaluate the simple XPath-style patterns produced by the payload
/// generator (`//tag[@a="v"][@b]`, `//*[@a="v"]`) against a document.
pub fn xpath_matches(html: &str, pattern: &str) -> bool {
    let Some(rest) = pattern.strip_prefix("//") else {
        return false;
    };
    let tag_end = rest.find('[').unwrap_or(rest.len());
    let tag = &rest[..tag_end];
    let attr_part = &rest[tag_end..];

    // parse [@k="v"] / [@k] groups
    let mut attrs: Vec<(String, Option<String>)> = Vec::new();
    let mut chars = attr_part;
    while let Some(start) = chars.find("[@") {
        let Some(end) = chars[start..].find(']') else {
            break;
        };
        let inner = &chars[start + 2..start + end];
        if let Some((k, v)) = inner.split_once('=') {
            attrs.push((k.to_string(), Some(v.trim_matches('"').to_string())));
        } else {
            attrs.push((inner.to_string(), None));
        }
        chars = &chars[start + end + 1..];
    }

    let document = Html::parse_document(html);
    for node in document.tree.root().descendants() {
        if let Node::Element(el) = node.value() {
            if tag != "*" && el.name() != tag {
                continue;
            }
            let el_attrs: std::collections::HashMap<&str, &str> = el.attrs().collect();
            let all_match = attrs.iter().all(|(k, v)| match el_attrs.get(k.as_str()) {
                Some(actual) => match v {
                    Some(expected) => *actual == expected,
                    None => true,
                },
                None => false,
            });
            if all_match {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_text_context() {
        let locs = find_locations("<html><body>hello scanabcr world</body></html>", "scanabcr");
        assert!(locs.contains(&HtmlMatch::Text));
    }

    #[test]
    fn finds_attr_value_context() {
        let locs = find_locations("<input value=\"scanabcr\">", "scanabcr");
        assert!(locs.contains(&HtmlMatch::AttrValue));
    }

    #[test]
    fn finds_comment_context() {
        let locs = find_locations("<html><!-- scanabcr --></html>", "scanabcr");
        assert!(locs.contains(&HtmlMatch::Comment));
    }

    #[test]
    fn matches_attr_xpath() {
        assert!(xpath_matches(
            "<svg onload=\"confirm(1)\">x</svg>",
            "//*[@onload=\"confirm(1)\"]"
        ));
        assert!(!xpath_matches(
            "<svg onload=\"confirm(2)\">x</svg>",
            "//*[@onload=\"confirm(1)\"]"
        ));
    }

    #[test]
    fn builds_xpath_for_fragment() {
        let xp = xpath_for_fragment("\"><img src=a onerror=alert(1)>");
        assert!(xp.starts_with("//img["), "unexpected: {xp}");
        assert!(xp.contains("[@src=\"a\"]"), "unexpected: {xp}");
        assert!(xp.contains("[@onerror=\"alert(1)\"]"), "unexpected: {xp}");
    }
}
