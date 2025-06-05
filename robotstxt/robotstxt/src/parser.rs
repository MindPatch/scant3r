// Copyright 2020 Folyd
// Copyright 1999 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use crate::RobotsParseHandler;

#[derive(Eq, PartialEq)]
/// A enum represents key types in robotstxt.
pub enum ParseKeyType {
    // Generic highlevel fields.
    UserAgent,
    Sitemap,

    // Fields within a user-agent.
    Allow,
    Disallow,

    /// Unrecognized field; kept as-is. High number so that additions to the
    /// enumeration above does not change the serialization.
    Unknown = 128,
}

/// A robots.txt has lines of key/value pairs. A ParsedRobotsKey represents
/// a key.
///
/// This class can parse a text-representation (including common typos)
/// and represent them as an enumeration which allows for faster processing
/// afterwards.
/// For unparsable keys, the original string representation is kept.
pub struct ParsedRobotsKey {
    type_: ParseKeyType,
    key_text: String,
    /// Allow for typos such as DISALOW in robots.txt.
    allow_typo: bool,
}

impl Default for ParsedRobotsKey {
    fn default() -> Self {
        ParsedRobotsKey {
            type_: ParseKeyType::Unknown,
            allow_typo: true,
            key_text: String::new(),
        }
    }
}

impl ParsedRobotsKey {
    /// Parse given key text. Does not copy the text, so the text_key must stay
    /// valid for the object's life-time or the next `parse()` call.
    pub fn parse(&mut self, key: &str) {
        if self.validate_key(key, &["user-agent"], Some(&["useragent", "user agent"])) {
            self.type_ = ParseKeyType::UserAgent;
        } else if self.validate_key(key, &["allow"], None) {
            self.type_ = ParseKeyType::Allow;
        } else if self.validate_key(
            key,
            &["disallow"],
            Some(&["dissallow", "dissalow", "disalow", "diasllow", "disallaw"]),
        ) {
            self.type_ = ParseKeyType::Disallow;
        } else if self.validate_key(key, &["sitemap", "site-map"], None) {
            self.type_ = ParseKeyType::Sitemap;
        } else {
            self.type_ = ParseKeyType::Unknown;
            self.key_text = key.to_string();
        }
    }

    /// Returns the type of key.
    pub fn get_type(&self) -> &ParseKeyType {
        &self.type_
    }

    /// If this is an unknown key, get the text.
    pub fn get_unknown_text(&self) -> String {
        self.key_text.to_string()
    }

    fn validate_key(&self, key: &str, targets: &[&str], typo_targets: Option<&[&str]>) -> bool {
        let key = key.to_lowercase();
        let check = |target: &&str| key.starts_with(&target.to_lowercase());
        targets.iter().any(check)
            || (typo_targets.is_some()
                && self.allow_typo
                && typo_targets.unwrap().iter().any(check))
    }
}

/// A robotstxt parser.
pub struct RobotsTxtParser<'a, Handler: RobotsParseHandler> {
    robots_body: &'a str,
    handler: &'a mut Handler,
}

impl<'a, Handler: RobotsParseHandler> RobotsTxtParser<'a, Handler> {
    pub fn new(robots_body: &'a str, handler: &'a mut Handler) -> Self {
        RobotsTxtParser {
            robots_body,
            handler,
        }
    }

    /// Parse body of this Parser's robots.txt and emit parse callbacks. This will accept
    /// typical typos found in robots.txt, such as 'disalow'.
    ///
    /// Note, this function will accept all kind of input but will skip
    /// everything that does not look like a robots directive.
    pub fn parse(&mut self) {
        let utf_bom = [0xEF, 0xBB, 0xBF];
        // Certain browsers limit the URL length to 2083 bytes. In a robots.txt, it's
        // fairly safe to assume any valid line isn't going to be more than many times
        // that max url length of 2KB. We want some padding for
        // UTF-8 encoding/nulls/etc. but a much smaller bound would be okay as well.
        // If so, we can ignore the chars on a line past that.
        let max_line_len = 2083 * 8;
        let mut line_num = 0;
        let mut bom_pos = 0;
        let mut last_was_carriage_return = false;
        self.handler.handle_robots_start();

        let mut start = 0;
        let mut end = 0;
        // We should skip the rest part which exceed max_line_len
        // in the current line.
        let mut skip_exceed = 0;
        for (ch, char_len_utf8) in self
            .robots_body
            .chars()
            .map(|ch| (ch as usize, ch.len_utf8()))
        {
            // Google-specific optimization: UTF-8 byte order marks should never
            // appear in a robots.txt file, but they do nevertheless. Skipping
            // possible BOM-prefix in the first bytes of the input.
            if bom_pos < utf_bom.len() && ch == utf_bom[bom_pos] {
                bom_pos += 1;
                start += char_len_utf8;
                end += char_len_utf8;
                continue;
            }
            bom_pos = utf_bom.len();

            if ch != 0x0A && ch != 0x0D {
                // Non-line-ending char case.
                // Put in next spot on current line, as long as there's room.
                if (end - start) < max_line_len - 1 {
                    end += char_len_utf8;
                } else {
                    skip_exceed += 1;
                }
            } else {
                // Line-ending character char case.
                // Only emit an empty line if this was not due to the second character
                // of the DOS line-ending \r\n .
                let is_crlf_continuation = end == start && last_was_carriage_return && ch == 0x0A;
                if !is_crlf_continuation {
                    line_num += 1;
                    self.parse_and_emit_line(line_num, &self.robots_body[start..end]);
                }
                // Add skip_exceed to skip those chars.
                end += skip_exceed + char_len_utf8;
                start = end;
                last_was_carriage_return = ch == 0x0D;
                skip_exceed = 0;
            }
        }
        line_num += 1;
        self.parse_and_emit_line(line_num, &self.robots_body[start..end]);
        self.handler.handle_robots_end();
    }

    /// Attempts to parse a line of robots.txt into a key/value pair.
    ///
    /// On success, the parsed key and value, and true, are returned. If parsing is
    /// unsuccessful, `parse_key_value` returns two empty strings and false.
    pub fn parse_key_value(line: &str) -> (&str, &str, bool) {
        let mut line = line;
        // Remove comments from the current robots.txt line.
        if let Some(comment) = line.find('#') {
            line = &line[..comment].trim();
        }

        // Rules must match the following pattern:
        //   <key>[ \t]*:[ \t]*<value>
        let mut sep = line.find(':');
        if sep.is_none() {
            // Google-specific optimization: some people forget the colon, so we need to
            // accept whitespace in its stead.
            let white = " \t";

            sep = line.find(|c| white.contains(c));
            if let Some(sep) = sep {
                let val = &line[sep..].trim();
                if val.is_empty() || val.find(|c| white.contains(c)).is_some() {
                    // We only accept whitespace as a separator if there are exactly two
                    // sequences of non-whitespace characters.  If we get here, there were
                    // more than 2 such sequences since we stripped trailing whitespace
                    // above.
                    return ("", "", false);
                }
            }
        }

        if let Some(sep) = sep {
            // Key starts at beginning of line.
            let key = &line[..sep];
            if key.is_empty() {
                return ("", "", false);
            }

            // Value starts after the separator.
            let value = &line[(sep + 1)..];
            (key.trim(), value.trim(), true)
        } else {
            // Couldn't find a separator.
            ("", "", false)
        }
    }

    pub fn need_escape_value_for_key(key: &ParsedRobotsKey) -> bool {
        !matches!(
            key.get_type(),
            ParseKeyType::UserAgent | ParseKeyType::Sitemap
        )
    }

    fn parse_and_emit_line(&mut self, current_line: u32, line: &str) {
        match Self::parse_key_value(line) {
            (_, _, false) => {}
            (string_key, value, true) => {
                let mut key = ParsedRobotsKey::default();
                key.parse(string_key);
                if Self::need_escape_value_for_key(&key) {
                    let value = escape_pattern(value);
                    self.emit(current_line, &key, &value);
                } else {
                    self.emit(current_line, &key, value);
                }
            }
        }
    }

    fn emit(&mut self, line: u32, key: &ParsedRobotsKey, value: &str) {
        match key.get_type() {
            ParseKeyType::UserAgent => self.handler.handle_user_agent(line, value),
            ParseKeyType::Sitemap => self.handler.handle_sitemap(line, value),
            ParseKeyType::Allow => self.handler.handle_allow(line, value),
            ParseKeyType::Disallow => self.handler.handle_disallow(line, value),
            ParseKeyType::Unknown => {
                self.handler
                    .handle_unknown_action(line, &key.get_unknown_text(), value)
            }
        }
    }
}

const HEX_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

/// Canonicalize the allowed/disallowed path patterns.
///
/// UTF-8 multibyte sequences (and other out-of-range ASCII values) are percent-encoded,
/// and any existing percent-encoded values have their hex values normalised to uppercase.
///
/// For example:
/// ```txt
///     /SanJoséSellers ==> /Sanjos%C3%A9Sellers
///     %aa ==> %AA
/// ```
/// If the given path pattern is already adequately escaped,
/// the original string is returned unchanged.
pub fn escape_pattern(path: &str) -> String {
    let mut num_to_escape = 0;
    let mut need_capitalize = false;

    // First, scan the buffer to see if changes are needed. Most don't.
    let mut chars = path.bytes();
    loop {
        match chars.next() {
            // (a) % escape sequence.
            Some(c) if c as char == '%' => {
                match (
                    chars.next().map(|c| c as char),
                    chars.next().map(|c| c as char),
                ) {
                    (Some(c1), Some(c2)) if c1.is_digit(16) && c2.is_digit(16) => {
                        if c1.is_ascii_lowercase() || c2.is_ascii_lowercase() {
                            need_capitalize = true;
                        }
                    }
                    _ => {}
                }
            }
            Some(c) if c >= 0x80 => {
                // (b) needs escaping.
                num_to_escape += 1;
            }
            o => {
                // (c) Already escaped and escape-characters normalized (eg. %2f -> %2F).
                if o.is_none() {
                    break;
                }
            }
        }
    }
    // Return if no changes needed.
    if num_to_escape == 0 && !need_capitalize {
        return path.to_string();
    }

    let mut dest = String::with_capacity(num_to_escape * 2 + path.len() + 1);
    chars = path.bytes();
    loop {
        match chars.next() {
            Some(c) if c as char == '%' => {
                // (a) Normalize %-escaped sequence (eg. %2f -> %2F).
                match (
                    chars.next().map(|c| c as char),
                    chars.next().map(|c| c as char),
                ) {
                    (Some(c1), Some(c2)) if c1.is_digit(16) && c2.is_digit(16) => {
                        dest.push(c as char);
                        dest.push(c1.to_ascii_uppercase());
                        dest.push(c2.to_ascii_uppercase());
                    }
                    _ => {}
                }
            }
            Some(c) if c >= 0x80 => {
                // (b) %-escape octets whose highest bit is set. These are outside the ASCII range.
                dest.push('%');
                dest.push(HEX_DIGITS[(c as usize >> 4) & 0xf]);
                dest.push(HEX_DIGITS[c as usize & 0xf]);
            }
            Some(c) => {
                // (c) Normal character, no modification needed.
                dest.push(c as char);
            }
            None => {
                break;
            }
        }
    }
    dest
}

#[cfg(test)]
mod tests {
    #![allow(unused_variables)]

    use crate::parser::*;
    use crate::RobotsParseHandler;

    struct FooHandler;

    impl RobotsParseHandler for FooHandler {
        fn handle_robots_start(&mut self) {
            unimplemented!()
        }

        fn handle_robots_end(&mut self) {
            unimplemented!()
        }

        fn handle_user_agent(&mut self, line_num: u32, user_agent: &str) {
            unimplemented!()
        }

        fn handle_allow(&mut self, line_num: u32, value: &str) {
            unimplemented!()
        }

        fn handle_disallow(&mut self, line_num: u32, value: &str) {
            unimplemented!()
        }

        fn handle_sitemap(&mut self, line_num: u32, value: &str) {
            unimplemented!()
        }

        fn handle_unknown_action(&mut self, line_num: u32, action: &str, value: &str) {
            unimplemented!()
        }
    }

    #[test]
    fn test_parse_key_value<'a>() {
        type Target<'a> = RobotsTxtParser<'a, FooHandler>;
        let negative = ("", "", false);
        let positive = ("User-agent", "Googlebot", true);

        assert_eq!(negative, Target::parse_key_value("# "));
        assert_eq!(negative, Target::parse_key_value("# User-agent: Googlebot"));

        assert_eq!(positive, Target::parse_key_value("User-agent: Googlebot"));
        assert_eq!(positive, Target::parse_key_value("User-agent  Googlebot"));
        assert_eq!(positive, Target::parse_key_value("User-agent \t Googlebot"));
        assert_eq!(positive, Target::parse_key_value("User-agent\tGooglebot"));
        assert_eq!(
            positive,
            Target::parse_key_value("User-agent: Googlebot # 123")
        );
        assert_eq!(
            positive,
            Target::parse_key_value("User-agent\tGooglebot # 123")
        );
    }

    #[test]
    fn test_escape_pattern() {
        assert_eq!(
            "http://www.example.com",
            &escape_pattern("http://www.example.com")
        );
        assert_eq!("/a/b/c", &escape_pattern("/a/b/c"));
        assert_eq!("%AA", &escape_pattern("%aa"));
        assert_eq!("%AA", &escape_pattern("%aA"));
        assert_eq!("/Sanjos%C3%A9Sellers", &escape_pattern("/SanjoséSellers"));
        assert_eq!("%C3%A1", &escape_pattern("á"));
    }
}
