use console::style;

/// Build the console block for a finding: a blank line, the styled
/// message lines, and an optional highlighted snippet of the response.
pub fn finding_block(lines: &[String], snippet: Option<(&str, &str)>) -> String {
    let mut out = String::from("\n");
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    if let Some((text, needle)) = snippet {
        out.push_str(&highlight_snippet(text, needle, 20));
        out.push('\n');
    }
    out
}

/// Extract the context around the first matches of `needle` in `text`
/// (same slicing logic as the Python modules) with the match in bold red.
pub fn highlight_snippet(text: &str, needle: &str, before: usize) -> String {
    let mut out = String::new();
    for (start, end) in match_bounds(text, needle) {
        let from = start.saturating_sub(before);
        let slice = &text[from..end];
        if let Some(pos) = slice.find(needle) {
            out.push_str(&style(&slice[..pos]).dim().to_string());
            out.push_str(&style(needle).red().bold().to_string());
            out.push_str(&style(&slice[pos + needle.len()..]).dim().to_string());
        } else {
            out.push_str(&style(slice).dim().to_string());
        }
    }
    out
}

/// (start, end) byte offsets of every occurrence of `needle` in `text`.
pub fn match_bounds(text: &str, needle: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = text[from..].find(needle) {
        let start = from + pos;
        out.push((start, start + needle.len()));
        from = start + needle.len().max(1);
    }
    out
}
