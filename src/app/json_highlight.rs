//! Bounded JSON coloring. Source text is always escaped before styled-text parsing.
use slint::StyledText;

fn escape(text: &str, result: &mut String) {
    use std::fmt::Write;
    for ch in text.chars() {
        if ch.is_ascii_punctuation() || ch.is_ascii_whitespace() {
            let _ = write!(result, "&#{};", ch as u32);
        } else {
            result.push(ch);
        }
    }
}
pub fn line(text: &str) -> StyledText {
    // Large minified documents still remain editable; color work per visible line is bounded.
    let end = text.char_indices().nth(8192).map_or(text.len(), |(i, _)| i);
    let text = &text[..end];
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut markup = String::new();
    while at < bytes.len() {
        let start = at;
        let color = match bytes[at] {
            b'"' => {
                at += 1;
                while at < bytes.len() {
                    match bytes[at] {
                        b'\\' => at = (at + 2).min(bytes.len()),
                        b'"' => {
                            at += 1;
                            break;
                        }
                        _ => at += 1,
                    }
                }
                if bytes[at..].iter().find(|b| !b.is_ascii_whitespace()) == Some(&b':') {
                    "#9aaaff"
                } else {
                    "#79dcb4"
                }
            }
            b'-' | b'0'..=b'9' => {
                at += 1;
                while at < bytes.len()
                    && matches!(bytes[at], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    at += 1;
                }
                "#f2c57c"
            }
            b't' | b'f' | b'n' => {
                at += 1;
                while at < bytes.len() && bytes[at].is_ascii_alphabetic() {
                    at += 1;
                }
                "#d2a4f7"
            }
            _ => {
                at += text[at..].chars().next().unwrap().len_utf8();
                while at < bytes.len()
                    && !matches!(bytes[at], b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n')
                {
                    at += text[at..].chars().next().unwrap().len_utf8();
                }
                "#a5afc5"
            }
        };
        // Escaped invalid strings can end at a UTF-8 continuation byte. Keep the
        // highlighter total even while the user is midway through an edit.
        while at < bytes.len() && !text.is_char_boundary(at) {
            at += 1;
        }
        markup.push_str("<font color=\"");
        markup.push_str(color);
        markup.push_str("\">");
        escape(&text[start..at], &mut markup);
        markup.push_str("</font>");
    }
    StyledText::from_markdown(&markup).unwrap_or_else(|_| StyledText::from_plain_text(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_markup_is_escaped_and_incomplete_unicode_never_panics() {
        let mut escaped = String::new();
        escape(" <font>\\\"{}[]`&\t", &mut escaped);
        assert!(!escaped.contains('<') && !escaped.contains('`'));
        for sample in [
            "",
            "  \"ключ\": \"тест\",",
            "\"<font color='red'>x</font>\"",
            "\"\\я",
            "-1.2e+3 true false null",
            "\"C:\\\\Игры\\\\a.exe\"",
        ] {
            let result = line(sample);
            assert!(result != StyledText::default() || sample.is_empty());
        }
        let _ = line(&"я".repeat(10000));
    }
}
