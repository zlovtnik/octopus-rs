//! Java Pattern adaptation for DQ's bounded schema patterns.
//!
//! Java's default digit/word/space classes are ASCII; Rust's are Unicode.
//! Translate those classes and Java line terminators explicitly. Unsupported
//! flags and Java-only properties are rejected at registration.

use fancy_regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or unsupported Java schema pattern")]
pub struct PatternError;

const FINAL_TERMINATOR: &str = r"(?=\z|\r\n\z|[\r\u{0085}\u{2028}\u{2029}]\z|(?<!\r)\n\z)";

pub fn compile(pattern: &str) -> Result<Regex, PatternError> {
    if pattern.encode_utf16().count() > 256 {
        return Err(PatternError);
    }
    let mut output = String::new();
    let mut chars = pattern.chars().peekable();
    let (mut class_depth, mut quoted) = (0usize, false);
    let mut unicode_classes = false;
    let mut dot_all = false;
    // Global leading flags are the common registry form. Nested Java-specific
    // flags need scoped interpretation and are rejected rather than weakened.
    while output.is_empty() && chars.peek() == Some(&'(') {
        let rest: String = chars.clone().collect();
        if !rest.starts_with("(?") {
            break;
        }
        let Some(end) = rest.find(')') else { break };
        let flags = &rest[2..end];
        if flags.is_empty() || !flags.chars().all(|c| "Uusimdx".contains(c)) {
            break;
        }
        if flags.contains(['u', 'i', 'm', 'd', 'x']) {
            // Java ASCII-only case folding and Unicode case flags differ from
            // regex-syntax. Reject until a scoped equivalent is provided.
            return Err(PatternError);
        }
        unicode_classes |= flags.contains('U');
        dot_all |= flags.contains('s');
        for _ in 0..=end {
            chars.next();
        }
    }
    while let Some(c) = chars.next() {
        if quoted {
            if c == '\\' && chars.peek() == Some(&'E') {
                chars.next();
                quoted = false;
            } else {
                output.push_str(&regex::escape(&c.to_string()));
            }
            continue;
        }
        if c == '\\' {
            let escaped = chars.next().ok_or(PatternError)?;
            if matches!(escaped, 'K' | 'g') || (escaped == 'u' && chars.peek() == Some(&'{')) {
                return Err(PatternError);
            }
            let class = match escaped {
                'Q' => {
                    quoted = true;
                    continue;
                }
                'd' if !unicode_classes => Some("[0-9]"),
                'D' if !unicode_classes => Some("[^0-9]"),
                'w' if !unicode_classes => Some("[a-zA-Z_0-9]"),
                'W' if !unicode_classes => Some("[^a-zA-Z_0-9]"),
                's' if !unicode_classes => Some("[ \\t\\n\\x0B\\f\\r]"),
                'S' if !unicode_classes => Some("[^ \\t\\n\\x0B\\f\\r]"),
                'h' => Some("[\\t \\u{00a0}\\u{1680}\\u{180e}\\u{2000}-\\u{200a}\\u{202f}\\u{205f}\\u{3000}]"),
                'H' => Some("[^\\t \\u{00a0}\\u{1680}\\u{180e}\\u{2000}-\\u{200a}\\u{202f}\\u{205f}\\u{3000}]"),
                'v' => Some("[\\n\\x0B\\f\\r\\u{0085}\\u{2028}\\u{2029}]"),
                'V' => Some("[^\\n\\x0B\\f\\r\\u{0085}\\u{2028}\\u{2029}]"),
                'R' => Some("(?:\\r\\n|[\\n\\x0B\\f\\r\\u{0085}\\u{2028}\\u{2029}])"),
                'b' if !unicode_classes && class_depth == 0 => Some("(?:(?<=[a-zA-Z_0-9])(?![a-zA-Z_0-9])|(?<![a-zA-Z_0-9])(?=[a-zA-Z_0-9]))"),
                'B' if !unicode_classes && class_depth == 0 => Some("(?!(?:(?<=[a-zA-Z_0-9])(?![a-zA-Z_0-9])|(?<![a-zA-Z_0-9])(?=[a-zA-Z_0-9])))"),
                'Z' if class_depth == 0 => Some(FINAL_TERMINATOR),
                _ => None,
            };
            if let Some(class) = class {
                output.push_str(class);
            } else if escaped == 'p' || escaped == 'P' {
                if chars.next() != Some('{') {
                    return Err(PatternError);
                }
                let mut property = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(c) => property.push(c),
                        None => return Err(PatternError),
                    }
                }
                let property = match property.as_str() {
                    "javaWhitespace" => "\\t-\\r\\x1c-\\x20\\u{1680}\\u{2000}-\\u{2006}\\u{2008}-\\u{200a}\\u{2028}\\u{2029}\\u{205f}\\u{3000}",
                    "Lower" if !unicode_classes => "a-z",
                    "Upper" if !unicode_classes => "A-Z",
                    "ASCII" => "\\x00-\\x7f",
                    "Alpha" if !unicode_classes => "a-zA-Z",
                    "Digit" if !unicode_classes => "0-9",
                    "Alnum" if !unicode_classes => "a-zA-Z0-9",
                    "Punct" if !unicode_classes => "!-/:-@\\[-`{-~",
                    "Graph" if !unicode_classes => "\\x21-\\x7e",
                    "Print" if !unicode_classes => "\\x20-\\x7e",
                    "Blank" if !unicode_classes => " \\t",
                    "Cntrl" if !unicode_classes => "\\x00-\\x1f\\x7f",
                    "XDigit" if !unicode_classes => "a-fA-F0-9",
                    "Space" if !unicode_classes => " \\t\\n\\x0b\\f\\r",
                    // Unicode category and script spelling accepted by both.
                    p if p.len() <= 2 && p.chars().all(|c| c.is_ascii_alphabetic()) => {
                        output.push('\\');
                        output.push(escaped);
                        output.push('{');
                        output.push_str(p);
                        output.push('}');
                        continue;
                    }
                    _ => return Err(PatternError),
                };
                output.push('[');
                if escaped == 'P' {
                    output.push('^');
                }
                output.push_str(property);
                output.push(']');
            } else {
                output.push('\\');
                output.push(escaped);
            }
        } else {
            match c {
                '[' => class_depth += 1,
                ']' => class_depth = class_depth.saturating_sub(1),
                '.' if class_depth == 0 => {
                    output.push_str(if dot_all {
                        "(?s:.)"
                    } else {
                        "[^\\r\\n\\u{0085}\\u{2028}\\u{2029}]"
                    });
                    continue;
                }
                '$' if class_depth == 0 => {
                    output.push_str(FINAL_TERMINATOR);
                    continue;
                }
                '~' if class_depth > 0 => {
                    output.push_str(r"\x7e");
                    continue;
                }
                '(' if class_depth == 0 && chars.peek() == Some(&'?') => {
                    let rest: String = chars.clone().collect();
                    if !rest.chars().nth(1).is_some_and(|c| ":=!><".contains(c)) {
                        return Err(PatternError);
                    }
                    if rest.starts_with("?<")
                        && !rest.starts_with("?<=")
                        && !rest.starts_with("?<!")
                    {
                        let end = rest.find('>').ok_or(PatternError)?;
                        let name = &rest[2..end];
                        if !name.starts_with(|c: char| c.is_ascii_alphabetic())
                            || !name.chars().all(|c| c.is_ascii_alphanumeric())
                        {
                            return Err(PatternError);
                        }
                    }
                }
                _ => {}
            }
            output.push(c);
        }
    }
    Regex::new(&output).map_err(|_| PatternError)
}
