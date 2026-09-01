//! `dotenv/v1` parsing, validation, and normalization.
//!
//! Keyit v1 officially supports dotenv-style environment files. This
//! module defines the protocol-level interpretation of that format:
//! comments and blank lines are accepted, keys are validated, duplicate
//! keys are rejected, quoted values are decoded, and the resulting
//! document can be emitted either in its validated source form or in one
//! deterministic normalized form.
//!
//! The normalized form is value-preserving and presentation-destroying:
//! comments, blank lines, original quoting, and source order are not
//! retained. Revision payloads may keep the validated source text so
//! comments and grouping survive materialization, while diff/status code
//! can still use normalization for key/value comparisons.

use std::collections::{BTreeMap, HashSet};

use crate::error::ProtocolError;

/// A parsed `dotenv/v1` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotenvDocument {
    source: String,
    entries: Vec<DotenvEntry>,
}

impl DotenvDocument {
    /// Parses a dotenv document.
    pub fn parse(input: &str) -> Result<Self, ProtocolError> {
        let mut entries = Vec::new();
        let mut seen = HashSet::new();

        for (idx, raw_line) in input.lines().enumerate() {
            let line_number = idx + 1;
            let trimmed_start = raw_line.trim_start();

            if trimmed_start.is_empty() || trimmed_start.starts_with('#') {
                continue;
            }

            let assignment = trimmed_start
                .strip_prefix("export ")
                .unwrap_or(trimmed_start);
            let Some((raw_key, raw_value)) = assignment.split_once('=') else {
                return Err(dotenv_error(
                    line_number,
                    "expected KEY=value assignment".to_string(),
                ));
            };

            let key = raw_key.trim();
            validate_key(line_number, key)?;

            if !seen.insert(key.to_string()) {
                return Err(dotenv_error(
                    line_number,
                    format!("duplicate key \"{key}\""),
                ));
            }

            let value = parse_value(line_number, raw_value)?;
            entries.push(DotenvEntry {
                key: key.to_string(),
                value,
            });
        }

        Ok(Self {
            source: input.to_string(),
            entries,
        })
    }

    /// Returns the validated source text exactly as parsed.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns entries in source order.
    pub fn entries(&self) -> &[DotenvEntry] {
        &self.entries
    }

    /// Returns all keys in source order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.key.as_str())
    }

    /// Returns a deterministic representation of the document.
    ///
    /// Entries are sorted by key and values are always double-quoted
    /// with deterministic escaping. The output ends with a trailing
    /// newline when at least one entry exists.
    pub fn normalize(&self) -> String {
        let by_key: BTreeMap<&str, &str> = self
            .entries
            .iter()
            .map(|entry| (entry.key.as_str(), entry.value.as_str()))
            .collect();

        let mut out = String::new();
        for (key, value) in by_key {
            out.push_str(key);
            out.push('=');
            out.push('"');
            out.push_str(&escape_double_quoted(value));
            out.push('"');
            out.push('\n');
        }
        out
    }
}

/// One parsed dotenv assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotenvEntry {
    key: String,
    value: String,
}

impl DotenvEntry {
    /// The variable name.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The decoded value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

fn validate_key(line: usize, key: &str) -> Result<(), ProtocolError> {
    if key.is_empty() {
        return Err(dotenv_error(line, "key is empty".to_string()));
    }

    let mut chars = key.chars();
    let first = chars.next().expect("empty checked above");
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(dotenv_error(
            line,
            format!("key \"{key}\" must start with a letter or underscore"),
        ));
    }

    if let Some(bad) = chars.find(|c| !(*c == '_' || c.is_ascii_alphanumeric())) {
        return Err(dotenv_error(
            line,
            format!("key \"{key}\" contains invalid character '{bad}'"),
        ));
    }

    Ok(())
}

fn parse_value(line: usize, raw: &str) -> Result<String, ProtocolError> {
    let value = raw.trim_start();
    if value.is_empty() {
        return Ok(String::new());
    }

    if let Some(rest) = value.strip_prefix('"') {
        return parse_double_quoted(line, rest);
    }
    if let Some(rest) = value.strip_prefix('\'') {
        return parse_single_quoted(line, rest);
    }

    Ok(parse_unquoted(value))
}

fn parse_double_quoted(line: usize, raw: &str) -> Result<String, ProtocolError> {
    let mut out = String::new();
    let mut chars = raw.char_indices();

    while let Some((idx, ch)) = chars.next() {
        match ch {
            '"' => {
                ensure_comment_or_whitespace(line, &raw[idx + ch.len_utf8()..])?;
                return Ok(out);
            }
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    return Err(dotenv_error(
                        line,
                        "unterminated escape in double-quoted value".to_string(),
                    ));
                };
                match escaped {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    other => {
                        return Err(dotenv_error(
                            line,
                            format!("unsupported escape sequence \\{other}"),
                        ));
                    }
                }
            }
            other => out.push(other),
        }
    }

    Err(dotenv_error(
        line,
        "unterminated double-quoted value".to_string(),
    ))
}

fn parse_single_quoted(line: usize, raw: &str) -> Result<String, ProtocolError> {
    let Some(end) = raw.find('\'') else {
        return Err(dotenv_error(
            line,
            "unterminated single-quoted value".to_string(),
        ));
    };
    ensure_comment_or_whitespace(line, &raw[end + 1..])?;
    Ok(raw[..end].to_string())
}

fn parse_unquoted(raw: &str) -> String {
    let mut last_was_whitespace = false;
    for (idx, ch) in raw.char_indices() {
        if ch == '#' && last_was_whitespace {
            return raw[..idx].trim_end().to_string();
        }
        last_was_whitespace = ch.is_whitespace();
    }
    raw.trim_end().to_string()
}

fn ensure_comment_or_whitespace(line: usize, rest: &str) -> Result<(), ProtocolError> {
    let trailing = rest.trim_start();
    if trailing.is_empty() || trailing.starts_with('#') {
        return Ok(());
    }
    Err(dotenv_error(
        line,
        "unexpected characters after quoted value".to_string(),
    ))
}

fn escape_double_quoted(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn dotenv_error(line: usize, reason: String) -> ProtocolError {
    ProtocolError::DotenvParse { line, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_assignments() {
        let doc = DotenvDocument::parse("DATABASE_URL=postgres://local\nLOG_LEVEL=debug\n")
            .expect("valid dotenv");

        assert_eq!(doc.entries().len(), 2);
        assert_eq!(doc.entries()[0].key(), "DATABASE_URL");
        assert_eq!(doc.entries()[0].value(), "postgres://local");
        assert_eq!(doc.entries()[1].key(), "LOG_LEVEL");
        assert_eq!(doc.entries()[1].value(), "debug");
    }

    #[test]
    fn ignores_blank_lines_and_comments() {
        let doc =
            DotenvDocument::parse("\n# comment\nA=1\n\n  # another\nB=2\n").expect("valid dotenv");

        assert_eq!(doc.keys().collect::<Vec<_>>(), ["A", "B"]);
        assert_eq!(doc.source(), "\n# comment\nA=1\n\n  # another\nB=2\n");
    }

    #[test]
    fn supports_export_prefix() {
        let doc = DotenvDocument::parse("export API_KEY=secret\n").expect("valid dotenv");
        assert_eq!(doc.entries()[0].key(), "API_KEY");
        assert_eq!(doc.entries()[0].value(), "secret");
    }

    #[test]
    fn parses_quoted_values_and_escapes() {
        let doc = DotenvDocument::parse("A=\"line\\nnext\"\nB='literal # value'\n")
            .expect("valid dotenv");

        assert_eq!(doc.entries()[0].value(), "line\nnext");
        assert_eq!(doc.entries()[1].value(), "literal # value");
    }

    #[test]
    fn strips_unquoted_inline_comments_only_after_whitespace() {
        let doc =
            DotenvDocument::parse("A=abc#not-comment\nB=abc # comment\n").expect("valid dotenv");

        assert_eq!(doc.entries()[0].value(), "abc#not-comment");
        assert_eq!(doc.entries()[1].value(), "abc");
    }

    #[test]
    fn normalization_sorts_keys_and_quotes_values() {
        let doc = DotenvDocument::parse("B=two words\nA=\"one\\nline\"\n").expect("valid dotenv");

        assert_eq!(doc.normalize(), "A=\"one\\nline\"\nB=\"two words\"\n");
    }

    #[test]
    fn rejects_duplicate_keys() {
        let err = DotenvDocument::parse("A=1\nA=2\n").unwrap_err();
        assert!(matches!(err, ProtocolError::DotenvParse { line: 2, .. }));
    }

    #[test]
    fn rejects_invalid_keys() {
        let err = DotenvDocument::parse("1BAD=value\n").unwrap_err();
        assert!(matches!(err, ProtocolError::DotenvParse { line: 1, .. }));
    }

    #[test]
    fn rejects_unterminated_quotes() {
        let err = DotenvDocument::parse("A=\"unterminated\n").unwrap_err();
        assert!(matches!(err, ProtocolError::DotenvParse { line: 1, .. }));
    }

    #[test]
    fn rejects_unsupported_double_quote_escapes() {
        let err = DotenvDocument::parse("A=\"bad\\xescape\"\n").unwrap_err();
        assert!(matches!(err, ProtocolError::DotenvParse { line: 1, .. }));
    }
}
