use crate::hexpattern::{HexPattern, verify_at};

pub(crate) fn pattern_from_tokens(tokens: Vec<Option<u8>>) -> HexPattern {
    let text = tokens
        .iter()
        .map(|token| match token {
            Some(value) => format!("{value:02x}"),
            None => "??".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ");
    HexPattern::parse(&text).unwrap()
}

pub(crate) fn naive_matches(haystack: &[u8], pattern: &HexPattern) -> Vec<usize> {
    if haystack.len() < pattern.len() {
        return Vec::new();
    }
    (0..=haystack.len() - pattern.len())
        .filter(|position| verify_at(haystack, *position, pattern.bytes()))
        .collect()
}
