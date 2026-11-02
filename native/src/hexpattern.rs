//! Hex byte-pattern parsing, mirroring the Python plugin's `hexpattern.py` grammar.
//!
//! A pattern is whitespace-separated byte tokens: two hex digits, or `??` for a
//! wildcard byte that matches any value. Errors carry the same messages the Python
//! `rex_data_find` tool returns so callers see identical `invalid_pattern` text.

/// Raw pattern-string cap, matching `_MAX_PATTERN_CHARS` in the Python plugin.
pub const MAX_PATTERN_CHARS: usize = 8192;

/// Echoed-string cap, matching `_MAX_CHARS` in the Python plugin.
pub const TRUNCATE_CHARS: usize = 512;

/// A parse failure whose message is shown to the tool caller verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternError {
    pub message: String,
}

impl PatternError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PatternError {}

/// A parsed hex byte pattern: one entry per byte, `None` for a wildcard byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexPattern {
    bytes: Vec<Option<u8>>,
}

impl HexPattern {
    /// Parse a pattern such as `"48 8b ?? 05"`. All whitespace is ignored; each
    /// token is two hex digits or `??`.
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        let chars: Vec<char> = pattern
            .chars()
            .filter(|char| !char.is_whitespace())
            .collect();
        if chars.is_empty() {
            return Err(PatternError::new("empty hex pattern"));
        }
        if !chars.len().is_multiple_of(2) {
            return Err(PatternError::new("hex pattern must contain whole bytes"));
        }
        let bytes = chars
            .chunks(2)
            .map(|pair| {
                if pair == ['?', '?'] {
                    return Ok(None);
                }
                parse_hex_byte(pair).map(Some).ok_or_else(|| {
                    let token: String = pair.iter().collect();
                    PatternError::new(format!("invalid hex byte token '{token}'"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { bytes })
    }

    /// Number of bytes the pattern matches, wildcards included.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn bytes(&self) -> &[Option<u8>] {
        &self.bytes
    }

    /// The first concrete (non-wildcard) byte and its index in the pattern.
    pub fn first_concrete(&self) -> Option<(usize, u8)> {
        self.bytes
            .iter()
            .enumerate()
            .find_map(|(index, byte)| byte.map(|value| (index, value)))
    }

    /// The first maximal run of concrete bytes: its start index and values.
    ///
    /// This is the longest prefix of consecutive non-wildcard bytes starting at
    /// the pattern's first concrete byte; used as the multi-pattern automaton's
    /// prefilter needle.
    pub fn first_concrete_run(&self) -> Option<(usize, Vec<u8>)> {
        let start = self.bytes.iter().position(Option::is_some)?;
        let run = self.bytes[start..].iter().map_while(|byte| *byte).collect();
        Some((start, run))
    }
}

fn parse_hex_byte(pair: &[char]) -> Option<u8> {
    let [high, low] = pair else {
        return None;
    };
    Some((high.to_digit(16)? << 4 | low.to_digit(16)?) as u8)
}

/// Truncate an echoed string the way the Python plugin's `_truncate` does, so
/// error messages match character for character.
pub fn truncate_echo(text: &str, limit: usize) -> String {
    let total = text.chars().count();
    if total <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit).collect();
    format!("{kept}... [{} chars truncated]", total - limit)
}

/// True when `pattern` matches the bytes of `haystack` starting at `pos`.
///
/// The caller must ensure `pos + pattern.len() <= haystack.len()`; `verify_at`
/// still bounds-checks and reports `false` instead of panicking if not.
pub fn verify_at(haystack: &[u8], pos: usize, pattern: &[Option<u8>]) -> bool {
    pos.checked_add(pattern.len())
        .and_then(|end| haystack.get(pos..end))
        .is_some_and(|window| {
            window
                .iter()
                .zip(pattern)
                .all(|(byte, expected)| expected.is_none_or(|value| value == *byte))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(pattern: &str) -> Vec<Option<u8>> {
        HexPattern::parse(pattern).unwrap().bytes().to_vec()
    }

    #[test]
    fn parses_basic_pattern() {
        assert_eq!(
            parse_ok("48 8b ?? 05"),
            vec![Some(0x48), Some(0x8b), None, Some(0x05)]
        );
    }

    #[test]
    fn is_empty_reflects_pattern_bytes() {
        let empty = HexPattern { bytes: Vec::new() };
        let non_empty = HexPattern::parse("??").unwrap();

        assert!(empty.is_empty());
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn accepts_whitespace_free_and_mixed_whitespace() {
        assert_eq!(parse_ok("488b"), parse_ok("48 8b"));
        assert_eq!(parse_ok("48\t8b\n??\r05"), parse_ok("48 8b ?? 05"));
    }

    #[test]
    fn accepts_uppercase_hex() {
        assert_eq!(parse_ok("DE AD BEEF"), parse_ok("de ad beef"));
    }

    #[test]
    fn rejects_empty_and_odd_patterns() {
        assert_eq!(
            HexPattern::parse("   ").unwrap_err().message,
            "empty hex pattern"
        );
        assert_eq!(
            HexPattern::parse("48 8").unwrap_err().message,
            "hex pattern must contain whole bytes"
        );
    }

    #[test]
    fn rejects_bad_tokens() {
        assert_eq!(
            HexPattern::parse("48 zz").unwrap_err().message,
            "invalid hex byte token 'zz'"
        );
        // A lone '?' next to a digit is neither "??" nor a hex byte, so token parsing rejects it.
        assert_eq!(
            HexPattern::parse("4?").unwrap_err().message,
            "invalid hex byte token '4?'"
        );
        assert_eq!(
            HexPattern::parse("?a").unwrap_err().message,
            "invalid hex byte token '?a'"
        );
        // Divergences from the Python parser (native/README.md "Known
        // divergences" #3): int(token, 16) there parses a leading '+' and
        // Unicode decimal digits as ordinary bytes, and even passes '-1'
        // through to crash later, uncaught, in compile_hex_pattern's byte
        // conversion — the native parser takes ASCII hex digits only.
        assert_eq!(
            HexPattern::parse("+4").unwrap_err().message,
            "invalid hex byte token '+4'"
        );
        assert_eq!(
            HexPattern::parse("-1").unwrap_err().message,
            "invalid hex byte token '-1'"
        );
        assert_eq!(
            HexPattern::parse("４４").unwrap_err().message,
            "invalid hex byte token '４４'"
        );
    }

    #[test]
    fn finds_first_concrete_run() {
        let pattern = HexPattern::parse("?? ?? 48 8b ?? 8b 05").unwrap();
        assert_eq!(pattern.first_concrete_run(), Some((2, vec![0x48, 0x8b])),);
        assert_eq!(pattern.first_concrete(), Some((2, 0x48)));
    }

    #[test]
    fn run_stops_at_wildcard() {
        let pattern = HexPattern::parse("48 8b ?? 05").unwrap();
        assert_eq!(pattern.first_concrete_run(), Some((0, vec![0x48, 0x8b])));
    }

    #[test]
    fn all_wildcard_has_no_concrete_run() {
        let pattern = HexPattern::parse("?? ??").unwrap();
        assert_eq!(pattern.first_concrete_run(), None);
        assert_eq!(pattern.first_concrete(), None);
    }

    #[test]
    fn verify_checks_every_byte() {
        let hay = [0x10, 0x48, 0x99, 0x05, 0x20];
        let pattern = HexPattern::parse("?? 99 ?? 20").unwrap();
        assert!(verify_at(&hay, 1, pattern.bytes()));
        assert!(!verify_at(&hay, 0, pattern.bytes()));
    }

    #[test]
    fn verify_is_bounds_safe() {
        let hay = [0x10, 0x48];
        let pattern = HexPattern::parse("48 8b").unwrap();
        assert!(!verify_at(&hay, 1, pattern.bytes()));
        assert!(!verify_at(&hay, usize::MAX, pattern.bytes()));
    }

    #[test]
    fn truncate_echo_matches_python_helper() {
        let text = "a".repeat(600);
        assert_eq!(
            truncate_echo(&text, TRUNCATE_CHARS),
            format!("{}... [{} chars truncated]", "a".repeat(512), 88)
        );
        assert_eq!(truncate_echo("short", TRUNCATE_CHARS), "short");
    }
}
