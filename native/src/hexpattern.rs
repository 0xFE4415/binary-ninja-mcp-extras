//! Hex byte-pattern parsing, mirroring the Python plugin's `hexpattern.py`
//! grammar: separator-delimited tokens of two hex digits or `??`, with error
//! messages identical to the Python `rex_data_find` tool's.

/// Raw pattern-string cap, matching `_MAX_PATTERN_CHARS` in the Python plugin.
pub const MAX_PATTERN_CHARS: usize = 8192;

/// Echoed-string cap, matching `_MAX_CHARS` in the Python plugin.
pub const TRUNCATE_CHARS: usize = 512;

/// A parse failure whose message is shown to the tool caller verbatim.
/// `Debug` is the only derive: callers read `message` directly, so
/// Display/Error/equality/cloning would be a second, never-exercised path.
#[derive(Debug)]
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

/// A parsed hex byte pattern: one entry per byte, `None` for a wildcard byte.
#[derive(Debug)]
pub struct HexPattern {
    bytes: Vec<Option<u8>>,
}

impl HexPattern {
    /// Parse a pattern such as `"48 8b ?? 05"`. Whitespace (Python's
    /// `str.isspace()` set minus U+001C..U+001F, which are rejected) separates
    /// tokens; each token holds whole bytes of two hex digits or `??`.
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        if let Some(character) = pattern.chars().find(|char| is_rejected_separator(*char)) {
            return Err(PatternError::new(format!(
                "invalid separator U+{:04X}",
                character as u32
            )));
        }
        let tokens: Vec<&str> = pattern
            .split(char::is_whitespace)
            .filter(|token| !token.is_empty())
            .collect();
        if tokens.is_empty() {
            return Err(PatternError::new("empty hex pattern"));
        }
        if tokens
            .iter()
            .any(|token| !token.chars().count().is_multiple_of(2))
        {
            return Err(PatternError::new("hex pattern must contain whole bytes"));
        }
        let chars: Vec<char> = tokens.concat().chars().collect();
        // The length check above guarantees `as_chunks` leaves no remainder.
        let (pairs, remainder) = chars.as_chunks();
        debug_assert!(remainder.is_empty());
        let bytes = pairs
            .iter()
            .map(|&pair| {
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

    /// The first maximal run of concrete bytes (start index and values): the
    /// prefilter needle for both scan paths.
    pub fn first_concrete_run(&self) -> Option<(usize, Vec<u8>)> {
        let start = self.bytes.iter().position(Option::is_some)?;
        let run = self.bytes[start..].iter().map_while(|byte| *byte).collect();
        Some((start, run))
    }
}

/// Python treats these as whitespace, but the grammar rejects them as separators.
fn is_rejected_separator(character: char) -> bool {
    ('\u{1c}'..='\u{1f}').contains(&character)
}

fn parse_hex_byte([high, low]: [char; 2]) -> Option<u8> {
    Some((high.to_digit(16)? << 4 | low.to_digit(16)?) as u8)
}

/// Truncate an echoed string exactly the way the Python plugin's `_truncate` does.
pub fn truncate_echo(text: &str, limit: usize) -> String {
    let total = text.chars().count();
    if total <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit).collect();
    format!("{kept}... [{} chars truncated]", total - limit)
}

/// True when `pattern` matches `haystack` starting at `pos`. Bounds-checks,
/// returning `false` instead of panicking when the window overruns the haystack.
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
    use proptest::prelude::*;

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

    // Keep equal to PYTHON_SEPARATORS in tests/test_hexpattern.py and CONTRACTS.md.
    const SEPARATOR_CODE_POINTS: [u32; 25] = [
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003,
        0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F,
        0x3000,
    ];

    #[test]
    fn separators_are_exactly_the_pinned_set() {
        let mut accepted = Vec::new();
        for code_point in 0..=char::MAX as u32 {
            let Some(character) = char::from_u32(code_point) else {
                continue;
            };
            if HexPattern::parse(&format!("48{character}8b")).is_ok() {
                accepted.push(code_point);
            }
        }
        assert_eq!(accepted, SEPARATOR_CODE_POINTS);
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
        for odd in ["48 8", "9 0", "48 9 0", "4 8 8b", "48 8\nz"] {
            assert_eq!(
                HexPattern::parse(odd).unwrap_err().message,
                "hex pattern must contain whole bytes",
                "{odd:?}"
            );
        }
    }

    #[test]
    fn rejects_the_control_separators_naming_the_code_point() {
        for (pattern, name) in [
            ("48\u{1c}8b", "U+001C"),
            ("48\u{1d}8b", "U+001D"),
            ("48\u{1e}8b", "U+001E"),
            ("\u{1f}", "U+001F"),
        ] {
            assert_eq!(
                HexPattern::parse(pattern).unwrap_err().message,
                format!("invalid separator {name}")
            );
        }
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
        // Python rejects these too (test_parse_rejects_lenient_int_forms).
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
        assert_eq!(pattern.first_concrete_run(), Some((2, vec![0x48, 0x8b])));
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
    }

    proptest! {
        #[test]
        fn parses_generated_tokens_and_finds_the_first_maximal_concrete_run(
            tokens in prop::collection::vec(
                prop_oneof![Just(None::<u8>), any::<u8>().prop_map(Some)],
                1..128
            )
        ) {
            let text = tokens
                .iter()
                .map(|token| match token {
                    Some(byte) => format!("{byte:02x}"),
                    None => "??".to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ");
            let pattern = HexPattern::parse(&text).unwrap();
            let start = tokens.iter().position(Option::is_some);
            let expected_run = start.map(|start| {
                let bytes = tokens[start..]
                    .iter()
                    .map_while(|token| *token)
                    .collect();
                (start, bytes)
            });

            prop_assert_eq!(pattern.bytes(), tokens.as_slice());
            prop_assert_eq!(pattern.len(), tokens.len());
            prop_assert_eq!(pattern.first_concrete_run(), expected_run);
        }
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

    #[test]
    fn truncate_echo_counts_characters_not_bytes() {
        // Python len() on str counts characters, so a string of 512 two-byte
        // characters fits the limit exactly and is echoed untruncated.
        let at_cap = "è".repeat(TRUNCATE_CHARS);
        assert_eq!(truncate_echo(&at_cap, TRUNCATE_CHARS), at_cap);
        // One character over truncates by one character, not two bytes.
        let text = format!("{at_cap}è");
        assert_eq!(
            truncate_echo(&text, TRUNCATE_CHARS),
            format!("{at_cap}... [1 chars truncated]")
        );
    }
}
