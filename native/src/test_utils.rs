use crate::hexpattern::{HexPattern, verify_at};

pub(crate) struct ExpectedPagination {
    pub(crate) total: u64,
    pub(crate) truncated: bool,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

pub(crate) fn expected_pagination(
    available_matches: usize,
    offset: u64,
    limit: u64,
) -> ExpectedPagination {
    let available = available_matches as u64;
    let window_end = offset.saturating_add(limit);
    let truncated = available > window_end;
    ExpectedPagination {
        total: if truncated { window_end + 1 } else { available },
        truncated,
        start: offset.min(available) as usize,
        end: window_end.min(available) as usize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_pagination_covers_window_boundaries() {
        let truncated = expected_pagination(5, 1, 2);
        assert_eq!(truncated.total, 4);
        assert!(truncated.truncated);
        assert_eq!((truncated.start, truncated.end), (1, 3));

        let complete = expected_pagination(3, 1, 2);
        assert_eq!(complete.total, 3);
        assert!(!complete.truncated);
        assert_eq!((complete.start, complete.end), (1, 3));

        let beyond_end = expected_pagination(3, u64::MAX, 0);
        assert_eq!(beyond_end.total, 3);
        assert!(!beyond_end.truncated);
        assert_eq!((beyond_end.start, beyond_end.end), (3, 3));
    }
}

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
