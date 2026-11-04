//! In-memory single-pattern scan with the Python plugin's pagination contract:
//! every occurrence counts (overlapping included), scanning stops at the first
//! match past the `[offset, offset+limit)` window, and `total` is the count
//! reached before stopping.

use crate::hexpattern::{HexPattern, verify_at};
use memchr::{memchr_iter, memmem::Finder};
use std::ops::ControlFlow;

#[derive(Clone, Copy, Debug)]
pub struct Pagination {
    pub offset: u64,
    pub limit: u64,
}

/// Accumulated result of one pattern while scanning segment by segment.
#[derive(Debug, Default)]
pub struct RunningScan {
    /// Matches counted before the scan stopped.
    pub total: u64,
    /// True when at least one further match was proven to exist.
    pub truncated: bool,
    /// Absolute addresses inside the `[offset, offset+limit)` window, ascending.
    pub matches: Vec<u64>,
    /// Address of the last match `record_new` counted; None before the first.
    last_recorded: Option<u64>,
}

impl RunningScan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a match at `addr`; returns `false` when the scan window is
    /// exhausted and the caller must stop scanning entirely.
    pub fn record(&mut self, pagination: &Pagination, addr: u64) -> bool {
        if self.truncated {
            return false;
        }
        self.total += 1;
        let window_end = pagination.offset.saturating_add(pagination.limit);
        if self.total > pagination.offset && self.total <= window_end {
            self.matches.push(addr);
            true
        } else if self.total > window_end {
            self.truncated = true;
            false
        } else {
            true
        }
    }

    /// `record`, but only for an address this bucket has not counted yet: the
    /// multi-pattern walk's overlapping windows re-serve a shorter pattern's
    /// seam matches, and windows and matches both arrive in ascending address
    /// order, so an address at or below the last counted one is exactly such
    /// a repeat. The single-pattern walk never revisits an address and keeps
    /// using `record`, so a structural regression there cannot be masked by
    /// this dedup.
    pub fn record_new(&mut self, pagination: &Pagination, addr: u64) -> bool {
        if self.last_recorded.is_some_and(|last| addr <= last) {
            return !self.truncated;
        }
        self.last_recorded = Some(addr);
        self.record(pagination, addr)
    }

    pub fn is_done(&self) -> bool {
        self.truncated
    }
}

/// Enumerate every candidate start of an all-wildcard pattern in ascending
/// order, stopping at the first `record` decline — and what that stops is the
/// caller's call: the whole scan for the single-pattern walk, one bucket's
/// enumeration for the multi-pattern walk.
pub(crate) fn for_each_all_wildcard_candidate(
    haystack_len: usize,
    pattern_len: usize,
    base: u64,
    mut record: impl FnMut(u64) -> bool,
) -> bool {
    let candidates = (haystack_len + 1).saturating_sub(pattern_len);
    (0..candidates).all(|candidate| record(base + candidate as u64))
}

/// Scan one in-memory segment for `pattern` (`base` = absolute address of
/// `haystack[0]`), reporting occurrences in ascending order including
/// overlapping ones. Returns `false` when the window is exhausted; the caller
/// must stop scanning further segments.
pub fn scan_pattern(
    haystack: &[u8],
    base: u64,
    pattern: &HexPattern,
    pagination: &Pagination,
    running: &mut RunningScan,
) -> bool {
    if running.is_done() {
        return false;
    }
    if pattern.is_empty() {
        // `HexPattern::parse` rejects empty patterns, so this guards direct
        // construction only: nothing to count, nothing to stop for.
        return true;
    }
    let bytes = pattern.bytes();
    let pattern_len = bytes.len();
    if haystack.len() < pattern_len {
        return true;
    }
    if let Some((offset, run)) = pattern.first_concrete_run() {
        // Break(true): no later candidate can fit; Break(false): window exhausted.
        let mut visit = |hit: usize| -> ControlFlow<bool> {
            let Some(candidate) = hit.checked_sub(offset) else {
                return ControlFlow::Continue(());
            };
            if candidate
                .checked_add(pattern_len)
                .is_none_or(|end| end > haystack.len())
            {
                // Anchors only move right, so no later candidate can fit.
                return ControlFlow::Break(true);
            }
            if verify_at(haystack, candidate, bytes)
                && !running.record(pagination, base + candidate as u64)
            {
                return ControlFlow::Break(false);
            }
            ControlFlow::Continue(())
        };
        let flow = if let [anchor] = run[..] {
            // memchr_iter beats a per-hit memmem call when one byte is the needle.
            memchr_iter(anchor, haystack).try_for_each(&mut visit)
        } else {
            let finder = Finder::new(&run);
            let mut from = 0;
            let mut flow = ControlFlow::Continue(());
            while let Some(relative) = finder.find(&haystack[from..]) {
                let hit = from + relative;
                // Overlapping occurrences count, so resume one byte past the hit.
                from = hit + 1;
                flow = visit(hit);
                if flow.is_break() {
                    break;
                }
            }
            flow
        };
        if flow == ControlFlow::Break(false) {
            return false;
        }
    } else if !for_each_all_wildcard_candidate(haystack.len(), pattern_len, base, |addr| {
        running.record(pagination, addr)
    }) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexpattern::HexPattern;
    use proptest::prelude::*;

    fn pattern(text: &str) -> HexPattern {
        HexPattern::parse(text).unwrap()
    }

    /// Naive reference: every position where the pattern matches, ascending.
    fn naive_matches(haystack: &[u8], pat: &[Option<u8>]) -> Vec<usize> {
        if haystack.len() < pat.len() {
            return Vec::new();
        }
        (0..=haystack.len() - pat.len())
            .filter(|pos| {
                haystack[*pos..*pos + pat.len()]
                    .iter()
                    .zip(pat)
                    .all(|(byte, expected)| expected.is_none_or(|value| value == *byte))
            })
            .collect()
    }

    /// Build a pattern through the public parser from random tokens.
    fn pattern_from_tokens(tokens: Vec<Option<u8>>) -> HexPattern {
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

    #[test]
    fn finds_overlapping_matches_in_order() {
        let hay = b"ababab";
        let pat = pattern("61 62"); // "ab"
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_pattern(hay, 0x1000, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![0x1000, 0x1002, 0x1004]);
        assert_eq!(running.total, 3);
        assert!(!running.truncated);
    }

    #[test]
    fn record_new_ignores_duplicate_addresses_without_stopping() {
        let page = Pagination {
            offset: 0,
            limit: 1,
        };
        let mut running = RunningScan::new();

        assert!(running.record_new(&page, 0x1000));
        assert!(running.record_new(&page, 0x1000));
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, vec![0x1000]);

        assert!(!running.record_new(&page, 0x1001));
        assert!(!running.record_new(&page, 0x1000));
    }

    #[test]
    fn already_truncated_scan_stops_even_without_another_match() {
        let page = Pagination {
            offset: 0,
            limit: 0,
        };
        let mut running = RunningScan::new();
        assert!(!running.record(&page, 0x1000));

        let pat = pattern("ff");
        assert!(!scan_pattern(b"abc", 0x1000, &pat, &page, &mut running));
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, Vec::<u64>::new());
        assert!(running.truncated);
    }

    #[test]
    fn self_overlapping_pattern_counts_each_position() {
        let hay = b"aaaa";
        let pat = pattern("61 61"); // "aa"
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![0, 1, 2]);
    }

    #[test]
    fn window_skips_and_limits() {
        let hay = b"abababab";
        let pat = pattern("61 62");
        // Occurrences at 0, 2, 4, 6. Skip 3, collect 2: only occurrence 4 is
        // inside the window; the scan completes without truncation.
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 3,
            limit: 2,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![6]);
        assert_eq!(running.total, 4);
        assert!(!running.truncated);
        // Skip 1, collect 2: occurrences 2 and 3 fill the window, occurrence 4
        // lands past it and proves truncation.
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 1,
            limit: 2,
        };
        assert!(!scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![2, 4]);
        assert_eq!(running.total, 4);
        assert!(running.truncated);
        // A window that exactly covers the remaining occurrences does not
        // truncate: skip 1 of 2, take the other.
        let hay = b"abab";
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 1,
            limit: 2,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![2]);
        assert_eq!(running.total, 2);
        assert!(!running.truncated);
    }

    #[test]
    fn truncates_at_window_end_and_stops() {
        let hay = b"abababab";
        let pat = pattern("61 62");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 2,
        };
        assert!(!scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![0, 2]);
        assert_eq!(running.total, 3); // one past the window proves truncation
        assert!(running.truncated);
    }

    #[test]
    fn zero_limit_truncates_on_first_match() {
        let hay = b"ab";
        let pat = pattern("61");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 0,
        };
        assert!(!scan_pattern(hay, 0, &pat, &page, &mut running));
        assert!(running.matches.is_empty());
        assert_eq!(running.total, 1);
        assert!(running.truncated);
    }

    #[test]
    fn offset_beyond_match_count_is_not_truncated() {
        let hay = b"ab";
        let pat = pattern("61");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 10,
            limit: 5,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert!(running.matches.is_empty());
        assert_eq!(running.total, 1);
        assert!(!running.truncated);
    }

    #[test]
    fn all_wildcard_matches_every_position() {
        let hay = [7u8, 8, 9];
        let pat = pattern("?? ??");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_pattern(&hay, 0x10, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![0x10, 0x11]);
    }

    #[test]
    fn pattern_longer_than_haystack_matches_nothing() {
        let hay = b"a";
        let pat = pattern("61 62");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.total, 0);
    }

    proptest! {
        #[test]
        fn agrees_with_naive_reference_on_generated_inputs(
            hay in prop::collection::vec(0u8..4, 0..64),
            tokens in prop::collection::vec(
                prop_oneof![Just(None::<u8>), (0u8..4).prop_map(Some)],
                1..6
            )
        ) {
            let pat = pattern_from_tokens(tokens);
            let naive = naive_matches(&hay, pat.bytes());
            for offset in [0u64, 1, 3, u64::MAX] {
                for limit in [0u64, 1, 5, 100] {
                    let mut running = RunningScan::new();
                    let page = Pagination { offset, limit };
                    let keep_going = scan_pattern(&hay, 0, &pat, &page, &mut running);
                    let window_end = offset.saturating_add(limit);
                    let available = naive.len() as u64;
                    let truncated = available > window_end;
                    let expected_total = if truncated { window_end + 1 } else { available };
                    let page_start = offset.min(available) as usize;
                    let page_end = window_end.min(available) as usize;
                    let expected: Vec<u64> = naive[page_start..page_end]
                        .iter()
                        .map(|pos| *pos as u64)
                        .collect();
                    prop_assert_eq!(running.total, expected_total, "offset {} limit {}", offset, limit);
                    prop_assert_eq!(running.truncated, truncated, "offset {} limit {}", offset, limit);
                    prop_assert_eq!(running.matches, expected, "offset {} limit {}", offset, limit);
                    prop_assert_eq!(keep_going, !truncated, "offset {} limit {}", offset, limit);
                }
            }
        }
    }
}
