//! One-pass multi-pattern scan: hex patterns with `??` wildcards cannot enter
//! an Aho-Corasick automaton directly, but every occurrence contains its first
//! concrete byte run at a fixed offset — so all patterns' concrete runs go into
//! one automaton, `find_overlapping_iter` yields every run hit (overlaps
//! included, keeping self-overlapping patterns correct), and each hit is
//! verified against its full pattern. The result equals the naive scan.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::hexpattern::{HexPattern, verify_at};
use crate::scan::{Pagination, RunningScan, for_each_all_wildcard_candidate};

/// Cap on the number of patterns one `rx_multi_find` call accepts.
pub const MAX_MULTI_PATTERNS: usize = 64;

struct NeedleOwner {
    pattern_index: usize,
    needle_offset: usize,
}

/// The compiled multi-pattern matcher for one `rx_multi_find` call.
pub struct MultiMatcher {
    automaton: AhoCorasick,
    /// Owners per automaton pattern id; several owners may share one needle
    /// when different patterns start with the same concrete run.
    owners: Vec<Vec<NeedleOwner>>,
    /// Indices of patterns with no concrete byte at all; scanned directly
    /// instead of through the automaton.
    wildcard_only: Vec<usize>,
}

impl MultiMatcher {
    /// Compile one automaton covering every pattern that has a concrete run.
    pub fn new(patterns: &[HexPattern]) -> Self {
        let mut needle_ids: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut needles: Vec<Vec<u8>> = Vec::new();
        let mut owners: Vec<Vec<NeedleOwner>> = Vec::new();
        let mut wildcard_only = Vec::new();
        for (pattern_index, pattern) in patterns.iter().enumerate() {
            let Some((needle_offset, run)) = pattern.first_concrete_run() else {
                wildcard_only.push(pattern_index);
                continue;
            };
            let next_id = needles.len();
            let id = *needle_ids.entry(run.clone()).or_insert(next_id);
            if id == next_id {
                needles.push(run);
                owners.push(Vec::new());
            }
            owners[id].push(NeedleOwner {
                pattern_index,
                needle_offset,
            });
        }
        let automaton = AhoCorasick::builder()
            // Standard semantics report every hit as seen — what find_overlapping_iter needs.
            .match_kind(MatchKind::Standard)
            .build(&needles)
            .expect("aho-corasick build of concrete byte runs");
        Self {
            automaton,
            owners,
            wildcard_only,
        }
    }

    /// Scan one in-memory segment for every pattern, updating per-pattern
    /// buckets (`base` = absolute address of `haystack[0]`). `patterns` must be
    /// the same slice the matcher was compiled from: owner entries index into
    /// it. Returns `false` when every bucket's window is exhausted.
    pub fn scan_segment(
        &self,
        haystack: &[u8],
        base: u64,
        patterns: &[HexPattern],
        buckets: &mut [RunningScan],
        pagination: &Pagination,
    ) -> bool {
        for hit in self.automaton.find_overlapping_iter(haystack) {
            for owner in &self.owners[hit.pattern().as_usize()] {
                let bucket = &mut buckets[owner.pattern_index];
                if bucket.is_done() {
                    continue;
                }
                let pattern = &patterns[owner.pattern_index];
                let Some(candidate) = hit.start().checked_sub(owner.needle_offset) else {
                    continue;
                };
                if !verify_at(haystack, candidate, pattern.bytes()) {
                    continue;
                }
                // Shorter patterns re-see their seam matches in the next
                // window; count each address once.
                if !bucket.record_new(pagination, base + candidate as u64)
                    && buckets.iter().all(RunningScan::is_done)
                {
                    return false;
                }
            }
        }
        // All-wildcard buckets scan directly so each bucket's address order
        // stays ascending; a declined candidate ends only its own enumeration,
        // so the helper's `false` is deliberately ignored here.
        for &pattern_index in &self.wildcard_only {
            for_each_all_wildcard_candidate(
                haystack.len(),
                patterns[pattern_index].len(),
                base,
                |addr| buckets[pattern_index].record_new(pagination, addr),
            );
        }
        !buckets.iter().all(RunningScan::is_done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn parse_all<S: AsRef<str>>(patterns: &[S]) -> Vec<HexPattern> {
        patterns
            .iter()
            .map(|text| HexPattern::parse(text.as_ref()).unwrap())
            .collect()
    }

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

    fn scan_all(
        haystack: &[u8],
        base: u64,
        pattern_texts: &[&str],
        offset: u64,
        limit: u64,
    ) -> Vec<RunningScan> {
        let patterns = parse_all(pattern_texts);
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        let pagination = Pagination { offset, limit };
        matcher.scan_segment(haystack, base, &patterns, &mut buckets, &pagination);
        buckets
    }

    // Known-answer test for the crate behavior this design rests on:
    // find_overlapping_iter must report self-overlapping occurrences.
    #[test]
    fn aho_corasick_reports_overlapping_hits() {
        let patterns = parse_all(&["61 61"]); // "aa"
        let matcher = MultiMatcher::new(&patterns);
        let hits: Vec<usize> = matcher
            .automaton
            .find_overlapping_iter(b"aaaa".as_slice())
            .map(|hit| hit.start())
            .collect();
        assert_eq!(hits, vec![0, 1, 2]);
    }

    #[test]
    fn finds_overlapping_matches_per_pattern() {
        let buckets = scan_all(b"ababab", 0x1000, &["61 62"], 0, 50);
        assert_eq!(buckets[0].matches, vec![0x1000, 0x1002, 0x1004]);
        assert_eq!(buckets[0].total, 3);
        assert!(!buckets[0].truncated);
    }

    #[test]
    fn two_patterns_route_to_their_own_buckets() {
        let buckets = scan_all(b"xy ab ab zz", 0, &["61 62", "78 79"], 0, 50);
        assert_eq!(buckets[0].matches, vec![3, 6]);
        assert_eq!(buckets[1].matches, vec![0]);
        assert_eq!(buckets[1].total, 1);
    }

    #[test]
    fn shared_prefix_runs_disambiguate_by_verification() {
        // Both patterns share the run "48 8b"; verification tells them apart.
        let buckets = scan_all(
            &[0x48, 0x8b, 0x05, 0x48, 0x8b, 0xff, 0x48, 0x8b],
            0,
            &["48 8b 05", "48 8b ff"],
            0,
            50,
        );
        assert_eq!(buckets[0].matches, vec![0]);
        assert_eq!(buckets[1].matches, vec![3]);
        assert_eq!(buckets[0].total, 1);
        assert_eq!(buckets[1].total, 1);
    }

    #[test]
    fn window_skips_collects_and_truncates() {
        // "ab" occurs at 0, 2, 4, 6. Window [1, 3): occurrence 1 is skipped,
        // occurrences 2 and 3 are collected, occurrence 4 proves truncation.
        let buckets = scan_all(b"abababab", 0, &["61 62"], 1, 2);
        assert_eq!(buckets[0].matches, vec![2, 4]);
        assert_eq!(buckets[0].total, 4);
        assert!(buckets[0].truncated);
    }

    #[test]
    fn wildcard_only_pattern_matches_every_position() {
        let buckets = scan_all(&[1u8, 2, 3], 0x10, &["?? ??"], 0, 50);
        assert_eq!(buckets[0].matches, vec![0x10, 0x11]);
        assert!(!buckets[0].truncated);
    }

    #[test]
    fn wildcard_only_bucket_truncates() {
        let buckets = scan_all(&[1u8, 2, 3, 4], 0, &["?? ??"], 0, 1);
        assert_eq!(buckets[0].matches, vec![0]);
        assert_eq!(buckets[0].total, 2);
        assert!(buckets[0].truncated);
    }

    #[test]
    fn exhausted_bucket_does_not_collect_more() {
        let patterns = parse_all(&["61 62", "78 79"]);
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        let pagination = Pagination {
            offset: 0,
            limit: 1,
        };
        // Hits arrive in haystack order ("xy" first). After "ab"'s bucket
        // truncates on its second hit, the "xy" bucket must already be filled.
        let alive = matcher.scan_segment(b"xy ab ab", 0, &patterns, &mut buckets, &pagination);
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![3]);
        assert!(buckets[0].truncated);
        assert_eq!(buckets[1].matches, vec![0]);
        assert!(!buckets[1].truncated);
    }

    #[test]
    fn all_buckets_exhausted_stops_the_scan() {
        let patterns = parse_all(&["61 62"]);
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> = vec![RunningScan::new()];
        let pagination = Pagination {
            offset: 0,
            limit: 1,
        };
        let alive = matcher.scan_segment(b"ab ab ab", 0, &patterns, &mut buckets, &pagination);
        assert!(!alive);
        assert!(buckets[0].truncated);
    }

    #[test]
    fn multi_segment_accumulation_across_calls() {
        let patterns = parse_all(&["61 62"]);
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> = vec![RunningScan::new()];
        let pagination = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(matcher.scan_segment(b"ab", 0x10, &patterns, &mut buckets, &pagination));
        assert!(matcher.scan_segment(b"ab ab", 0x20, &patterns, &mut buckets, &pagination));
        assert_eq!(buckets[0].matches, vec![0x10, 0x20, 0x23]);
        assert_eq!(buckets[0].total, 3);
    }

    proptest! {
        #[test]
        fn agrees_with_naive_reference_on_generated_inputs(
            haystack in prop::collection::vec(0u8..4, 0..48),
            token_sets in prop::collection::vec(
                prop::collection::vec(
                    prop_oneof![Just(None::<u8>), (0u8..4).prop_map(Some)],
                    1..5
                ),
                1..6
            )
        ) {
            let patterns: Vec<HexPattern> = token_sets
                .into_iter()
                .map(pattern_from_tokens)
                .collect();
            let naive: Vec<Vec<usize>> = patterns
                .iter()
                .map(|pattern| {
                    if haystack.len() < pattern.len() {
                        Vec::new()
                    } else {
                        (0..=haystack.len() - pattern.len())
                            .filter(|pos| {
                                haystack[*pos..*pos + pattern.len()]
                                    .iter()
                                    .zip(pattern.bytes())
                                    .all(|(byte, expected)| {
                                        expected.is_none_or(|value| value == *byte)
                                    })
                            })
                            .collect()
                    }
                })
                .collect();
            let matcher = MultiMatcher::new(&patterns);
            for offset in [0u64, 1, 2, u64::MAX] {
                for limit in [0u64, 1, 2, 100] {
                    let mut buckets: Vec<RunningScan> =
                        (0..patterns.len()).map(|_| RunningScan::new()).collect();
                    let pagination = Pagination { offset, limit };
                    let alive = matcher.scan_segment(
                        &haystack,
                        0,
                        &patterns,
                        &mut buckets,
                        &pagination,
                    );
                    for (index, bucket) in buckets.iter().enumerate() {
                        let window_end = offset.saturating_add(limit);
                        let available = naive[index].len() as u64;
                        let truncated = available > window_end;
                        let expected_total = if truncated { window_end + 1 } else { available };
                        let page_start = offset.min(available) as usize;
                        let page_end = window_end.min(available) as usize;
                        let expected: Vec<u64> = naive[index][page_start..page_end]
                            .iter()
                            .map(|pos| *pos as u64)
                            .collect();
                        prop_assert_eq!(bucket.total, expected_total, "pattern {} offset {} limit {}", index, offset, limit);
                        prop_assert_eq!(bucket.truncated, truncated, "pattern {} offset {} limit {}", index, offset, limit);
                        prop_assert_eq!(&bucket.matches, &expected, "pattern {} offset {} limit {}", index, offset, limit);
                    }
                    let all_done = buckets.iter().all(RunningScan::is_done);
                    prop_assert_eq!(!alive, all_done, "offset {} limit {}", offset, limit);
                }
            }
        }
    }
}
