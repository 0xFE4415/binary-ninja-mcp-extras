//! Multi-pattern scan: each pattern whose bucket is still open is scanned
//! over the window with the single-pattern prefilter loop (memchr / memmem on
//! its first concrete run), so hot needles cost one tight loop each and a
//! finished bucket costs nothing.

use crate::hexpattern::HexPattern;
use crate::scan::{Pagination, RunningScan, scan_window};

/// Cap on the number of patterns one `rx_multi_find` call accepts.
pub const MAX_MULTI_PATTERNS: usize = 64;

/// Scan one in-memory segment for every pattern, updating per-pattern
/// buckets (`base` = absolute address of `haystack[0]`). `patterns` and
/// `buckets` are index-aligned. Returns `false` when every bucket's window
/// is exhausted.
pub fn scan_segment(
    haystack: &[u8],
    base: u64,
    patterns: &[HexPattern],
    buckets: &mut [RunningScan],
    pagination: &Pagination,
) -> bool {
    for (pattern, bucket) in patterns.iter().zip(buckets.iter_mut()) {
        if bucket.is_done() {
            continue;
        }
        // Overlapping windows re-serve a shorter pattern's seam matches;
        // record_new counts each address once. A declined record ends only
        // this bucket's scan.
        scan_window(haystack, base, pattern, |addr| {
            bucket.record_new(pagination, addr)
        });
    }
    !buckets.iter().all(RunningScan::is_done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{naive_matches, pattern_from_tokens};
    use proptest::prelude::*;

    fn parse_all<S: AsRef<str>>(patterns: &[S]) -> Vec<HexPattern> {
        patterns
            .iter()
            .map(|text| HexPattern::parse(text.as_ref()).unwrap())
            .collect()
    }

    fn scan_all(
        haystack: &[u8],
        base: u64,
        pattern_texts: &[&str],
        offset: u64,
        limit: u64,
    ) -> Vec<RunningScan> {
        let patterns = parse_all(pattern_texts);
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        let pagination = Pagination { offset, limit };
        scan_segment(haystack, base, &patterns, &mut buckets, &pagination);
        buckets
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
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        let pagination = Pagination {
            offset: 0,
            limit: 1,
        };
        // Hits arrive in haystack order ("xy" first). After "ab"'s bucket
        // truncates on its second hit, the "xy" bucket must already be filled.
        let alive = scan_segment(b"xy ab ab", 0, &patterns, &mut buckets, &pagination);
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![3]);
        assert!(buckets[0].truncated);
        assert_eq!(buckets[1].matches, vec![0]);
        assert!(!buckets[1].truncated);
    }

    #[test]
    fn all_buckets_exhausted_stops_the_scan() {
        let patterns = parse_all(&["61 62"]);
        let mut buckets: Vec<RunningScan> = vec![RunningScan::new()];
        let pagination = Pagination {
            offset: 0,
            limit: 1,
        };
        let alive = scan_segment(b"ab ab ab", 0, &patterns, &mut buckets, &pagination);
        assert!(!alive);
        assert!(buckets[0].truncated);
    }

    #[test]
    fn multi_segment_accumulation_across_calls() {
        let patterns = parse_all(&["61 62"]);
        let mut buckets: Vec<RunningScan> = vec![RunningScan::new()];
        let pagination = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_segment(
            b"ab",
            0x10,
            &patterns,
            &mut buckets,
            &pagination
        ));
        assert!(scan_segment(
            b"ab ab",
            0x20,
            &patterns,
            &mut buckets,
            &pagination
        ));
        assert_eq!(buckets[0].matches, vec![0x10, 0x20, 0x23]);
        assert_eq!(buckets[0].total, 3);
    }

    // Window walk as rx_multi_find drives it: advance by `chunk`, overlap by the
    // longest pattern minus one, stop once every bucket is exhausted.
    fn walk_windows(
        haystack: &[u8],
        base: u64,
        patterns: &[HexPattern],
        chunk: usize,
        pagination: &Pagination,
    ) -> Vec<RunningScan> {
        let overlap = patterns.iter().map(HexPattern::len).max().unwrap() - 1;
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        for start in (0..haystack.len()).step_by(chunk) {
            let end = (start + chunk + overlap).min(haystack.len());
            let alive = scan_segment(
                &haystack[start..end],
                base + start as u64,
                patterns,
                &mut buckets,
                pagination,
            );
            assert_eq!(alive, !buckets.iter().all(RunningScan::is_done));
            if !alive {
                break;
            }
        }
        buckets
    }

    // Seeded (xorshift) differential test over multi-window walks: shared first
    // bytes, wildcard-leading and wildcard-only patterns, patterns longer than a
    // tail window, seam matches seen by two windows, buckets finishing mid-window.
    #[test]
    fn seeded_window_walks_agree_with_naive_reference() {
        let mut state = 0x2545f4914f6cdd1du64;
        let mut next = |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        let shapes = [
            "00",
            "01",
            "00 00",
            "00 01",
            "00 ??",
            "?? 00",
            "?? ??",
            "?? ?? ??",
            "00 01 02",
            "00 ?? 02",
            "?? 01 02",
            "01 01 01 01",
            "00 00 00 00 00 00 00 00 ?? 01",
        ];
        let pages = [
            (0, 0),
            (0, 1),
            (0, 3),
            (2, 2),
            (5, 100),
            (0, 1000),
            (u64::MAX, 0),
        ];
        for _ in 0..400 {
            let haystack: Vec<u8> = (0..next(160)).map(|_| next(3) as u8).collect();
            let count = 1 + next(6) as usize;
            let texts: Vec<&str> = (0..count)
                .map(|_| shapes[next(shapes.len() as u64) as usize])
                .collect();
            let patterns = parse_all(&texts);
            let chunk = 1 + next(24) as usize;
            let (offset, limit) = pages[next(pages.len() as u64) as usize];
            let pagination = Pagination { offset, limit };
            let base = 0x4000;
            let buckets = walk_windows(&haystack, base, &patterns, chunk, &pagination);
            for (text, (pattern, bucket)) in texts.iter().zip(patterns.iter().zip(&buckets)) {
                let naive = naive_matches(&haystack, pattern);
                let window_end = offset.saturating_add(limit);
                let available = naive.len() as u64;
                let truncated = available > window_end;
                let page_start = offset.min(available) as usize;
                let page_end = window_end.min(available) as usize;
                let expected: Vec<u64> = naive[page_start..page_end]
                    .iter()
                    .map(|pos| base + *pos as u64)
                    .collect();
                let context =
                    format!("{text:?} chunk {chunk} page ({offset}, {limit}) hay {haystack:?}");
                assert_eq!(
                    bucket.total,
                    if truncated { window_end + 1 } else { available },
                    "{context}"
                );
                assert_eq!(bucket.truncated, truncated, "{context}");
                assert_eq!(bucket.matches, expected, "{context}");
            }
        }
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
                .map(|pattern| naive_matches(&haystack, pattern))
                .collect();
                for offset in [0u64, 1, 2, u64::MAX] {
                for limit in [0u64, 1, 2, 100] {
                    let mut buckets: Vec<RunningScan> =
                        (0..patterns.len()).map(|_| RunningScan::new()).collect();
                    let pagination = Pagination { offset, limit };
                    let alive = scan_segment(
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
