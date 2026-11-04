//! The `rx_multi_find` tool: many hex byte patterns in one scan.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use binaryninja::mcp::tool::{
    McpToolAnnotations, McpToolCall, McpToolError, McpToolInfo, McpToolResult, TypedMcpTool,
};

use super::walk::for_each_segment;
use super::{
    MAX_LIMIT, READ_CHUNK, default_limit, matches_json, parse_checked_pattern, resolve_bounds,
    validate_pagination,
};
use crate::hexpattern::HexPattern;
use crate::multi::{MAX_MULTI_PATTERNS, scan_segment};
use crate::scan::RunningScan;

// No `binary` field — same server-reserved argument rule as `DataFindArgs`.
#[derive(Deserialize, JsonSchema)]
pub struct MultiFindArgs {
    #[schemars(length(min = 1, max = MAX_MULTI_PATTERNS))]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default = "default_limit")]
    #[schemars(range(min = 0, max = MAX_LIMIT))]
    pub limit: u32,
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub offset: u64,
}

/// `rx_multi_find`: many hex patterns in one pass over the bytes via
/// per-pattern prefilter scans — the capability the Python plugin cannot offer.
pub(super) struct RxMultiFind;

impl TypedMcpTool for RxMultiFind {
    type Args = MultiFindArgs;

    fn info(&self) -> McpToolInfo {
        McpToolInfo::new(
            "rx_multi_find",
            "Search multiple hex patterns in one Rust pass; use instead of repeated, slower `rex_data_find` calls.",
        )
        .with_annotations(McpToolAnnotations::READ_ONLY)
    }

    fn invoke(
        &self,
        call: &McpToolCall,
        args: MultiFindArgs,
    ) -> Result<McpToolResult, McpToolError> {
        // The published schema caps the list (minItems/maxItems), but nothing
        // on the server enforces array length before `invoke`: the typed
        // adapter only deserializes, and an empty list would also violate
        // `longest_pattern_overlap`'s precondition below.
        if args.patterns.is_empty() {
            return Err(McpToolError::invalid_params(
                "at least one pattern is required",
            ));
        }
        if args.patterns.len() > MAX_MULTI_PATTERNS {
            return Err(McpToolError::new(
                "too_many_patterns",
                format!("at most {MAX_MULTI_PATTERNS} patterns are allowed"),
            ));
        }
        let pagination = validate_pagination(args.limit, args.offset)?;
        let patterns = args
            .patterns
            .iter()
            .enumerate()
            .map(|(index, text)| {
                parse_checked_pattern(text).map_err(|error| prefix_pattern_error(index, error))
            })
            .collect::<Result<Vec<_>, McpToolError>>()?;
        let view = call.require_binary_view()?;
        let bounds = resolve_bounds(&view, args.section.as_deref())?;
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        let overlap = longest_pattern_overlap(&patterns);
        for_each_segment(&*view, READ_CHUNK, bounds, overlap, |base, data| {
            scan_segment(data, base, &patterns, &mut buckets, &pagination)
        });
        let results = args
            .patterns
            .iter()
            .zip(buckets.iter())
            .map(|(text, bucket)| {
                json!({
                    "pattern": text,
                    "total": bucket.total,
                    "truncated": bucket.truncated,
                    "matches": matches_json(&bucket.matches),
                })
            })
            .collect::<Vec<_>>();
        Ok(McpToolResult::structured(json!({
            "total": buckets.iter().map(|bucket| bucket.total).sum::<u64>(),
            "truncated": buckets.iter().any(|bucket| bucket.truncated),
            "results": results,
        })))
    }
}

/// Multi-pattern parse failures name the offending entry.
fn prefix_pattern_error(index: usize, error: McpToolError) -> McpToolError {
    let (code, message) = (error.code, error.message);
    McpToolError::new(code, format!("pattern {index}: {message}"))
}

// Chunked-walk overlap: the longest pattern's length minus one, so every
// pattern's matches straddling a chunk edge stay visible in one window.
// Precondition: `patterns` is non-empty (the tool rejects an empty list first).
fn longest_pattern_overlap(patterns: &[HexPattern]) -> u64 {
    (patterns
        .iter()
        .map(HexPattern::len)
        .max()
        .expect("non-empty pattern list")
        - 1) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Pagination;
    use crate::test_utils::{naive_matches, pattern_from_tokens};
    use crate::tools::testing::FakeView;
    use proptest::prelude::*;

    #[test]
    fn multi_parse_errors_name_the_pattern_index() {
        let error = parse_checked_pattern("48 zz")
            .map_err(|e| prefix_pattern_error(2, e))
            .unwrap_err();
        assert_eq!(error.code, "invalid_pattern");
        assert_eq!(error.message, "pattern 2: invalid hex byte token 'zz'");
    }

    // The multi-pattern walk overlaps windows by the LONGEST pattern minus one:
    // a per-pattern shorter overlap would drop the longer pattern's match
    // straddling a chunk edge.
    #[test]
    fn multi_walk_overlaps_by_the_longest_pattern() {
        let patterns = vec![
            HexPattern::parse("33 eb").unwrap(),
            HexPattern::parse("33 eb 00").unwrap(),
        ];
        let mut buckets = vec![RunningScan::new(), RunningScan::new()];
        let view = FakeView {
            segments: vec![(0x1000, 0x1008)],
            unreadable_segments: Vec::new(),
            runs: vec![(0x1000, b"\x00\x00\x00\x33\xeb\x00\x00\x00".to_vec())],
        };
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let overlap = longest_pattern_overlap(&patterns);
        let alive = for_each_segment(&view, 4, None, overlap, |base, data| {
            scan_segment(data, base, &patterns, &mut buckets, &page)
        });
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![0x1003]);
        assert_eq!(buckets[1].matches, vec![0x1003]);
    }

    // The overlap protecting the longest pattern re-exposes the seam zone to
    // its successor window: a shorter pattern's match there is fully visible in
    // two consecutive windows and must still count once per bucket. Regression:
    // '33 eb' starting exactly at the 0x1004 seam was recorded in window 0 and
    // again in window 1.
    #[test]
    fn multi_seam_matches_of_shorter_patterns_are_counted_once() {
        let patterns = vec![
            HexPattern::parse("33 eb").unwrap(),
            HexPattern::parse("33 eb 00").unwrap(),
        ];
        let mut buckets = vec![RunningScan::new(), RunningScan::new()];
        // Seam at 0x1004 (chunk 4, overlap longest-1 = 2): '33 eb' starts
        // exactly on it, so windows 0 and 1 both see it whole; 0x1009 is a
        // control that only window 2 covers. The 3-byte pattern's matches at
        // the same addresses fit one window each.
        let view = FakeView {
            segments: vec![(0x1000, 0x1010)],
            unreadable_segments: Vec::new(),
            runs: vec![(
                0x1000,
                b"\x00\x00\x00\x00\x33\xeb\x00\x00\x00\x33\xeb\x00\x00\x00\x00\x00".to_vec(),
            )],
        };
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let overlap = longest_pattern_overlap(&patterns);
        let alive = for_each_segment(&view, 4, None, overlap, |base, data| {
            scan_segment(data, base, &patterns, &mut buckets, &page)
        });
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![0x1004, 0x1009]);
        assert_eq!(buckets[0].total, 2);
        assert!(!buckets[0].truncated);
        assert_eq!(buckets[1].matches, vec![0x1004, 0x1009]);
        assert_eq!(buckets[1].total, 2);
        assert!(!buckets[1].truncated);
    }

    proptest! {
        #[test]
        fn chunked_multi_scan_matches_naive_results(
            haystack in prop::collection::vec(0u8..4, 0..64),
            token_sets in prop::collection::vec(
                prop::collection::vec(
                    prop_oneof![Just(None::<u8>), (0u8..4).prop_map(Some)],
                    1..6
                ),
                1..6
            ),
            chunk in 1u64..16,
            offset in prop_oneof![0u64..10, Just(u64::MAX)],
            limit in prop_oneof![0u64..10, Just(u64::MAX)]
        ) {
            let patterns: Vec<HexPattern> = token_sets
                .into_iter()
                .map(pattern_from_tokens)
                .collect();
                let mut buckets: Vec<RunningScan> =
                (0..patterns.len()).map(|_| RunningScan::new()).collect();
            let base = 0x1000;
            let view = FakeView {
                segments: vec![(base, base + haystack.len() as u64)],
                unreadable_segments: Vec::new(),
                runs: vec![(base, haystack.clone())],
            };
            let pagination = Pagination { offset, limit };
            let overlap = longest_pattern_overlap(&patterns);
            let alive = for_each_segment(&view, chunk, None, overlap, |window_base, data| {
                scan_segment(data, window_base, &patterns, &mut buckets, &pagination)
            });

            for (index, (pattern, bucket)) in patterns.iter().zip(&buckets).enumerate() {
                let window_end = offset.saturating_add(limit);
                let naive = naive_matches(&haystack, pattern);
                let available = naive.len() as u64;
                let truncated = available > window_end;
                let expected_total = if truncated { window_end + 1 } else { available };
                let page_start = offset.min(available) as usize;
                let page_end = window_end.min(available) as usize;
                let expected: Vec<u64> = naive[page_start..page_end]
                    .iter()
                    .map(|position| base + *position as u64)
                    .collect();
                prop_assert_eq!(bucket.total, expected_total, "pattern {}", index);
                prop_assert_eq!(bucket.truncated, truncated, "pattern {}", index);
                prop_assert_eq!(&bucket.matches, &expected, "pattern {}", index);
            }
            prop_assert_eq!(alive, !buckets.iter().all(RunningScan::is_done));
        }
    }
}
