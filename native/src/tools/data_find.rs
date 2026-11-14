//! The `rx_data_find` tool: one hex byte pattern per scan.

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
use crate::hexpattern::MAX_PATTERN_CHARS;
use crate::scan::{RunningScan, scan_pattern};

// No `binary` field: it is a server-reserved argument — `BNRegisterMcpTool`
// rejects a schema that declares it, and the server strips it before invoking.
#[derive(Deserialize, JsonSchema)]
pub struct DataFindArgs {
    /// Hex byte pattern, e.g. "48 8b ?? 05"; each byte is 2 ASCII hex digits or "??".
    #[schemars(length(max = MAX_PATTERN_CHARS))]
    pub pattern: String,
    /// Only search within this section.
    #[serde(default)]
    pub section: Option<String>,
    /// Maximum matches to return.
    #[serde(default = "default_limit")]
    #[schemars(range(min = 0, max = MAX_LIMIT))]
    pub limit: u32,
    /// Matches to skip before collecting results.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub offset: u64,
}

/// `rx_data_find`: the Python plugin's `rex_data_find` contract, scan in native Rust.
pub(super) struct RxDataFind;

fn response_json(running: &RunningScan) -> serde_json::Value {
    json!({
        "total": running.total,
        "truncated": running.truncated,
        "matches": matches_json(&running.matches),
    })
}

impl TypedMcpTool for RxDataFind {
    type Args = DataFindArgs;

    fn info(&self) -> McpToolInfo {
        McpToolInfo::new(
            "rx_data_find",
            "Search mapped memory for a hex pattern in Rust; about 7.5x faster than `rex_data_find` on a whole-view scan, no faster on `.text`.",
        )
        .with_annotations(McpToolAnnotations::READ_ONLY)
    }

    fn invoke(
        &self,
        call: &McpToolCall,
        args: DataFindArgs,
    ) -> Result<McpToolResult, McpToolError> {
        // View resolution first, matching the Python handler's order.
        let view = call.require_binary_view()?;
        let pagination = validate_pagination(args.limit, args.offset)?;
        let pattern = parse_checked_pattern(&args.pattern)?;
        let bounds = resolve_bounds(&view, args.section.as_deref())?;
        let overlap = pattern.len().saturating_sub(1) as u64;
        let mut running = RunningScan::new();
        for_each_segment(&*view, READ_CHUNK, bounds, overlap, |base, data| {
            scan_pattern(data, base, &pattern, &pagination, &mut running)
        });
        Ok(McpToolResult::structured(response_json(&running)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexpattern::HexPattern;
    use crate::scan::Pagination;
    use crate::test_utils::{expected_pagination, naive_matches, pattern_from_tokens};
    use crate::tools::testing::{FakeView, scan_fake_view};
    use proptest::prelude::*;

    #[test]
    fn response_includes_page_fields() {
        let mut running = RunningScan::new();
        running.total = 2;
        running.truncated = true;
        running.matches.push(0x1000);

        assert_eq!(
            response_json(&running),
            serde_json::json!({
                "total": 2,
                "truncated": true,
                "matches": ["0x1000"],
            })
        );
    }

    fn scan_page(view: &FakeView, pattern: &HexPattern, offset: u64, limit: u64) -> RunningScan {
        scan_fake_view(
            view,
            4,
            None,
            pattern.len().saturating_sub(1) as u64,
            pattern,
            &Pagination { offset, limit },
        )
    }

    #[test]
    fn finds_a_match_across_a_seam_between_adjacent_segments() {
        let view = FakeView {
            segments: vec![(0x1000, 0x1004), (0x1004, 0x1008)],
            unreadable_segments: Vec::new(),
            runs: vec![(0x1000, b"\x00\x00\x00\x90\x91\x00\x00\x00".to_vec())],
        };
        let pattern = HexPattern::parse("90 91").unwrap();
        assert_eq!(scan_page(&view, &pattern, 0, 10).matches, vec![0x1003]);
    }

    #[test]
    fn does_not_bridge_an_unreadable_neighbour_or_a_gap() {
        let bytes = b"\x00\x00\x00\x90\x91\x00\x00\x00".to_vec();
        let pattern = HexPattern::parse("90 91").unwrap();
        let unreadable_neighbour = FakeView {
            segments: vec![(0x1000, 0x1004), (0x1004, 0x1008)],
            unreadable_segments: vec![(0x1004, 0x1008)],
            runs: vec![(0x1000, bytes.clone())],
        };
        assert_eq!(scan_page(&unreadable_neighbour, &pattern, 0, 10).total, 0);
        let gap = FakeView {
            segments: vec![(0x1000, 0x1004), (0x1005, 0x1008)],
            unreadable_segments: Vec::new(),
            runs: vec![(0x1000, bytes)],
        };
        assert_eq!(scan_page(&gap, &pattern, 0, 10).total, 0);
    }

    #[test]
    fn finds_matches_across_chunk_boundaries() {
        // Python test_data_find_finds_matches_across_chunk_boundaries analog.
        let view = FakeView {
            segments: vec![(0x1000, 0x1008)],
            unreadable_segments: Vec::new(),
            runs: vec![(0x1000, b"\x00\x00\x33\xeb\x00\x00\x33\xeb".to_vec())],
        };
        let pattern = HexPattern::parse("33 eb").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let running = scan_fake_view(&view, 4, None, 1, &pattern, &page);
        assert_eq!(running.total, 2);
        assert_eq!(running.matches, vec![0x1002, 0x1006]);
    }

    // Python test_data_find_matches_straddling_chunk_boundaries analog: a match
    // straddling the chunk edge is visible only because each window extends
    // pattern_length - 1 bytes past the chunk, and a match starting exactly at
    // the edge is reported once because every match start belongs to one window.
    #[test]
    fn straddling_and_boundary_matches_are_found_exactly_once() {
        let pattern = HexPattern::parse("33 eb").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let straddle = FakeView {
            segments: vec![(0x1000, 0x1008)],
            unreadable_segments: Vec::new(),
            runs: vec![(0x1000, b"\x00\x00\x00\x33\xeb\x00\x00\x00".to_vec())],
        };
        let running = scan_fake_view(&straddle, 4, None, 1, &pattern, &page);
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, vec![0x1003]);

        let boundary = FakeView {
            segments: vec![(0x1000, 0x1008)],
            unreadable_segments: Vec::new(),
            runs: vec![(0x1000, b"\x00\x00\x00\x00\x33\xeb\x00\x00".to_vec())],
        };
        let running = scan_fake_view(&boundary, 4, None, 1, &pattern, &page);
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, vec![0x1004]);
    }

    // Short and empty window reads (unreadable holes) must not stall the walk:
    // the position advances regardless, so matches after the hole are recovered.
    #[test]
    fn recovers_matches_after_short_and_empty_reads() {
        let view = FakeView {
            segments: vec![(0x2000, 0x2010)],
            unreadable_segments: Vec::new(),
            runs: vec![
                (0x2000, b"\x90\x90".to_vec()), // short read: 2 of 5 requested
                (0x2008, b"\x33\xeb".to_vec()), // match after the hole
            ],
        };
        let pattern = HexPattern::parse("33 eb").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let running = scan_fake_view(&view, 4, None, 1, &pattern, &page);
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, vec![0x2008]);
    }

    // A segment whose readability flag is off must be skipped up front: even with
    // bytes present under it, the walk opens zero windows on it (the Python
    // test_data_find_skips_unreadable_segments analog, flag-modeled).
    #[test]
    fn unreadable_segments_are_skipped_up_front() {
        let pattern = HexPattern::parse("33 eb").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let view = FakeView {
            segments: vec![(0x1000, 0x1008), (0x2000, 0x2008)],
            unreadable_segments: vec![(0x1000, 0x1008)],
            runs: vec![
                (0x1000, b"\x33\xeb\x33\xeb\x33\xeb\x33\xeb".to_vec()),
                (0x2000, b"\x33\xeb\x00\x00\x00\x00\x00\x00".to_vec()),
            ],
        };
        let running = scan_fake_view(&view, 4, None, 1, &pattern, &page);
        // Only the readable segment is walked; the unreadable one contributes nothing.
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, vec![0x2000]);
    }

    #[test]
    fn limit_at_the_cap_through_the_scan_path() {
        // Python test_data_find_caps_limit analog: exactly at the cap the
        // limit is honored through the real chunked scan (production
        // READ_CHUNK), and the scan stops one match past the window.
        let view = FakeView {
            segments: vec![(0x1000, 0x1000 + 600)],
            unreadable_segments: Vec::new(),
            runs: vec![(0x1000, vec![0x90; 600])],
        };
        let pattern = HexPattern::parse("90").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 500,
        };
        let running = scan_fake_view(&view, READ_CHUNK, None, 0, &pattern, &page);
        assert_eq!(running.matches.len(), 500);
        assert_eq!(running.total, 501);
        assert!(running.truncated);
        assert_eq!(running.matches[0], 0x1000);
        assert_eq!(running.matches[499], 0x1000 + 499);
    }

    // Python test_data_find_pages_tile_the_full_result analog: consecutive
    // pages (limit 2, offset 0, 2, 4, ...) reproduce the full untruncated
    // result with no gaps or duplicates.
    #[test]
    fn pages_tile_the_full_result() {
        let mut next = crate::test_rng(0x7a11_1a11);
        for case in 0..32u32 {
            let blob_len = (next() % 48) as usize;
            let blob: Vec<u8> = (0..blob_len).map(|_| (next() % 4) as u8).collect();
            let segment = (0x2000, 0x2000 + (blob_len.max(1)) as u64);
            let view = FakeView {
                segments: vec![segment],
                unreadable_segments: Vec::new(),
                runs: vec![(0x2000, blob)],
            };
            let pat_len = 1 + (next() % 3) as usize;
            let tokens: Vec<String> = (0..pat_len)
                .map(|_| {
                    if next().is_multiple_of(3) {
                        "??".to_string()
                    } else {
                        format!("{:02x}", next() % 4)
                    }
                })
                .collect();
            let pattern = HexPattern::parse(&tokens.join(" ")).unwrap();
            let full = scan_page(&view, &pattern, 0, 500);
            assert!(!full.truncated, "case {case}");
            assert_eq!(full.matches.len() as u64, full.total, "case {case}");
            let true_total = full.total;

            let tiled: Vec<u64> = (0..=true_total)
                .step_by(2)
                .flat_map(|page_offset| scan_page(&view, &pattern, page_offset, 2).matches)
                .collect();
            assert_eq!(tiled, full.matches, "case {case}");

            // Every offset pages the exact expected slice.
            for page_offset in 0..=true_total {
                let page = scan_page(&view, &pattern, page_offset, 2);
                let expected_page = expected_pagination(full.matches.len(), page_offset, 2);
                let expected = full.matches[expected_page.start..expected_page.end].to_vec();
                assert_eq!(page.matches, expected, "case {case} offset {page_offset}");
                assert_eq!(
                    page.total, expected_page.total,
                    "case {case} offset {page_offset}"
                );
                assert_eq!(
                    page.truncated, expected_page.truncated,
                    "case {case} offset {page_offset}"
                );
            }

            // An arbitrary adversarial (but valid) limit/offset pair.
            let limit = (next() % 501) as u64;
            let offset = ((next() as u64) << 32) | next() as u64;
            let page = scan_page(&view, &pattern, offset, limit);
            let expected_page = expected_pagination(full.matches.len(), offset, limit);
            let expected = full.matches[expected_page.start..expected_page.end].to_vec();
            assert_eq!(page.matches, expected, "case {case}");
            assert_eq!(page.total, expected_page.total, "case {case}");
            assert_eq!(page.truncated, expected_page.truncated, "case {case}");
        }
    }

    proptest! {
        #[test]
        fn chunked_single_scan_matches_naive_results(
            haystack in prop::collection::vec(0u8..4, 0..64),
            tokens in prop::collection::vec(
                prop_oneof![Just(None::<u8>), (0u8..4).prop_map(Some)],
                1..6
            ),
            chunk in 1u64..16,
            offset in prop_oneof![0u64..10, Just(u64::MAX)],
            limit in prop_oneof![0u64..10, Just(u64::MAX)]
        ) {
            let pattern = pattern_from_tokens(tokens);
            let base = 0x1000;
            let view = FakeView {
                segments: vec![(base, base + haystack.len() as u64)],
                unreadable_segments: Vec::new(),
                runs: vec![(base, haystack.clone())],
            };
            let overlap = (pattern.len() - 1) as u64;
            let pagination = Pagination { offset, limit };
            let running = scan_fake_view(
                &view,
                chunk,
                None,
                overlap,
                &pattern,
                &pagination,
            );

            let naive = naive_matches(&haystack, &pattern);
            let available = naive.len() as u64;
            let window_end = offset.saturating_add(limit);
            let truncated = available > window_end;
            let expected_total = if truncated { window_end + 1 } else { available };
            let page_start = offset.min(available) as usize;
            let page_end = window_end.min(available) as usize;
            let expected: Vec<u64> = naive[page_start..page_end]
                .iter()
                .map(|position| base + *position as u64)
                .collect();

            prop_assert_eq!(running.total, expected_total);
            prop_assert_eq!(running.truncated, truncated);
            prop_assert_eq!(running.matches, expected);
        }

        #[test]
        fn chunked_multi_segment_scan_matches_each_segment_independently(
            first in prop::collection::vec(0u8..4, 1..48),
            second in prop::collection::vec(0u8..4, 1..48),
            tokens in prop::collection::vec(
                prop_oneof![Just(None::<u8>), (0u8..4).prop_map(Some)],
                1..6
            ),
            gap in 1u64..8,
            chunk in 1u64..16,
            offset in prop_oneof![0u64..10, Just(u64::MAX)],
            limit in prop_oneof![0u64..10, Just(u64::MAX)]
        ) {
            let pattern = pattern_from_tokens(tokens);
            let first_start = 0x1000;
            let first_end = first_start + first.len() as u64;
            let second_start = first_end + gap;
            let view = FakeView {
                segments: vec![
                    (first_start, first_end),
                    (second_start, second_start + second.len() as u64),
                ],
                unreadable_segments: Vec::new(),
                runs: vec![(first_start, first.clone()), (second_start, second.clone())],
            };
            let pagination = Pagination { offset, limit };
            let running = scan_fake_view(
                &view,
                chunk,
                None,
                (pattern.len() - 1) as u64,
                &pattern,
                &pagination,
            );

            let mut naive: Vec<u64> = naive_matches(&first, &pattern)
                .into_iter()
                .map(|position| first_start + position as u64)
                .collect();
            naive.extend(
                naive_matches(&second, &pattern)
                    .into_iter()
                    .map(|position| second_start + position as u64),
            );
            let expected_page = expected_pagination(naive.len(), offset, limit);
            let expected = naive[expected_page.start..expected_page.end].to_vec();

            prop_assert_eq!(running.total, expected_page.total);
            prop_assert_eq!(running.truncated, expected_page.truncated);
            prop_assert_eq!(running.matches, expected);
        }
    }
}
