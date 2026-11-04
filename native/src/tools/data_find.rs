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
    #[schemars(length(max = MAX_PATTERN_CHARS))]
    pub pattern: String,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default = "default_limit")]
    #[schemars(range(min = 0, max = MAX_LIMIT))]
    pub limit: u32,
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub offset: u64,
}

/// `rx_data_find`: the Python plugin's `rex_data_find` contract, scan in native Rust.
pub(super) struct RxDataFind;

impl TypedMcpTool for RxDataFind {
    type Args = DataFindArgs;

    fn info(&self) -> McpToolInfo {
        McpToolInfo::new(
            "rx_data_find",
            "Find all occurrences of a hex byte pattern in mapped memory.",
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
        Ok(McpToolResult::structured(json!({
            "total": running.total,
            "truncated": running.truncated,
            "matches": matches_json(&running.matches),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexpattern::HexPattern;
    use crate::scan::Pagination;
    use crate::tools::testing::{FakeView, scan_fake_view};
    use proptest::prelude::*;

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

    fn naive_matches(haystack: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
        if haystack.len() < pattern.len() {
            return Vec::new();
        }
        (0..=haystack.len() - pattern.len())
            .filter(|pos| {
                haystack[*pos..*pos + pattern.len()]
                    .iter()
                    .zip(pattern)
                    .all(|(byte, expected)| expected.is_none_or(|value| value == *byte))
            })
            .collect()
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
            let overlap = (pattern.len() - 1) as u64;

            let full_page = Pagination {
                offset: 0,
                limit: 500,
            };
            let full = scan_fake_view(&view, 4, None, overlap, &pattern, &full_page);
            assert!(!full.truncated, "case {case}");
            assert_eq!(full.matches.len() as u64, full.total, "case {case}");
            let true_total = full.total;

            let mut tiled = Vec::new();
            for page_offset in (0..=true_total).step_by(2) {
                let page = scan_fake_view(
                    &view,
                    4,
                    None,
                    overlap,
                    &pattern,
                    &Pagination {
                        offset: page_offset,
                        limit: 2,
                    },
                );
                tiled.extend(page.matches);
            }
            assert_eq!(tiled, full.matches, "case {case}");

            // Every offset pages the exact expected slice.
            for page_offset in 0..=true_total {
                let page = scan_fake_view(
                    &view,
                    4,
                    None,
                    overlap,
                    &pattern,
                    &Pagination {
                        offset: page_offset,
                        limit: 2,
                    },
                );
                let expected: Vec<u64> = full
                    .matches
                    .iter()
                    .skip(page_offset as usize)
                    .take(2)
                    .copied()
                    .collect();
                assert_eq!(page.matches, expected, "case {case} offset {page_offset}");
                assert_eq!(
                    page.total,
                    true_total.min(page_offset.saturating_add(3)),
                    "case {case} offset {page_offset}"
                );
                assert_eq!(
                    page.truncated,
                    true_total > page_offset + 2,
                    "case {case} offset {page_offset}"
                );
            }

            // An arbitrary adversarial (but valid) limit/offset pair.
            let limit = (next() % 501) as u64;
            let offset = ((next() as u64) << 32) | next() as u64;
            let page = scan_fake_view(
                &view,
                4,
                None,
                overlap,
                &pattern,
                &Pagination { offset, limit },
            );
            let expected: Vec<u64> = full
                .matches
                .iter()
                .skip(offset as usize)
                .take(limit as usize)
                .copied()
                .collect();
            assert_eq!(page.matches, expected, "case {case}");
            assert_eq!(
                page.total,
                true_total.min(offset.saturating_add(limit).saturating_add(1)),
                "case {case}"
            );
            assert_eq!(
                page.truncated,
                true_total > offset.saturating_add(limit),
                "case {case}"
            );
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

            let naive = naive_matches(&haystack, pattern.bytes());
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
    }
}
