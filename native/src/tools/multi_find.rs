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
use crate::multi::{MAX_MULTI_PATTERNS, MultiMatcher};
use crate::scan::RunningScan;

/// Arguments of `rx_multi_find`. No `binary` field — same server-reserved
/// argument rule as `DataFindArgs`.
#[derive(Deserialize, JsonSchema)]
pub struct MultiFindArgs {
    /// Hex byte patterns, e.g. ["48 8b ?? 05", "e8 ?? ?? ?? ??"]; "??" matches any single byte.
    #[schemars(length(min = 1, max = MAX_MULTI_PATTERNS))]
    pub patterns: Vec<String>,
    /// Only search within this section.
    #[serde(default)]
    pub section: Option<String>,
    /// Maximum number of matches per pattern to return (0 to 500).
    #[serde(default = "default_limit")]
    #[schemars(range(min = 0, max = MAX_LIMIT))]
    pub limit: u32,
    /// Number of matches to skip per pattern before collecting results (>= 0).
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub offset: u64,
}

/// `rx_multi_find`: many hex patterns in one pass over the bytes via a
/// multi-pattern automaton — the capability the Python plugin cannot offer.
pub(super) struct RxMultiFind;

impl TypedMcpTool for RxMultiFind {
    type Args = MultiFindArgs;

    fn info(&self) -> McpToolInfo {
        McpToolInfo::new(
            "rx_multi_find",
            "Find occurrences of many hex byte patterns in one pass over mapped memory. \
             A single multi-pattern automaton scan replaces N sequential rex_data_find calls; \
             each pattern gets its own rex_data_find-style match list with the same \
             limit/offset pagination and truncated flag.",
        )
        .with_annotations(McpToolAnnotations::READ_ONLY)
    }

    fn invoke(
        &self,
        call: &McpToolCall,
        args: MultiFindArgs,
    ) -> Result<McpToolResult, McpToolError> {
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
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        let overlap = longest_pattern_overlap(&patterns);
        for_each_segment(&*view, READ_CHUNK, bounds, overlap, |base, data| {
            matcher.scan_segment(data, base, &patterns, &mut buckets, &pagination)
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

/// Chunked-walk overlap for a pattern list: the longest pattern's length minus
/// one, so every pattern's matches straddling a chunk edge stay visible in one
/// window.
///
/// Precondition: `patterns` is non-empty — `RxMultiFind` rejects an empty list
/// before reaching this and the tests pass literal non-empty lists — so
/// `.max()` cannot be `None` and needs no fallback value.
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
    use crate::tools::testing::FakeView;

    #[test]
    fn multi_parse_errors_name_the_pattern_index() {
        let error = parse_checked_pattern("48 zz")
            .map_err(|e| prefix_pattern_error(2, e))
            .unwrap_err();
        assert_eq!(error.code, "invalid_pattern");
        assert_eq!(error.message, "pattern 2: invalid hex byte token 'zz'");
    }

    /// The multi-pattern walk overlaps windows by the LONGEST pattern minus
    /// one: a per-pattern shorter overlap would drop the longer pattern's
    /// match straddling a chunk edge.
    #[test]
    fn multi_walk_overlaps_by_the_longest_pattern() {
        let patterns = vec![
            HexPattern::parse("33 eb").unwrap(),
            HexPattern::parse("33 eb 00").unwrap(),
        ];
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets = vec![RunningScan::new(), RunningScan::new()];
        let view = FakeView {
            segments: vec![(0x1000, 0x1008)],
            runs: vec![(0x1000, b"\x00\x00\x00\x33\xeb\x00\x00\x00".to_vec())],
        };
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let overlap = longest_pattern_overlap(&patterns);
        let alive = for_each_segment(&view, 4, None, overlap, |base, data| {
            matcher.scan_segment(data, base, &patterns, &mut buckets, &page)
        });
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![0x1003]);
        assert_eq!(buckets[1].matches, vec![0x1003]);
    }

    /// The overlap that protects the longest pattern re-exposes the seam zone
    /// of every window in its successor: a shorter pattern's match starting
    /// there is fully visible in two consecutive windows and must still be
    /// counted once per bucket — the per-pattern `rex_data_find` contract the
    /// multi result promises. Regression: '33 eb' starting exactly at the
    /// 0x1004 seam was recorded in window 0 and again in window 1.
    #[test]
    fn multi_seam_matches_of_shorter_patterns_are_counted_once() {
        let patterns = vec![
            HexPattern::parse("33 eb").unwrap(),
            HexPattern::parse("33 eb 00").unwrap(),
        ];
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets = vec![RunningScan::new(), RunningScan::new()];
        // Seam at 0x1004 (chunk 4, overlap longest-1 = 2): '33 eb' starts
        // exactly on it, so windows 0 and 1 both see it whole; 0x1009 is a
        // control that only window 2 covers. The 3-byte pattern's matches at
        // the same addresses fit one window each.
        let view = FakeView {
            segments: vec![(0x1000, 0x1010)],
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
            matcher.scan_segment(data, base, &patterns, &mut buckets, &page)
        });
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![0x1004, 0x1009]);
        assert_eq!(buckets[0].total, 2);
        assert!(!buckets[0].truncated);
        assert_eq!(buckets[1].matches, vec![0x1004, 0x1009]);
        assert_eq!(buckets[1].total, 2);
        assert!(!buckets[1].truncated);
    }
}
