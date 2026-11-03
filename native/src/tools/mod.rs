//! The MCP tools this plugin registers: `rx_data_find` (the Python plugin's
//! contract with the scan in native Rust) and `rx_multi_find` (many patterns in
//! one pass). Shared Python-parity validation and result shaping live here;
//! both tools walk memory through [`walk`].

mod data_find;
mod multi_find;
mod walk;

#[cfg(test)]
mod testing;

use binaryninja::binary_view::BinaryView;
use binaryninja::mcp::tool::{McpToolError, register_typed_mcp_tool};
use serde_json::json;

use crate::hexpattern::{HexPattern, MAX_PATTERN_CHARS, TRUNCATE_CHARS, truncate_echo};
use crate::scan::Pagination;

use data_find::RxDataFind;
use multi_find::RxMultiFind;

/// `rex_data_find`'s limit cap.
const MAX_LIMIT: u64 = 500;

/// Window-read size cap, matching `_READ_CHUNK` in the Python plugin.
const READ_CHUNK: u64 = 4 * 1024 * 1024;

fn default_limit() -> u32 {
    50
}

fn invalid_param(name: &str, requirement: &str) -> McpToolError {
    McpToolError::invalid_params(format!("Invalid integer parameter '{name}': {requirement}"))
}

/// Validate `limit`/`offset` like the Python plugin's `_validate_range`: the
/// schema already rejects these for typed calls; this keeps direct invocation
/// identical.
fn validate_pagination(limit: u32, offset: u64) -> Result<Pagination, McpToolError> {
    let limit = u64::from(limit);
    if limit > MAX_LIMIT {
        return Err(invalid_param(
            "limit",
            &format!("Must be at most {MAX_LIMIT}"),
        ));
    }
    Ok(Pagination { offset, limit })
}

fn parse_checked_pattern(pattern: &str) -> Result<HexPattern, McpToolError> {
    // Length in characters, matching the Python plugin's len() check.
    if pattern.chars().count() > MAX_PATTERN_CHARS {
        return Err(McpToolError::new(
            "pattern_too_large",
            format!("pattern exceeds {MAX_PATTERN_CHARS} characters"),
        ));
    }
    HexPattern::parse(pattern).map_err(|error| McpToolError::new("invalid_pattern", error.message))
}

/// Resolve the optional section name to inclusive-exclusive bounds, mirroring
/// the Python plugin's `_resolve_section`.
fn resolve_bounds(
    view: &BinaryView,
    section: Option<&str>,
) -> Result<Option<(u64, u64)>, McpToolError> {
    section
        .map(|name| {
            view.section_by_name(name)
                .map(|section| (section.start(), section.end()))
                .ok_or_else(|| section_not_found_error(name))
        })
        .transpose()
}

/// The `section_not_found` error with the Python plugin's exact truncated text.
fn section_not_found_error(name: &str) -> McpToolError {
    McpToolError::new(
        "section_not_found",
        format!("no section named '{}'", truncate_echo(name, TRUNCATE_CHARS)),
    )
}

fn matches_json(matches: &[u64]) -> serde_json::Value {
    json!(
        matches
            .iter()
            .map(|address| format!("{address:#x}"))
            .collect::<Vec<_>>()
    )
}

/// Register both tools; returns false when the core rejects a definition.
pub fn register() -> bool {
    register_typed_mcp_tool(RxDataFind).is_some() && register_typed_mcp_tool(RxMultiFind).is_some()
}

#[cfg(test)]
mod tests {
    use super::data_find::DataFindArgs;
    use super::multi_find::MultiFindArgs;
    use super::*;
    use crate::multi::MAX_MULTI_PATTERNS;

    #[test]
    fn pagination_rejects_over_limit() {
        let error = validate_pagination(501, 0).unwrap_err();
        assert_eq!(error.code, "invalid_params");
        assert_eq!(
            error.message,
            "Invalid integer parameter 'limit': Must be at most 500"
        );
        assert!(validate_pagination(500, 0).is_ok());
        assert!(validate_pagination(0, 0).is_ok());
    }

    // The published schema's caps must equal the runtime-enforced consts, or a
    // value drifting between them is rejected by one gate and accepted by the
    // other; compilation alone cannot catch a schemars attribute dropping its const.
    #[test]
    fn schema_caps_equal_the_runtime_consts() {
        let data_find = serde_json::to_value(schemars::schema_for!(DataFindArgs)).unwrap();
        let properties = &data_find["properties"];
        assert_eq!(
            properties["pattern"]["maxLength"].as_u64(),
            Some(MAX_PATTERN_CHARS as u64)
        );
        assert_eq!(properties["limit"]["maximum"].as_u64(), Some(MAX_LIMIT));
        assert_eq!(properties["limit"]["minimum"].as_u64(), Some(0));
        assert_eq!(properties["offset"]["minimum"].as_u64(), Some(0));

        let multi_find = serde_json::to_value(schemars::schema_for!(MultiFindArgs)).unwrap();
        let properties = &multi_find["properties"];
        assert_eq!(properties["patterns"]["minItems"].as_u64(), Some(1));
        assert_eq!(
            properties["patterns"]["maxItems"].as_u64(),
            Some(MAX_MULTI_PATTERNS as u64)
        );
        assert_eq!(properties["limit"]["maximum"].as_u64(), Some(MAX_LIMIT));
        assert_eq!(properties["limit"]["minimum"].as_u64(), Some(0));
    }

    #[test]
    fn pattern_size_and_parse_errors() {
        let long = "48 ".repeat(2731); // 8193 chars after trim
        let error = parse_checked_pattern(&long).unwrap_err();
        assert_eq!(error.code, "pattern_too_large");
        assert_eq!(error.message, "pattern exceeds 8192 characters");

        let error = parse_checked_pattern("48 zz").unwrap_err();
        assert_eq!(error.code, "invalid_pattern");
        assert_eq!(error.message, "invalid hex byte token 'zz'");

        let error = parse_checked_pattern("").unwrap_err();
        assert_eq!(error.code, "invalid_pattern");
        assert_eq!(error.message, "empty hex pattern");
    }

    #[test]
    fn section_not_found_error_text_and_truncation() {
        let error = section_not_found_error(".text");
        assert_eq!(error.code, "section_not_found");
        assert_eq!(error.message, "no section named '.text'");

        let long = "a".repeat(600);
        let error = section_not_found_error(&long);
        assert_eq!(
            error.message,
            format!(
                "no section named '{}... [88 chars truncated]'",
                "a".repeat(512)
            )
        );
    }

    #[test]
    fn pattern_of_exactly_the_cap_is_accepted() {
        // Python test_data_find_rejects_oversized_pattern boundary analog:
        // exactly 8192 characters pass, one more is rejected.
        let at_cap = "90".repeat(MAX_PATTERN_CHARS / 2);
        assert_eq!(at_cap.chars().count(), MAX_PATTERN_CHARS);
        let pattern = parse_checked_pattern(&at_cap).unwrap();
        assert_eq!(pattern.len(), MAX_PATTERN_CHARS / 2);

        let over = "90".repeat(MAX_PATTERN_CHARS / 2 + 1);
        let error = parse_checked_pattern(&over).unwrap_err();
        assert_eq!(error.code, "pattern_too_large");
        assert_eq!(error.message, "pattern exceeds 8192 characters");
    }
}
