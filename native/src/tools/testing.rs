//! Test doubles for the chunked segment walk, shared by the tool test
//! modules: the `BinaryView` FFI cannot run outside the core, so tests drive
//! the walk through the `ChunkedReadView` seam instead.

use super::walk::{ChunkedReadView, for_each_segment};
use crate::hexpattern::HexPattern;
use crate::scan::{Pagination, RunningScan, scan_pattern};

/// A tiny stand-in for BinaryView: ascending, non-overlapping readable
/// runs. A read returns the contiguous bytes available from `position`
/// inside the run it starts in — the short or empty read an unreadable
/// hole produces.
pub(super) struct FakeView {
    pub(super) segments: Vec<(u64, u64)>,
    pub(super) runs: Vec<(u64, Vec<u8>)>,
}

impl ChunkedReadView for FakeView {
    fn segment_ranges(&self) -> Vec<(u64, u64)> {
        self.segments.clone()
    }

    fn read_into(&self, buffer: &mut [u8], position: u64) -> usize {
        for (start, bytes) in &self.runs {
            let run_end = *start + bytes.len() as u64;
            if position >= *start && position < run_end {
                let offset = (position - start) as usize;
                let taken = bytes.len().min(offset + buffer.len());
                let copied = taken - offset;
                buffer[..copied].copy_from_slice(&bytes[offset..taken]);
                return copied;
            }
        }
        0
    }
}

/// Drive the production `for_each_segment` — clamp_to_bounds +
/// for_each_window + the reusable read buffer — with FakeView standing in
/// for the BinaryView FFI, which cannot run in tests.
pub(super) fn scan_fake_view(
    view: &FakeView,
    chunk: u64,
    bounds: Option<(u64, u64)>,
    overlap: u64,
    pattern: &HexPattern,
    pagination: &Pagination,
) -> RunningScan {
    let mut running = RunningScan::new();
    for_each_segment(view, chunk, bounds, overlap, |base, data| {
        scan_pattern(data, base, pattern, pagination, &mut running)
    });
    running
}
