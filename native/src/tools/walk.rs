//! The chunked segment walk both tools traverse memory through: mapped
//! segments clipped to the optional section bounds, read in overlapping
//! windows so no single read ever allocates the whole segment.

use binaryninja::binary_view::{BinaryView, BinaryViewBase};

/// Clip a segment's address range to the optional section bounds; `None` when
/// nothing remains (empty ranges yield no windows in the walk below).
fn clamp_to_bounds(range: (u64, u64), bounds: Option<(u64, u64)>) -> Option<(u64, u64)> {
    let (start, end) = match bounds {
        None => range,
        Some((low, high)) => (range.0.max(low), range.1.min(high)),
    };
    (start < end).then_some((start, end))
}

/// Walk `[start, end)` in overlapping read windows, mirroring the Python
/// plugin's chunked-read loop in `_iter_pattern_matches`.
///
/// Invariant re-derived from that loop: window k reads
/// `[start + k*chunk, min(start + k*chunk + chunk + overlap, end))` and
/// `position` advances by `chunk` unconditionally — the windows depend only on
/// `(start, end, chunk, overlap)`, never on what the reads return. Consecutive
/// windows overlap by exactly `overlap` bytes, so every (`overlap + 1`)-byte
/// match whose start address lies in window k is fully visible in window k, and
/// every match start belongs to exactly one window: no match is missed and none
/// is reported twice. Advancing past short or empty reads (unreadable holes) is
/// what recovers matches located after the hole.
///
/// `overlap` is the scan's pattern length minus one (the longest pattern's, for
/// the multi-pattern scan). `window(position, read_size)` returns `false` to
/// stop the walk early.
fn for_each_window<F>(start: u64, end: u64, chunk: u64, overlap: u64, mut window: F) -> bool
where
    F: FnMut(u64, u64) -> bool,
{
    let mut position = start;
    while position < end {
        let read_size = (chunk + overlap).min(end - position);
        if !window(position, read_size) {
            return false;
        }
        let Some(next) = position.checked_add(chunk) else {
            break;
        };
        position = next;
    }
    true
}

/// The view surface the chunked segment walk needs: mapped ranges plus bounded
/// reads. A local seam so tests can drive `for_each_segment` itself — the
/// `BinaryView` FFI cannot run outside the core, and a test-local copy of the
/// composition would drift from the wiring it claims to cover.
pub(super) trait ChunkedReadView {
    /// Ascending, non-overlapping readable address ranges.
    fn segment_ranges(&self) -> Vec<(u64, u64)>;
    /// Fill `buffer` from `position`, returning the bytes actually read —
    /// fewer than requested (or none) at an unreadable hole.
    fn read_into(&self, buffer: &mut [u8], position: u64) -> usize;
}

impl ChunkedReadView for BinaryView {
    fn segment_ranges(&self) -> Vec<(u64, u64)> {
        self.segments()
            .iter()
            .map(|segment| {
                let range = segment.address_range();
                (range.start, range.end)
            })
            .collect()
    }

    fn read_into(&self, buffer: &mut [u8], position: u64) -> usize {
        BinaryViewBase::read(self, buffer, position)
    }
}

/// Read every mapped segment (clipped to `bounds`) through the chunked window
/// walk and run `step` over each window's bytes in address order. `step`
/// receives the window's base address and the bytes actually read, which may be
/// shorter than requested (or empty) when the core hits an unreadable hole.
pub(super) fn for_each_segment<V: ChunkedReadView, F>(
    view: &V,
    chunk: u64,
    bounds: Option<(u64, u64)>,
    overlap: u64,
    mut step: F,
) -> bool
where
    F: FnMut(u64, &[u8]) -> bool,
{
    // One reusable buffer for the largest possible window, allocated once per
    // scan — never the whole segment (a multi-GB segment must not allocate).
    let mut buffer = vec![0u8; usize::try_from(chunk + overlap).unwrap_or(usize::MAX)];
    for (start, end) in view.segment_ranges() {
        let Some((start, end)) = clamp_to_bounds((start, end), bounds) else {
            continue;
        };
        let alive = for_each_window(start, end, chunk, overlap, |position, read_size| {
            let read_size = read_size as usize;
            let size = view.read_into(&mut buffer[..read_size], position);
            step(position, &buffer[..size])
        });
        if !alive {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_advance_by_chunk_with_overlap_tail() {
        let mut windows = Vec::new();
        assert!(for_each_window(
            0x1000,
            0x1008,
            4,
            1,
            |position, read_size| {
                windows.push((position, read_size));
                true
            }
        ));
        // Each window extends overlap bytes past its chunk; the walk ends when
        // position reaches the segment end.
        assert_eq!(windows, vec![(0x1000, 5), (0x1004, 4)]);

        let mut windows = Vec::new();
        assert!(for_each_window(
            0x1000,
            0x1008,
            4,
            0,
            |position, read_size| {
                windows.push((position, read_size));
                true
            }
        ));
        assert_eq!(windows, vec![(0x1000, 4), (0x1004, 4)]);
    }

    #[test]
    fn window_walk_stops_when_the_scan_is_exhausted() {
        let mut visited = Vec::new();
        assert!(!for_each_window(0, 100, 4, 0, |position, _| {
            visited.push(position);
            false
        }));
        assert_eq!(visited, vec![0]);
    }

    #[test]
    fn clamp_to_bounds_clamps_and_drops_empty_ranges() {
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), None),
            Some((0x1000, 0x2000))
        );
        // Section strictly inside the segment: both sides clamp.
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), Some((0x1002, 0x1006))),
            Some((0x1002, 0x1006))
        );
        // Section larger than the segment: the segment wins on both sides.
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), Some((0, 0x10000))),
            Some((0x1000, 0x2000))
        );
        // Disjoint section and segment: nothing to scan.
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), Some((0x3000, 0x4000))),
            None
        );
        // Section starting exactly at the segment end: empty.
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), Some((0x2000, 0x3000))),
            None
        );
    }
}
