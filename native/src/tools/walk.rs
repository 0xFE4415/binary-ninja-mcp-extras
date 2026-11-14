//! The chunked segment walk both tools traverse memory through: mapped
//! segments clipped to the optional section bounds, read in overlapping
//! windows so no single read ever allocates the whole segment.

use binaryninja::binary_view::{BinaryView, BinaryViewBase};

fn clamp_to_bounds(range: (u64, u64), bounds: Option<(u64, u64)>) -> Option<(u64, u64)> {
    let (start, end) = match bounds {
        None => range,
        Some((low, high)) => (range.0.max(low), range.1.min(high)),
    };
    (start < end).then_some((start, end))
}

/// Sort ranges and merge those that touch or overlap, so a match can span
/// the seam between adjacent segments.
fn merge_touching(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Readable ranges of a view from its `(start, end, readable)` segments. A view
/// with no segments at all, such as a Raw view, is one range over `whole`.
fn readable_ranges(segments: &[(u64, u64, bool)], whole: (u64, u64)) -> Vec<(u64, u64)> {
    if segments.is_empty() {
        return vec![whole];
    }
    segments
        .iter()
        .filter(|(_, _, readable)| *readable)
        .map(|(start, end, _)| (*start, *end))
        .collect()
}

/// Walk [start, end) in windows of `chunk + overlap` bytes, advancing by `chunk`
/// unconditionally: consecutive windows overlap by `overlap` bytes, so every
/// (`overlap + 1`)-byte match start is fully visible in exactly one window, and
/// advancing past short reads (unreadable holes) recovers matches after the hole.
fn for_each_window<F>(start: u64, end: u64, chunk: u64, overlap: u64, mut window: F) -> bool
where
    F: FnMut(u64, u64) -> bool,
{
    std::iter::successors(Some(start), |position| position.checked_add(chunk))
        .take_while(|position| *position < end)
        .all(|position| window(position, (chunk + overlap).min(end - position)))
}

/// Read surface for the chunked walk — a local seam so tests can drive
/// `for_each_segment` without the BinaryView FFI, which cannot run outside the core.
pub(super) trait ChunkedReadView {
    /// Readable address ranges: segments whose readability flag is off are
    /// dropped at the source, so the walk never opens a window on them. The
    /// walk merges ranges that touch.
    fn segment_ranges(&self) -> Vec<(u64, u64)>;
    /// Fill `buffer` from `position`, returning the bytes actually read —
    /// fewer than requested (or none) at an unreadable hole.
    fn read_into(&self, buffer: &mut [u8], position: u64) -> usize;
}

impl ChunkedReadView for BinaryView {
    fn segment_ranges(&self) -> Vec<(u64, u64)> {
        // Segment::readable() is the core's readability flag for the segment's
        // range; skipping here saves the whole walk, not just the reads.
        let segments: Vec<(u64, u64, bool)> = self
            .segments()
            .iter()
            .map(|segment| {
                let range = segment.address_range();
                (range.start, range.end, segment.readable())
            })
            .collect();
        readable_ranges(&segments, (self.start(), self.start() + self.len()))
    }

    fn read_into(&self, buffer: &mut [u8], position: u64) -> usize {
        BinaryViewBase::read(self, buffer, position)
    }
}

/// Read every readable mapped segment (clipped to `bounds`) through the window
/// walk, feeding `step` each window's base address and the bytes actually read.
/// Returns `false` as soon as `step` declines a window.
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
    // One reusable buffer for the largest possible window — never a whole-segment allocation.
    let mut buffer = vec![0u8; usize::try_from(chunk + overlap).unwrap_or(usize::MAX)];
    merge_touching(view.segment_ranges())
        .into_iter()
        .filter_map(|range| clamp_to_bounds(range, bounds))
        .all(|(start, end)| {
            for_each_window(start, end, chunk, overlap, |position, read_size| {
                let size = view.read_into(&mut buffer[..read_size as usize], position);
                step(position, &buffer[..size])
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn merge_touching_joins_adjacent_and_overlapping_ranges_only() {
        assert_eq!(
            merge_touching(vec![(0x2000, 0x2010), (0x1000, 0x1004), (0x1004, 0x1008)]),
            vec![(0x1000, 0x1008), (0x2000, 0x2010)]
        );
        assert_eq!(
            merge_touching(vec![(0x1000, 0x1010), (0x1008, 0x1020), (0x1010, 0x1018)]),
            vec![(0x1000, 0x1020)]
        );
        // A one-byte gap keeps the ranges apart.
        assert_eq!(
            merge_touching(vec![(0x1000, 0x1004), (0x1005, 0x1008)]),
            vec![(0x1000, 0x1004), (0x1005, 0x1008)]
        );
        assert_eq!(merge_touching(Vec::new()), Vec::new());
    }

    #[test]
    fn readable_ranges_skips_unreadable_segments() {
        let segments = [
            (0x1000, 0x1004, true),
            (0x1004, 0x1008, false),
            (0x2000, 0x2004, true),
        ];
        assert_eq!(
            readable_ranges(&segments, (0, 0x4000)),
            vec![(0x1000, 0x1004), (0x2000, 0x2004)]
        );
    }

    #[test]
    fn readable_ranges_scans_the_whole_view_only_when_it_has_no_segments() {
        assert_eq!(readable_ranges(&[], (0, 0x4b78)), vec![(0, 0x4b78)]);
        // Segments that are all unreadable are not the same as no segments.
        assert_eq!(
            readable_ranges(&[(0x1000, 0x1004, false)], (0, 0x4b78)),
            Vec::new()
        );
    }

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

    proptest! {
        #[test]
        fn every_overlap_sized_match_start_is_covered_by_exactly_one_window(
            start in 0u64..1024,
            length in 0u64..128,
            chunk in 1u64..32,
            overlap in 0u64..32,
        ) {
            let end = start + length;
            let mut windows = Vec::new();
            let completed = for_each_window(start, end, chunk, overlap, |position, read_size| {
                windows.push((position, read_size));
                true
            });
            prop_assert!(completed);

            if let Some(last_match_start) = end.checked_sub(overlap + 1) {
                for match_start in start..=last_match_start {
                    let visible_windows = windows
                        .iter()
                        .filter(|(position, read_size)| {
                            *position <= match_start
                                && match_start + overlap < *position + *read_size
                        })
                        .count();
                    prop_assert_eq!(visible_windows, 1, "start {}, chunk {}, overlap {}", match_start, chunk, overlap);
                }
            }
        }
    }
}
