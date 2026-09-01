//! `DissasmViewer` jump-arrow lane assignment and rendering
//! (spec `02_VIEWER_DISSASM` §6, §6.1).
//!
//! C++ anchors: `DissasmAsmPreCacheData::PrepareLabelArrows`
//! (`DissasmX86.cpp:611-700`), arrow glyph rendering
//! (`DissasmX86.cpp:140-159`).
//!
//! Over the current pre-cache fill, the first up-to-three in-range
//! `call`/`jmp` instructions become arrow "starts"; each is matched
//! to the cached line at its target address. For every start/target
//! pair the lower line (by document line) gets
//! [`line_arrow_flag::DRAW_STARTING_LINE`], the higher gets
//! [`line_arrow_flag::DRAW_ENDING_LINE`], and every line between them
//! (inclusive) is OR-marked with that pair's lane bit
//! (`DRAW_LINE1`/`2`/`3`). Only three arrow columns render, so lanes
//! 4/5 are defined but never drawn.

use super::pre_cache::{instruction_flag, line_arrow_flag, DissasmAsmPreCacheLine};

/// C++ `textColumnIndicatorArrowLinesSpace` (`DissasmX86.cpp:37`):
/// arrow lane cap.
pub const ARROW_LANES: usize = 3;

/// Lane bit for the `pair_index`-th start/target pair (C++ switch on
/// `++lineIndex`, `DissasmX86.cpp:680-698`): pair 0 → `DRAW_LINE1`, …
const fn lane_for_pair(pair_index: usize) -> u8 {
    match pair_index {
        0 => line_arrow_flag::DRAW_LINE1,
        1 => line_arrow_flag::DRAW_LINE2,
        2 => line_arrow_flag::DRAW_LINE3,
        3 => line_arrow_flag::DRAW_LINE4,
        _ => line_arrow_flag::DRAW_LINE5,
    }
}

/// C++ `PrepareLabelArrows` (`DissasmX86.cpp:611-700`).
///
/// Clears every line's arrow flags, then assigns start/end markers
/// and lane bits for the in-range branch targets. Operates on the
/// cached fill in document-line order (the vector the C++ code
/// iterates by pointer).
pub fn prepare_label_arrows(cached: &mut [DissasmAsmPreCacheLine]) {
    for line in cached.iter_mut() {
        line.line_arrow_to_draw = line_arrow_flag::NO_LINES;
    }
    let Some(first) = cached.first() else {
        return;
    };
    let minimal_address = first.address;
    let maximal_address = cached.last().map_or(minimal_address, |l| l.address);

    // Collect up to ARROW_LANES branch instructions whose target
    // lands inside the fill.
    let mut start_indices: Vec<usize> = Vec::with_capacity(ARROW_LANES);
    for (idx, line) in cached.iter().enumerate() {
        if line.flags != instruction_flag::CALL && line.flags != instruction_flag::JMP {
            continue;
        }
        let Some(hex) = line.hex_value else {
            continue;
        };
        if hex < minimal_address || hex > maximal_address {
            continue;
        }
        start_indices.push(idx);
        if start_indices.len() >= ARROW_LANES {
            break;
        }
    }
    if start_indices.is_empty() {
        return;
    }

    // Sort the starts by target address (C++ sorts the pointer list
    // by hexValue).
    start_indices.sort_by_key(|&i| cached.get(i).and_then(|l| l.hex_value).unwrap_or(0));

    // Two-pointer merge: for each start (target address ascending)
    // find the cache line whose address equals it (addresses ascend
    // through the fill).
    let mut label_indices: Vec<usize> = Vec::with_capacity(start_indices.len());
    let mut cache_cursor = 0_usize;
    let mut label_it = 0_usize;
    while label_it < start_indices.len() && cache_cursor < cached.len() {
        let target = start_indices
            .get(label_it)
            .and_then(|&i| cached.get(i))
            .and_then(|l| l.hex_value)
            .unwrap_or(0);
        if cached.get(cache_cursor).map(|l| l.address) == Some(target) {
            label_indices.push(cache_cursor);
            label_it = label_it.saturating_add(1);
        } else {
            cache_cursor = cache_cursor.saturating_add(1);
        }
    }

    // Pair each start with its matched target; mark the span.
    for (pair_index, (&start_idx, &label_idx)) in
        start_indices.iter().zip(label_indices.iter()).enumerate()
    {
        let start_line = cached.get(start_idx).map_or(0, |l| l.current_line);
        let label_line = cached.get(label_idx).map_or(0, |l| l.current_line);
        // The visually lower document line is the "start" marker.
        let (low, high) = if start_line < label_line {
            (start_idx, label_idx)
        } else {
            (label_idx, start_idx)
        };
        if let Some(line) = cached.get_mut(low) {
            line.line_arrow_to_draw = line_arrow_flag::DRAW_STARTING_LINE;
        }
        if let Some(line) = cached.get_mut(high) {
            line.line_arrow_to_draw = line_arrow_flag::DRAW_ENDING_LINE;
        }
        let lane = lane_for_pair(pair_index);
        for line in cached.get_mut(low..=high).unwrap_or(&mut []) {
            line.line_arrow_to_draw |= lane;
        }
    }
}

/// C++ arrow glyph rendering (`DissasmX86.cpp:140-159`), spec §6.1.
///
/// The 3-character arrow column for one line's `line_arrow_to_draw`
/// bitmask. Only lanes 1–3 map to columns; a start/end line fills the
/// gaps with `-` and terminates column 2 with `<` (start) or `>`
/// (end). Returns three spaces when no arrows apply.
#[must_use]
pub fn arrow_glyphs(line_arrow_to_draw: u8) -> [char; ARROW_LANES] {
    let mut chars = [' '; ARROW_LANES];
    if line_arrow_to_draw == line_arrow_flag::NO_LINES {
        return chars;
    }
    if line_arrow_to_draw & line_arrow_flag::DRAW_LINE1 != 0 {
        chars[0] = '|';
    }
    if line_arrow_to_draw & line_arrow_flag::DRAW_LINE2 != 0 {
        chars[1] = '|';
    }
    if line_arrow_to_draw & line_arrow_flag::DRAW_LINE3 != 0 {
        chars[2] = '|';
    }
    let is_start = line_arrow_to_draw & line_arrow_flag::DRAW_STARTING_LINE != 0;
    let is_end = line_arrow_to_draw & line_arrow_flag::DRAW_ENDING_LINE != 0;
    if is_start || is_end {
        for ch in &mut chars {
            if *ch == ' ' {
                *ch = '-';
            }
        }
        chars[2] = if is_start { '<' } else { '>' };
    }
    chars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branch(current_line: u32, address: u64, flags: u8, target: u64) -> DissasmAsmPreCacheLine {
        DissasmAsmPreCacheLine {
            address,
            current_line,
            hex_value: Some(target),
            flags,
            ..DissasmAsmPreCacheLine::default()
        }
    }

    fn plain(current_line: u32, address: u64) -> DissasmAsmPreCacheLine {
        DissasmAsmPreCacheLine {
            address,
            current_line,
            ..DissasmAsmPreCacheLine::default()
        }
    }

    #[test]
    fn single_forward_jump_marks_span_and_glyphs() {
        // 5 lines at addresses 100..104; line 0 jumps to 103.
        let mut cached = vec![
            branch(0, 100, instruction_flag::JMP, 103),
            plain(1, 101),
            plain(2, 102),
            plain(3, 103),
            plain(4, 104),
        ];
        prepare_label_arrows(&mut cached);
        // Lower line (0) is the start marker, target line (3) the end.
        assert_eq!(
            cached[0].line_arrow_to_draw,
            line_arrow_flag::DRAW_STARTING_LINE | line_arrow_flag::DRAW_LINE1
        );
        assert_eq!(cached[1].line_arrow_to_draw, line_arrow_flag::DRAW_LINE1);
        assert_eq!(cached[2].line_arrow_to_draw, line_arrow_flag::DRAW_LINE1);
        assert_eq!(
            cached[3].line_arrow_to_draw,
            line_arrow_flag::DRAW_ENDING_LINE | line_arrow_flag::DRAW_LINE1
        );
        assert_eq!(cached[4].line_arrow_to_draw, line_arrow_flag::NO_LINES);
        // Glyphs: '|' lane plus start/end terminators.
        assert_eq!(arrow_glyphs(cached[0].line_arrow_to_draw), ['|', '-', '<']);
        assert_eq!(arrow_glyphs(cached[1].line_arrow_to_draw), ['|', ' ', ' ']);
        assert_eq!(arrow_glyphs(cached[3].line_arrow_to_draw), ['|', '-', '>']);
        assert_eq!(arrow_glyphs(cached[4].line_arrow_to_draw), [' ', ' ', ' ']);
    }

    #[test]
    fn backward_jump_swaps_start_and_end() {
        // Line 3 jumps back to 100 (line 0). Target line is the
        // lower document line → it becomes the start marker.
        let mut cached = vec![
            plain(0, 100),
            plain(1, 101),
            plain(2, 102),
            branch(3, 103, instruction_flag::JMP, 100),
        ];
        prepare_label_arrows(&mut cached);
        assert_eq!(
            cached[0].line_arrow_to_draw,
            line_arrow_flag::DRAW_STARTING_LINE | line_arrow_flag::DRAW_LINE1
        );
        assert_eq!(
            cached[3].line_arrow_to_draw,
            line_arrow_flag::DRAW_ENDING_LINE | line_arrow_flag::DRAW_LINE1
        );
    }

    #[test]
    fn out_of_range_and_missing_targets_are_ignored() {
        let mut cached = vec![
            branch(0, 100, instruction_flag::CALL, 9999), // target outside fill
            {
                let mut l = branch(1, 101, instruction_flag::JMP, 102);
                l.hex_value = None; // no immediate
                l
            },
            plain(2, 102),
        ];
        prepare_label_arrows(&mut cached);
        assert!(cached.iter().all(|l| l.line_arrow_to_draw == line_arrow_flag::NO_LINES));
    }

    #[test]
    fn three_lane_cap_and_distinct_lanes() {
        // Four eligible forward jumps, but only 3 lanes are used.
        let mut cached = vec![
            branch(0, 100, instruction_flag::JMP, 101),
            branch(1, 101, instruction_flag::JMP, 102),
            branch(2, 102, instruction_flag::JMP, 103),
            branch(3, 103, instruction_flag::JMP, 104),
            plain(4, 104),
        ];
        prepare_label_arrows(&mut cached);
        // Only the first three branch instructions become starts, so
        // line 3's own start marker is never assigned by a 4th lane;
        // it is still touched as a target/span member. Verify three
        // distinct lane bits appear across the fill.
        let mut lanes_seen = 0_u8;
        for line in &cached {
            lanes_seen |= line.line_arrow_to_draw
                & (line_arrow_flag::DRAW_LINE1
                    | line_arrow_flag::DRAW_LINE2
                    | line_arrow_flag::DRAW_LINE3);
        }
        assert_eq!(
            lanes_seen,
            line_arrow_flag::DRAW_LINE1 | line_arrow_flag::DRAW_LINE2 | line_arrow_flag::DRAW_LINE3
        );
    }

    #[test]
    fn glyphs_render_all_three_vertical_lanes() {
        let all_lanes = line_arrow_flag::DRAW_LINE1
            | line_arrow_flag::DRAW_LINE2
            | line_arrow_flag::DRAW_LINE3;
        assert_eq!(arrow_glyphs(all_lanes), ['|', '|', '|']);
        // Start marker with no vertical lane: dashes then '<'.
        assert_eq!(arrow_glyphs(line_arrow_flag::DRAW_STARTING_LINE), ['-', '-', '<']);
        assert_eq!(arrow_glyphs(line_arrow_flag::DRAW_ENDING_LINE), ['-', '-', '>']);
        // No flags → blanks.
        assert_eq!(arrow_glyphs(line_arrow_flag::NO_LINES), [' ', ' ', ' ']);
    }

    #[test]
    fn empty_fill_is_safe() {
        let mut cached: Vec<DissasmAsmPreCacheLine> = Vec::new();
        prepare_label_arrows(&mut cached);
        assert!(cached.is_empty());
    }
}
