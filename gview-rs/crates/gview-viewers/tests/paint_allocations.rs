//! `00_APP §6.3`: the paint path must not allocate.
//!
//! This lives in an integration test rather than a `#[cfg(test)]`
//! module because a counting `#[global_allocator]` needs `unsafe impl
//! GlobalAlloc`, and the library crate is `#![forbid(unsafe_code)]`
//! (`CLAUDE.md §6`). The test binary is a separate crate, so the
//! library's guarantee is untouched.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use appcui::prelude::*;
use gview_core::cache::DataCache;
use gview_core::object::Object;
use gview_core::source::MemorySource;
use gview_core::zones::ZonesList;
use gview_view::buffer_viewer::layout::{BufferCursor, BufferLayout, CharacterFormatMode};
use gview_view::buffer_viewer::paint::paint_rows;
use gview_view::traits::SmartViewer;
use gview_view::view_control::ViewControl;
use gview_viewers::{BufferView, BufferViewSettings, RowColors, SurfaceRowSink};
use std::sync::{Arc, Mutex as StdMutex};

/// Forwards every allocation to the system allocator, counting the
/// ones made on the current thread while [`COUNTING`] is armed.
///
/// The counters are **thread-local**: `cargo test` runs the tests of a
/// binary in parallel, and the test harness itself allocates while
/// reporting results, so a process-wide counter would charge one
/// test's frames with another thread's allocations. `const`-initialised
/// so that reading them never allocates.
struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every method forwards its arguments unchanged to the system
// allocator, which is the only allocator this binary uses; the counter
// is a plain relaxed atomic and does not itself allocate.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // `try_with` because a thread tearing its TLS down still
        // allocates, and accessing a destroyed slot would panic.
        let counting = COUNTING.try_with(Cell::get).unwrap_or(false);
        if counting {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get().saturating_add(1)));
        }
        // SAFETY: `layout` is forwarded unchanged; the caller upholds
        // `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was produced by `System.alloc` with the same
        // `layout`, since every allocation is forwarded there.
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Arms the counter for the duration of `body` and returns how many
/// allocations this thread made inside it.
fn count_allocations(body: impl FnOnce()) -> usize {
    ALLOCATIONS.with(|count| count.set(0));
    COUNTING.with(|armed| armed.set(true));
    body();
    COUNTING.with(|armed| armed.set(false));
    ALLOCATIONS.with(Cell::get)
}

fn colors() -> RowColors {
    let attr = CharAttribute::with_color(Color::White, Color::Black);
    RowColors {
        address: attr,
        numbers: attr,
        text: attr,
    }
}

#[test]
fn one_hundred_painted_frames_allocate_nothing() {
    let mut layout = BufferLayout {
        char_format_mode: CharacterFormatMode::Hex,
        nr_cols: 16,
        ..BufferLayout::default()
    };
    layout.update_view_sizes(120, 11);

    let data: Vec<u8> = (0..4096_usize).map(|i| (i & 0xFF) as u8).collect();
    let mut cache = DataCache::new(Box::new(MemorySource::new(data)), 0);
    let mut zones = ZonesList::new();
    let mut surface = Surface::new(120, 12);
    let cursor = BufferCursor::default();

    // Warm the lazily-filled buffers (cache page, zone viewport cache)
    // first: the rule is about steady-state frames, and the very first
    // frame legitimately fills the cache.
    {
        let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
        paint_rows(&layout, cursor, &mut cache, &mut zones, &mut sink);
    }

    let allocations = count_allocations(|| {
        for _ in 0..100 {
            let mut sink = SurfaceRowSink::new(&mut surface, layout, colors());
            let summary = paint_rows(&layout, cursor, &mut cache, &mut zones, &mut sink);
            assert_eq!(summary.rows_painted, layout.visible_rows);
        }
    });

    assert_eq!(allocations, 0, "100 painted frames must not allocate");
}


/// `00_APP §6.3`: `BufferView::on_paint` must not allocate either —
/// the control's scratch buffers are fields sized at mount.
#[test]
fn one_hundred_buffer_view_frames_allocate_nothing() {
    let data: Vec<u8> = (0..4096_usize).map(|i| (i & 0xFF) as u8).collect();
    let object = Arc::new(StdMutex::new(Object::from_buffer(&data, "sample.bin", 0)));
    let mut view = BufferView::from_settings(object, BufferViewSettings::default());
    OnResize::on_resize(&mut view, Size::new(0, 0), Size::new(120, 12));

    let theme = Theme::new(Themes::Default);
    let mut surface = Surface::new(120, 12);
    // Warm the cache page and the zone viewport cache first.
    OnPaint::on_paint(&view, &mut surface, &theme);

    let allocations = count_allocations(|| {
        for _ in 0..100 {
            OnPaint::on_paint(&view, &mut surface, &theme);
        }
    });

    assert_eq!(allocations, 0, "100 BufferView frames must not allocate");
}

/// The bottom bar formats into an inline scratch, so it does not
/// allocate either.
#[test]
fn the_cursor_information_bar_allocates_nothing() {
    let data: Vec<u8> = (0..256_usize).map(|i| (i & 0xFF) as u8).collect();
    let object = Arc::new(StdMutex::new(Object::from_buffer(&data, "sample.bin", 0)));
    let mut view = BufferView::from_settings(object, BufferViewSettings::default());
    OnResize::on_resize(&mut view, Size::new(0, 0), Size::new(120, 12));
    let mut bar = Surface::new(80, 1);
    view.paint_cursor_information(&mut bar, 80, 1);

    let allocations = count_allocations(|| {
        for _ in 0..100 {
            view.paint_cursor_information(&mut bar, 80, 1);
        }
    });
    assert_eq!(allocations, 0, "100 cursor bars must not allocate");
}
