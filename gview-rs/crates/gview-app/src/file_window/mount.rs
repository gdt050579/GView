//! Viewer mounting: turning the model's [`ViewerSlot`]s into the real
//! `AppCUI` viewer controls of `gview-viewers`
//! (spec `00_APP §5.2 (1)`, `§5.3`; design decisions `§0.3 D2`–`D4`).
//!
//! C++ anchor: `GViewCore/src/App/FileWindow.cpp` — the constructor
//! (L36-78) creates the `view` tab, each `CreateViewer` overload
//! (L125-161) does
//! `view->CreateChildControl<Viewer::Instance>(Reference<Object>, &settings)`,
//! and `Start()` (L322-328) makes page 0 current. The C++ `Settings`
//! object is *moved* into the instance (`std::move(data)`); this module
//! keeps that contract: [`ViewerSlot::take_request`] hands the
//! `ViewerRequest` over once, so a plugin's `ZonesList` is never
//! cloned.
//!
//! | `ViewerKind` | Control | Settings |
//! |--------------|---------|----------|
//! | `Buffer` | [`BufferView`] | `BufferViewerRequest` + [`MountContext::colorizer`] when `position_to_color` |
//! | `Text` | [`TextView`] | defaults (the encoding is detected from the cache) |
//! | `Container` | [`ContainerView`] | `ContainerViewerRequest` + the enumerate / open hooks |
//! | `Dissasm` | [`DissasmView`] | `DissasmViewerRequest` |
//! | `Grid`, `Lexical`, `Image` | [`UnavailableView`] | the viewer name (`§5.3.4`) |
//!
//! The last row is the defined placeholder of `§5.3.4`, not a stub: the
//! window opens, `F4` still cycles, and the page states what is
//! missing. It disappears when `grid-view-control`,
//! `lexical-view-control` and `image-view-control` land.
//!
//! Every mounted control publishes its cursor state into the
//! [`SharedCursorInfo`] slot it is given (`§5.3.5`); the window's
//! bottom bar reads the slot of the current view, because sibling
//! `AppCUI` controls cannot borrow one another the way C++
//! `CursorInformation` reaches into `GetCurrentView()`.

use appcui::prelude::*;

use gview_plugin::type_plugin::{ViewerKind, ViewerRequest};
use gview_view::buffer_viewer::color::PositionToColorCallback;
use gview_view::container_viewer::open::OpenItemInterface;
use gview_view::container_viewer::tree::EnumerateInterface;
use gview_view::traits::{SharedObject, SmartViewer};
use gview_view::view_control::ViewControl;
use gview_viewers::{
    BufferView, BufferViewSettings, ContainerView, ContainerViewSettings, DissasmView, DissasmViewSettings,
    FindProvider, SharedCursorInfo, TextView, TextViewSettings, UnavailableView,
};

use crate::instance::window_lifecycle::ViewerSlot;

/// A viewer control mounted on one page of the window's `view` tab.
///
/// The C++ keeps `Reference<ViewControl>` children; `AppCUI-rs` hands
/// out typed [`Handle`]s, so the window stores the kind alongside the
/// handle and resolves it with `control_mut` when it needs the live
/// control (`§5.6`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MountedViewer {
    /// Hex / binary viewer.
    Buffer(Handle<BufferView>),
    /// Plain-text viewer.
    Text(Handle<TextView>),
    /// Archive / VFS tree viewer.
    Container(Handle<ContainerView>),
    /// Disassembly viewer.
    Dissasm(Handle<DissasmView>),
    /// Placeholder page for a viewer kind this build lacks (`§5.3.4`).
    Unavailable(Handle<UnavailableView>),
}

/// Which viewer dialog a page can open (C++ `ShowGoToDialog` /
/// `ShowFindDialog` / `ShowCopyDialog`).
///
/// Declared here rather than in `file_window.rs` so [`MountedViewer`]
/// can answer for its own page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewDialog {
    /// `GoTo`.
    GoTo,
    /// Find.
    Find,
    /// Copy.
    Copy,
}

/// Host-side services handed to one viewer at mount time
/// (C++ `Settings::Set*Callback`, spec `§5.3.1`, `§5.3.3`).
///
/// Every boxed hook is *moved* into the control: the plugin stays
/// UI-free (`D3`) and the control never borrows the plugin.
pub struct MountContext<'a> {
    /// The window's single [`SharedObject`]; every viewer gets a clone
    /// (`02_SMART_VIEWERS_DEEP` §C.2 — one `DataCache` per window).
    pub object: &'a SharedObject,
    /// `SetPositionToColorCallback` (`Buffer` only); consumed when the
    /// request has `position_to_color` set, dropped otherwise.
    pub colorizer: Option<Box<dyn PositionToColorCallback + Send>>,
    /// `SetEnumerateCallback` (`Container` only).
    pub enumerator: Option<Box<dyn EnumerateInterface + Send>>,
    /// `SetOpenItemCallback` (`Container` only).
    pub opener: Option<Box<dyn OpenItemInterface + Send>>,
    /// The window's Find engine (`Buffer` only, `§5.6`): installed at
    /// mount, armed when the Find dialog compiles a pattern.
    pub find: Option<Box<dyn FindProvider>>,
    /// The bottom-bar slot this page publishes into (`§5.3.5`).
    pub cursor: SharedCursorInfo,
    /// Page index in the `view` tab.
    pub index: usize,
}

impl core::fmt::Debug for MountContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountContext")
            .field("index", &self.index)
            .field("has_colorizer", &self.colorizer.is_some())
            .field("has_enumerator", &self.enumerator.is_some())
            .field("has_opener", &self.opener.is_some())
            .field("has_find", &self.find.is_some())
            .finish_non_exhaustive()
    }
}

impl MountContext<'_> {
    /// A context carrying no plugin hook (the `DefaultTypePlugin`
    /// case, and every viewer whose kind has no hook).
    #[must_use]
    pub fn plain(object: &SharedObject, cursor: SharedCursorInfo, index: usize) -> MountContext<'_> {
        MountContext {
            object,
            colorizer: None,
            enumerator: None,
            opener: None,
            find: None,
            cursor,
            index,
        }
    }
}

impl MountedViewer {
    /// `true` when the mounted control implements `dialog`
    /// (C++ `ViewControl::Show*Dialog` returning `false` in the base
    /// class is what makes the `FileWindow` print its error text).
    ///
    /// `Container` and `Unavailable` implement none; `Text` has no
    /// Find dialog (C++ `TextViewer::ShowFindDialog` is not
    /// implemented — `02_VIEWER_TEXT`).
    #[must_use]
    pub const fn implements(self, dialog: ViewDialog) -> bool {
        match self {
            Self::Buffer(_) | Self::Dissasm(_) => true,
            Self::Text(_) => !matches!(dialog, ViewDialog::Find),
            Self::Container(_) | Self::Unavailable(_) => false,
        }
    }

    /// `true` when `handle` addresses this page's control.
    ///
    /// `AppCUI` handles compare across types (`Handle<A> == Handle<B>`
    /// compares the raw slot), so one helper answers for every
    /// variant — that is how an event handler finds the page that
    /// raised it.
    #[must_use]
    pub fn matches<T>(self, handle: Handle<T>) -> bool {
        match self {
            Self::Buffer(h) => h == handle,
            Self::Text(h) => h == handle,
            Self::Container(h) => h == handle,
            Self::Dissasm(h) => h == handle,
            Self::Unavailable(h) => h == handle,
        }
    }

    /// The viewer kind this page shows, for diagnostics and tests.
    #[must_use]
    pub const fn kind_name(self) -> &'static str {
        match self {
            Self::Buffer(_) => "Buffer",
            Self::Text(_) => "Text",
            Self::Container(_) => "Container",
            Self::Dissasm(_) => "Dissasm",
            Self::Unavailable(_) => "Unavailable",
        }
    }
}

/// Mounts the control for `slot` on tab page `page`
/// (C++ `FileWindow::CreateViewer`).
///
/// The slot's [`ViewerRequest`] is **taken**, never cloned: after this
/// call `slot.request()` is `None` and the plugin's `ZonesList` lives
/// inside the control.
pub fn mount_viewer(tab: &mut Tab, page: u32, slot: &mut ViewerSlot, ctx: MountContext<'_>) -> MountedViewer {
    let name = slot.name().to_owned();
    let kind = slot.kind();
    let request = slot.take_request();
    let MountContext {
        object,
        colorizer,
        enumerator,
        opener,
        find,
        cursor,
        index: _,
    } = ctx;
    match kind {
        ViewerKind::Buffer => {
            let settings = buffer_settings(request, colorizer, find, cursor, name);
            let view = BufferView::from_settings(SharedObject::clone(object), settings);
            MountedViewer::Buffer(tab.add(page, view))
        }
        ViewerKind::Text => {
            let settings = TextViewSettings {
                cursor_info: cursor,
                custom_name: Some(name),
                ..TextViewSettings::default()
            };
            let view = TextView::from_settings(SharedObject::clone(object), settings);
            MountedViewer::Text(tab.add(page, view))
        }
        ViewerKind::Container => {
            let settings = ContainerViewSettings {
                request: request.and_then(|r| r.container).unwrap_or_default(),
                enumerator,
                opener,
                cursor_info: cursor,
                custom_name: Some(name),
                ..ContainerViewSettings::default()
            };
            let view = ContainerView::from_settings(SharedObject::clone(object), settings);
            MountedViewer::Container(tab.add(page, view))
        }
        ViewerKind::Dissasm => {
            let settings = DissasmViewSettings {
                request: request.and_then(|r| r.dissasm).unwrap_or_default(),
                cursor_info: cursor,
                custom_name: Some(name),
            };
            let view = DissasmView::from_settings(SharedObject::clone(object), settings);
            MountedViewer::Dissasm(tab.add(page, view))
        }
        // `§5.3.4`: a defined placeholder until the three remaining
        // control tasks land.
        ViewerKind::Grid | ViewerKind::Lexical | ViewerKind::Image => {
            MountedViewer::Unavailable(tab.add(page, UnavailableView::new(&name, cursor)))
        }
    }
}

/// `BufferViewerRequest` → [`BufferViewSettings`].
///
/// C++ `SetPositionToColorCallback` is what turns opcode colouring on;
/// a colourer offered by a plugin that did not ask for it is dropped
/// here rather than silently enabling the feature.
fn buffer_settings(
    request: Option<ViewerRequest>,
    colorizer: Option<Box<dyn PositionToColorCallback + Send>>,
    find: Option<Box<dyn FindProvider>>,
    cursor: SharedCursorInfo,
    name: String,
) -> BufferViewSettings {
    let request = request.and_then(|r| r.buffer).unwrap_or_default();
    let colorizer = if request.position_to_color { colorizer } else { None };
    BufferViewSettings {
        request,
        colorizer,
        cursor_info: cursor,
        // Installed unarmed: `Ctrl+F` compiles the pattern into the
        // window's shared session and `Ctrl+F7` then repeats it
        // (`§5.6`).
        find,
        custom_name: Some(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_core::object::Object;
    use gview_view::buffer_viewer::color::BufferColor;
    use gview_core::zones::ZonesList;
    use gview_plugin::type_plugin::{BufferViewerRequest, ContainerViewerRequest, DissasmViewerRequest};
    use gview_view::traits::ViewerSettings;
    use gview_view::view_control::ViewControl;
    use std::sync::{Arc, Mutex};

    /// A colourer that marks every offset, so the test can prove the
    /// hook reached the control.
    struct AllRed;

    impl PositionToColorCallback for AllRed {
        fn color_for_buffer(&mut self, offset: u64, buf: &[u8]) -> Option<BufferColor> {
            Some(BufferColor {
                start: offset,
                end: offset.saturating_add(buf.len() as u64).saturating_sub(1),
                color: CharAttribute::with_color(Color::Red, Color::Black),
            })
        }
    }

    fn object(bytes: &[u8]) -> SharedObject {
        Arc::new(Mutex::new(Object::from_buffer(bytes, "sample.bin", 0)))
    }

    fn slot(request: ViewerRequest) -> ViewerSlot {
        let mut settings = crate::instance::window_lifecycle::ViewerSlotSettings::default();
        settings.set_request(request);
        ViewerSlot::from_settings(object(&[]), settings)
    }

    #[test]
    fn every_kind_mounts_a_page_and_takes_its_request() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(80, 25, "Paint.Enable(false)\nPaint('mounted')")
            .build()
            .expect("debug app");
        let mut win = Window::new("mount", layout!("d:f"), window::Flags::None);
        let tab_handle = win.add(Tab::new(layout!("d:f"), tab::Flags::None));
        let data = object(b"MZ\x90\x00");

        let mut zones = ZonesList::new();
        zones.add(0, 1, CharAttribute::with_color(Color::White, Color::Black), "hdr");
        let buffer = ViewerRequest::buffer(BufferViewerRequest {
            zones,
            position_to_color: true,
            ..BufferViewerRequest::default()
        });
        let mut buffer_slot = slot(buffer);

        let mounted = {
            let tab = win.control_mut(tab_handle).expect("tab");
            let page = tab.add_tab("Buffer View");
            mount_viewer(
                tab,
                page,
                &mut buffer_slot,
                MountContext {
                    object: &data,
                    colorizer: Some(Box::new(AllRed)),
                    enumerator: None,
                    opener: None,
                    find: None,
                    cursor: SharedCursorInfo::new(),
                    index: 0,
                },
            )
        };
        assert!(matches!(mounted, MountedViewer::Buffer(_)));
        assert_eq!(mounted.kind_name(), "Buffer");
        // The request (and with it the `ZonesList`) was moved out.
        assert!(buffer_slot.request().is_none());

        // The other kinds, each on its own page.
        for (request, expected) in [
            (ViewerRequest::new(ViewerKind::Text), "Text"),
            (ViewerRequest::container(ContainerViewerRequest::default()), "Container"),
            (ViewerRequest::dissasm(DissasmViewerRequest::default()), "Dissasm"),
            (ViewerRequest::new(ViewerKind::Grid), "Unavailable"),
            (ViewerRequest::new(ViewerKind::Lexical), "Unavailable"),
            (ViewerRequest::new(ViewerKind::Image), "Unavailable"),
        ] {
            let mut page_slot = slot(request);
            let tab = win.control_mut(tab_handle).expect("tab");
            let page = tab.add_tab(page_slot.name());
            let mounted = mount_viewer(
                tab,
                page,
                &mut page_slot,
                MountContext::plain(&data, SharedCursorInfo::new(), 1),
            );
            assert_eq!(mounted.kind_name(), expected);
            assert!(page_slot.request().is_none());
        }

        app.add_window(win);
        app.run();
    }

    #[test]
    fn dialog_support_matches_the_controls() {
        let buffer = MountedViewer::Buffer(Handle::None);
        let text = MountedViewer::Text(Handle::None);
        let container = MountedViewer::Container(Handle::None);
        let dissasm = MountedViewer::Dissasm(Handle::None);
        let unavailable = MountedViewer::Unavailable(Handle::None);
        for dialog in [ViewDialog::GoTo, ViewDialog::Find, ViewDialog::Copy] {
            assert!(buffer.implements(dialog));
            assert!(dissasm.implements(dialog));
            assert!(!container.implements(dialog));
            assert!(!unavailable.implements(dialog));
        }
        assert!(text.implements(ViewDialog::GoTo));
        assert!(text.implements(ViewDialog::Copy));
        // C++ `TextViewer` has no Find dialog.
        assert!(!text.implements(ViewDialog::Find));
    }

    #[test]
    fn a_colorizer_without_position_to_color_is_dropped() {
        let settings = buffer_settings(
            Some(ViewerRequest::buffer(BufferViewerRequest::default())),
            Some(Box::new(AllRed)),
            None,
            SharedCursorInfo::new(),
            String::from("Buffer View"),
        );
        assert!(format!("{settings:?}").contains("has_colorizer: false"));

        let settings = buffer_settings(
            Some(ViewerRequest::buffer(BufferViewerRequest {
                position_to_color: true,
                ..BufferViewerRequest::default()
            })),
            Some(Box::new(AllRed)),
            None,
            SharedCursorInfo::new(),
            String::from("Buffer View"),
        );
        assert!(format!("{settings:?}").contains("has_colorizer: true"));
        assert_eq!(settings.custom_name(), Some("Buffer View"));
    }

    #[test]
    fn a_slot_without_a_request_still_mounts_with_defaults() {
        let _ui = crate::UI_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut app = App::debug(60, 20, "Paint.Enable(false)\nPaint('x')")
            .build()
            .expect("debug app");
        let mut win = Window::new("mount", layout!("d:f"), window::Flags::None);
        let tab_handle = win.add(Tab::new(layout!("d:f"), tab::Flags::None));
        let data = object(&[]);

        let mut empty = slot(ViewerRequest::new(ViewerKind::Buffer));
        // Simulate a second mount attempt: the request is already gone.
        assert!(empty.take_request().is_some());
        assert!(empty.take_request().is_none());

        let mounted = {
            let tab = win.control_mut(tab_handle).expect("tab");
            let page = tab.add_tab("Buffer View");
            mount_viewer(
                tab,
                page,
                &mut empty,
                MountContext::plain(&data, SharedCursorInfo::new(), 0),
            )
        };
        assert!(matches!(mounted, MountedViewer::Buffer(_)));
        assert_eq!(empty.name(), "Buffer View");
        app.add_window(win);
        app.run();
    }
}
