Plugin development
==================

This page is for developers who want to add new file format support (Type plugins) or
extend GView. Use the public API only; internal APIs are not stable for plugins.

Public vs internal API
----------------------

* **GView.hpp** (``GViewCore/include/GView.hpp``) — Public API. All types, interfaces,
  and utilities for plugins live here. Plugins must rely only on this header.

* **Internal.hpp** (``GViewCore/src/include/Internal.hpp``) — Private implementation.
  Used only inside GViewCore. Do not use in Type or Generic plugins.

Type plugin contract
--------------------

Every Type plugin must export these C functions (``extern "C"``):

* **Validate** — Return whether a buffer matches this file type (magic, extension, etc.).
* **CreateInstance** — Return a new instance of your TypeInterface implementation.
* **PopulateWindow** — Configure viewers and panels for the opened file.
* **UpdateSettings** — Register patterns, priority, and commands in the INI layer.

Your plugin class must inherit ``GView::TypeInterface`` and implement:

* **GetTypeName()** — Plugin display name.
* **RunCommand(string_view)** — Handle custom commands (e.g. from menus).
* **UpdateKeys(KeyboardControlsInterface*)** — Register keyboard shortcuts.
* **GetSmartAssistantContext(...)** — Provide context for the smart assistant (can return minimal JSON).

Smart viewers
-------------

Each Type plugin chooses which viewers to create in ``PopulateWindow``. Available
viewers and their settings classes:

* **BufferViewer** — Hex/binary with zones, colors, bookmarks. Settings:
  ``GView::View::BufferViewer::Settings``
* **TextViewer** — Plain text with line wrapping. Settings:
  ``GView::View::TextViewer::Settings``
* **LexicalViewer** — Syntax-highlighted code with folding. Settings:
  ``GView::View::LexicalViewer::Settings``
* **ImageViewer** — Image display. Settings: ``GView::View::ImageViewer::Settings``
* **GridViewer** — Tabular data (CSV, etc.). Settings:
  ``GView::View::GridViewer::Settings``
* **DissasmViewer** — Disassembly (Capstone) with type annotations. Settings:
  ``GView::View::DissasmViewer::Settings``
* **ContainerViewer** — Tree view for archives / container content. Settings:
  ``GView::View::ContainerViewer::Settings``

Key interfaces
--------------

**Object** — The opened file, buffer, or process. From ``TypeInterface`` you get
``obj`` (pointer to Object). Use ``obj->GetData()`` for a ``DataCache&`` and
``obj->GetName()`` / ``obj->GetPath()`` for identification.

**DataCache** — Cached access to file/buffer data. Use ``Get(offset, size, failIfCannotRead)``
for a ``BufferView``, ``CopyToBuffer(...)`` for a copy, and ``Copy<T>(offset, object)`` to
read a struct. ``GetSize()`` gives the total size.

**WindowInterface** — In ``PopulateWindow`` you receive a ``Reference<WindowInterface>``.
Call ``GetObject()`` to get the Object, ``CreateViewer(settings)`` for each viewer,
and ``AddPanel(Pointer<TabPage>(...), vertical)`` for custom panels.

Adding a new Type plugin
-------------------------

1. Create a directory under ``Types/YOUR_PLUGIN/`` (e.g. ``Types/MyFormat/``).
2. Add ``include/your_plugin.hpp`` with your TypeInterface implementation.
3. Add ``src/your_plugin.cpp`` (and optional panels) with the exported functions
   (Validate, CreateInstance, PopulateWindow, UpdateSettings).
4. Add a ``CMakeLists.txt`` (copy from an existing Type such as ``Types/PREFETCH``).
5. In the repository root ``CMakeLists.txt``, add ``add_subdirectory(Types/YOUR_PLUGIN)``.

Coding conventions
------------------

* **C++20** — Required (set in CMake).
* **Naming** — PascalCase for types and functions, camelCase for variables.
* **Strings** — Prefer ``std::string_view``; use ``FixSizeString<N>`` or
  ``LocalString<N>`` for fixed/stack buffers.
* **Pointers** — Use ``Reference<T>`` (non-owning) and ``Pointer<T>`` (owning) from
  AppCUI; avoid raw ``new``/``delete``.
* **Errors** — Use ``CHECK(condition, returnValue, "message")`` for validation;
  ``GView::Utils::ErrorList`` for multiple errors; ``GView::Utils::GStatus`` when
  returning a status message.
* **Data access** — Use ``DataCache`` and ``BufferView``; avoid unnecessary copies.

Common patterns
---------------

Creating viewers in PopulateWindow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get your type from the window, configure the settings (zones, callbacks), then create
the viewer and add panels::

   PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win) {
       auto myType = win->GetObject()->GetContentType<MyTypeFile>();

       BufferViewer::Settings settings;
       settings.AddZone(0, sizeof(Header), ColorPair{Color::White, Color::DarkBlue}, "Header");
       settings.SetPositionToColorCallback(myType.ToBase<BufferViewer::PositionToColorInterface>());
       win->CreateViewer(settings);

       win->AddPanel(Pointer<TabPage>(new MyPanel(myType, win)), true);
       return true;
   }

Reading file data
~~~~~~~~~~~~~~~~~

Use ``Object::GetData()`` to get a ``DataCache&``. Use ``Copy<T>`` for structs and
``Get()`` for variable-length data::

   bool MyTypeFile::Update() {
       auto& data = obj->GetData();
       if (!data.Copy<MyHeader>(0, header)) return false;
       auto buf = data.Get(offset, size, true);
       if (!buf.IsValid()) return false;
       return true;
   }

PositionToColorInterface (buffer highlighting)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implement this interface so the buffer viewer can color ranges by offset::

   bool MyTypeFile::GetColorForBuffer(uint64 offset, BufferView buf, BufferColor& result) {
       if (offset >= section.start && offset < section.end) {
           result.start = section.start;
           result.end = section.end;
           result.color = ColorPair{Color::Yellow, Color::DarkRed};
           return true;
       }
       result.Reset();
       return false;
   }


Generic plugins
---------------

Generic plugins work with any file type and are registered via ``GView.ini``
(see :doc:`configuration`). They usually provide dialogs or operations (e.g. hashes,
entropy, comparison). Implement them under ``GenericPlugins/`` and register in INI;
they do not implement the Type plugin contract above.

Quick reference
---------------

* **Add new file format** — ``Types/NEW_TYPE/`` — TypeInterface, Validate, PopulateWindow
* **Add generic operation** — ``GenericPlugins/`` — Window-based dialogs
* **Add hash algorithm** — ``GViewCore/src/Hashes/`` — Hash classes in GView.hpp
* **Add decoding** — ``GViewCore/src/Decoding/`` — Decoding namespace
* **Modify viewer behavior** — ``GViewCore/src/View/`` — ViewControl, Settings
* **Add keyboard shortcut** — TypeInterface — UpdateKeys(), KeyboardControl
* **Add panel to Type** — ``Types/*/src/Panel*.cpp`` — TabPage, ListView
* **AI assistant context** — TypeInterface — GetSmartAssistantContext()
