GView in a web browser (WebAssembly)
====================================

GView can be compiled with `Emscripten <https://emscripten.org>`_ into a static web site: the AppCUI browser frontend
draws the interface in an HTML5 canvas and the whole application (viewers and plugins) runs inside the page. Nothing is
sent to a server - the files you open are read by the WebAssembly module in your browser tab.

What is different from the native GView
---------------------------------------

* **Files.** The page has an in-memory file system. Files given to the page with the **Open files...** button or by
  dropping them on the page are copied to ``/files`` and opened right away. **File > Open** browses that folder too.
  The files (and ``GView.ini``) are lost when the tab is closed or reloaded.
* **Plugins** are linked into the executable (``GVIEW_STATIC_PLUGINS``) instead of being loaded from ``Types/`` and
  ``GenericPlugins/``. Not available in the browser build:

  * the **PDF** type plugin (podofo, openjpeg, tiff and jbig2dec are not built for WebAssembly);
  * the **FileDownloader** generic plugin (needs libcurl).

* **Network features** are not built (``GVIEW_ENABLE_NETWORK=OFF``): the auto-updater (and ``GViewUpdater``), Learning
  and Evaluation Mode and the Smart Assistant requests. The remote TUI (``GVIEW_ENABLE_REMOTE``) is always off.
* **Clipboard.** Copy / paste works inside GView, but it is not shared with the operating system yet.
* **Keyboard.** The browser keeps some shortcuts for itself (for example Ctrl+W, Ctrl+T, Ctrl+N). The ``Keyboard.Ctrl`` /
  ``Keyboard.Alt`` keys of the ``[AppCUI]`` section remap the modifiers if needed.
* Closing the last window does not end GView: the desktop stays open so more files can be dropped on the page.

Building
--------

Requirements: an activated `emsdk <https://emscripten.org/docs/getting_started/downloads.html>`_ (``EMSDK`` set,
``emcc`` in ``PATH``; the build is verified with Emscripten 6.0.12), CMake 3.24+ and Ninja. The dependencies (OpenSSL,
zlib, capstone, minizip-ng, sqlite3, re2, nlohmann-json) are built by vcpkg with the ``wasm32-emscripten`` triplet.

.. code-block:: bash

   # Windows: emsdk_env.ps1 / emsdk_env.bat, Linux / macOS: source ./emsdk_env.sh
   cmake --preset wasm
   cmake --build build/wasm --target GView

On Windows, vcpkg needs ``pkg-config`` in ``PATH`` to build ``minizip-ng`` for WebAssembly (for example the
``pkgconf`` of MSYS2, or the one vcpkg downloads under ``AppCUI/vcpkg/downloads/tools/msys2``).

The site is written to ``bin/wasm``: ``GView.html``, ``GView.mjs``, ``GView.wasm``, ``appcui-host.js``, the JuliaMono font
and ``serve.py``. Browsers do not load WebAssembly from ``file://`` URLs, so serve the folder over HTTP:

.. code-block:: bash

   python bin/wasm/serve.py GView

Any static web server works, as long as it serves ``.mjs`` as ``text/javascript`` and ``.wasm`` as
``application/wasm``.

How it works
------------

* ``GVIEW_STATIC_PLUGINS`` builds GViewCore and every plugin as static libraries. The block holding the entry points of a
  plugin is declared with ``GVIEW_PLUGIN_ENTRY_POINTS``: ``extern "C"`` for shared plugins, and a namespace unique to the
  plugin (``GViewStaticPlugin_<Name>``) for static ones. CMake generates the table of the linked plugins
  (``cmake/StaticPlugins.cpp.in``) and GViewCore looks the entry points up by name
  (``GViewCore/src/include/StaticPlugins.hpp``) instead of loading ``lib<Name>.tpl`` / ``lib<Name>.gpl``.
* ``GViewCore/src/App/BrowserHost.cpp`` exports the functions the page uses to give files to GView
  (``gview_browser_alloc`` / ``gview_browser_add_file``). Files are opened from the desktop's ``OnFrameUpdate``, never
  while a modal window is open.
* Modal windows suspend the C++ stack with Asyncify (see the AppCUI documentation of the browser frontend). With
  Asyncify, ``AppCUI::Application::Run()`` does not return.
