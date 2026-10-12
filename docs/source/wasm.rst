GView in a web browser (WebAssembly)
====================================

GView can be compiled with `Emscripten <https://emscripten.org>`_ into a static web site: the AppCUI browser frontend
draws the interface in an HTML5 canvas and the whole application (viewers and plugins) runs inside the page. The files
you open are analysed by the WebAssembly module in your browser tab and are never uploaded. The only network traffic is
Learning and Evaluation Mode, once you connect, towards the course server named in your connection string.

Try it
------

**Open GView in your browser:** `app/GView.html <app/GView.html>`_

Drop files on the page (or use **Open files...**) to analyze them. Click inside the page to give GView the keyboard
focus. The app is rebuilt from every commit to ``main``, so it can be ahead of the latest release.

..
   docs.yml copies the web build next to this page as app/ (GView.html, GView.mjs, GView.wasm, appcui-host.js,
   gview-page.js, gview-storage.js, gview-storage-worker.js, the font, serve.py) plus app/GView-Web-wasm32.zip(.sha256).
   Keep the links above and below in sync with that step.

Downloads
---------

The same static site can be run offline or put on your own web server:

* **Latest build from main:** `GView-Web-wasm32.zip <app/GView-Web-wasm32.zip>`_
  (`SHA-256 <app/GView-Web-wasm32.zip.sha256>`_).
* **Releases:** every `GitHub Release <https://github.com/gdt050579/GView/releases>`_ carries
  ``GView-<version>-Web-wasm32.zip``. It is built from source like the native archives, is listed in ``SHA256SUMS``, has
  a SLSA provenance attestation, and its code files (``GView.wasm``, ``GView.mjs``, ``GView.html``,
  ``appcui-host.js``, ``gview-page.js``, ``gview-storage.js``, ``gview-storage-worker.js``) are signed with Sigstore.
  The release notes list the verification commands.

Unzip the archive and serve the folder over HTTP (see `Building`_ for why ``file://`` does not work):

.. code-block:: bash

   python serve.py GView

What is different from the native GView
---------------------------------------

* **Files.** The page has an in-memory file system. Files given to the page with the **Open files...** button or by
  dropping them on the page are copied to ``Files`` in the home folder (``/home/web_user/Files``, also reachable as
  ``/files``) and opened right away. **File > Open** browses that folder too. Everything under the home folder is
  **kept in the browser** across reloads and visits (see `Persistent storage`_).
* **Settings.** The settings file is ``/app.ini`` (AppCUI names it after the virtual executable ``/app.wasm``) and
  holds the same content as ``GView.ini``. GView keeps a copy in the ``localStorage`` of the site (key
  ``GView/GView.ini``). The copy is restored when the page loads and updated within about half a second of every
  change, so settings, key bindings and the theme survive a reload. Clearing the site data of the page resets them,
  and the first-run tutorial is shown again. When the browser blocks ``localStorage`` (some private modes, blocked
  site data), the settings last only as long as the tab. With several tabs open, the last change wins. Secrets are
  never written to it: the Learning connection string is kept encrypted by the persistent storage instead.
* **Plugins** are linked into the executable (``GVIEW_STATIC_PLUGINS``) instead of being loaded from ``Types/`` and
  ``GenericPlugins/``. Not available in the browser build:

  * the **PDF** type plugin (podofo, openjpeg, tiff and jbig2dec are not built for WebAssembly);
  * the **FileDownloader** generic plugin (needs libcurl).

* **Learning and Evaluation Mode** works (*Options > Learning and Evaluation Mode*): it talks to the course server
  through the ``fetch()`` API of the page (``GVIEW_ENABLE_BROWSER_NETWORK``). The server must allow the origin of the
  page (CORS) and its certificate must be trusted by the browser: a connection string that pins a private certificate
  authority (``caPem``) is refused. Policies that require screen protection cannot be met in a page. Details:
  :doc:`learning_mode_protocol`, section *16. Browser clients*.
* **Other network features** are not built (``GVIEW_ENABLE_NETWORK=OFF``, no libcurl): the auto-updater (and
  ``GViewUpdater``), the Smart Assistant requests and FileDownloader. The remote TUI (``GVIEW_ENABLE_REMOTE``) is
  always off.
* **Clipboard.** Copy / paste works inside GView, but it is not shared with the operating system yet.
* **Keyboard.** The browser keeps some shortcuts for itself (for example Ctrl+W, Ctrl+T, Ctrl+N). The ``Keyboard.Ctrl`` /
  ``Keyboard.Alt`` keys of the ``[AppCUI]`` section remap the modifiers if needed.
* Closing the last window does not end GView: the desktop stays open so more files can be dropped on the page.

Persistent storage
------------------

Everything under the home folder (``/home/web_user``) is kept: the files given to the page, the files GView writes
next to them (Dropper output, disassembly caches, exports), the Learning task files saved in ``file`` mode
(``Documents/GView/<week>``). ``/tmp`` and the rest of the in-memory file system are not.

* **Where.** In the storage of the site: the Origin Private File System for the content, IndexedDB for the list of
  files. Every file is encrypted with AES-256-GCM in 1 MiB chunks under a key that the page cannot export: live
  malware samples are never written in clear into the browser profile (an antivirus would otherwise quarantine them
  and corrupt the store). This does not protect them from other pages of the *same* web origin: host GView on an
  origin of its own.
* **When.** A dropped file is kept as soon as it is opened (the page streams it to a storage worker, no extra copy).
  Files written by GView are kept once they stop changing (the home folder is checked every ~2 s), and at once when
  the page is hidden. Closing the tab right after saving a file can still lose that last file.
* **Startup.** The newest files are copied back into memory when the page loads, up to 64 MiB; the others are listed
  by **File > Stored files** and loaded when opened from there (a large sample never slows down the start).
* **File > Stored files** lists what is kept (size, date, in memory or not) and opens, downloads (an export: blocked by
  a course policy that disables ``Export``), deletes files, and forgets the saved Learning connection.
* **Limits.** The browser decides how much a site may keep and may evict it under storage pressure unless the page was
  granted *persistent* storage (requested automatically; shown in **Stored files**). Private windows and blocked site
  data keep files for the tab only. Safari removes the data of a site that was not used for 7 days unless it was added
  to the home screen. Clearing the site data removes everything. Several tabs share the same store (writes are
  serialized with a Web Lock).

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

The site is written to ``bin/wasm``: ``GView.html``, ``GView.mjs``, ``GView.wasm``, ``appcui-host.js``, ``gview-page.js``,
``gview-storage.js``, ``gview-storage-worker.js``, the JuliaMono font and ``serve.py``. Browsers do not load WebAssembly
from ``file://`` URLs, so serve the folder over HTTP:

.. code-block:: bash

   python bin/wasm/serve.py GView

Any static web server works, as long as it serves ``.mjs`` / ``.js`` as ``text/javascript`` and ``.wasm`` as
``application/wasm``. The page sets a Content-Security-Policy (no inline script; ``connect-src`` limited to the site,
``https:`` and the local machine); a server may send a stricter one.

Continuous integration
----------------------

The WebAssembly build is part of CI and uses the composite action ``.github/actions/build-wasm``. That action runs on
Linux, installs the pinned emsdk release (the tag is checked against its commit), configures with the ``wasm`` preset
and copies the files of the site out of ``bin/wasm``. ``bin/wasm`` also holds the static libraries of the build, so the
action copies an explicit list of files.

* ``ci.yml`` builds it for every push and pull request. The site is kept for 7 days as the ``GView-Web-wasm32``
  artifact of the run.
* ``docs.yml`` builds it for every push to ``main`` and publishes it with the documentation (`Try it`_).
* ``deploy_release.yml`` builds it without caches, signs it and attaches ``GView-<version>-Web-wasm32.zip`` to the
  release (`Downloads`_).

To move to another Emscripten release, update ``emsdk_version`` and ``emsdk_commit`` (the commit of that emsdk tag) in
``.github/actions/build-wasm/action.yml`` and the version mentioned in `Building`_.

How it works
------------

* ``GVIEW_STATIC_PLUGINS`` builds GViewCore and every plugin as static libraries. The block holding the entry points of a
  plugin is declared with ``GVIEW_PLUGIN_ENTRY_POINTS``: ``extern "C"`` for shared plugins, and a namespace unique to the
  plugin (``GViewStaticPlugin_<Name>``) for static ones. CMake generates the table of the linked plugins
  (``cmake/StaticPlugins.cpp.in``) and GViewCore looks the entry points up by name
  (``GViewCore/src/include/StaticPlugins.hpp``) instead of loading ``lib<Name>.tpl`` / ``lib<Name>.gpl``.
* ``GViewCore/src/App/BrowserHost.cpp`` exports the functions the page uses to give files to GView
  (``gview_browser_alloc`` / ``gview_browser_add_file`` / ``gview_browser_last_stored``). Files are opened from the
  desktop's ``OnFrameUpdate``, never while a modal window is open.
* ``GViewCore/src/App/BrowserStorage.cpp`` keeps the home folder in the persistent storage (``GView/web/gview-storage.js``
  and ``gview-storage-worker.js``): restore at startup, change detection (``Storage::Diff``, unit tested), secrets.
* Learning and Evaluation Mode uses ``Security/Learning/LearningHttpFetch.cpp`` as its transport. There are no
  threads: a network job runs on the UI thread and is run again once its response has arrived
  (``Security/Learning/JobReplay.hpp``, ``BackgroundWorkerWasm.cpp``) - no stack is ever suspended for the network.
* Modal windows suspend the C++ stack with Asyncify (see the AppCUI documentation of the browser frontend). With
  Asyncify, ``AppCUI::Application::Run()`` does not return.
