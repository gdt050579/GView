GView usage
===========

First run
---------

Pre-built archives are produced by the CI/CD pipeline for each supported operating
system. Download the archive for your platform and run the main binary (``GView`` or
``GView.exe`` on Windows).

Windows
~~~~~~~
Unzip the release archive and run ``GView.exe`` (tested on Windows 10 x64).

Linux
~~~~~
Builds are made on Ubuntu 20.04 (Intel). Precompiled binaries run on Ubuntu 20.04 and
Ubuntu 22.04. Older images (e.g. Ubuntu 18.04) may have incompatible GLIBC.

macOS / OS X
~~~~~~~~~~~~
You may see a warning that macOS cannot verify the app. Until binaries are digitally
signed and notarized, you must manually allow each binary to run in System Preferences
→ Security & Privacy. Do not disable Gatekeeper system-wide.

Building from source
--------------------

* **CMake** is used to build the project on all platforms.
* **vcpkg** is used for dependencies; see the repository `.github/workflows/ci.yml`
  for the build pipeline.

Clone with submodules::

   git clone --recurse-submodules <repo-url>/GView.git

Configure and build:

**Windows (Visual Studio):**

   cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
   cmake --build build --config Release

**Linux / macOS:**

   cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
   cmake --build build

**With tests:** add ``-DENABLE_TESTS=ON``. The build produces a ``GViewTesting``
executable; unit tests live in ``**/tests_*.cpp`` and are driven by
``cmake/core_testing.cmake``.

Configuration
-------------

GView is configured via ``GView.ini`` next to the executable. If the file is missing,
run ``GView reset`` from the CLI to create a default one. See :doc:`configuration`
for the INI format and options.

Dependencies
------------

Dependencies are managed via vcpkg (``vcpkg.json``). Main third-party libraries:
AppCUI (terminal UI, subproject), Capstone (disassembly), OpenSSL (crypto), SQLite3,
zlib, PCRE2, LLVMDemangle (symbol demangling).
