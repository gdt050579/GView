GView development
=================

Testing
-------

* Tests are enabled with ``-DENABLE_TESTS=ON`` at configure time.
* Unit tests are in files matching ``**/tests_*.cpp``.
* The testing build produces a ``GViewTesting`` executable instead of ``GView``.
* The ``run_core_tests()`` macro from ``cmake/core_testing.cmake`` is used to
  register test sources.

Run the test executable from your build directory after building with tests enabled.

GitHub workflows
----------------

Workflows run on push to ``main`` and on ``pull_request``. To run them for other
branches, create a draft PR or trigger manually from the Actions page: choose the
workflow and use **Run workflow** when it has a ``workflow_dispatch`` trigger.

All workflows share the composite action in ``.github/actions/build`` (configure,
build, test, sign, package). The WebAssembly build (:doc:`wasm`) has its own composite
action, ``.github/actions/build-wasm`` (pinned emsdk, ``wasm`` preset, site collection,
signing, packaging). Third-party actions are pinned to commit SHAs and updated by
Dependabot.

* ``ci.yml`` - Release build on Windows, macOS (Intel) and Linux; Apple Silicon and
  Linux arm64 are non-blocking experimental lanes. A Linux lane builds the
  WebAssembly version and keeps the site as the ``GView-Web-wasm32`` artifact for 7
  days, so a PR can be tried in a browser (unzip, then ``python serve.py GView``).
* ``testing.yml`` - unit tests. Windows is gating; Linux and macOS report only until
  they are consistently green (flip ``experimental`` in the matrix to make them gating).
* ``codeql-analysis.yml`` - CodeQL ``security-extended`` (C/C++, Python, workflows),
  on every PR and weekly on ``main``. ``AppCUI`` and ``3rdPartyLibs`` are excluded.
* ``sanitizers.yml`` - unit tests under ASan + UBSan, weekly and on demand.
* ``format-check.yml`` - ``git clang-format`` (LLVM 19) on the lines a PR changes.
* ``workflow-lint.yml`` - ``zizmor`` and ``actionlint`` for the workflow files.
* ``scorecard.yml`` - OpenSSF Scorecard.
* ``docs.yml`` - builds this documentation with ``-W`` on PRs. Every push to ``main``
  also builds the WebAssembly version and deploys both to GitHub Pages: the app is
  published in ``app/`` next to the documentation (see :doc:`wasm`).
* ``increase_version.yml`` - bumps ``GVIEW_VERSION`` after every push to ``main``.
* ``deploy_release.yml`` - manual release: dependencies built from source, binaries
  signed with Sigstore, archives attested (SLSA provenance), GitHub Release created
  with ``SHA256SUMS`` and verification instructions. Besides the native archives, the
  release carries ``GView-<version>-Web-wasm32.zip`` (the WebAssembly build). Its name
  holds no operating system, so the auto-updater never selects it.