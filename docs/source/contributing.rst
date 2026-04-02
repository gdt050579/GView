GView contributing
==================

Start contributing
------------------

1. **Clone with submodules**::

      git clone --recurse-submodules <your-repo-link>/GView.git

2. **Build** — Use CMake and vcpkg as described in :doc:`usage`. Enable tests with
   ``-DENABLE_TESTS=ON``.

3. **Documentation** — Sphinx sources are under ``docs/``. Install tooling::

      pip install -r docs/requirements.txt

   Build HTML docs::

      cd docs && make html

   Output is in ``docs/build/html``.

4. **Code style** — Follow the project's C++20 conventions: ``PascalCase`` for types
   and functions, ``camelCase`` for variables. Use only the public API in
   ``GViewCore/include/GView.hpp`` for plugin development. See :doc:`plugin_development`
   for the plugin contract, patterns, and conventions.

5. **Pull requests** — Open PRs against ``main``. CI runs on push and on pull requests;
   ensure builds and tests pass.

Reporting issues
----------------

Use the repository issue tracker for bugs and feature requests. Check existing issues
and use the provided templates when possible.
