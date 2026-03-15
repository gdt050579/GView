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