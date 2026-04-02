GView Global Plugins
====================

Generic plugins work with any file type and are registered via INI configuration.
They provide dialogs or operations that apply universally, such as:

* **Hashes** — Compute MD5, SHA, CRC and other hashes over selection or file
* **Entropy** — Entropy analysis and visualization
* **Dropper** — Extract artifacts from buffers
* **Sync Compare** — File comparison
* **Unpacker** — Decompression utilities

These plugins are configured in ``GView.ini`` under ``[Generic.*]`` sections.
See :doc:`configuration` for the configuration file format.

.. toctree::
   :maxdepth: 1
   :caption: Reference

   character_table
   hashes