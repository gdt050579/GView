Updates
=======

GView checks GitHub Releases for a newer version once a day and offers to install it.

How it works for the user
-------------------------

* The first time GView starts on a given day, it asks GitHub in the background whether a newer release exists.
  Nothing is shown when GView is up to date, offline, or when the check fails.
* The first time a newer version is found, GView shows the **Update available** dialog with the installed and the new
  version, the publish date, the download size and the release notes. The dialog waits until no other dialog is open.

  * **Install update** downloads and verifies the release, then asks for a final confirmation. GView closes, replaces its
    files and restarts in the same terminal with the same command line.
  * **Remind me later** (or closing the dialog) hides the prompt for that version for ``UpdateRemindAfterDays`` days.
  * **Skip this version** never prompts for that version again. A newer version is offered normally.
  * **Copy link** copies the release page link to the clipboard.

  "Remind me later" is the default button, and Enter alone never installs. When the dialog opens by itself, its buttons
  ignore input for one second, so keystrokes meant for a viewer cannot answer it.

* **Help > Check for updates** runs the same check on demand. It also offers a version that was skipped or postponed.
* Updates are not offered while Learning and Evaluation Mode is active, because an update would end the session.

How an update is installed
--------------------------

1. GView downloads the release archive of the current operating system into ``<GView folder>/.update/`` and checks its
   SHA-256 against the ``SHA256SUMS`` file published with the release. The archive is validated (no absolute paths,
   ``..``, links, device names, duplicates, encrypted entries or oversized entries) and extracted to
   ``.update/staging-<version>/``. The installation itself is not modified yet.
2. After the confirmation GView closes its interface. It copies ``GViewUpdater`` to a private temporary folder and runs it.
3. ``GViewUpdater`` validates the staged files, then replaces each file of the installation by renaming the current file
   into ``.update/old-<version>/`` and the staged file into its place. Every move is written to a journal. If a move fails,
   the journal is replayed backwards and the installation is left exactly as it was.
4. GView waits for ``GViewUpdater``, then starts the new GView with the original command line and waits for it.
5. The next start of GView removes the backup folder.

Files that are not part of the release are never touched: ``GView.ini``, themes and plugins you added stay in place.
If the update fails and cannot be rolled back, GView prints the location of the backup folder and of the journal. The
previous files can be copied back from there by hand.

``GViewUpdater`` has no dependency on the GView libraries, so it keeps working while they are being replaced. It is not
meant to be started manually.

Configuration
-------------

The updater reads these keys from the ``[GView]`` section of ``GView.ini``:

+------------------------------+-----------------------------------------------------------------+---------------------------------------------------------------+
| Key                          | Default                                                         | Meaning                                                       |
+==============================+=================================================================+===============================================================+
| ``UpdateCheck``              | ``true``                                                        | Daily background check. ``false`` disables it; the menu entry |
|                              |                                                                 | keeps working.                                                |
+------------------------------+-----------------------------------------------------------------+---------------------------------------------------------------+
| ``UpdateIncludePreReleases`` | ``true``                                                        | Also offer releases marked as pre-release on GitHub. Every    |
|                              |                                                                 | GView release so far is a pre-release.                        |
+------------------------------+-----------------------------------------------------------------+---------------------------------------------------------------+
| ``UpdateFeedUrl``            | ``https://api.github.com/repos/gdt050579/GView/releases?...``   | GitHub "list releases" API URL. Only ``https://`` is accepted.|
+------------------------------+-----------------------------------------------------------------+---------------------------------------------------------------+
| ``UpdateCheckIntervalHours`` | ``24``                                                          | Minimum delay between two automatic checks (1 to 720).        |
+------------------------------+-----------------------------------------------------------------+---------------------------------------------------------------+
| ``UpdateRemindAfterDays``    | ``7``                                                           | Delay of "Remind me later". ``0`` never reminds about the     |
|                              |                                                                 | same version again.                                           |
+------------------------------+-----------------------------------------------------------------+---------------------------------------------------------------+
| ``UpdateProxy``              | empty                                                           | Proxy for the update requests. ``https_proxy`` from the       |
|                              |                                                                 | environment is honoured as well.                              |
+------------------------------+-----------------------------------------------------------------+---------------------------------------------------------------+

GView also stores its own state there: ``UpdateLastCheck``, ``UpdateLastSeenVersion``, ``UpdateRemindAt``,
``UpdateSkippedVersion``, ``UpdateETag`` and ``UpdateCachedFeedVersion``. Deleting them resets the update prompts.

Limitations
-----------

* GView must be able to write to its own folder. When it cannot (for example under ``Program Files`` or ``/opt``), the
  dialog only offers to copy the release link and the update has to be installed manually.
* On Linux and macOS, the automatic check runs only with frontends that deliver frame updates (SDL). The terminal
  (ncurses) frontend of the current AppCUI version does not, so only **Help > Check for updates** is available there.
* A release without ``SHA256SUMS`` cannot be installed automatically; download it from the release page instead.

Testing with a local server
---------------------------

Builds configured with ``-DDISSASM_DEV=1`` accept an ``http://`` feed and releases without a checksum list, so the whole
flow can be tested against a local web server:

1. Build GView twice: an "old" build with a lower ``GVIEW_VERSION`` and a "new" build.
2. Zip the ``bin/<Config>`` folder of the new build (the archive root is the content of ``bin/<Config>``, like the
   release archives), compute ``sha256sum`` into ``SHA256SUMS`` and write a ``releases.json`` that copies
   the GitHub format (``tag_name``, ``draft``, ``prerelease``, ``html_url``, ``body``, ``published_at`` and ``assets`` with
   ``name``, ``size`` and ``browser_download_url``).
3. Serve the folder with ``python -m http.server 8080`` and set
   ``UpdateFeedUrl = "http://127.0.0.1:8080/releases.json"`` and ``UpdateLastCheck = 0`` in the old build's ``GView.ini``.
4. Start the old build. The dialog appears after the first frame; **Help > Check for updates** works as well.

In these development builds only, setting the environment variable ``GVIEW_UPDATE_TEST_AUTOACCEPT=1`` answers
**Install update** and the final confirmation automatically, so the download, install and restart can be tested without
a keyboard. The variable is inherited by the restarted GView. Release builds ignore it.
