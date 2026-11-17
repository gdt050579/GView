Learning and Evaluation Mode - implementation report
====================================================

This page is the ground truth for what the GView client implements for Learning and Evaluation Mode (protocol v2).
It is kept identical to ``plans/LEARNING_MODE_IMPLEMENTED.md`` (the copy consumed by the course-server team) and
complements the design contract ``plans/LEARNING_MODE_PROTOCOL_SPEC.md``. Where the client differs from that
contract, the difference is listed in `14. Deviations from the protocol spec`_ and the spec has been updated.

.. contents::
   :local:
   :depth: 2

1. Overview and threat model
----------------------------

A teacher runs a course server that hands out tasks (problems), resources and a **signed policy**. The student
pastes a connection string into GView (*Options > Learning and Evaluation Mode*, or ``GView learn <connectionString>``).
GView then:

1. connects over verified TLS and authenticates with a secret access token;
2. receives a policy, verifies its Ed25519 signature over the raw bytes, then validates schema, digest, subject,
   server and validity window - and only then applies it;
3. enforces the policy: disabled features, plugin whitelist, watermark, memory-only storage, screen protection;
4. lists Weeks > Problems/Resources, delivers task content either into page-locked memory (``memory``) or to a
   file chosen by the student (``file``), verifying SHA-256 in both cases;
5. submits flags (with an optional explanation) using idempotency keys;
6. sends privacy-preserving telemetry (event-level + counters) in the background;
7. keeps the student's private notes and shows the teachers' course notes (`18. Course notes`_), when the course
   server offers them;
8. saves the student's work on a task (names, comments, the replay journal) to the course server and resumes it on
   another computer, and shows the teacher's published solution side by side or replays it step by step
   (`19. Work documents, solutions and the replay journal`_), when the course server offers it.

**What is guaranteed** (against a student using an unmodified GView build):

* no policy is applied unless it verifies with the public key from the connection string (or the INI fallback); a
  missing key means the policy is refused, never silently ignored;
* a verified policy is never downgraded by a later unverifiable or legacy answer;
* memory-only task content is never written to disk by GView itself (no temp files, no disassembly cache, no
  exports, no "drop to disk" for signature checks) and is wiped when its window closes;
* every policy-gated GView entry point listed in `7. Feature enforcement matrix`_ refuses the action, says so, and
  records a ``feature_blocked`` telemetry event;
* telemetry never contains user-authored text, file paths, clipboard content or keystrokes.

**What is not guaranteed** (best effort, see CCIS sec. 4.5 / 9.3): a photo of the screen, retyping content, a
patched/rebuilt GView (it is open source), external tools reading process memory, OS-level screenshot tools on
platforms without capture exclusion, and the clipboard paths of AppCUI's own controls (see `Limitations`_).

2. Connection string
--------------------

::

   v1:  base64( base64(token) "#" base64(serverUrl) )
   v2:  base64( base64(token) "#" base64(serverUrl) "#" base64(policyPublicKeyHex) [ "#" base64(extraJson) ] )

* Standard base64 alphabet. Decoding is strict: no whitespace inside, no foreign characters, padding optional,
  non-canonical trailing bits rejected. Surrounding whitespace (copy/paste) is trimmed.
* ``token``: 16..256 printable ASCII characters (0x21-0x7E). Anything else (CR/LF in particular) is rejected because
  the token travels in an HTTP header.
* ``serverUrl``: ``https://host[:port][/path]``, no user-info, query or fragment; trailing ``/`` removed, scheme and
  host lower-cased. ``http://`` is accepted **only** for ``localhost``, ``127.0.0.1`` or ``[::1]`` and only when
  ``[GView] LearningAllowPlainHttpLocalhost=true`` (teacher-laptop labs).
* ``policyPublicKeyHex``: exactly 64 hex characters (raw 32-byte Ed25519 key).
* ``extraJson`` (optional JSON object): ``label`` (string, shown in the window) and ``caPem`` (base64 of a PEM
  certificate used as the *only* trust anchor for that deployment, e.g. a self-signed server certificate).

Worked example (token ``tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd``, server ``https://re.example.edu``, the stub
server's public key ``7fd806c7f2a9e88ec89bb6cca8ba6a2b4b225aa85e488e8222be9dc2acadf094``)::

   v1 = ZEc5clgwRkNRMFJGUmtkSVNVcExURTFPVDFCUlVsTlVWVlpYV0ZsYU1ERXlNelExTmpjNE9XRmlZMlE9I2FIUjBjSE02THk5eVpTNWxlR0Z0Y0d4bExtVmtkUT09
   v2 = ZEc5clgwRkNRMFJGUmtkSVNVcExURTFPVDFCUlVsTlVWVlpYV0ZsYU1ERXlNelExTmpjNE9XRmlZMlE9I2FIUjBjSE02THk5eVpTNWxlR0Z0Y0d4bExtVmtkUT09I04yWmtPREEyWXpkbU1tRTVaVGc0WldNNE9XSmlObU5qWVRoaVlUWmhNbUkwWWpJeU5XRmhPRFZsTkRnNFpUZ3lNakppWlRsa1l6SmhZMkZrWmpBNU5BPT0=
   v2 + extra {"label":"RE 2026 - Group A"} =
        ZEc5clgwRkNRMFJGUmtkSVNVcExURTFPVDFCUlVsTlVWVlpYV0ZsYU1ERXlNelExTmpjNE9XRmlZMlE9I2FIUjBjSE02THk5eVpTNWxlR0Z0Y0d4bExtVmtkUT09I04yWmtPREEyWXpkbU1tRTVaVGc0WldNNE9XSmlObU5qWVRoaVlUWmhNbUkwWWpJeU5XRmhPRFZsTkRnNFpUZ3lNakppWlRsa1l6SmhZMkZrWmpBNU5BPT0jZXlKc1lXSmxiQ0k2SWxKRklESXdNallnTFNCSGNtOTFjQ0JCSW4wPQ==

INI keys (section ``[GView]`` of ``gview.ini``):

=================================== ================================================================================
Key                                 Meaning
=================================== ================================================================================
``ServerConnectionString``          Saved only after a *successful, verified* connect; used to reconnect on open.
``PolicyPublicKey``                 64 hex chars; used when the connection string has no key (v1).
``LearningAllowPlainHttpLocalhost`` ``true``/``false`` (default ``false``), see above.
``LearningDownloadFolder``          Base folder for ``file`` deliveries (empty = ``<Documents>/GView``), see `File mode`_.
``LearningTrustedLaunchOrigins``    Web build only: course servers approved for the one-click launch (space separated
                                    origins, written after the first *Connect* of the trust prompt; see section 17).
``Key.LearningSubmitFlag``          Shortcut of "Submit flag for this task" in a task window (default Ctrl+Alt+F).
=================================== ================================================================================

3. Access token and request headers
-----------------------------------

The token is a secret bearer credential. Every request is an HTTPS ``POST`` with:

=========================== ==========================================================================
Header                      Value
=========================== ==========================================================================
``XAppUserID``              the access token
``X-GView-Client``          client version (``GVIEW_VERSION``, e.g. ``0.390.0``)
``X-GView-Protocol``        ``2``
``X-GView-Platform``        ``CurrentPlatform()``: ``windows-x64``, ``linux-arm64``, ``macos-arm64``, ... and
                            ``web-wasm32`` for GView running in a web page (`16. Browser clients`_)
``X-GView-Policy``          id of the policy currently in force (omitted before the first policy)
``Content-Type``            ``application/json; charset=utf-8`` (body ``{}`` unless noted)
``Accept``                  ``application/json, application/octet-stream``
=========================== ==========================================================================

Transport rules (libcurl): ``CURLOPT_SSL_VERIFYPEER=1``, ``CURLOPT_SSL_VERIFYHOST=2``, TLS >= 1.2, protocols
restricted to ``https`` (or ``http`` for the localhost exception), **redirects are never followed** (the token must
only reach the configured server), the Windows certificate store is trusted (``CURLSSLOPT_NATIVE_CA``) unless
``caPem`` is supplied, in which case it is the only trust anchor (``CURLOPT_CAINFO_BLOB``). Timeouts: connect 10 s,
JSON requests 60 s, downloads 300 s, telemetry 15 s (2 s for the final flush at exit). Response caps: Connect 256 KiB
(decoded policy 64 KiB), JSON 4 MiB, binaries 256 MiB, telemetry/submit replies 64 KiB. All network I/O runs on a
worker thread; results are applied on the UI thread. Ending the session or exiting cancels the running request
(checked about every second) instead of waiting for its timeout.

4. Endpoints
------------

All endpoints are ``POST``. Error envelope for every non-2xx answer::

   { "status": "error", "code": "POLICY_EXPIRED", "details": "human readable", "retryable": false }

Codes understood (HTTP mapping as in the spec): ``BAD_REQUEST`` 400, ``UNAUTHORIZED`` 401, ``FORBIDDEN`` 403,
``NOT_FOUND`` 404, ``RATE_LIMITED`` 429 (+ ``Retry-After`` seconds), ``POLICY_EXPIRED`` 403, ``POLICY_NOT_STARTED`` 403,
``ALREADY_SOLVED`` 409, ``ITEM_DISABLED`` 404, ``UNSUPPORTED_CLIENT`` 426, ``SERVER_ERROR`` 500, ``PAYLOAD_TOO_LARGE`` 413
and ``CONFLICT`` 409 (note and work endpoints only). When the body is not an envelope the code is derived from the HTTP
status; ``PAYLOAD_TOO_LARGE`` is always derived from 413, and a 409 of a note or work endpoint is always ``CONFLICT``
(a 409 of ``SubmitFlag`` stays ``ALREADY_SOLVED``). ``TRANSPORT_ERROR`` and ``PROTOCOL_ERROR`` are client-side only.

============================== =========================================================================================
Endpoint                       Client behaviour
============================== =========================================================================================
``/GView/Connect``             Sent first. ``404``/``405`` => retried once on legacy ``/GView/``.
``/GView/``                    Legacy connect. Empty/non-JSON ``200`` => legacy session (see `11. Catalogue model`_).
``/GView/GetWeeks``            Catalogue. ``404``/``405`` => legacy ``/GView/GetProblems`` (flat array).
``/GView/GetProblems/<name>``  Problem download (bytes + delivery headers).
``/GView/GetResource/<name>``  Resource download (``file``/``text`` kinds only; ``link`` uses the catalogue URL).
``/GView/SubmitFlag``          Submission (`10. Submission`_).
``/GView/Telemetry``           Batches (`9. Telemetry`_).
``/GView/GetNotes``            Course notes (`18. Course notes`_): after Connect when ``policy.notes.enabled``, and
                               each time the Notes window opens.
``/GView/SaveNote``            Autosave of a student note (compare-and-set on ``revision``).
``/GView/DeleteNote``          Deletion of a student note (``404`` = already gone).
``/GView/SaveTeacherNote``     Course-staff editor only (``canEditTeacherNotes``).
``/GView/DeleteTeacherNote``   Course-staff editor only.
``/GView/GetWork``             Course work (`19. Work documents, solutions and the replay journal`_): the caller's own
                               work document of a problem, the solutions it may see (metadata), staff capability,
                               audiences, ``maxBytes``. Resume, Save (conflict path), *Open with work*.
``/GView/SaveWork``            Explicit *Save work to course* / the close prompt (compare-and-set on ``revision``).
``/GView/GetSolution``         Compare / Replay / *Open solution*: a solution with its document.
``/GView/PublishSolution``     Course staff only (``canPublishSolutions``); one solution per (problem, audience).
``/GView/DeleteSolution``      Course staff only (client support, no UI in this version).
``/GView/Heartbeat``           Not used by the client.
============================== =========================================================================================

Connect response (protocol 2)::

   { "status": "ok", "protocolVersion": 2, "serverVersion": "2.0.0", "serverTime": 1759400000,
     "policy": "<base64 of the exact policy bytes>", "policySignature": "<base64 of a 64-byte Ed25519 signature>",
     "user": { "displayName": "Student 17", "score": 120 } }

A JSON object without ``policy`` and without ``protocolVersion >= 2`` is treated as legacy. A protocol-2 answer
without ``policy``/``policySignature`` is an error. ``serverTime`` is informational (the client validates with its
own clock and 120 s skew).

Item names are validated before they are placed in a URL: ``[A-Za-z0-9_-]{1,64}``.

5. Policy (schema 2)
--------------------

Signature: ``Ed25519.verify(publicKey, policyBytes, signature)`` with OpenSSL ``EVP_DigestVerify`` over the exact
decoded bytes, **before** any parsing. Validation order and error codes (the code prefixes the message and is the
``reason`` of ``policy_rejected``):

1. ``POLICY_KEY_MISSING`` - no 32-byte public key (connection string v2 or ``PolicyPublicKey``);
2. ``POLICY_SIGNATURE_INVALID`` - signature does not verify;
3. ``POLICY_SCHEMA_UNSUPPORTED`` - ``schema`` is not ``2``;
4. ``POLICY_MALFORMED`` - structure/types (see below);
5. ``POLICY_DIGEST_MISMATCH`` - digest check;
6. ``POLICY_SUBJECT_MISMATCH`` - ``subject != hex(sha256(token))[0:16]`` (constant-time compare);
7. ``POLICY_SERVER_MISMATCH`` - ``serverUrl`` (normalised) differs from the connection string's server;
8. ``POLICY_NOT_STARTED`` / ``POLICY_EXPIRED`` - ``startsAt - 120 <= now <= endsAt + 120``;
9. platform: ``requireScreenProtect`` and capture exclusion unavailable => state *Error* (restrictions applied,
   no task can be opened).

Fields (unknown top-level fields are ignored; a *present* field with a wrong type is an error):

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Field
     - Required / default
     - Rules
   * - ``schema``
     - required
     - must be 2
   * - ``id``
     - required
     - ``[A-Za-z0-9_.-]{1,64}``; sent as ``X-GView-Policy``
   * - ``digest``
     - required
     - 64 lowercase hex
   * - ``purpose``
     - ""
     - <= 256 chars, no control characters
   * - ``issuedAt``
     - 0
     - unsigned integer
   * - ``startsAt`` / ``endsAt``
     - required
     - unsigned, ``endsAt > 0``, ``endsAt >= startsAt``
   * - ``subject``
     - required
     - 16 lowercase hex
   * - ``serverUrl``
     - ""
     - when present it must match the connection string's server
   * - ``disabledFeatures``
     - []
     - ``Copy, Export, SaveAs, Plugins, LLMHints, Clipboard, Screenshots``; **unknown names are rejected**
   * - ``allowedPlugins``
     - []
     - <= 256 names ``[A-Za-z0-9_.-]{1,64}``; applies when ``Plugins`` is disabled; matched case-insensitively
   * - ``storageMode``
     - ``file``
     - ``file`` or ``memory``
   * - ``watermark``
     - ""
     - <= 128 chars, shown in every file window title
   * - ``bestEffortScreenProtect``
     - true
     - see `8. Screen protection`_
   * - ``requireScreenProtect``
     - false
     - see `8. Screen protection`_
   * - ``telemetry.enabled``
     - false
     - nothing is collected or sent when false
   * - ``telemetry.flushIntervalSeconds``
     - 60
     - clamped to [5, 3600]
   * - ``telemetry.maxBatchEvents``
     - 500
     - clamped to [1, 5000]; the queue holds 4x this
   * - ``telemetry.idleThresholdSeconds``
     - 120
     - clamped to [10, 86400]
   * - ``telemetry.eventLevel``
     - true
     - false => counters only, no events
   * - ``submission.allowInTool``
     - true
     - false => Submit hidden
   * - ``submission.requireExplanation``
     - false
     - explanation mandatory for every problem
   * - ``submission.explanationMaxChars``
     - 2000
     - clamped to [0, 100000]
   * - ``notes``
     - absent
     - optional object; absent = server without course notes => no Notes UI
   * - ``notes.enabled``
     - false
     - false => "Course notes are disabled by your teacher", ``GetNotes`` is not called
   * - ``notes.maxChars``
     - 20000
     - clamped to [100, 100000]; ``GetNotes.maxChars`` (request time) replaces it once received
   * - ``contentEncryption``
     - ""
     - "" or ``aes-256-gcm-hkdf-v1``; **required** when ``storageMode=memory``
   * - ``contentKeyId``
     - ""
     - 16 lowercase hex; **required** with ``contentEncryption``

Digest: the server serialises the policy with ``"digest":""`` (compact separators, sorted keys), takes
``sha256`` of those bytes and embeds the hex value. The client verifies it by blanking the (unique) occurrence of
``"digest":"<hex>"`` (or ``"digest": "<hex>"``) in the received bytes and hashing the result. The digest must appear
exactly once.

Re-entrancy: a connect while a policy is in force validates the new policy completely; only a *valid* policy
replaces the current one (a different ``id`` emits ``policy_applied``). Failed reconnects and legacy answers leave
the current policy in force.

Implementation: ``GViewCore/src/Security/RestrictedMode.cpp`` (``VerifyAndParsePolicy``, ``Internal::Activate``
returning an ``ActivationReport``). The policy object is signed public data and is not page-locked; secrets are
(see below).

6. Content delivery
-------------------

Download response headers: ``X-GView-Delivery: memory|file`` (required in v2), ``X-GView-SHA256`` (hex of the plaintext,
required in v2), ``X-GView-Encrypted: 0|1``, ``X-GView-Filename`` (sanitised: base name only, no reserved device names,
no ``<>:"|?*`` or control characters, <= 128 chars), ``X-GView-Item-Version``.

Effective mode = most restrictive of ``policy.storageMode``, the catalogue ``deliveryMode`` and ``X-GView-Delivery``
(``memory`` wins). Legacy sessions always use memory mode (historic behaviour).

``aes-256-gcm-hkdf-v1``::

   key   = HKDF-SHA256(ikm = UTF8(accessToken), salt = UTF8(policy.id), info = "GView-Content-v1", L = 32)
   keyId = hex(sha256(key))[0:16]                     -> must equal policy.contentKeyId (checked before decrypting)
   aad   = UTF8(itemName) || 0x00 || UTF8(policy.id)
   blob  = "GVE1" || iv(12) || ciphertext || tag(16)

Rules: an encrypted blob requires an active policy; a memory delivery that is **not** encrypted is refused when the
policy declares ``contentEncryption``; the SHA-256 of the plaintext is verified in all v2 cases.

Memory mode: the blob is decrypted directly into a ``LockedBuffer`` (``VirtualAlloc`` + ``VirtualLock`` - the
working set is grown if needed - / ``mmap`` + ``mlock`` + ``MADV_DONTDUMP``), the HTTP buffers use an allocator that
zeroes memory before freeing it, and the viewer reads straight from the locked buffer through a read-only
``LockedMemoryDataObject`` (no ``MemoryFile`` copy). The buffer is wiped when the window closes. The window is bound
to the item; for memory items GView never reads or writes the disassembly cache, never exports, and skips WinTrust
(which would need the file on disk; the embedded OpenSSL signature check still runs).

Derived objects: GView does not track which window an in-memory object (``Object::Type::MemoryBuffer``, e.g. an entry
extracted from an archive) was opened from. While a memory item - or an object derived from one - is open, every new
in-memory object is therefore treated as memory-only as well (``LearningSession::OnObjectCreated``), until its own
window closes. Objects opened from disk are never affected.

Known residual plaintext copies (honest list): GView's ``DataCache`` chunk cache (up to ``CacheSize``, 10 MiB by
default, ordinary heap), parser/viewer-derived structures (strings, disassembly text, images), AppCUI screen buffers.
Pinning can fail silently (Windows working-set quota, Linux ``RLIMIT_MEMLOCK``); content is then still wiped but may
have been paged.

File mode
^^^^^^^^^

There is no Save dialog. A delivered file goes to ``<base>/<server>/<week>/<file>``: ``<base>`` is
``LearningDownloadFolder`` or ``<Documents>/GView``, ``<server>`` the host of the server URL (``course.example.edu``,
a port becomes ``_8443``), ``<week>`` the week name and ``<file>`` the delivered file name. Every component comes from
the server and is made safe for Windows, Linux and macOS (``SanitizePathComponent``: separators, ``<>:"|?*``, control
characters and invalid UTF-8 become ``_``; leading/trailing dots and spaces are dropped; device names such as ``CON``
get a ``_`` prefix; long names are cut on a UTF-8 boundary, keeping the extension).

Each week folder holds a manifest, ``.gview-items.json`` (hidden on Windows), mapping every item to its file and to the
SHA-256 of the version GView wrote (``TaskFiles.hpp``):

* a file name already owned by another item (compared case-insensitively) is prefixed with the item name
  (``p2-task.exe``); item names are unique on a server, so weeks whose names sanitize alike cannot collide either;
* opening an item whose local copy still hashes to the catalogue ``sha256`` opens that copy without a download;
* otherwise the item is downloaded and compared: same content - the local copy is opened; local copy unchanged since
  GView wrote it but the server has a new version - it is replaced; local copy changed (or a file GView did not write
  is in the way) - the student is asked whether to replace it with the server version or open it as it is.

Writes go to ``<name>.part``, are re-hashed from disk, then atomically moved into place
(``MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`` / ``rename``). Any failure removes the ``.part`` file.

Secrets: the access token is held in a ``SecureString`` (wiped allocator) and the content key in a ``LockedBuffer``;
both are erased by *End session* and at exit. libcurl's own copy of the header list is freed without wiping, the
connection field's text and the saved ``ServerConnectionString`` (which contains the token) remain - the latter is
stored in ``gview.ini`` in plain text, as before this work.

7. Feature enforcement matrix
-----------------------------

Every gate goes through ``GView::App::IsBlockedByPolicy`` (or ``IsExportBlockedFor(object, ...)``), which shows a
"Blocked by course policy" notice (at most once per 5 s per feature) and records ``feature_blocked``. Commands are
also hidden from the command bar where GView builds it. Under a ``memory`` storage policy, ``Export`` and ``SaveAs``
are restricted even if not listed.

============== =========================================================================================================
Feature        Gated locations
============== =========================================================================================================
Copy           ``FileWindow::ShowCopyDialog`` (Ctrl+C / Ctrl+Insert in every viewer);
               ``BufferViewer::Instance::ShowCopyDialog``; ``TextViewer::Instance::ShowCopyDialog``;
               ``DissasmViewer::Instance::ShowCopyDialog``; all clipboard writes via ``GView::App::SetClipboardText``
Clipboard      ``GView::App::SetClipboardText`` (BufferViewer ``CopyDialog``, TextViewer, DissasmViewer, Hashes generic
               plugin MD5/SHA256 copy, learning link dialog - the Copy button is disabled)
Export         GridViewer export cell/column (hidden + gated); ``DissasmViewer::CommandExportAsmFile``;
               ``DissasmViewer::SaveCacheData``/``LoadCacheData`` (skipped); Dropper generic plugin; PE
               ``Resources::SaveCurrentResource``; ``GView::App::DropToTemporaryFile`` (silent: no notice, no
               ``feature_blocked``; used by the PE ``DigitalSignature`` WinTrust copy and by ZIP for nested archives
               larger than the cache); PDF
               ``ExtractAndSaveTextWithDialog``; JS ``AST::DumpVisitor`` debug dumps
SaveAs         ``LexicalViewer::Instance::ShowSaveAsDialog`` (hidden + gated; memory items also blocked)
Plugins        runtime filter in ``Instance::IdentifyTypePlugin_FirstMatch/BestMatch/WithSelectedType``,
               ``SelectTypeDialog::PopulateTypes``, final check in ``Instance::Add`` (falls back to the default viewer);
               generic plugins hidden in ``Instance::UpdateCommandBar`` and refused in ``Instance::OnEvent``
LLMHints       ``SmartAssistantPromptInterfaceProxy::AskSmartAssistant`` (single choke point for every prompt); the Smart
               Assistants tab is not created for new windows
Screenshots    see `8. Screen protection`_
Watermark      ``FileWindow::RefreshTitle`` ("<name> - <watermark>") for new and already open windows
============== =========================================================================================================

What remains possible: see `1. Overview and threat model`_ and `Limitations`_.

8. Screen protection
--------------------

Protection is *requested* when ``bestEffortScreenProtect`` or ``requireScreenProtect`` is true or ``Screenshots`` is
disabled. It is *applied* when capture exclusion succeeds on at least one GView-owned window.

=============================== ======================================================================================
Platform / frontend             Behaviour
=============================== ======================================================================================
Windows, SDL frontend           ``SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`` (fallback ``WDA_MONITOR``) on
                                every visible top-level window of the process => applied. PrintScreen and Win+Shift+S
                                are blocked by a low-level keyboard hook running on its own message-pumping thread.
Windows, console frontend       The console window belongs to conhost/Windows Terminal, so capture exclusion cannot be
                                applied => **not applied**; the keyboard hook is still installed.
Linux                           No capture-exclusion API; only ``PR_SET_DUMPABLE=0`` => not applied.
macOS                           Not implemented for the terminal frontend => not applied.
=============================== ======================================================================================

``requireScreenProtect=true`` and not applied => session state *Error*, tasks cannot be opened, the window explains
the platform limitation and ``screen_protect_failed{reason:"unsupported_platform"}`` is recorded. Everything is
reverted on deactivation (hook thread stopped, affinity reset).

9. Telemetry
------------

Only windows opened from the course catalogue produce item events. Batches are posted by a background thread every
``flushIntervalSeconds`` and immediately after ``submit``, ``task_close`` and ``policy_applied``; at exit
``session_end`` is flushed synchronously with a 2 s cap.

Batch::

   { "sessionId": "<uuid4, one per session, kept across reconnects>", "policyId": "...", "policyDigest": "...",
     "clientVersion": "0.390.0", "platform": "windows-x64", "sentAt": 1759403100,
     "events": [ { "seq": 1, "t": 1759401000, "type": "task_open", "item": "w1_stack_var", "itemVersion": 3, "mode": "memory" } ],
     "counters": { "w1_stack_var": { "jump_follow": 12, "...": 0, "viewer_open": {"Dissasm": 1}, "feature_blocked": {"Copy": 1} } } }

Event whitelist (any other field, or an ``item`` on an event that does not allow it, is refused by the client):

========================= ====== ===============================================
Event                     item   fields
========================= ====== ===============================================
``session_start``         no     -
``session_end``           no     ``reason`` (``exit``, ``user``, ``policy_expired``, ``policy_ended``)
``policy_applied``        no     ``mode``
``policy_rejected``       no     ``reason`` (a ``POLICY_*`` code)
``task_open``             yes    ``itemVersion``, ``mode``
``task_close``            yes    -
``resource_open``         yes    ``itemVersion``, ``mode``
``viewer_open``           yes    ``viewer`` (Buffer, Text, Lexical, Image, Grid, Dissasm, Container, Other)
``jump_follow``           yes    ``from``, ``to`` (``0x..`` hex), ``kind`` (mnemonic, ``[a-z0-9.]{<=15}``)
``jump_back``             yes    -
``jump_forward``          yes    -
``goto_entrypoint``       yes    -
``goto_dialog``           yes    -
``comment_add``           yes    -
``comment_edit``          yes    -
``comment_remove``        yes    -
``label_rename``          yes    -
``note_add``              yes    - (a note was started in a course window: Ctrl+F11; never its text)
``idle``                  yes    ``seconds``
``feature_blocked``       yes    ``feature``
``submit``                yes    ``clientSubmissionId``
``client_error``          no     ``message`` (constant strings from GView code), ``fatal``
``screen_protect_failed`` no     ``reason``
========================= ====== ===============================================

Counters (totals since session start, per item; the server replaces them): ``jump_follow``, ``jump_back``,
``jump_forward``, ``goto_entrypoint``, ``goto_dialog``, ``comment_add``, ``comment_edit``, ``comment_remove``,
``label_rename``, ``note_add``, ``idle_seconds``, ``active_seconds``, ``dissasm_seconds`` and the maps ``viewer_open``
and ``feature_blocked``.

Activity model: GView repaints only in response to input, so a repaint of a file window is the activity signal.
Idle starts when no activity happened for ``idleThresholdSeconds``; one ``idle{seconds}`` event is recorded when
activity resumes. Active and Dissasm seconds accrue while a course window has focus and the user is not idle.

Delivery: ``seq`` is monotonic per ``sessionId`` and preserved across retries (the server de-duplicates on
``(sessionId, seq)``). ``2xx`` => removed; ``429``/``5xx``/network error => kept and retried at the next flush;
any other ``4xx`` => dropped. The queue holds ``maxBatchEvents x 4`` events (oldest dropped). A ``403
POLICY_EXPIRED`` on telemetry expires the session. Batches stay below 900 KiB.

Privacy: never sent - comment text, label names, note contents, clipboard content, keystrokes, file paths, user
files opened outside the catalogue, screenshots. ``telemetry.enabled=false`` or no policy => nothing is recorded and
no thread runs. ``policy_rejected`` is only ever sent when a previously verified policy with telemetry enabled is in
force (a rejected policy cannot grant consent).

10. Submission
--------------

Body (``application/json``)::

   { "problem": "w1_stack_var", "flag": "3", "explanation": "...", "clientSubmissionId": "<uuid4>",
     "policyId": "pol_...", "policyDigest": "...", "clientVersion": "0.390.0", "clientTime": 1759403000 }

* The flag is trimmed, must be non-empty and <= 512 bytes; the explanation is required when the policy or the
  problem requires it and is limited to ``explanationMaxChars``.
* ``clientSubmissionId`` is a UUIDv4 created once per *new answer* (problem + flag + explanation fingerprint). A retry
  after a transport failure, 408, 429 or 5xx reuses it; any answer from the server that grades or refuses the attempt
  consumes it, so the next submission is a new attempt; editing the answer creates a new id.
* ``submit{clientSubmissionId}`` telemetry is recorded and a flush requested.
* Response: ``correct``, ``points``, ``attempts``, ``alreadySolved``, ``duplicate``, ``details``, ``totalScore`` are
  shown. ``409 ALREADY_SOLVED`` is informational. ``403 POLICY_EXPIRED`` expires the session.
* Legacy servers (no ``correct`` field): ``correct = (status == "ok")``.
* UI: catalogue *Submit flag* button, or Ctrl+Alt+F (``Key.LearningSubmitFlag``) in a task window.

11. Catalogue model
-------------------

``GetWeeks`` is parsed defensively: weeks/items with ``enabled:false`` are hidden (the server should never send
them), items with invalid names, unknown ``kind``/``deliveryMode`` or non-http(s) links are dropped and counted
("N entries hidden"), duplicates are dropped, strings are capped and control characters removed. Weeks are sorted by
``order`` then ``id``; items by ``order`` then ``name``. ``kind``: ``file`` and ``text`` are downloaded (text opens in
the Text/Lexical viewer), ``link`` shows the URL read-only (Copy only if ``Clipboard`` is allowed).

Legacy servers: ``/GView/`` with an empty 200 => *Legacy* state: no restrictions are applied (there is nothing to
verify), the catalogue comes from the flat ``GetProblems`` list as a single week, submissions use the legacy verdict.
The window says so explicitly.

12. Session state machine
-------------------------

::

     Disconnected --Connect--> Connecting --verified policy------------> Active --endsAt+120s / POLICY_EXPIRED--> Expired
          ^                        |  \--legacy (empty 200)-------------> Legacy  (catalogue + submit, no restrictions)
          |                        \---any failure (no policy yet)-----> Error   (no task can be opened)
          |                Active --requireScreenProtect unmet--> Error (restrictions applied, tasks blocked)
          |                Active/Expired/Error --Reconnect--> Connecting (current policy stays in force until a newer validates)
          +--End session (only when no learning window is open) / exit-- any state

Expired keeps the restrictions applied (already open windows stay protected); downloads and submissions are refused;
one final ``session_end`` is flushed and flushing stops.

13. Verification
----------------

Environment: Windows 11 Enterprise 10.0.26200, MSVC 19.44 (VS 2022 17.14), Debug, Catch2 3.10.0, OpenSSL 3.5.2,
libcurl 8.16.0 (OpenSSL backend), Python 3.11.9 + cryptography 50.0.1 for the stub server.

==== ========================================================================================== ========================
Case Tests (``GViewCore/src/Security/Learning/tests_learning.cpp``)                              Result
==== ========================================================================================== ========================
T1   ``session connect T1 (valid policy)``, ``policy verification`` (valid), ``encrypted memory     passed
     download through the session``, E2E ``end-to-end against the stub server``
T2   ``policy verification`` (tampered byte, wrong key, missing key), ``session rejects invalid     passed
     policies``, E2E ``hostile stub server`` (``--tamper-policy``)
T3   ``policy verification`` (expired, not started, skew), ``POLICY_EXPIRED from the server =>      passed
     Expired``, E2E unknown/disabled item => ``NOT_FOUND``
T4   ``policy activation and enforcement state (T4)`` (every feature flag, whitelist,               passed (state); entry
     re-entrancy); headless UI script: Ctrl+C in a task window => "Blocked by course policy"        points by review + UI
T5   ``content encryption round trip``, ``download processing`` (no file in CWD/TEMP, key-id        passed
     mismatch, unencrypted refusal, SHA mismatch), ``file mode atomic write``, ``locked buffer
     hygiene``, E2E (Python-encrypted blobs), hostile E2E (``--corrupt-blob``)
T6   ``idempotency keys``, ``submission flow and idempotent retries``, E2E ``duplicate:true``      passed
T7   ``telemetry known sequence (T7)``, ``telemetry contract table``, E2E de-duplication             passed
T8   ``telemetry whitelist, bounds and flush outcomes`` (network failure keeps events),            passed
     ``reconnect re-validates``, ``requireScreenProtect unsupported => refusal``
N    Course notes: ``policy notes object``, ``note text helpers``, ``note request bodies``,         passed
     ``GetNotes parsing``, ``note error mapping``, ``notes availability follows the policy``,
     ``notes autosave``, ``notes network errors retry the same request``, ``notes 409 keeps the
     server copy and the local text``, ``notes 403 hides the Notes UI``, ``notes 404, refusals and
     deletion``, ``notes are saved at session end``, ``notes conflicts left unresolved, deletions
     and GetNotes failures``, ``notes of another account are dropped``,
     ``course notes of the teacher``, ``note text never reaches telemetry or the disk``; E2E
     ``course notes end-to-end against the stub server`` (student, ``--staff``,
     ``--notes-forbidden``, ``--notes off``)
==== ========================================================================================== ========================

Totals on this machine (course notes, 2026-11-08, RelWithDebInfo): ``libGViewCore.exe "[learning]"`` runs 52 cases (49
unit cases + the three hidden end-to-end cases, which skip without a stub server), 1260 assertions pass; against
four stub servers (default, ``--staff``, ``--notes-forbidden``, ``--notes off``) ``"[integration]"`` passes 2 cases / 122
assertions; the full ``ctest`` suite (324 tests) passes; the WebAssembly build of ``GViewCore`` compiles. Cross-implementation vectors (`Test vectors`_) are asserted by
``cross-implementation test vectors``.

How to reproduce::

   cmake -S . -B build-test -DENABLE_TESTS=ON && cmake --build build-test --config Debug
   ctest --test-dir build-test -C Debug
   python tools/learning_mode_stub_server.py --quiet --require-explanation      # prints the connection string
   set GVIEW_LEARNING_STUB_CS=<printed connection string>
   rem optional, course notes variants (each on its own --port):
   rem   --staff => GVIEW_LEARNING_STUB_STAFF_CS, --notes-forbidden => GVIEW_LEARNING_STUB_FORBIDDEN_CS,
   rem   --notes off => GVIEW_LEARNING_STUB_NOTES_OFF_CS
   bin\Debug\libGViewCore.exe "[integration]"

Manual check of the UI: ``GView learn <connection string printed by the stub>``.

Test vectors
~~~~~~~~~~~~

The stub key is derived from a public seed and is **for tests only**.

========================= ================================================================================
Input / output            Value
========================= ================================================================================
token                     ``tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd``
subject                   ``f1988ba4bd709819``
content key (pol id       ``7e6629f6db625710f19a7c0bdac5dd6881699b65aa8a90659966bd24539c35fb``
``pol_2026w1_ab12cd``)
contentKeyId              ``4ae23e4dafdc826d``
AAD (item                 ``77315f737461636b5f76617200706f6c5f3230323677315f616231326364``
``w1_stack_var``)
public key                ``7fd806c7f2a9e88ec89bb6cca8ba6a2b4b225aa85e488e8222be9dc2acadf094``
========================= ================================================================================

Signed policy (``serverUrl`` ``https://re.example.edu``, verified at ``now = 1759400000``)::

   {"allowedPlugins":[],"bestEffortScreenProtect":true,"digest":"5e6a9108d33760ebce5fc15585d40a7081d3eddaaa743eab771d0e535039eff8","disabledFeatures":["Copy","Export"],"endsAt":1760004800,"id":"pol_2026w1_ab12cd","issuedAt":1759400000,"purpose":"Evaluation week 1","requireScreenProtect":false,"schema":2,"serverUrl":"https://re.example.edu","startsAt":1759399880,"storageMode":"file","subject":"f1988ba4bd709819","submission":{"allowInTool":true,"explanationMaxChars":2000,"requireExplanation":false},"telemetry":{"enabled":true,"eventLevel":true,"flushIntervalSeconds":60,"idleThresholdSeconds":120,"maxBatchEvents":500},"watermark":"Student 17"}

   signature (base64) = LnnH52/44aGmbhfBVmmv7LwdQoUSTaNppaRMhuE4W4tBy0rKPLyUIbVAlUa2Jw/cuy3jjOSjIkWPkFzbPNdWBQ==

Limitations
~~~~~~~~~~~

* **AppCUI controls write to the clipboard on their own** (Ctrl+C in ``ListView``/``TreeView``/``Grid`` panels,
  ``TextField``/``TextArea`` selections, theme editor, window manager notes) through ``AppCUI::OS::Clipboard`` and
  are not gated, because the AppCUI submodule was not modified. Paste is not blocked either. Proposed upstream fix: a
  process-wide clipboard policy callback in ``AppCUI::OS::Clipboard`` (``SetText``/``GetText`` consult it), installed
  by GView on activation.
* Screen capture cannot be prevented on the Windows console frontend, Linux or macOS (`8. Screen protection`_).
* Frontends without frame updates (ncurses on Linux/macOS) run network operations synchronously on the UI thread,
  bounded by the timeouts above. GView enables AppCUI's FPS mode so that the Windows console and SDL frontends
  deliver ``OnFrameUpdate`` (~30 Hz, no repaint unless something changed); on those frontends the automatic connect
  when the Learning window opens is deferred to its first frame so that it runs on the worker.
* Idle/active time is derived from repaints (approximation).
* ``Retry-After`` is shown to the user but telemetry retries simply wait for the next flush interval.
* Plugins outside GViewCore can still write files through code paths not listed in the matrix; the plugin
  whitelist (``Plugins`` + ``allowedPlugins``) is the control for those (e.g. ``FileDownloader``).
* Residual plaintext copies and secrets: see `6. Content delivery`_.

14. Deviations from the protocol spec
-------------------------------------

All of these are additional strictness or clarifications; ``plans/LEARNING_MODE_PROTOCOL_SPEC.md`` was updated.

1. Extra validation step ``POLICY_SERVER_MISMATCH``: a non-empty ``serverUrl`` must equal the connection string's
   server (scheme/host case-insensitive, trailing ``/`` ignored).
2. Course-server policies must be ``schema: 2`` (schema 1 is only accepted by the file-based ``LoadPolicyFromFiles``).
3. ``storageMode: memory`` requires ``contentEncryption`` and ``contentKeyId``; ``contentEncryption`` requires
   ``contentKeyId``; present fields with wrong JSON types are rejected (fail closed).
4. Unencrypted ``memory`` deliveries are refused when the policy declares ``contentEncryption``; ``X-GView-SHA256``
   and ``X-GView-Delivery`` are mandatory in protocol 2.
5. Telemetry: explicit per-event field whitelist (table above); ``note_add`` counter; ``eventLevel:false`` means
   counters only; item events only for catalogue windows; ``policy_rejected`` only with prior consent.
6. Screen protection is requested by ``bestEffortScreenProtect`` *or* ``requireScreenProtect`` *or* a disabled
   ``Screenshots`` feature.
7. Under a ``memory`` storage policy ``Export`` and ``SaveAs`` are restricted for every object.
8. Telemetry numeric parameters and ``explanationMaxChars`` are clamped to the ranges listed in `5. Policy (schema 2)`_.
9. Redirects are never followed; ``caPem`` replaces (does not extend) the system trust store.
10. Item names must match ``[A-Za-z0-9_-]{1,64}`` (Django ``SlugField`` compatible).
11. ``/GView/Heartbeat`` is not used by the client.
12. Course notes: the clarifications listed in `18. Course notes`_ (*Clarifications of spec §10.11*).
13. Course work and solutions: the clarifications listed in `19. Work documents, solutions and the replay journal`_
    (*Clarifications of spec §10.12*).

15. Open questions for the server implementer
---------------------------------------------

0. Browser clients need CORS and a platform-aware policy: see `16. Browser clients`_.

1. Please make sure ``policy.serverUrl`` is exactly the URL put in connection strings (otherwise use an empty
   ``serverUrl``) - the client rejects mismatches.
2. Accept the ``note_add`` counter and the ``reason`` values listed for ``session_end``.
3. Should ``eventLevel:false`` also suppress session lifecycle events server-side? The client sends counters only.
4. The client treats any ``4xx`` except ``408``/``429`` on ``SubmitFlag`` as consuming the idempotency key (e.g. a
   ``400`` for a missing explanation). Confirm the server does not store a ``Submission`` row in that case.
5. Confirm that a protocol-2 download of a ``kind=link`` resource is never needed (the client uses the catalogue URL).
6. Legacy flat ``GetProblems`` items carry no ``deliveryMode``/``sha256``; for v2 clients please always serve
   ``GetWeeks``.
7. Course notes: ``SaveNote`` re-sends the scope on every save, so a note attached to an item that was hidden later
   gets ``404`` on every edit. Could the server accept an *unchanged* scope on an update (the note keeps its scope, as
   §10.11 says), or answer ``ITEM_DISABLED`` so the client can tell it from an unknown note id?
8. Course notes: ``maxChars`` can be 100000 characters, but ``SaveNote`` bodies are capped at 256 KiB; 100000
   characters of non-ASCII text (2-4 bytes each in UTF-8) do not fit. The client refuses such a save locally with an
   explicit message; please raise the body cap to at least ``4 x maxChars + 4 KiB`` (or document the byte limit).

16. Browser clients
-------------------

GView also runs inside a web page (``docs/source/wasm.rst``, ``GVIEW_ENABLE_BROWSER_NETWORK``, ON by default for the
WebAssembly build). The protocol is unchanged; the transport and the platform are different.

**Transport.** A page has no sockets: requests go through ``fetch()`` (``LearningHttpFetch.cpp``) and the browser owns
TLS. The desktop rules map as follows:

=================================== ====================================================================================
Desktop (libcurl)                   Browser (fetch)
=================================== ====================================================================================
``VERIFYPEER``/``VERIFYHOST``,      enforced by the browser (a page can not skip certificate validation)
TLS >= 1.2
``https`` only (localhost http      ``CheckTransportRequirements``: ``https://`` only; ``http://`` only when the page itself
exception)                          is served from the local machine *and* ``LearningAllowPlainHttpLocalhost=true``
redirects never followed            ``redirect: "error"``
``caPem`` as the only trust anchor  **impossible** - the browser always uses the system store. A connection string with
                                    ``caPem`` is refused before any request (fail closed), never widened silently
response caps, timeouts, cancel     ``Content-Length`` check + counting stream reader, ``AbortController``
-                                   ``credentials: "omit"``, ``referrerPolicy: "no-referrer"``, ``cache: "no-store"``;
                                    the page CSP allows ``connect-src`` to ``https:`` (and the loopback for development)
=================================== ====================================================================================

**CORS (server side, required).** Every endpoint answers the ``OPTIONS`` preflight of the allowed GView web origins
(exact origins, e.g. the GitHub Pages site or the self-hosted one; no ``*`` is needed since no cookie is sent):

::

   Access-Control-Allow-Origin:   <origin of the GView page>      (and Vary: Origin)
   Access-Control-Allow-Methods:  POST
   Access-Control-Allow-Headers:  XAppUserID, X-GView-Client, X-GView-Protocol, X-GView-Policy, X-GView-Platform,
                                  Content-Type, Accept
   Access-Control-Expose-Headers: X-GView-Delivery, X-GView-SHA256, X-GView-Encrypted, X-GView-Filename,
                                  X-GView-Item-Version, Retry-After, Content-Length
   Access-Control-Max-Age:        600

Without ``Expose-Headers`` the delivery headers are invisible to the page and every download is refused (they are
mandatory in protocol 2). ``tools/learning_mode_stub_server.py --cors-origin <origin>`` implements all of this.

**Platform-aware policies (server decides, client fails closed).** Every request carries
``X-GView-Platform: web-wasm32``. A page can not exclude itself from screen capture, can not pin memory and is open to
the developer tools of the browser, so:

* ``requireScreenProtect`` is never met in a browser: the session goes to *Error* and no task can be opened (as on the
  other platforms without capture exclusion);
* ``LockedBuffer`` reports ``IsLocked() == false`` (the memory of the page is a JavaScript ``ArrayBuffer``): memory
  mode still decrypts in place, wipes on close and never touches the file system, but cannot prevent paging;
* the server may issue a dedicated policy for ``web-wasm32`` (e.g. ``bestEffortScreenProtect: false``), refuse with
  ``426 UNSUPPORTED_CLIENT``, or keep the same policy and accept the weaker guarantees.

**No threads.** A page has none (they would need COOP/COEP headers). A network job runs on the UI thread and is
re-run from the start each time one of its responses arrives (``JobReplay.hpp``, ``BackgroundWorkerWasm.cpp``); the
side effects before a request (a telemetry batch) run once. The UI keeps running while requests are in flight;
*End session* aborts the request in flight. Telemetry is flushed every ``flushIntervalSeconds`` from the session tick,
and once more when the page is hidden; at *End session* the last batch is sent with ``keepalive`` without waiting for
the answer. A tab in the background is throttled by the browser (down to one timer per minute after a few minutes),
so its network jobs complete only when it becomes visible again.

**Secrets at rest.** ``ServerConnectionString`` is not stored in ``GView.ini`` by the web build (the page keeps
``GView.ini`` in clear in its ``localStorage``): it is kept AES-GCM encrypted by the persistent storage of the page,
under a non-extractable key (*File > Stored files > Forget Learning connection*). Learning task files saved in
``file`` mode land in the home folder and are kept like any other file; ``memory`` content is never written to the
file system and therefore never stored.

17. One-click launch of the web build
-------------------------------------

The course portal can open the web build already connected: the student presses *Open GView in the browser* and
pastes nothing. The connection string is never put in a URL (it holds a long-lived bearer token, and URLs end up in
the history, history sync and screenshots). The URL carries a **one-time launch code** instead, which the page
exchanges for the connection string. Desktop builds are not concerned: the portal still shows them the connection
string, and ``GView learn <connectionString>`` is unchanged.

**Launch URL.** The portal redirects the student to::

   <GView page URL>#launch=<code>&server=<url-encoded base URL of the course server>

=========== ============================================================================================================
Parameter   Format
=========== ============================================================================================================
``launch``  ``^[A-Za-z0-9_-]{32,64}$`` (one-time code; anything else and the whole launch is refused as invalid)
``server``  absolute ``https://`` URL; ``http://`` only to ``localhost``/``127.0.0.1``/``[::1]`` and only when the page
            itself is served from the local machine (same rule as ``PageIsServedLocally``). No user info, query or
            fragment. Endpoint = ``server`` (trailing ``/`` removed) + ``/GView/WebLaunch``
=========== ============================================================================================================

Unknown parameters are ignored. The fragment is never sent to the web server that hosts GView.

**Endpoint.** ``POST <server>/GView/WebLaunch`` with ``Content-Type: application/json``, ``X-GView-Protocol: 2``,
``X-GView-Client: <version>``, ``X-GView-Platform: web-wasm32`` and the body ``{"code": "<launch code>"}``; no
``XAppUserID`` (the code is the credential). ``fetch`` options: ``credentials: "omit"``, ``cache: "no-store"``,
``redirect: "error"``, ``referrerPolicy: "no-referrer"``. The server answers the CORS preflight like every other
endpoint, for its allowed GView origins only (any other origin, or no ``Origin``: ``403 FORBIDDEN``).

============================================== ==========================================================================
Answer                                         Client
============================================== ==========================================================================
200 ``{"status":"ok","connectionString":...}`` continue with the connection string (below)
401 ``UNAUTHORIZED``                           "This launch link has expired or was already used. Open GView again from
                                               the course page."
403 ``FORBIDDEN``                              the ``details`` of the server (this page's origin is not allowed)
426 ``UNSUPPORTED_CLIENT``                     "The course server requires a newer GView version ..."
429 ``RATE_LIMITED``                           "Too many attempts, wait N s ..." (``Retry-After``)
5xx, network error, timeout                    a generic error that says to open GView again from the course page
============================================== ==========================================================================

The code is single use and expires 5 minutes after the click: the request is **never retried** automatically (a lost
answer may already have consumed it). A new code is obtained by opening GView again from the course page.

**Page (``gview-page.js``), before GView starts.**

1. If the fragment has a ``launch`` parameter, it is removed at once with ``history.replaceState`` - whatever the
   values - so a reload, a bookmark or the history never carry the code.
2. ``launch`` and ``server`` are validated; an invalid link is reported as such and **nothing is sent**.
3. The ``WebLaunch`` request starts immediately, in parallel with the download of ``GView.wasm`` (several MB).
4. The outcome is published in ``globalThis.gviewLaunch`` (``state``: ``none``/``pending``/``ok``/``error``/``taken``,
   ``serverOrigin``, ``connectionString``, ``error``, ``done``). GView polls it from its frames without blocking and
   the page empties ``connectionString`` as soon as GView has taken it.

The code and the connection string are never written to the console, the status bar, ``localStorage`` or
``sessionStorage``.

**GView (``App/BrowserLaunch.cpp``, ``RunLearningLaunch`` in ``App/LearningModeWindow.cpp``),** once the persistent
storage is restored, the outcome is known and no modal window is open:

1. The connection string is validated with the same parser and checks as a pasted one, and must be version 2 with
   the policy public key; the origin of its server URL must equal the origin the code was redeemed at
   (``ValidateLaunchConnectionString``). Otherwise nothing is connected.
2. **Trust prompt, once per server origin and browser:** *"Connect to the course server <host>? Only continue if you
   opened GView from your course page."* [Connect] [Cancel]. *Connect* adds the origin to
   ``[GView] LearningTrustedLaunchOrigins`` (not secret; kept with the other settings); later launches from that
   origin connect without asking. This keeps a crafted link (``#launch=x&server=https://attacker``) from silently
   pointing GView at another server on a deployment whose page CSP allows any ``https:`` server.
3. **Another connection is replaced.** If a session with another server or token is active, it is ended like *End
   session* does (``session_end`` with reason ``user``, its pending telemetry sent with **its own** token, restrictions
   removed). A different stored connection string is forgotten.
4. The connection string is connected exactly as if it had been pasted into *Options > Learning and Evaluation Mode*,
   whose window opens on the connection and the catalogue.
5. It is stored (encrypted secret ``learning.connectionString``) only after a successful, verified connect - so a
   reload reconnects like after a paste, when the Learning and Evaluation Mode window is opened.
6. Any error opens that window with the message above and an **empty** connection field, so the string can still be
   pasted by hand; a connection string stored before is left untouched.

Test server: ``tools/learning_mode_stub_server.py --launch-code <code>`` answers ``/GView/WebLaunch`` once and with
``401`` afterwards (``--launch-token`` another student, ``--launch-server-url`` a connection string for another server,
``--launch-delay-ms`` a slow answer). For a page served locally::

   python tools/learning_mode_stub_server.py --http --cors-origin http://127.0.0.1:8765 --launch-code <code>
   # page setting: [GView] LearningAllowPlainHttpLocalhost = true, then open
   # http://127.0.0.1:8765/GView.html#launch=<code>&server=http%3A%2F%2F127.0.0.1%3A8443

Without ``--cors-origin`` the request is refused (403), and in its default TLS mode the stub hands out a connection
string with ``caPem``, which the web client refuses.

18. Course notes
----------------

Students write private notes in GView while they analyse a task; the course server keeps them and returns them only to
their owner. Teachers write *course notes* (for every student or one lab group, ``G1``/``G2``) that students read in
GView. A note is general or attached to one week, problem or resource by name (spec §10.11). Implementation:
``GViewCore/src/Security/Learning/LearningNotes.{hpp,cpp}`` (wire format, sync model), ``LearningSession`` (requests,
autosave pump), ``GViewCore/src/App/LearningNotesWindow.cpp`` (UI).

**Availability.** The optional policy object ``"notes": {"enabled": bool, "maxChars": int}`` decides at connect time:

=============================== ========================================================================================
State                           Client behaviour
=============================== ========================================================================================
no ``notes`` object (or no      no Notes UI at all (a server without notes); Ctrl+F11 keeps the local note of the window
policy, legacy server)
``enabled: false``              "Course notes are disabled by your teacher"; ``GetNotes`` is never called
``enabled: true``               ``GetNotes`` right after Connect and each time the Notes window opens
``403 FORBIDDEN`` on            the Notes UI is hidden ("Course notes are disabled by your teacher") until the next connect;
``GetNotes``/``SaveNote``/      nothing more is sent; unsaved text stays in memory and is saved after a reconnect that
``DeleteNote``                  finds notes on again (until *End session* / exit, which erase it)
=============================== ========================================================================================

**Endpoints as implemented** (same headers and transport rules as every other call; no new request header, so the
browser build needs no CORS change):

::

   POST /GView/GetNotes        {}
     <- {"status":"ok","maxChars":20000,"serverTime":..,"canEditTeacherNotes":false,
         "mine":[{"id":"<uuid>","title","body","scope":{..},"revision":3,"createdAt":..,"updatedAt":..}],
         "teacher":[{"id":12,"title","body","scope":{..},"audience":"all"|"G1"|"G2","updatedAt":..
                     [, "enabled","order","revision","createdAt" for course staff]}]}
   POST /GView/SaveNote        {"id":"<uuid4>","title","body","scope":{"kind":"general"}
                                | {"kind":"week"|"problem"|"resource","name":".."}[, "revision":<last seen>]}
     <- {"status":"ok","id","revision","updatedAt","created"}
   POST /GView/DeleteNote      {"id":"<uuid>"}                                   <- {"status":"ok"}
   POST /GView/SaveTeacherNote {["id":<int>, "revision":<int>,] "title","body"
                                [, "scope", "audience", "enabled", "order"]}     <- same as SaveNote, integer id
   POST /GView/DeleteTeacherNote {"id":<int>}                                    <- {"status":"ok"}

Parsing is defensive: the answer must be a JSON object with ``status`` ``ok``; ``maxChars`` is clamped to
[100, 100000]; student notes need an id ``[A-Za-z0-9_-]{1,64}`` and a ``revision >= 1``, teacher notes an integer
``id >= 1`` (others are dropped and counted); duplicates are dropped; a missing, ``null``, unknown or invalid scope is
*general*; titles are single-line (control characters => spaces, <= 200 characters), bodies keep ``\n`` and ``\t``
(``\r`` removed, other control characters => spaces, <= 100000 characters); at most 2000 entries per list; the
answer is capped at 32 MiB (save/delete answers 64 KiB). Scope names sent by the client: item names
``[A-Za-z0-9_-]{1,64}``, week names 1..256 characters without control characters.

**Sync of the student's notes** (``NotesSync``, memory only):

* A note gets its UUIDv4 when it is created locally (*New note*, or Ctrl+F11 in a task window without a note for that
  item) and keeps it for its lifetime. A new note nobody typed into is not sent; it is created on the server with its
  first text.
* Autosave: about 2 s after the last keystroke (debounce, never one request per keystroke), when the Notes window
  closes, on *Save now*, and at *End session* / exit (bounded: 2 s per request, 5 s in total). Each note has at most
  one request at a time; the request carries the last ``revision`` the server returned (omitted for a create) and the
  answer's ``revision`` is stored. The session tick (run from every frame of the desktop) drives the autosave,
  the retries and their answers also while the Notes window is closed. Frontends without frame updates (ncurses)
  save on close, on *Save now* and at session end only.
* *End session* / exit / switching to another account: a conflict that is still waiting for its ``GetNotes`` turns
  the local text into a ``"(local copy)"`` note and notes the server refused get one more attempt; then the notes
  are wiped. Text that still cannot be sent (no network, notes turned off) is lost with the session, and *End
  session* warns about it beforehand.
* Before sending: ``\r\n``/``\r`` => ``\n``, NUL removed, title normalised as above. A body longer than ``maxChars``
  characters, or a request above 256 KiB, is not sent; the editor says so and the text stays.
* Network errors, ``408``, ``429`` (``Retry-After`` honoured), ``5xx`` and malformed ``2xx`` answers: the *same*
  request is sent again later (back-off 2, 4, 8 .. 60 s). Creates and updates are idempotent on the server, so a
  retry after a lost answer is answered ``200``; text typed in the meantime is sent afterwards, with the revision that
  answer returned.
* ``409 CONFLICT``: ``GetNotes`` is fetched again; the server copy replaces the note, and the local text - unless it is
  identical - becomes a new note ``"<title> (local copy)"`` with the same scope (created right away). The student is
  told. Nothing is overwritten silently.
* ``404``: the note is unknown (deleted elsewhere) or its week/item is not visible. ``GetNotes`` is fetched again; if
  the note is gone it is created again right away. Otherwise (or if that create is refused for its scope) the editor
  shows the error and nothing is retried until the note is edited or its scope changed.
* A ``GetNotes`` that fails with a retryable error is retried with the same back-off; any other failure is shown in
  the window and retried only by *Refresh* or the next opening of the window.
* Other refusals (``400`` validation, ``413``, ``401``, ...): the server's ``details`` are shown; no retry until the
  next edit.
* ``403 POLICY_EXPIRED``: the session expires (`12. Session state machine`_); notes are not sent while the session
  is not *Active*.
* ``GetNotes`` merge: notes without local changes take the server copy; notes with unsaved changes keep the local text
  (the next save meets the revision check); notes deleted elsewhere disappear unless they have unsaved text, which is
  then created again.
* Deleting a note sends ``DeleteNote`` (``404`` = already gone); a note that never reached the server is just dropped.
* A connect with another account or server first makes one last bounded attempt to save unsaved text to the account
  it belongs to, then wipes the notes in memory: text of one account is never sent to another. *End session* and exit
  wipe them too (strings are zeroed).

**Course-staff editor.** Shown only when ``canEditTeacherNotes`` is true: create, edit, enable/disable, order,
audience (``all``/``G1``/``G2``), scope and delete course notes. Saves are explicit (*Save course note*): an update
sends the revision of the listed note; ``409`` reloads the list and keeps the teacher's text in the editor, so saving
again replaces the server version on purpose. Teacher creates are not retried automatically (the id is
server-generated, a retry could duplicate the note); after a network error the teacher saves again. A ``403`` on a
teacher endpoint only removes the teacher editor (the token is not course staff); student notes stay.

**Notes window** (*Notes* button of the Learning window, or Ctrl+F11 in a task window opened from the catalogue):
"My notes" (the notes of the open item first, highlighted) and "Course notes" grouped by scope (the open item first,
then general, then each week/item); hidden course notes are listed greyed out for staff only. The editor has a title,
a scope selector (general, every week, problem and resource of the catalogue; preselected to the open item) and a
plain-text body (monospace, as everything in GView), with a character counter and the sync state (saved / unsaved /
saving / retrying / error). Course notes are read-only for students. Ctrl+F11 in a task window opens the newest note
of that item or starts one; outside Learning mode, and in windows not opened from the catalogue, Ctrl+F11 keeps its
local note.

**Privacy and restricted mode.** Note text exists in memory only: it is sent to the course server in ``SaveNote``
(and received in the student's own ``GetNotes``) and nowhere else - never written to disk by GView (no cache, no
temporary file, no log), never in telemetry (``note_add`` stays a bare count, recorded once when a note started in a
course window gets its first text). The Notes editor is the student's own text: Copy/Export/SaveAs restrictions
neither block it nor are bypassed by it - it offers no way to insert task content (no "insert selection"), and its
plain AppCUI text controls behave like the submission explanation field (see `Limitations`_).

**Limits.** Body <= ``maxChars`` characters (default 20000, request time value from ``GetNotes``), title <= 200
characters, 500 notes per student and ``60`` note requests per minute per token (server side, ``429`` +
``Retry-After``), request bodies <= 256 KiB.

**Stub server.** ``tools/learning_mode_stub_server.py`` implements the five endpoints with the compare-and-set and
idempotency rules, the visibility rule for scopes, the limits and the rate limit; ``--notes on|off|absent``,
``--notes-forbidden``, ``--staff``, ``--group``, ``--notes-max-chars`` and ``--notes-rate-limit`` select the cases.

**Clarifications of spec §10.11** (written back to ``plans/LEARNING_MODE_PROTOCOL_SPEC.md``):

1. A ``notes`` object without ``enabled`` means off; a present ``notes`` field with a wrong JSON type is
   ``POLICY_MALFORMED`` like every other policy field (§9.2).
2. Only ``403 FORBIDDEN`` of ``GetNotes``/``SaveNote``/``DeleteNote`` hides the Notes UI; ``403 POLICY_EXPIRED``
   expires the session; a ``403`` of ``SaveTeacherNote``/``DeleteTeacherNote`` only removes the teacher editor.
3. A ``409`` of a note endpoint is ``CONFLICT`` whatever its body says; a ``409`` of ``SubmitFlag`` stays
   ``ALREADY_SOLVED``.
4. Unknown or invalid scopes received from the server are shown (and, when the note is saved again, sent) as general.
5. Teacher notes are saved explicitly and creates are never retried automatically; student notes autosave.
6. ``404`` on ``SaveNote`` is resolved with a fresh ``GetNotes`` (see open question 7).

19. Work documents, solutions and the replay journal
----------------------------------------------------

Students save their work on a task (the names, comments, variables, collapsible zones, bookmarks they added in the
disassembly, plus the *replay journal* of how they got there) to the course server and resume it on another computer.
Teachers publish a *solution* of a problem for every student or one lab group; students open it next to their own
window (read only) or replay it step by step. Only the user's changes travel, never the ``.dissasm.cache`` (binary, it
holds every label of the analysis). Spec §10.12. Implementation: ``GViewCore/src/Security/Learning/LearningWork.{hpp,cpp}``
(wire format), ``LearningSession`` (requests), ``GViewCore/src/View/DissasmViewer/DissasmWorkDocument.{hpp,cpp}``
(document), ``DissasmReplay*.{hpp,cpp}`` (journal, recorder, playback, editor), ``GViewCore/src/App/LearningCourseDialogs.cpp``
and ``LearningModeWindow.cpp`` (UI).

**Availability.** The optional policy object ``"work": {"enabled": bool, "maxBytes": int}`` (``maxBytes`` clamped to
[64 KiB, 16 MiB], default 2 MiB) decides at connect time:

=============================== ========================================================================================
State                           Client behaviour
=============================== ========================================================================================
no ``work`` object (or no       no Save / Resume / Compare UI at all (a server without course work); the *Course* menu
policy, legacy server)          keeps *Course note* / *Submit flag*
``enabled: false``              students: "Saving course work is disabled by your teacher" (rows shown disabled); course
                                staff (``canPublishSolutions``) are never gated by the switch
``enabled: true``               everything is available while the session is *Active*
``403 FORBIDDEN`` on            students: the Save / Resume / Compare rows are disabled until the next connect;
``GetWork``/``SaveWork``        a ``403`` on ``PublishSolution`` / ``DeleteSolution`` only removes the staff capability
=============================== ========================================================================================

``Connect`` may add ``user.canPublishSolutions`` (bool) and ``user.audiences`` (``["all","G1","G2"]``, a wrong type is
ignored); every ``GetWork`` answer is authoritative and replaces them. ``GetWeeks`` problems may add
``me.workSavedAt`` / ``me.workRevision`` (0 = nothing saved) and ``solutionAvailable`` / ``solutionHasReplay`` (a
solution is published for this student; ``solutionHasReplay`` without ``solutionAvailable`` is ignored).

**Endpoints as implemented** (same headers and transport rules as every other call, one ``POST`` per request with a
constant path; the document is embedded as a JSON object, never as a string):

::

   POST /GView/GetWork          {"problem":"<name>"}
     <- {"status":"ok","serverTime":..,"maxBytes":2097152,"canPublishSolutions":false,"audiences":["all","G1","G2"],
         "work": null | {"revision":3,"updatedAt":..,"clientVersion":"0.409.0","hasReplay":true,"replaySteps":57,
                         "document":{..}},
         "solutions":[{"id":7,"audience":"all"|"G1"|"G2","revision":2,"updatedAt":..,"enabled":true,
                       "hasReplay":true,"replaySteps":120}]}
   POST /GView/SaveWork         {"problem","document":{..},"hasReplay":bool,"replaySteps":int[, "revision":<last seen>]}
     <- {"status":"ok","revision":4,"updatedAt":..,"created":false}
   POST /GView/GetSolution      {"problem"[, "id":<int>]}
     <- {"status":"ok","solution":{"id","audience","revision","updatedAt","enabled","hasReplay","replaySteps",
                                   "document":{..}}}
   POST /GView/PublishSolution  {"problem"[, "id":<int>, "revision":<int>],"audience","document":{..},
                                 "hasReplay","replaySteps","enabled":true}            (course staff)
     <- {"status":"ok","id":7,"revision":3,"updatedAt":..,"created":true}
   POST /GView/DeleteSolution   {"id":<int>}                                         (course staff)
     <- {"status":"ok"}

Rules:

* A hidden or unknown problem is ``404`` (students cannot probe hidden problems; staff see hidden ones). ``work`` is
  always the caller's own document: staff never read a student's document through GView.
* ``solutions`` lists metadata only; students get the *enabled* solutions of ``all`` and of their group, staff every
  one. ``GetSolution`` without ``id`` returns the solution of the student's group, else the one of ``all``; ``404`` when
  there is none ("No solution of the teacher is available for you yet").
* Compare-and-set exactly as ``SaveNote``: ``revision`` omitted = create; a create when work exists, or a stale
  ``revision``, is ``409 CONFLICT`` (``retryable: false``, nothing written); an identical create / update retried after
  a lost answer is answered ``200`` (``created: false``) with the revision it produced. The client only reports the
  conflict; the UI resolves it (below).
* One solution per (problem, audience). ``PublishSolution`` without ``id`` when one exists is ``409 CONFLICT`` whose
  envelope also carries ``"id"`` and ``"revision"`` of the existing solution; the client asks "Replace it?" and sends
  again with them. ``id`` requires ``revision`` (``400``).
* Document validation (client before sending, server again): a JSON object, ``format ==
  "gview-disassembly-annotations"``, integer ``version`` in [1, 1], no NUL anywhere (raw or ``\u0000``), nesting <= 64,
  the compact dump <= ``maxBytes`` => otherwise ``400`` (``413 PAYLOAD_TOO_LARGE`` above the body cap). The client
  sends the compact canonical dump (``nlohmann::json::dump()``, keys sorted) and refuses locally, without a request,
  a document above ``min(policy.work.maxBytes, GetWork maxBytes, 2 MiB)``.
* ``hasReplay`` / ``replaySteps`` are client-declared metadata (``replaySteps`` is 0 without a replay) so that the
  catalogue and the Learning window can show "solution+replay" without the server parsing documents; the server
  stores the document opaque.
* Caps: request bodies 2 MiB + 64 KiB on ``SaveWork`` / ``PublishSolution`` (64 KiB otherwise); answers 4 MiB
  (``GetWork`` / ``GetSolution``) or 64 KiB; at most 64 solutions listed (more are dropped and counted); rate bucket
  ``work`` = the notes bucket, 60 requests per minute per token (``429`` + ``Retry-After``).
* Errors: ``403 POLICY_EXPIRED`` expires the session; ``403 FORBIDDEN`` as in the table above; other errors show the
  server's ``details``. Solution entries without a valid ``id``/``revision``/``audience`` are dropped.

**The work document** (``DissasmWorkDocument.hpp``) is the annotations document of *Export annotations*
(``BuildAnnotationsDocument``: ``format``, ``version``, ``file``, ``zones``: names, comments, repeatable comments,
variables, structures, numbers in decimal, collapsible zones, functions, prototypes, bookmarks, the assistant's
suggestions; keyed by VA) plus two keys that older importers ignore:

::

   { "format": "gview-disassembly-annotations", "version": 1, "file": "p16.exe", "zones": [ .. ],
     "meta":   { "kind": "work" | "solution", "clientVersion": "0.409.0", "savedAt": 1760000000,
                 "problem": "w1_stack_var", "itemVersion": 1, "sha256": "<the catalogue sha256 of the task>" },
     "replay": { "version": 1, "startedAt": 1759990000,
                 "zones":  [ { "fileOffset": "0x400", "addressBase": "0x401000" } ],
                 "events": [ ["v", 12, 0, "0x401000", "l", "k"],
                             ["j", 3, 0, "0x401010", "i", 0, "0x401080", "l", "call", "follow"],
                             ["b", 5, 0, "0x401010", "i"],
                             ["e", 20, 0, "0x401080", "l", "name", {"before": "sub_401080", "after": "decrypt"}],
                             ["u", 2, 0, "0x401080", "l", "name", 3, {..}],
                             ["i", 0, "server-work"], ["a", 0, 0] ] } }

An event is ``[tag, dt, ...]`` (``dt``: seconds since the previous event). A *place* is ``zone, address (VA hex),
anchor kind (i instruction / l label / v variable)[, frameOffset (v only)]``. Tags: ``v`` visit (``k`` keyboard /
``m`` mouse), ``j`` jump (from, to, mnemonic, kind: ``follow``, ``entry``, ``goto``, ``xref``, ``band``, ``search``,
``bookmark``, ``other``), ``b`` / ``f`` back / forward in the jumps history, ``e`` edit, ``u`` / ``r`` undo / redo
(``ref`` = the index of the event it undoes, or ``null``), ``i`` import (``file``, ``server-work``,
``server-solution``), ``a`` new analysis of a zone. Edit kinds use the annotations vocabulary (``comment``, ``name``,
``variable``, ``decimal``, ``zoneAdd``, ``zoneRemove``, ``dataRanges``, ``functions``, ``variableStructures``,
``operandStructure``, ``operandConstant``, ``repeatableComment``, ``prototypes``); payloads: ``{"before","after"}``
(texts; a missing key = none), ``{"operand"}``, ``{"first","last","name","collapsed"}``, lists ``{"before":[..],
"after":[..]}``. Reading is tolerant (an unreadable zone or event is skipped and counted); a wrong ``format`` or a
newer ``version`` is an error; a ``replay`` of a newer version is dropped. ``"encoding"`` is reserved (no compression
in v1: a lab document is 4-40 KB). The server must store the document as received (opaque JSON).

**The replay journal.** Recorded by every Dissasm view (also outside Learning mode): the lines visited, the jumps, the
edits, undo / redo, imports and new analyses. Idle scrolling is not kept: a keyboard move becomes a visit after the
cursor rests 600 ms on a code line (a click at once), the same place visited again is one visit, at most the last 3
visits before an operation are kept and the visits after the last operation are dropped. Limits: 200 000 events,
4096 zones, texts 64 KiB, mnemonics 15 characters (the recorder stops at the caps). It is stored in the
``.dissasm.cache`` as the record ``DissasmReplayJournal`` (magic ``GDRJ``, version 1, LEB128 varints, zigzag for signed
values, strings ``[varint size][bytes]`` without NUL; ``DISSASM_CACHE_VERSION`` stays 2):

::

   [u32 magic][u32 version][u64 startedAt][varint zoneCount] zoneCount x [varint fileOffset][varint addressBase]
   [varint eventCount] eventCount x [u8 kind][varint dt] then by kind:
     place = [varint zone][u8 anchorKind][varint address][svarint frameOffset: Variable only]
     Visit: place [u8 source] | Jump: place(to) place(from) [u8 jumpKind][u8 size][mnemonic] | Back/Forward: place
     Edit: place [u8 editKind] payload | Undo/Redo: place [u8 editKind][varint ref+1] payload
     Import: [u8 source] | Reanalysis: [varint zone]

Decoding is all or nothing (an invalid record => an empty journal; its raw bytes are written back unchanged unless
new events were recorded). An older GView that re-saves the cache drops the record. Typical size: a visit 4-6 bytes,
a jump ~12, a rename ~20 + the names; a two-hour lab 5-15 KB. Under a policy that restricts ``Export`` the cache is
not written at all: the course server is then the only persistence of the journal.

**User interface.**

* *Course* menu (``Ctrl+Alt+L``, ``[Keys.GView] LearningCourse``; on the command bar of every window of a problem of
  the course): *Save work to course* (document size, replay steps), *Resume work from course* ("saved <time>", or
  "(no saved work)"), *Compare with the teacher's solution* / *Replay the teacher's solution* (when the catalogue says
  a solution / a replay is published for the student), *Course note*, *Submit flag*; course staff add *Publish
  solution...* and *Edit replay journal...*. In a solution window the only command is *Close solution window*.
  Disabled rows say why (disabled by the teacher, not connected, no disassembly view).
* *Save work*: counts (names, comments, variables, zones, bookmarks), the checkbox "Include replay journal" (checked),
  the size against the limit (refused above it), then "Saved: revision N (size) at <time>"; the window is clean. On
  ``409``: ``GetWork`` tells when the server copy was saved; *Keep server copy* loads it into the window (import
  semantics), *Overwrite* saves again with the revision just fetched, *Cancel* does nothing.
* Close prompt: closing a student's task window with changes (an edit, a journal event) not on the server asks
  *Save and close* / *Close without saving* / *Cancel* (only when course work is available; the journal is dropped
  from the document when it would exceed the limit).
* *Resume*: from the menu it confirms "Add the saved work to this window?" (the document wins where both have a
  name / comment; nothing is deleted); opening a task from the Learning window offers it automatically when the
  server has saved work and the window is empty (no cache, empty journal, no edit). *Open with work* in the Learning
  window loads it without asking. A document saved for another version of the task file (``meta.sha256`` differs
  from the catalogue) is confirmed first. The document is applied once the disassembly is analysed (first paint).
* *Compare*: ``GetSolution``, then a second window of the same task, role *Solution* (title "<name> - Teacher
  solution"): file mode opens the same local task file, memory mode a copy of the bytes in locked memory
  (memory-only). The two windows are tiled side by side (student left), the focus goes back to the student.
  *Replay* opens role *Replay* ("<name> - Teacher solution (replay)"): the window starts without the solution's
  annotations and plays the journal back with ``Alt+Left`` / ``Alt+Right`` / ``Alt+Home`` / ``Alt+End`` (command bar
  *Back*, *Forward*, *To start*, *To end*); the status line shows "Replay: step 12/57 - comment added at 0x401040";
  a step first ends the pending analyses and prepares every code zone (as the other commands do); events whose place this analysis does not have are skipped.
  *Open solution* in the Learning window opens the same windows on their own (no tiling).
* Solution windows are read only: no edit command, no undo / redo, no import / export / signatures, no assistant; a
  refused key shows one notification (at most every 3 s); the right-click menu only expands / collapses zones and
  clears selections; bookmarks are listed without *Delete*; they never read nor write a ``.dissasm.cache``; no
  telemetry item events are recorded for them.
* *Publish solution* (course staff, re-checked when sent): audience ("All students", "Group G1", "Group G2" from
  ``audiences``), "Include replay (N steps)", size, confirmation, then ``PublishSolution`` (a ``409`` with ``id``
  offers to replace the existing solution of that audience), then the catalogue is refreshed.
* *Edit replay journal* (``[Keys.View.Dissasm] EditReplayJournal``, no default key; course staff in a task window,
  anyone outside Learning mode): ``# | +time | Kind | Address / label | Text``, *Delete*, *Delete visits before*,
  *Compact*, *Close*; it works on a copy and asks "Apply the changes (N entries removed)?".
* Learning window: column *Course* ("work <date>", "solution", "solution+replay"), buttons *Open with work* and
  *Open solution* (enabled for the selected problem), *Details* lines for the saved work and the solution.

**Privacy.** Annotation text and the journal leave the machine only on an explicit *Save work* (or *Save and close*)
and *Publish solution*, and come back only to their owner (``GetWork``) or to the intended audience (``GetSolution``).
They are never in telemetry (the whitelist is unchanged; solution windows record no item events), never in logs. A
memory-mode task's solution window reads a copy of the task bytes in locked memory and writes nothing to disk.

**Stub server.** ``tools/learning_mode_stub_server.py`` implements the five endpoints with these rules;
``--work on|off|absent`` (the policy object; ``off``: ``GetWork``/``SaveWork`` answer ``403`` to students),
``--work-max-bytes``, ``--staff-token`` (course staff), ``--group G1|G2``; the work requests share the notes rate
bucket (``--notes-rate-limit``). State is in memory, per process.

**Clarifications of spec §10.12** (written back to ``plans/LEARNING_MODE_PROTOCOL_SPEC.md``):

1. A ``work`` object without ``enabled`` means off; a present ``work`` field with a wrong JSON type is
   ``POLICY_MALFORMED``.
2. Course staff (``canPublishSolutions``) are never gated by ``work.enabled`` or a ``403`` of the own-work endpoints.
3. A ``409`` of a work endpoint is ``CONFLICT`` whatever its body says; for ``PublishSolution`` the envelope may name
   the existing solution (``id``, ``revision``).
4. ``GetSolution`` without ``id`` prefers the student's group over ``all``.
5. The client never retries a ``409`` by itself: the user chooses (keep the server copy / overwrite / replace).
6. ``DeleteSolution`` is implemented in the client session but has no UI yet (the course website manages solutions).

