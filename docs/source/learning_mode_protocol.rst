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
6. sends privacy-preserving telemetry (event-level + counters) in the background.

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
``LearningDownloadFolder``          Default folder for ``file`` deliveries (empty = ``<Documents>/GView/<week>``).
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
worker thread; results are applied on the UI thread.

4. Endpoints
------------

All endpoints are ``POST``. Error envelope for every non-2xx answer::

   { "status": "error", "code": "POLICY_EXPIRED", "details": "human readable", "retryable": false }

Codes understood (HTTP mapping as in the spec): ``BAD_REQUEST`` 400, ``UNAUTHORIZED`` 401, ``FORBIDDEN`` 403,
``NOT_FOUND`` 404, ``RATE_LIMITED`` 429 (+ ``Retry-After`` seconds), ``POLICY_EXPIRED`` 403, ``POLICY_NOT_STARTED`` 403,
``ALREADY_SOLVED`` 409, ``ITEM_DISABLED`` 404, ``UNSUPPORTED_CLIENT`` 426, ``SERVER_ERROR`` 500. When the body is not an
envelope the code is derived from the HTTP status. ``TRANSPORT_ERROR`` and ``PROTOCOL_ERROR`` are client-side only.

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

Known residual plaintext copies (honest list): GView's ``DataCache`` chunk cache (up to ``CacheSize``, 10 MiB by
default, ordinary heap), parser/viewer-derived structures (strings, disassembly text, images), AppCUI screen buffers.
Pinning can fail silently (Windows working-set quota, Linux ``RLIMIT_MEMLOCK``); content is then still wiped but may
have been paged.

File mode: the student picks the destination in a Save dialog (default ``LearningDownloadFolder`` or
``<Documents>/GView/<week>``); the content is written to ``<name>.part``, re-hashed from disk, then atomically moved
into place (``MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`` / ``rename``). Any failure removes the ``.part`` file.

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
               ``Resources::SaveCurrentResource``; PE ``DigitalSignature`` drop-to-disk for WinTrust; PDF
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
``note_add``              yes    -
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
==== ========================================================================================== ========================

Totals on this machine: 27 learning unit test cases / 635 assertions pass (the two end-to-end cases
are hidden and need the stub server: 58 + 12 assertions pass, 705 in total); the full ``ctest`` suite (33 cases) passes. Cross-implementation
vectors (`Test vectors`_) are asserted by ``cross-implementation test vectors``.

How to reproduce::

   cmake -S . -B build-test -DENABLE_TESTS=ON && cmake --build build-test --config Debug
   ctest --test-dir build-test -C Debug
   python tools/learning_mode_stub_server.py --quiet --require-explanation      # prints the connection string
   set GVIEW_LEARNING_STUB_CS=<printed connection string>
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
  deliver ``OnFrameUpdate`` (~30 Hz, no repaint unless something changed).
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

15. Open questions for the server implementer
---------------------------------------------

1. Please make sure ``policy.serverUrl`` is exactly the URL put in connection strings (otherwise use an empty
   ``serverUrl``) - the client rejects mismatches.
2. Accept the ``note_add`` counter and the ``reason`` values listed for ``session_end``.
3. Should ``eventLevel:false`` also suppress session lifecycle events server-side? The client sends counters only.
4. The client treats any ``4xx`` except ``408``/``429`` on ``SubmitFlag`` as consuming the idempotency key (e.g. a
   ``400`` for a missing explanation). Confirm the server does not store a ``Submission`` row in that case.
5. Confirm that a protocol-2 download of a ``kind=link`` resource is never needed (the client uses the catalogue URL).
6. Legacy flat ``GetProblems`` items carry no ``deliveryMode``/``sha256``; for v2 clients please always serve
   ``GetWeeks``.
