Security and restricted mode
=============================

GView provides a **Restricted Mode** (exposed in the UI as Learning and Evaluation
Mode) for exam and assessment scenarios where you need to limit features, enforce
time windows, and reduce leakage of sensitive content (e.g. task binaries).

Public API (GView.hpp)
----------------------

The following are in ``GView::Security::RestrictedMode``:

* **Policy** — Configuration: schema, id, digest, purpose, issuedAt/startsAt/endsAt, subject
  (token binding), serverUrl, disabled features, allowed plugins list, storage mode (``File`` /
  ``Memory``), watermark text, best-effort / required screen protection, telemetry settings,
  submission settings, content encryption and content key id.
* **Feature** — Enum of features that can be disabled: Copy, Export, SaveAs, Plugins,
  LLMHints, Clipboard, Screenshots.
* **LoadPolicyFromFiles(jsonPath, signaturePath, publicKey, outPolicy)** — Load and
  verify an Ed25519-signed policy JSON. Returns ``GStatus``; on success, ``outPolicy``
  is filled.
* **VerifyAndParsePolicy(rawJson, signature, publicKey, subject, serverUrl, now, outPolicy)** —
  Verify and parse a schema-2 policy delivered by a course server (signature first, then
  schema, digest, subject, server and validity window with 120 s skew).
* **IsActive()** — Returns whether restricted mode is currently active.
* **GetCurrentPolicy()** — Returns a copy of the current policy (``std::optional``).
* **IsFeatureDisabled(feature)** — Lock-free query, usable from plugins.

Plugins should use ``GView::App::IsBlockedByPolicy``, ``IsExportBlockedFor`` and
``SetClipboardText`` for every operation that copies, exports or saves content, so that the
user gets a consistent notice and the attempt is recorded.

The UI calls this mode **Learning and Evaluation Mode** (*Options* menu, or
``GView learn <connectionString>``). When it is active, disabled features are unavailable in
the UI (e.g. save, copy, export), only plugins listed in the policy are allowed, and the policy
watermark is shown in every window title. The full protocol, enforcement matrix and
limitations are in :doc:`learning_mode_protocol`. This supports fair
evaluation and reduces easy copying of task content. See :doc:`education` for the
typical workflow (connect to server, load policy, request task, submit solution,
telemetry).

Limitations
-----------

Restricted mode is best-effort. It does not prevent all leakage (e.g. photographing
the screen, typing content elsewhere, or patching the open-source binary). It is
designed to raise the effort required to cheat and to keep task data off disk when
using memory-only buffers.
