Security and restricted mode
=============================

GView provides a **Restricted Mode** (exposed in the UI as Learning and Evaluation
Mode) for exam and assessment scenarios where you need to limit features, enforce
time windows, and reduce leakage of sensitive content (e.g. task binaries).

Public API (GView.hpp)
----------------------

The following are in ``GView::Security::RestrictedMode``:

* **Policy** — Configuration: id, purpose, time window (startsAt/endsAt), disabled
  features, allowed plugins list, watermark text, screen protection option, content key id.
* **Feature** — Enum of features that can be disabled: Copy, Export, SaveAs, Plugins,
  LLMHints, Clipboard, Screenshots.
* **LoadPolicyFromFiles(jsonPath, signaturePath, publicKey, outPolicy)** — Load and
  verify an Ed25519-signed policy JSON. Returns ``GStatus``; on success, ``outPolicy``
  is filled.
* **IsActive()** — Returns whether restricted mode is currently active.
* **GetCurrentPolicy()** — Returns the current policy (read-only) or nullptr.

When restricted mode is active, disabled features are unavailable in the UI (e.g. save,
copy, export), and only plugins listed in the policy are allowed. This supports fair
evaluation and reduces easy copying of task content. See :doc:`education` for the
typical workflow (connect to server, load policy, request task, submit solution,
telemetry).

Limitations
-----------

Restricted mode is best-effort. It does not prevent all leakage (e.g. photographing
the screen, typing content elsewhere, or patching the open-source binary). It is
designed to raise the effort required to cheat and to keep task data off disk when
using memory-only buffers.
