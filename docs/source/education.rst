GView use in education
======================

This page describes how GView can be used in educational settings for learning and
evaluation, including the Learning and Evaluation Mode (built on :doc:`security`),
the typical workflow, and security considerations. The exact protocol, data formats and
enforcement points are documented in :doc:`learning_mode_protocol`.

Use case
--------

Step-by-step workflow
~~~~~~~~~~~~~~~~~~~~~

**Step 1: Launch GView and connect to the course server.**

The student launches GView, selects *Options > Learning and Evaluation Mode* (or
starts ``GView learn <connectionString>``) and pastes the connection string received from
the teacher. The connection string contains the student's secret access token, the server
address and the public key used to verify policies. GView connects over verified TLS; if
the server accepts the token, it returns a policy (JSON) signed with Ed25519.

**Step 2: Load and apply the policy in GView.**

After the policy is received, GView verifies its signature, the student binding and its
validity window before applying it (a policy that does not verify is refused and nothing is
restricted or unlocked). Features that are disabled by the policy become unusable (e.g., save,
copy, export) and plugins outside the whitelist become unavailable; blocked actions show a
"Blocked by course policy" notice. The window shows the policy, its remaining time, the
storage mode and whether screen protection could be applied on this platform. From this point on, the student works in a
controlled environment that allows a fair evaluation of their skills. The features
needed for the student to perform the analysis remain accessible, so their
workflow is not impacted.

**Step 3: Request a task.**

The window lists the published **weeks**; each week contains **problems** (graded tasks,
with current points and the student's attempts) and **resources** (files, text notes and
links shared by the teacher). Disabled weeks and items are never shown. *Details* shows the
description; *Open* (or Enter) downloads the selected item.

Typically this is binary executable files (e.g., PE files). Depending on the policy and the
item, the content is either kept in memory only (encrypted in transit, decrypted into locked
memory, never written to disk) or saved to a folder chosen by the student and opened from
there. In both cases its SHA-256 is verified.

**Step 4: Perform the analysis.**

The student follows the usual process used in laboratories. First, the student
inspects the raw bytes from a binary perspective using the Buffer Viewer. This
helps get a bigger picture and understand the global structure and the kind of data
involved.

If working with an executable file, the student then analyzes the content using the
Disassembly Viewer to observe the disassembled code. The student can follow jump and
call instructions to see control flow and destinations. To keep track of
information, they can add comments to the code.

In an example scenario, the requirement might be to identify the value of the third
variable from the stack. Upon inspection, the student can determine that the
correct value is 3.

**Step 5: Submit the solution.**

The student submits the solution directly from GView (*Submit flag* in the catalogue, or
Ctrl+Alt+F in the task window), optionally - or, if the course requires it, mandatorily -
together with a short explanation of the reasoning:

* If the solution is wrong, the server returns a failure response, and the student
  can try again.
* If the solution is correct, the server returns a success response and the number
  of points assigned for that task.
* If the network fails, *Retry* resends the same submission (same submission id), so a
  retry is never counted as an extra attempt.

This immediate feedback lets students receive grading instantly, without waiting for
human evaluation and intervention.

**Step 6: Send telemetry.**

When the policy enables it, telemetry is sent to the server in the background. It is used
for course improvement only. No invasive data is collected: GView records that an action
happened (a followed jump, a comment added, a viewer opened) but never comment text, labels,
notes, clipboard content, keystrokes or files outside the course. In this use case, the
focus is on the following metrics:

* time to solve;
* number of attempts;
* feature usage of GView.

Why this use case is important in education
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

One main advantage of this approach is that it supports both learning and
evaluation in the same way. During labs, students learn to use GView and its
features (e.g., following jumps, annotating code) and gain confidence. Because the
same process is used for evaluation, when the evaluation starts we can measure
reverse engineering skills rather than tool setup skills.

Telemetry is useful from a teaching perspective. We monitor whether features are
used and how often. If some features are not used, this can mean one of three
things:

1. The feature was not properly explained.
2. The student is not yet familiar with it.
3. The student prefers not to use it (e.g., personal preference).

This information helps improve the entire course. Depending on how students behave
in certain situations, we can see which topics need clearer explanations, which
tasks are confusing, or which GView features need better integration in the
learning workflow. We also track whether the tool reaches invalid states (e.g.,
crashes). In this way, we can better understand where students struggle and where
support is needed, even when that is not explicitly communicated to the teachers.

Security and limitations
-------------------------

The Learning and Evaluation Mode is designed to reduce the risk of leakage, improve
fairness, and make cheating harder during evaluation, but it cannot achieve that
perfectly.

The mode provides a secure way to send tasks and receive metrics and responses over
a secured network connection. Leaking binaries is harder when they are kept in
secured memory only (not on disk). This is reinforced by disabling copy, save, and
export. On Windows, the screen is protected from screenshots.

However, students can still bypass these protections: for example, by taking a
photo of the screen with a phone, typing the content manually into another
application, patching GView (since it is open source), or using an external tool.

We treat the Learning and Evaluation Mode as a best-effort protection that
substantially raises the effort required to cheat, rather than as a perfect
solution. In an educational environment, students might be tempted to copy
binaries to use other tools or to share them. The goal is to reduce easy access
without making the tool so restrictive that students fight the tool instead of
working with it.
