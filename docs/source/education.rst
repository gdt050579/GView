GView use in education
======================

This page describes how GView can be used in educational settings for learning and
evaluation, including the Learning and Evaluation Mode (built on :doc:`security`),
the typical workflow, and security considerations.

Use case
--------

Step-by-step workflow
~~~~~~~~~~~~~~~~~~~~~

**Step 1: Launch GView and connect to the course server.**

The student launches GView and selects the Learning and Evaluation Mode from the
menu options. Then the student connects securely to the course server using a
unique login token. Each student is assigned a unique token used to identify them.
If the server accepts the connection, it returns the policy in JSON format.

**Step 2: Load and apply the policy in GView.**

After the policy is received, it is automatically loaded in GView: features that
are disabled by the policy become unusable (e.g., save, copy, export), and plugins
that are disabled become unavailable. From this point on, the student works in a
controlled environment that allows a fair evaluation of their skills. The features
needed for the student to perform the analysis remain accessible, so their
workflow is not impacted.

**Step 3: Request a task.**

The student can now request problems to work on. GView uses the student's token and
sends a secure request to the server for a specific task (or for the next available
task, depending on the policy).

If the server accepts the request, it streams back binary content to GView along
with the task requirements. Typically this is binary executable files (e.g., PE
files). That content is opened inside GView either as a buffer (from memory only) or
from a file (depending on the policy), enabling the student to start their analysis.

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

The student submits the solution directly from GView:

* If the solution is wrong, the server returns a failure response, and the student
  can try again.
* If the solution is correct, the server returns a success response and the number
  of points assigned for that task.

This immediate feedback lets students receive grading instantly, without waiting for
human evaluation and intervention.

**Step 6: Send telemetry.**

At the end of the task, telemetry data is securely sent to the server. It is used
for course improvement only. No invasive data is collected. In this use case, the
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
