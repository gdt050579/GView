# Security Policy

GView is used to analyze malware, corrupted files and deliberately malformed data. A parser bug that can be
triggered by a crafted input (crash, out-of-bounds read, memory corruption, hang) is a security issue, not a
regular bug.

## Supported versions

Only the latest release and the `main` branch receive fixes.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/gdt050579/GView/security/advisories/new>

Include the GView version (or commit), the platform, the sample that triggers the issue (or a minimal
reproduction) and the observed behavior. You will receive an acknowledgement within 7 days.

## What the CI already checks

- CodeQL (`security-extended`) on every pull request and weekly on `main`
- Unit tests under AddressSanitizer / UndefinedBehaviorSanitizer (scheduled)
- OpenSSF Scorecard and zizmor / actionlint for the workflows themselves
- Release archives carry SLSA build-provenance attestations; binaries are signed with Sigstore
  (see the verification instructions on every release page)
