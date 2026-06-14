# Security Policy

## Reporting a vulnerability

Please do **not** open public issues for security vulnerabilities. Report them
privately to becush@gmail.com (or via GitHub private security advisories once the
repository is hosted).

Include the affected version/commit, a description, reproduction steps, and
impact. We aim to acknowledge within 5 business days and to coordinate a fix and
disclosure timeline with you.

## Scope and important caveat

`cargo-fips` is a compliance-**assurance and evidence** tool. It is **not** a
cryptographic module, not FIPS-validated, and not a substitute for CMVP
validation or an auditor's judgment. A passing `check` means "no detected drift
from the declared, validated configuration," not "validated." Reports that the
tool fails to *confer* compliance are out of scope by design.

In scope:

- Incorrect assurance results that could lead a user to believe a non-compliant
  build is compliant (e.g. missing a competing crypto crate, or misclassifying an
  operating environment).
- Registry data integrity (tampering, unverifiable data).
- Attestation integrity (forgeable or tamperable evidence output).
- Standard software vulnerabilities in the tool itself.

Out of scope:

- The security of the underlying validated modules (report to their vendors and
  CMVP).
- Issues requiring an already-compromised build host or toolchain.

## Supported versions

Pre-1.0: only the latest `main` is supported.
