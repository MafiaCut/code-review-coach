# Security Policy

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in a public issue. Use GitHub's
private vulnerability reporting feature for this repository, or contact the
repository owner privately if that feature is unavailable.

Include the affected version, reproduction steps, impact, and any suggested
mitigation. You should receive an acknowledgement within seven days.

## Supported versions

Security fixes are applied to the latest release on the `main` branch.

## Security model

Code Review Coach treats submitted diffs as untrusted text and never executes
them. GitHub webhook requests require a configured secret and a valid
`X-Hub-Signature-256` signature.
