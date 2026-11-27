# Security Policy

## Supported versions

Security fixes are applied to the latest published minor version.

## Reporting a vulnerability

Privately report a suspected vulnerability through the repository's [Security Advisory reporting form](https://github.com/draarivpatel-ui/node-appsec-middleware/security/advisories/new). Do not open a public issue for a suspected vulnerability.

Please include:

- A minimal reproduction that uses synthetic input only.
- The affected project version, commit or action ref, and Node.js version.
- The expected security boundary and the observed violation.
- Logs, output, or proof-of-concept code needed to reproduce the finding, with real secrets removed.

Never include a real token, cookie, password, private key, production log line or real personal data in a report.

Vulnerability handling steps:

1. The maintainer acknowledges the private report within 72 hours.
2. The maintainer reproduces the finding against the latest supported version and confirms severity within 14 days when enough information is available.
3. A fix is developed privately, with regression coverage where practical.
4. The maintainer coordinates the advisory, affected versions, reporter credit and disclosure date with the reporter.
5. The target coordinated disclosure window is 90 days or less from acknowledgment. If more time is needed, the maintainer and reporter agree on a new date before disclosure.

## Scope

Reports are especially welcome for:

- Authentication or verification bypasses
- Prototype pollution or parser differentials
- CRLF injection
- Open redirects or CORS policy confusion
- SSRF policy bypasses
- Archive extraction escapes
- Secret leakage in logs or error responses

## Response goals

Reports are triaged as quickly as possible. If a report is valid, a fix, regression test, and advisory are prepared before public disclosure where practical.
