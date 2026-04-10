# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1.0 | No |

## Reporting a Vulnerability

Please do not open public issues for suspected vulnerabilities.

Preferred disclosure path:
1. Open a private vulnerability report via GitHub Security Advisories for this repository.
2. Include reproduction details, impact, and affected version/commit.
3. If possible, include a minimal proof-of-concept.

## What to Include

- Threat model and attack preconditions
- Steps to reproduce
- Expected vs actual behavior
- Potential impact (confidentiality/integrity/availability)
- Suggested remediation (optional)

## Response Expectations

- Initial triage acknowledgment target: within 3 business days
- Follow-up with status/mitigation plan target: within 7 business days

## Scope Notes

In-scope examples:
- Key compromise due to protocol or implementation bugs
- Authentication bypass in handshake
- Replay protection bypass
- FFI memory safety issues

Out-of-scope examples:
- Build environment misconfiguration in third-party forks
- Denial-of-service caused by intentionally malformed usage outside documented API contracts
