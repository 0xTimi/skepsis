# Security Policy

## Supported versions

Skepsis is pre-1.0; security fixes land on the latest `0.x` release.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

Please **do not open a public issue** for security vulnerabilities in Skepsis
itself.

Instead, use GitHub's private
[**Report a vulnerability**](https://github.com/0xTimi/skepsis/security/advisories/new)
workflow (Security → Advisories). This keeps the report confidential until a fix
is ready.

We aim to acknowledge reports within **72 hours** and to ship a fix or mitigation
within **90 days**, coordinating disclosure with you.

## Scope

Skepsis executes code during dynamic verification (`skepsis verify` compiles
and runs a supplied C harness). Treat harnesses as untrusted input and run
verification in a sandbox or container. Reports about the verifier executing
harness code as designed are out of scope; reports about the verifier being
tricked into running code **outside** the harness path are in scope.

## Responsible use

Skepsis is a defensive and research tool. Only run it against code you are
authorized to audit.
