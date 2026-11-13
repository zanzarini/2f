# Security policy

2F is security software. Vulnerability reports are welcome and are handled
with priority.

## Reporting a vulnerability

Do not open a public issue for an exploitable problem. Use GitHub's private
reporting: **Security → Report a vulnerability** on this repository.

Include, where possible:

- which claim in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) does not hold;
- the smallest sequence of requests or database changes that shows it;
- the version or commit you tested.

Reports are acknowledged, and reporters are credited in the fix unless they
ask otherwise.

## Scope

Anything that breaks a row of the threat model table, for example:

- a receipt that verifies for an action other than the one authorized;
- an approval accepted without a signature from an enrolled, sealed credential;
- a way to gain approver, API key or policy power with only database access;
- a change to the audit log that `twof audit verify` does not report;
- an approval page that displays something other than what is signed.

The "Known limits" section of the threat model lists accepted limitations. A
report that turns one of them into a practical attack is in scope.

## Supported versions

The project is pre 1.0. Fixes land on `main`.
