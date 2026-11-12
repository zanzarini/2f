# Security policy

2F is security software. Reports of weaknesses are welcome and treated as the
most useful contributions the project can receive.

## Reporting a vulnerability

Please do not open a public issue for something exploitable. Use GitHub's
private reporting instead: **Security → Report a vulnerability** on this
repository.

Include what you can of:

- which claim in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) does not hold;
- the smallest sequence of requests or database changes that shows it;
- the version or commit you tested.

You will get an acknowledgement, and credit in the fix unless you prefer not.

## What counts

Anything that breaks a row of the threat model table, for example:

- a receipt that verifies for an action other than the one authorized;
- an approval accepted without a signature from an enrolled, sealed credential;
- a way to gain approver, API key or policy power with only database access;
- a change to the audit log that `twof audit verify` does not report;
- an approval page that displays something other than what is signed.

The "Known limits" section of the threat model lists what is already known and
accepted; a report that turns one of those into a practical attack is still
welcome.

## Supported versions

The project is pre 1.0. Fixes land on `main`.
