# Security Policy

## Supported versions

nl6 is pre-1.0 and ships from a single line. Security fixes land on `main` and
go out in the next tagged release; only the **latest release** is supported.
There are no maintained release branches — upgrade to the newest `vX.Y.Z` to
receive fixes.

| Version         | Supported          |
| --------------- | ------------------ |
| Latest release  | :white_check_mark: |
| Older releases  | :x:                |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's
[**private vulnerability reporting**](https://github.com/labmonkeys-space/nl6/security/advisories/new)
(Security → Advisories → *Report a vulnerability*). This opens a private
advisory visible only to you and the maintainers.

If you cannot use GitHub advisories, email **ronny@no42.org** with the details.

Please include, as far as you can:

- the affected version (`nl6 -version`) and platform;
- a description of the issue and its impact;
- reproduction steps or a proof of concept;
- any suggested remediation.

## What to expect

- **Acknowledgement** within 5 business days.
- An initial assessment (severity, affected versions) once the report is
  triaged.
- Coordinated disclosure: we agree on a timeline with you, ship a fix in a new
  release, and publish an advisory crediting you (unless you prefer to remain
  anonymous).

nl6 is a network **device simulator** intended for test labs and monitoring
validation — it is not hardened for exposure on untrusted networks. Running it
outside an isolated lab (it needs root for TUN/netns, opens SNMP/SSH/HTTPS/gNMI
listeners, and can emit flow/trap/syslog/telemetry traffic) is out of scope for
a vulnerability report; deploy it in a controlled environment.

## Verifying release artifacts

Release binaries, packages, the checksums file, and the container image are
signed with [cosign](https://docs.sigstore.dev/) (keyless, via GitHub OIDC) and
carry SLSA build provenance. See the **Verify a release** section of
[`RELEASING.md`](RELEASING.md) for the exact `cosign verify` /
`gh attestation verify` commands.
