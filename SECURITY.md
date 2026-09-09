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

## Dependency advisories

Not every dependency in this repository reaches the simulator.

Advisories against [`go/go.mod`](go/go.mod), the container image, or the pinned
GitHub Actions are **in scope**: those reach the nl6 binary or the release
pipeline that signs it.

The npm tree at the repository root is different.
It belongs to `nl6-docs`, the Docusaurus site published at <https://nl6.eu>.
The build already treats the two as separate products: the release pipeline's
SBOM covers the shipped binary and deliberately excludes the website toolchain,
which gets its own SBOM alongside the site.
[`.github/workflows/docs.yml`](.github/workflows/docs.yml) is the only workflow
that invokes npm, and it runs on pushes to `main`, after a release, or on
manual dispatch.
It has no `pull_request` trigger, so a pull request never builds the site.
The release workflow never invokes npm, so an npm advisory cannot affect the
nl6 binary, the container image, or any signed release artifact.
Such advisories are triaged, but they are not nl6 vulnerabilities.
Where no upstream fix exists we may dismiss them with a stated reason rather
than leave them open indefinitely.
The published site is itself an artifact, and a report about the site is
welcome; its impact ceiling is the site.

This section is about **advisories in dependencies**, not about **malicious
packages**.
A compromised package in the docs build would execute in CI with write access
to the repository.
That is in scope. Report it.

## Verifying release artifacts

Release binaries, packages, the checksums file, and the container image are
signed with [cosign](https://docs.sigstore.dev/) (keyless, via GitHub OIDC) and
carry SLSA build provenance. See the **Verify a release** section of
[`RELEASING.md`](RELEASING.md) for the exact `cosign verify` /
`gh attestation verify` commands.
