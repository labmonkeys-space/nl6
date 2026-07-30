# Releasing nl6

There are only two things to know:

- **Stable releases are tag-driven.** Pushing a `vMAJOR.MINOR.PATCH` tag
  (e.g. `v0.3.2`) to `main` runs `.github/workflows/release.yml`: it runs the
  quality gates, builds the Linux amd64/arm64 simulator binaries + the
  cross-platform `nl6-reconcile` CLI + `.deb`/`.rpm` packages, **cosign-signs**
  the checksums file and the container image (keyless, via GitHub OIDC),
  generates an **SBOM** (syft — SPDX JSON plus a self-contained HTML report)
  and **SLSA build provenance**, creates a
  **draft** GitHub Release with everything attached, and pushes a
  multi-platform image to `ghcr.io/labmonkeys-space/nl6:<tag>` and the floating
  `:latest`. A maintainer then curates the notes, verifies the signatures, and
  **publishes** the draft. The public landing page advertises this version.
  **Prerelease tags** (`v…-rc1`, `-beta`, …) are excluded from the trigger —
  they never release and never move `:latest`.
- **Release candidates are `main`.** Every push to `main` runs
  `.github/workflows/ci.yml`, which (on success) publishes the floating
  Docker image `ghcr.io/labmonkeys-space/nl6:rc`. There are **no
  RC git tags, no numbered RCs, no pre-release GitHub Releases** — `:rc`
  always reflects the latest main and testers pull it to exercise
  unreleased work. The landing page is unaffected.

The docs site (`.github/workflows/docs.yml`) rebuilds after each successful
Release run so the landing-page hero eyebrow
(`v<stable-version> · Apache-2.0 · Go <minor>`) tracks the latest tag.

Values that used to drift between releases are now derived at build time:

| Value                               | Source                                  | Who updates it              |
| ----------------------------------- | --------------------------------------- | --------------------------- |
| App version on landing page         | `git describe --tags --abbrev=0`        | **automatic**               |
| Go version on landing page          | parsed from `go/go.mod`                 | **automatic**               |
| License on landing page             | constant in `docusaurus.config.ts`      | only on license change      |
| GitHub Release (draft)              | `softprops/action-gh-release` (`draft: true`) | **maintainer publishes** after curating notes + verifying signatures |
| Cosign signatures + SBOM + provenance | `release.yml` (cosign keyless, syft + blitsbom HTML report, attest-build-provenance) | **automatic**       |
| Docker `:latest` tag on GHCR        | pushed by `release.yml` on stable tag   | **automatic**               |
| Docker `:rc` tag on GHCR            | pushed by `ci.yml` on every main push   | **automatic**               |
| `.deb` / `.rpm` package version     | `APP_VERSION` (= tag) → `make packages` | **automatic**               |
| Nix package version                 | hardcoded in `deploy/packages/nix/package.nix` | **manual bump before tagging** (asserted in `release.yml`) |

The checklist below covers only what a human still has to decide or verify.

## Before you tag

1. **`main` is green.** Check the `CI` status on the most recent commit
   (`Release` only runs after a tag push, so it has nothing to report yet).
   Don't release on a red main.
2. **No release-blocking PRs open.** Skim
   [`gh pr list --repo labmonkeys-space/nl6`](https://github.com/labmonkeys-space/nl6/pulls)
   for anything labelled `release-blocker` or in-flight that should ship
   together with the tag.
3. **Pick a version.** Follow [SemVer](https://semver.org/):
   - `MAJOR` — breaking CLI flag or HTTP API changes
   - `MINOR` — new device types, new protocols, new flags that default off
   - `PATCH` — bug fixes, doc-only changes, no behavioural surprises
   Check the last tag with `git describe --tags --abbrev=0` and increment.
4. **Bump the Nix package version.** Run the release helper and commit the
   result to `main` **before** tagging:

   ```sh
   make set-nix-version APP_VERSION=vX.Y.Z
   git commit -s deploy/packages/nix/package.nix -m "chore(release): nix vX.Y.Z"
   ```

   This writes `X.Y.Z` into
   [`deploy/packages/nix/package.nix`](deploy/packages/nix/package.nix) from the
   same `APP_VERSION` the deb/rpm/Docker artifacts use — no hand-editing. Nix is
   the *only* package whose version isn't derived from the tag at build time (a
   flake can't read the git tag), so this string is committed; `release.yml`
   asserts it equals the tag and fails the release if it drifts. The `.deb`/
   `.rpm` and Docker versions need no edit. Note: `vendorHash` in the same file
   is **not** a release step — only touch it when `go.mod`/`go.sum` changes.
5. **Optional: skim the auto-generated release notes.** On GitHub, draft a
   release against `main` without publishing to preview what
   `generate_release_notes: true` will produce. If the output is noisy (lots
   of `chore:` / `docs:` commits drowning out user-visible changes), plan to
   edit the notes post-publish.

## Cut a release

Annotated tags don't need their own sign-off — DCO is enforced per-commit on
`main`, not on the tag object.

```sh
# Fetch the latest main
git checkout main
git pull --ff-only

# Create an annotated tag (annotated, not lightweight — we want metadata)
git tag -a vX.Y.Z -m "vX.Y.Z"

# Push the tag to origin — this is what fires release.yml
git push origin vX.Y.Z
```

## Exercising pre-release changes

There is no separate RC release step. Every merge to `main` triggers
`ci.yml`, which on success publishes `ghcr.io/labmonkeys-space/nl6:rc`.
Testers who want the latest unreleased work pull:

```sh
docker pull ghcr.io/labmonkeys-space/nl6:rc
```

The `:rc` tag is always overwritten in place — it points at whatever `main`
last built successfully. There are no immutable pre-release tags; rollback
to a specific pre-release commit is via `@<sha256:...>` digest on the image
or by rebuilding from the corresponding `main` commit. `:latest` and the
landing page are never affected by pre-release activity. And should a
prerelease tag (`v…-rc1`, `-beta`, …) ever be pushed by accident, the Release
trigger's `!v*-*` filter ignores it — no release, no moved `:latest`.

## After you tag

Watch the two workflows that run in sequence:

1. **`Release`** (`.github/workflows/release.yml`) — triggered by the tag push.
   Builds binaries, creates the GH Release, publishes the Docker image. Expect
   ~5–10 min.
2. **`Docs`** (`.github/workflows/docs.yml`) — triggered via `workflow_run`
   after `Release` succeeds. Rebuilds the Docusaurus site and deploys to
   `gh-pages`. The landing-page hero eyebrow will now read `vX.Y.Z`.

The Release is created as a **draft** — review it, verify the artifacts, then
publish:

- [ ] The draft Release has the correct tag and attaches the binaries
      (`nl6-linux-amd64/arm64`, `nl6-reconcile-<os>-<arch>`), `.deb`/`.rpm`,
      `checksums.txt` + `checksums.txt.cosign.bundle`, `nl6.sbom.spdx.json`, and
      `nl6.sbom.report.html` (open it — it is the readable view of the SPDX JSON
      and needs no tooling).
- [ ] **Verify the signatures + provenance** (see the next section). Do this on
      the draft assets before publishing.
- [ ] **Product-SBOM sanity** — `nl6.sbom.spdx.json` describes the shipped binary, not the repo.
      Check: the main module `github.com/labmonkeys-space/nl6/go` carries the tag's version, no package has version `UNKNOWN`, there are zero npm packages, and no package has `licenseConcluded: NOASSERTION` (syft concludes cache-resolved modules; the main module, stdlib, and the file-root package are filled by `make sbom-curate`, which fails the release if they go missing).
      Note `licenseDeclared` stays `NOASSERTION` on most Go modules by design — buildinfo carries no declarations — so grep the concluded field, not the whole file.
      The website has its own SBOM, retained as a workflow artifact (`nl6-website-sbom`) on each docs-deploy run — it is not a release asset and deliberately not published on the site.
- [ ] Curate the release notes — the auto-generated list is a starting point;
      trim `chore:`/`docs:`/deps noise down to user-visible highlights.
      One-time, first release after 2026-07-30: call out that `nl6.sbom.spdx.json` narrowed from a whole-repo scan (~1,400 packages, mostly the docs toolchain) to the shipped binary's modules; anyone consuming the npm inventory moves to the website SBOM. Delete this line once shipped.
- [ ] `ghcr.io/labmonkeys-space/nl6:vX.Y.Z` and `:latest` both updated
      (check the "Packages" panel on the repo page).
- [ ] **Publish** the draft:

      ```sh
      gh release edit vX.Y.Z --draft=false --repo labmonkeys-space/nl6
      ```

- [ ] <https://labmonkeys-space.github.io/nl6/> hero eyebrow shows
      `vX.Y.Z · Apache-2.0 · Go <minor>`. If the site didn't refresh,
      retrigger the docs workflow manually:
      `gh workflow run docs.yml --repo labmonkeys-space/nl6`.

## Verify a release

Signatures are **keyless** (Sigstore + GitHub OIDC); there is no long-lived
public key. Verification pins the signing identity to this repo's release
workflow and the GitHub Actions OIDC issuer.

```sh
IDENTITY='^https://github.com/labmonkeys-space/nl6/.github/workflows/release.yml@refs/tags/v.*$'
ISSUER='https://token.actions.githubusercontent.com'

# 1. Checksums file (cosign sign-blob, new bundle format). Then check the
#    artifacts against it.
cosign verify-blob checksums.txt \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
sha256sum -c checksums.txt

# 2. Container image (cosign sign).
cosign verify ghcr.io/labmonkeys-space/nl6:vX.Y.Z \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

# 3. SLSA build provenance (binaries + image), via the GitHub attestation API.
#
# CAVEAT (gh 2.96.0, #343): `gh attestation verify` prints its human summary
# ONLY on a terminal. Redirect it, pipe it, or run it from a script and it
# exits 0 with zero bytes on both streams — indistinguishable from a broken
# command. Verification still ran; only the report is suppressed. So do not
# judge success by output: use --format json and extract the result, which
# prints in every context.
gh attestation verify nl6-linux-amd64 --repo labmonkeys-space/nl6 \
  --format json --jq '.[].verificationResult.statement.predicateType'
# -> https://slsa.dev/provenance/v1   (anything else, or a non-zero exit, is a failure)

gh attestation verify oci://ghcr.io/labmonkeys-space/nl6:vX.Y.Z --repo labmonkeys-space/nl6 \
  --format json --jq '.[].verificationResult.statement.predicateType'

# The full verification detail (verified identity, timestamps, all subjects)
# is in the JSON if you drop the --jq filter.
```

## Troubleshooting

**Release workflow failed halfway through.** Delete the tag and re-cut:

```sh
git push origin :refs/tags/vX.Y.Z   # delete remote tag
git tag -d vX.Y.Z                   # delete local tag
# fix the underlying issue, then tag + push again
```

Do **not** force-push over a tag whose Release was already published —
downstreams may have pulled binaries. Bump the patch version instead
(`vX.Y.Z+1`).

**Docs site shows the old version after release succeeded.** The docs workflow
is triggered by `workflow_run` which runs on the default branch context. If
`main` advanced past the release commit and the latest tag is no longer
reachable from `HEAD` (rare — would require a revert), `git describe --tags
--abbrev=0` could resolve to an earlier tag. Check
<https://github.com/labmonkeys-space/nl6/actions/workflows/docs.yml> for
the last docs run's resolved version, and retrigger manually with
`gh workflow run docs.yml` if needed.

**Need a hotfix release against an older minor.** This project currently does
not maintain release branches; all releases are cut from `main`. If that
changes, update this document.

## What is *not* a manual step

If you find yourself editing any of the following during a release, stop and
fix the automation instead — drift here is exactly what this document exists
to prevent:

- A version string hardcoded in `src/**` or `docs/**`. (The one sanctioned
  exception is `deploy/packages/nix/package.nix` — a flake genuinely cannot
  read the git tag, so its version is bumped by hand per step 4 above and
  guarded by a `release.yml` assertion.)
- A Go version hardcoded in any docs page (parse from `go/go.mod`).
- A `:latest` or `:rc` Docker tag pushed from a workstation.
- A pre-release Git tag (`-rc`, `-beta`, etc.). The `:rc` image is fed by
  main pushes in `ci.yml`; there is no corresponding tag to cut, and
  `release.yml`'s `!v*-*` trigger filter ignores one if it's pushed anyway.
