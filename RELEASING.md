# Releasing nl6

There are only two things to know:

- **Stable releases are tag-driven.** Pushing a `vMAJOR.MINOR.PATCH` tag
  (e.g. `v0.3.2`) to `main` runs `.github/workflows/release.yml`: it builds
  Linux amd64/arm64 binaries, publishes a GitHub Release with
  auto-generated notes, and pushes a multi-platform Docker image to
  `ghcr.io/labmonkeys-space/nl6:<tag>` and the floating `:latest`
  alias. The public landing page advertises this version.
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
| Release notes on GitHub             | `softprops/action-gh-release` auto      | maintainer may edit post-hoc|
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
landing page are never affected by pre-release activity.

## After you tag

Watch the two workflows that run in sequence:

1. **`Release`** (`.github/workflows/release.yml`) — triggered by the tag push.
   Builds binaries, creates the GH Release, publishes the Docker image. Expect
   ~5–10 min.
2. **`Docs`** (`.github/workflows/docs.yml`) — triggered via `workflow_run`
   after `Release` succeeds. Rebuilds the Docusaurus site and deploys to
   `gh-pages`. The landing-page hero eyebrow will now read `vX.Y.Z`.

Verify:

- [ ] GitHub Release exists with the correct tag and attached
      `nl6-linux-amd64` + `nl6-linux-arm64` binaries.
- [ ] Release notes are acceptable — edit on GitHub if the auto-generated
      content bundled in too much noise.
- [ ] `ghcr.io/labmonkeys-space/nl6:vX.Y.Z` and `:latest` both updated
      (check the "Packages" panel on the repo page).
- [ ] <https://labmonkeys-space.github.io/nl6/> hero eyebrow shows
      `vX.Y.Z · Apache-2.0 · Go <minor>`. If the site didn't refresh,
      retrigger the docs workflow manually:
      `gh workflow run docs.yml --repo labmonkeys-space/nl6`.

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
  main pushes in `ci.yml`; there is no corresponding tag to cut.
