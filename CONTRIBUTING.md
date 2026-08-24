# Contributing to nl6

Thanks for your interest in nl6. This document covers the essentials for
getting a change merged.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Start from an issue

Work starts from a GitHub issue, not a drive-by PR. Before you write code:

- Search [existing issues](https://github.com/labmonkeys-space/nl6/issues) for
  the bug or feature.
- If none exists, open one (bug report or enhancement) so the change can be
  discussed and scoped.
- Reference the issue from your PR with a closing keyword (`Closes #123`).

For security problems, **do not** open a public issue — see
[SECURITY.md](SECURITY.md).

## Develop

nl6 is a Go simulator; the docs site is Docusaurus. CI runs `make` targets, so
use the same ones locally.

```sh
# Build the simulator
cd go/nl6 && go mod tidy && go build -o nl6 .

# Run the full test suite
cd go && go test ./...

# Run a single test
go test ./nl6/ -run TestSomething
```

See [CLAUDE.md](CLAUDE.md) for the full build/run reference (flags, architecture,
conventions). Running the simulator needs root for TUN/network-namespace setup.

Before pushing, run the same quality gates CI does:

```sh
make fmt-check   # gofmt + goimports
make lint        # golangci-lint
```

`make lint` pins `GOOS=linux` deliberately. The simulator is Linux-only and much
of it — including whole test files — sits behind `//go:build linux`, so linting
with a macOS host's own GOOS analyses a different build than CI and reports
findings CI will never see. The target also retries once with a clean analysis
cache on failure, because a stale cache can invent findings that do not exist.

New and edited source files carry an SPDX license header — see the "Source file
headers" section of [CLAUDE.md](CLAUDE.md) for the exact form (forked upstream
files keep their original Apache header).

## Commit

Follow [Conventional Commits](https://www.conventionalcommits.org/):
`<type>[scope]: <description>`, where `type` is one of `feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`. Breaking
changes append `!` or add a `BREAKING CHANGE:` footer.

Every commit needs two trailers, in this order:

```
Assisted-by: <Agent>:<model> [optional tools]
Signed-off-by: Your Name <you@example.com>
```

- **`Signed-off-by`** is the [Developer Certificate of Origin](https://developercertificate.org/)
  sign-off. Add it with `git commit -s`, using your real name and email. It
  certifies you have the right to submit the code under the project's license.
  **The DCO check is enforced on every commit** — a PR with an unsigned commit
  cannot merge.
- **`Assisted-by`** is required when a commit was written with AI assistance
  (e.g. `Assisted-by: ClaudeCode:claude-opus-4-8`). The human signer remains
  responsible for reviewing the change and for license compliance — the
  `Assisted-by` trailer records the tool, the `Signed-off-by` records the
  accountable human. Omit it for fully hand-written commits.

## Open a pull request

- Keep PRs focused — one logical change, separately reviewable.
- Fill in the [PR template](.github/pull_request_template.md); include the
  `Closes #<issue>` line.
- CI must be green: build, tests, and code quality all run as required checks,
  plus dependency review and Actions linting. `main` is protected and
  squash-merged.
- Update docs in the same PR as the behaviour they describe (a pipeline change
  updates `RELEASING.md`; a flag change updates `CLAUDE.md`).

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license this project ships under.
