#!/usr/bin/env node
/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * check-doc-orphans.mjs — fail the docs build when a doc page is not
 * referenced in sidebars.ts. Docusaurus leaves such pages reachable only by
 * direct URL (never in the menu) and treats it as a non-fatal warning, so
 * orphans slip through unnoticed (three loadtest-* docs did). This escalates
 * that to a hard error.
 *
 * The docs plugin is configured with `path: 'docs'`, `blog: false`, and no
 * per-doc `id`/`slug` frontmatter, so a doc's id is just its path under
 * `docs/` minus the extension — which is exactly how sidebars.ts references
 * it (`'reference/x'` or `link: {id: 'reference/x'}`). We check that each
 * tracked doc's id appears as a quoted string in sidebars.ts.
 *
 * It also fails a page without a `description` in its front matter. Docusaurus
 * otherwise falls back to the first paragraph for the meta description and the
 * generated section index, which is often a warning or a code lead-in.
 *
 * Finally it fails a page that cites a tracker issue outside a code block:
 * `nl6#123`, `owner/repo#123`, `(#123)`, `issue #123`, `PR #123`, or an issue
 * or pull request URL. A reader needs the cause, not the ticket.
 */

import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// Docs intentionally excluded from every sidebar (none today). Add an id here
// with a reason if a standalone page is ever linked only from the navbar.
const ALLOWLIST = new Set([]);

const sidebars = readFileSync('sidebars.ts', 'utf8');

// Directories under docs/ that the docs plugin EXCLUDES from the site
// (docusaurus.config.ts `docs.exclude`). Files there are working documents
// (design specs, implementation plans), never pages, so they cannot be
// orphans. Keep this list in step with the config's `exclude` globs.
const EXCLUDED_DIRS = ['docs/superpowers/'];

// git-tracked doc files under docs/ — matches exactly what CI checks out and
// builds (untracked scratch files are ignored, as they are by the build).
const files = execSync('git ls-files docs', { encoding: 'utf8' })
  .split('\n')
  .filter((f) => /\.mdx?$/.test(f))
  .filter((f) => !EXCLUDED_DIRS.some((d) => f.startsWith(d)));

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const orphans = [];
for (const file of files) {
  const id = file.replace(/^docs\//, '').replace(/\.mdx?$/, '');
  if (ALLOWLIST.has(id)) continue;
  // Match the id only as a fully-quoted token so `reference/snmp` never
  // satisfies `reference/snmp-traps` (and vice-versa).
  const quoted = new RegExp(`['"\`]${escapeRe(id)}['"\`]`);
  if (!quoted.test(sidebars)) orphans.push(id);
}

if (orphans.length > 0) {
  console.error(
    `\n✗ ${orphans.length} doc page(s) are not referenced in sidebars.ts ` +
      `(orphaned — unreachable from the site menu):`
  );
  for (const id of orphans) console.error(`    - docs/${id}.md`);
  console.error(
    `\nAdd each to the matching sidebar in sidebars.ts, or (rarely) to the ` +
      `ALLOWLIST in scripts/check-doc-orphans.mjs with a reason.\n`
  );
  process.exit(1);
}

// Front matter is the block between a leading `---` line and the next one.
// CRLF files are normalised first, and a description must hold text once its
// quotes are stripped, so `description: ""` does not pass.
const frontMatter = (text) => {
  const m = text.replace(/\r\n/g, '\n').match(/^---\n([\s\S]*?)\n---\n/);
  return m ? m[1] : '';
};
const hasDescription = (fm) => {
  const m = fm.match(/^description:[ \t]*(.*)$/m);
  return m !== null && /[A-Za-z0-9]/.test(m[1].replace(/^["']|["']$/g, ''));
};
const undescribed = files.filter((f) => !hasDescription(frontMatter(readFileSync(f, 'utf8'))));
if (undescribed.length > 0) {
  console.error(
    `\n✗ ${undescribed.length} doc page(s) have no \`description\` front matter:`
  );
  for (const f of undescribed) console.error(`    - ${f}`);
  console.error(
    `\nAdd a one-sentence \`description:\` to the page's front matter.\n`
  );
  process.exit(1);
}

// Public pages cite no tracker issues; release notes keep the history.
const issueRef = new RegExp(
  [
    String.raw`\b[\w.-]+#\d+(?![\w-])`, // nl6#123, owner/repo#123, not an anchor like page.md#1-intro
    String.raw`\(#\d+\)`, // (#123)
    String.raw`\b(?:issues?|PRs?|pull requests?)\s+#\d+`, // issue #123, PR #123
    String.raw`github\.com\/[^\s)]*\/(?:issues|pull)\/\d+`,
  ].join('|'),
  'i'
);
// A fence closes only on the same character repeated at least as often as it
// opened, so a ``` sample inside a ~~~~ or ```` block does not end the block.
const fenceOpen = /^\s*(`{3,}|~{3,})/;
const withIssueRefs = [];
for (const f of files) {
  let fence = null;
  readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
    const m = line.match(fenceOpen);
    if (fence === null && m) fence = m[1];
    else if (fence !== null && m && m[1][0] === fence[0] && m[1].length >= fence.length && line.trim() === m[1]) fence = null;
    else if (fence === null && issueRef.test(line)) withIssueRefs.push(`${f}:${i + 1}`);
  });
}
if (withIssueRefs.length > 0) {
  console.error(`\n✗ ${withIssueRefs.length} issue reference(s) in public doc pages:`);
  for (const loc of withIssueRefs) console.error(`    - ${loc}`);
  console.error(`\nState the cause in words instead of citing the issue.\n`);
  process.exit(1);
}

console.log(`✓ all ${files.length} doc page(s) are referenced in sidebars.ts, carry a description, and cite no issues`);
