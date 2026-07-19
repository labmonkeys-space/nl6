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
 */

import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// Docs intentionally excluded from every sidebar (none today). Add an id here
// with a reason if a standalone page is ever linked only from the navbar.
const ALLOWLIST = new Set([]);

const sidebars = readFileSync('sidebars.ts', 'utf8');

// git-tracked doc files under docs/ — matches exactly what CI checks out and
// builds (untracked scratch files are ignored, as they are by the build).
const files = execSync('git ls-files docs', { encoding: 'utf8' })
  .split('\n')
  .filter((f) => /\.mdx?$/.test(f));

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

console.log(`✓ all ${files.length} doc page(s) are referenced in sidebars.ts`);
