#!/usr/bin/env node
/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * check-npm-overrides.mjs — report which package.json `overrides` entries
 * still change dependency resolution.
 *
 * An override is added to force a patched version of a transitive dep. Once
 * upstream catches up, the entry becomes inert: it no longer changes anything,
 * but it is still a version ceiling npm and Dependabot must respect, so it
 * silently blocks the upgrade it was once meant to deliver. Nothing in the
 * normal workflow prompts anyone to remove one — seven of nine entries had gone
 * inert before this script existed.
 *
 * Method: resolve the tree twice — once as-is, once with the `overrides` block
 * stripped — and diff the resolved version *set* per overridden name. Sets, not
 * single versions, because dropping a global override can split one hoisted
 * copy into several.
 *
 * REPORT-ONLY, and deliberately not a CI gate. Its result depends on the state
 * of the npm registry rather than on the commit under test, so the same commit
 * can pass today and fail tomorrow with nobody having changed anything — a
 * check that goes red on its own trains reviewers to ignore it. An entry going
 * inert is also good news (upstream caught up), warranting a cleanup PR rather
 * than a broken build. Contrast check-doc-orphans.mjs, which *is* a hard gate
 * because an orphaned doc is a deterministic property of the commit.
 *
 * Always exits 0.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const overrides = pkg.overrides ?? {};

// Flatten to the leaf package whose version an entry actually forces:
//   "uuid": "^11"                  -> uuid            (global)
//   "sockjs": { "uuid": "^11" }    -> sockjs>uuid     (scoped)
const entries = [];
for (const [key, value] of Object.entries(overrides)) {
  if (typeof value === 'string') {
    entries.push({ label: key, name: key, range: value });
  } else {
    for (const [child, range] of Object.entries(value)) {
      if (typeof range === 'string') {
        entries.push({ label: `${key}>${child}`, name: child, range });
      }
    }
  }
}

if (entries.length === 0) {
  console.log('no overrides declared — nothing to audit');
  process.exit(0);
}

/** Resolved version set per package name, from a lockfile on disk. */
function resolvedVersions(lockPath) {
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  const out = new Map();
  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    if (!path) continue;
    const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
    if (!out.has(name)) out.set(name, new Set());
    out.get(name).add(meta.version);
  }
  return out;
}

const withOverrides = resolvedVersions('package-lock.json');

// Resolve a copy of the manifest with `overrides` stripped. --package-lock-only
// runs npm's resolver against the registry without downloading ~1400 tarballs.
const tmp = mkdtempSync(join(tmpdir(), 'nl6-override-audit-'));
let without;
try {
  const stripped = { ...pkg };
  delete stripped.overrides;
  writeFileSync(join(tmp, 'package.json'), JSON.stringify(stripped, null, 2));
  console.log('resolving without overrides (network, no install)…\n');
  execFileSync('npm', ['install', '--package-lock-only', '--no-audit', '--no-fund'], {
    cwd: tmp,
    stdio: 'ignore',
  });
  without = resolvedVersions(join(tmp, 'package-lock.json'));
} catch (err) {
  console.error(`could not resolve without overrides: ${err.message}`);
  console.error('(needs network access — skipping audit)');
  process.exit(0);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

const fmt = (set) => (set ? [...set].sort().join(', ') : '—');
const inert = [];
const pad = Math.max(...entries.map((e) => e.label.length + e.range.length + 1));

for (const entry of entries) {
  const a = withOverrides.get(entry.name);
  const b = without.get(entry.name);
  const same = fmt(a) === fmt(b);
  if (same) inert.push(entry);
  const head = `${entry.label} ${entry.range}`.padEnd(pad);
  console.log(
    `  ${same ? 'INERT       ' : 'load-bearing'}  ${head}  with: ${fmt(a)}  without: ${fmt(b)}`
  );
}

console.log();
if (inert.length === 0) {
  console.log(`✓ all ${entries.length} override(s) are load-bearing`);
} else {
  console.log(`${inert.length} of ${entries.length} override(s) are inert and can be removed:`);
  for (const e of inert) console.log(`    - ${e.label}`);
  console.log(
    '\nRemoving an inert entry must not move the lockfile — regenerate and ' +
      'confirm zero version changes. Report-only: this never fails the build.'
  );
}
