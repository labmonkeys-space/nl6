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
 * Method: resolve the tree twice from the *same* manifest — once with the
 * `overrides` block, once without — and diff the resolved install paths for
 * each overridden package.
 *
 * Two details that a naive implementation gets wrong:
 *
 *   - Both sides must be resolved fresh, in the same run. Reading the "with"
 *     side from the committed package-lock.json compares a lock resolved at
 *     some past date (possibly under a different overrides block) against a
 *     resolution done today, so ordinary registry drift reads as
 *     "load-bearing".
 *
 *   - The diff must be per install *path*, not per package name. A scoped
 *     override (`"sockjs": {"uuid": …}`) only changes where a copy is placed:
 *     if another consumer independently resolves the same version the override
 *     forces, the set of versions is identical with and without it, and the
 *     entry looks inert while genuinely holding an advisory fix in place.
 *     Comparing paths catches the nested copy appearing or disappearing.
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

const NM = 'node_modules/';
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const overrides = pkg.overrides ?? {};

// Flatten to the leaf package whose version an entry forces:
//   "uuid": "^11"                  -> { label: 'uuid',        name: 'uuid' }
//   "sockjs": { "uuid": "^11" }    -> { label: 'sockjs>uuid', name: 'uuid' }
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

/**
 * Map of install path -> version for every package in a lockfile.
 * Skips workspace/link entries (bare directory paths with no `node_modules/`
 * segment) and anything without a concrete version, so a future workspace
 * cannot produce nonsense keys.
 */
function resolvedPaths(lockPath) {
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  const out = new Map();
  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    if (!path || !path.includes(NM) || !meta?.version) continue;
    out.set(path, meta.version);
  }
  return out;
}

/** Install paths for one package name, as a sorted "path@version" list. */
function pathsFor(all, name) {
  const suffix = NM + name;
  return [...all.entries()]
    .filter(([path]) => path === suffix || path.endsWith('/' + suffix))
    .map(([path, version]) => `${path}@${version}`)
    .sort();
}

/** Render for humans: hoisted copies as a bare version, nested as `parent:version`. */
function fmt(list) {
  if (list.length === 0) return '—';
  return list
    .map((entry) => {
      const at = entry.lastIndexOf('@');
      const [path, version] = [entry.slice(0, at), entry.slice(at + 1)];
      const inner = path.lastIndexOf(NM);
      const parent = inner > 0 ? path.slice(0, inner - 1).split(NM).pop() : null;
      return parent ? `${parent}:${version}` : version;
    })
    .sort()
    .join(', ');
}

/**
 * Resolve the manifest in a temp dir, optionally with the overrides block
 * stripped, and return its install-path map. `--package-lock-only` runs npm's
 * resolver against the registry without downloading ~1400 tarballs.
 */
function resolve(withOverrides) {
  const dir = mkdtempSync(join(tmpdir(), 'nl6-override-audit-'));
  try {
    const manifest = { ...pkg };
    if (!withOverrides) delete manifest.overrides;
    writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest, null, 2));
    execFileSync('npm', ['install', '--package-lock-only', '--no-audit', '--no-fund'], {
      cwd: dir,
      // Capture stderr so a malformed manifest, an auth failure or a missing
      // npm is reported as itself rather than misattributed to "no network".
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    return resolvedPaths(join(dir, 'package-lock.json'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log('resolving twice (with and without overrides; network, no install)…\n');

let withOv;
let withoutOv;
try {
  withOv = resolve(true);
  withoutOv = resolve(false);
} catch (err) {
  // No process.exit() inside the try: it terminates synchronously without
  // unwinding, so resolve()'s finally would never remove the temp dir.
  console.error(`could not resolve: ${err.message}`);
  const stderr = err.stderr?.toString().trim();
  if (stderr) console.error(stderr);
  console.error('\naudit skipped (report-only, not a failure)');
  withOv = null;
}

if (withOv) {
  const inert = [];
  const pad = Math.max(...entries.map((e) => e.label.length + e.range.length + 1));

  for (const entry of entries) {
    const a = pathsFor(withOv, entry.name);
    const b = pathsFor(withoutOv, entry.name);
    const same = a.join('|') === b.join('|');
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
      '\nAfter removing one, regenerate the lockfile and confirm the resolved\n' +
        'versions did not move. Report-only: this never fails the build.'
    );
  }
}
