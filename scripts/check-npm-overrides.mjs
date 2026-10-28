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
 *   - Both sides must start from the same lockfile, in the same run. Reading
 *     the "with" side straight from the committed package-lock.json compares a
 *     lock resolved at some past date against a resolution done today, so
 *     ordinary registry drift reads as "load-bearing". Resolving both sides
 *     from no lockfile at all answers a different question: what a brand-new
 *     install would pick. That tree can contain newer consumers than the
 *     committed one. A fresh resolve picked mermaid 12, which already accepts a
 *     patched katex, so the katex override read as inert while the committed
 *     mermaid 11 still needed it. Seeding both sides with the committed lock
 *     asks the real question: what happens to the shipped tree if the
 *     overrides go.
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
 * Always exits 0. The pure parts are exported for check-npm-overrides.test.mjs.
 */

import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const NM = 'node_modules/';

// An override key may carry a version selector ("undici@>=5 <8"). Matching the
// raw key against install paths finds nothing on either side, and two empty
// lists compare equal, so the entry read as inert while it was load-bearing.
// The first `@` after position 0 starts the selector; position 0 is a scope.
export function packageName(key) {
  const at = key.indexOf('@', 1);
  return at === -1 ? key : key.slice(0, at);
}

// Flatten to the leaf package whose version an entry forces:
//   "uuid": "^11"                     -> { label: 'uuid',          name: 'uuid' }
//   "sockjs": { "uuid": "^11" }       -> { label: 'sockjs>uuid',   name: 'uuid' }
//   "undici@>=5 <8": "8.10.2"         -> { label: 'undici@>=5 <8', name: 'undici' }
//   "cheerio": { ".": "1.2.1", … }    -> { label: 'cheerio>.',     name: 'cheerio' }
// npm's "." child key overrides the parent package itself.
export function overrideEntries(overrides) {
  const entries = [];
  for (const [key, value] of Object.entries(overrides)) {
    if (typeof value === 'string') {
      entries.push({ label: key, name: packageName(key), range: value });
    } else {
      for (const [child, range] of Object.entries(value)) {
        if (typeof range === 'string') {
          const name = packageName(child === '.' ? key : child);
          entries.push({ label: `${key}>${child}`, name, range });
        }
      }
    }
  }
  return entries;
}

/**
 * Classify one entry from its install paths with and without overrides.
 * Absent on both sides means the audit cannot see the package, not that the
 * entry is harmless, so it is never offered for removal.
 */
export function classify(withPaths, withoutPaths) {
  if (withPaths.length === 0 && withoutPaths.length === 0) return 'unresolved';
  return withPaths.join('|') === withoutPaths.join('|') ? 'inert' : 'load-bearing';
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
export function pathsFor(all, name) {
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
 * stripped, starting from the committed lockfile when there is one, and return
 * its install-path map. `--package-lock-only` runs npm's resolver against the
 * registry without downloading ~1400 tarballs.
 */
function resolve(pkg, withOverrides) {
  const dir = mkdtempSync(join(tmpdir(), 'nl6-override-audit-'));
  try {
    const manifest = { ...pkg };
    if (!withOverrides) delete manifest.overrides;
    writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest, null, 2));
    if (existsSync('package-lock.json')) copyFileSync('package-lock.json', join(dir, 'package-lock.json'));
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

function main() {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  const entries = overrideEntries(pkg.overrides ?? {});

  if (entries.length === 0) {
    console.log('no overrides declared — nothing to audit');
    return;
  }

  console.log('resolving twice (with and without overrides; network, no install)…\n');

  let withOv;
  let withoutOv;
  try {
    withOv = resolve(pkg, true);
    withoutOv = resolve(pkg, false);
  } catch (err) {
    // No process.exit() inside the try: it terminates synchronously without
    // unwinding, so resolve()'s finally would never remove the temp dir.
    console.error(`could not resolve: ${err.message}`);
    const stderr = err.stderr?.toString().trim();
    if (stderr) console.error(stderr);
    console.error('\naudit skipped (report-only, not a failure)');
    return;
  }

  const inert = [];
  const unresolved = [];
  const pad = Math.max(...entries.map((e) => e.label.length + e.range.length + 1));
  const column = { 'load-bearing': 'load-bearing', inert: 'INERT       ', unresolved: 'UNRESOLVED  ' };

  for (const entry of entries) {
    const a = pathsFor(withOv, entry.name);
    const b = pathsFor(withoutOv, entry.name);
    const cls = classify(a, b);
    if (cls === 'inert') inert.push(entry);
    if (cls === 'unresolved') unresolved.push(entry);
    const head = `${entry.label} ${entry.range}`.padEnd(pad);
    console.log(`  ${column[cls]}  ${head}  with: ${fmt(a)}  without: ${fmt(b)}`);
  }

  console.log();
  const bearing = entries.length - inert.length - unresolved.length;
  if (bearing === entries.length) {
    console.log(`✓ all ${entries.length} override(s) are load-bearing`);
    return;
  }
  console.log(
    `${bearing} of ${entries.length} override(s) are load-bearing, ` +
      `${inert.length} inert, ${unresolved.length} unresolved`
  );
  for (const e of unresolved) {
    console.log(`  ? ${e.label}: package "${e.name}" resolved on neither side; check the key`);
  }
  if (inert.length > 0) {
    console.log('\nInert, can be removed:');
    for (const e of inert) console.log(`    - ${e.label}`);
    console.log(
      '\nAfter removing one, regenerate the lockfile and confirm the resolved\n' +
        'versions did not move. Report-only: this never fails the build.'
    );
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
