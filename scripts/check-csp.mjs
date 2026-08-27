#!/usr/bin/env node
/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * check-csp.mjs — fail the docs build when a built page is missing its
 * Content-Security-Policy, or carries one that does not cover what the page
 * actually contains.
 *
 * The policy is injected by src/plugins/csp-meta.ts at postBuild time. That
 * plugin derives the inline-script hashes from the same HTML it rewrites, so
 * it cannot disagree with itself — which is exactly why this check re-derives
 * them INDEPENDENTLY here rather than importing the plugin's helper. What it
 * catches is the plugin not running at all (a Docusaurus lifecycle change, a
 * dropped entry in the config), and any post-processing step that adds an
 * inline script to the output after the plugin has already hashed it.
 *
 * Run against build/ after `npm run build`.
 */

import {createHash} from 'node:crypto';
import {readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';

const OUT_DIR = process.argv[2] ?? 'build';

// Directives whose absence would make the policy pointless. Deliberately not a
// full comparison against the plugin's string: this asserts the security
// floor, not byte equality, so tightening the policy does not mean editing two
// files in lockstep.
const REQUIRED_DIRECTIVES = [
  'default-src',
  'base-uri',
  'object-src',
  'script-src',
  'style-src',
  'frame-src',
  'form-action',
];

// The content attribute must be double-quoted: every policy worth having
// contains keyword sources like 'self', so single quotes cannot delimit it.
const CSP_META_RE =
  /<meta[^>]+http-equiv=["']?Content-Security-Policy["']?[^>]*content="([^"]+)"/i;
// `\s*` before the closing `>`: `</script >` is a valid end tag, and a regex
// that misses it ends the match late and hashes the wrong bytes.
const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const TYPE_ATTR_RE = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;
const EXECUTABLE_SCRIPT_TYPES = new Set([
  '',
  'module',
  'text/javascript',
  'application/javascript',
  'text/ecmascript',
  'application/ecmascript',
  'text/jscript',
]);

const pages = readdirSync(OUT_DIR, {recursive: true})
  .filter((entry) => entry.endsWith('.html'))
  .map((entry) => path.join(OUT_DIR, entry));

if (pages.length === 0) {
  console.error(`check-csp: no HTML found under ${OUT_DIR}/ — did the build run?`);
  process.exit(1);
}

const failures = [];

for (const page of pages) {
  const html = readFileSync(page, 'utf8');
  const meta = CSP_META_RE.exec(html);
  if (!meta) {
    failures.push(`${page}: no Content-Security-Policy meta element`);
    continue;
  }
  const policy = meta[1];

  for (const directive of REQUIRED_DIRECTIVES) {
    if (!new RegExp(`(^|;)\\s*${directive}\\s`, 'i').test(policy)) {
      failures.push(`${page}: policy is missing the ${directive} directive`);
    }
  }

  if (/script-src[^;]*'unsafe-inline'/i.test(policy)) {
    failures.push(`${page}: script-src allows 'unsafe-inline' — use hashes instead`);
  }

  // The meta only governs what the parser reaches after it.
  if (meta.index > html.search(/<script|<link[^>]+rel=["']?stylesheet/i)) {
    failures.push(`${page}: CSP meta appears after a script or stylesheet it should govern`);
  }

  for (const match of html.matchAll(SCRIPT_RE)) {
    const attrs = match[1] ?? '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    const typeMatch = TYPE_ATTR_RE.exec(attrs);
    const type = (typeMatch?.[1] ?? typeMatch?.[2] ?? typeMatch?.[3] ?? '')
      .trim()
      .toLowerCase();
    if (!EXECUTABLE_SCRIPT_TYPES.has(type)) continue;
    const digest = createHash('sha256').update(match[2] ?? '', 'utf8').digest('base64');
    if (!policy.includes(`'sha256-${digest}'`)) {
      failures.push(
        `${page}: inline script not covered by script-src ` +
          `(expected 'sha256-${digest}'): ${(match[2] ?? '').trim().slice(0, 60)}…`,
      );
    }
  }
}

if (failures.length > 0) {
  console.error(`check-csp: ${failures.length} problem(s) in ${pages.length} page(s):`);
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(`check-csp: OK — ${pages.length} pages carry an enforceable CSP`);
