#!/usr/bin/env node
/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * inject-csp.mjs injects a Content-Security-Policy into every built HTML page.
 *
 * Usage: node scripts/inject-csp.mjs <build-dir>
 * Run by `npm run build` after `docusaurus build` has exited.
 *
 * Why a separate step and not a Docusaurus plugin: Docusaurus runs every
 * plugin's postBuild concurrently (Promise.all), so the order plugins are
 * listed in only decides which hook starts first. A plugin that scans the
 * output in postBuild can therefore miss pages another plugin is still
 * writing. The client-redirect stubs were missed that way under Node 26.
 * Once `docusaurus build` has exited, every postBuild has finished, so every
 * page exists.
 *
 * The site is served by GitHub Pages (see static/CNAME), which sends a fixed
 * set of response headers and offers no way to add our own. A `<meta
 * http-equiv>` policy is therefore the only delivery mechanism available
 * short of putting a proxy in front of the apex.
 *
 * Consequences of meta delivery, all deliberate:
 *   - `frame-ancestors`, `report-uri`/`report-to` and `sandbox` are IGNORED in
 *     a meta policy (browsers warn about them on the console), so they are not
 *     emitted. Clickjacking defence still needs a real header. It cannot be
 *     fixed from this repo.
 *   - The policy only governs what the parser reaches AFTER the meta element,
 *     so it is inserted immediately after `<meta charset>`. That puts it
 *     before the font stylesheet and before every script.
 *
 * script-src carries hashes rather than 'unsafe-inline': Docusaurus emits two
 * executable inline scripts (the colour-mode initialiser on every page and the
 * base-url misconfiguration banner on the landing page), and every redirect
 * stub carries its own. Hashes are computed from the emitted HTML after the
 * build rather than pinned in the config, so a Docusaurus upgrade that changes
 * any of these scripts cannot silently break the site. The
 * `application/ld+json` blocks Docusaurus also emits are data, not script,
 * and are not subject to script-src.
 *
 * style-src keeps 'unsafe-inline' and cannot drop it: prism-react-renderer
 * emits a `style` attribute per syntax-highlighted token (~8k of them across
 * the site) and Mermaid injects a `<style>` element per rendered diagram.
 *
 * scripts/check-csp.mjs verifies the result and fails `make docs-build` when
 * any page lacks an enforceable policy.
 */

import { createHash } from 'node:crypto';
import { readdir, readFile, stat, writeFile } from 'node:fs/promises';
import * as path from 'node:path';

const LOG_PREFIX = 'inject-csp';

// The one external origin the site loads from: the landing page pulls Inter
// and JetBrains Mono from Google Fonts (stylesheet from googleapis, the font
// files it references from gstatic).
const GOOGLE_FONTS_CSS = 'https://fonts.googleapis.com';
const GOOGLE_FONTS_FILES = 'https://fonts.gstatic.com';

// An end tag is `</` + name + anything up to `>`: the HTML parser accepts
// `</script >` and also `</script foo="bar">`, discarding the attributes
// (WHATWG §13.2.5.10). A regex that insists on `</script>`, or on `\s*>`,
// ends the match at the wrong place and hashes the wrong bytes, which for a
// hash allowlist means the browser blocks the script. Requiring whitespace
// after the name keeps `</scriptfoo>` from matching, since that is not an
// end tag.
const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script(?:\s[^>]*)?>/gi;
const TYPE_ATTR_RE = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;
const SRC_ATTR_RE = /\bsrc\s*=/i;
const CHARSET_META_RE = /<meta[^>]*\bcharset\s*=[^>]*>/i;
const HEAD_OPEN_RE = /<head\b[^>]*>/i;
// The lookahead keeps Content-Security-Policy-Report-Only from matching.
const CSP_META_RE = /<meta[^>]*\bhttp-equiv\s*=\s*["']?content-security-policy(?=["'\s>])/i;

// A `<script>` is only subject to script-src when the browser would execute
// it. Anything with another type (notably application/ld+json) is a data
// block. Empty type and a legacy `language=`-only tag both mean JavaScript.
const EXECUTABLE_SCRIPT_TYPES = new Set([
  '',
  'module',
  'text/javascript',
  'application/javascript',
  'text/ecmascript',
  'application/ecmascript',
  'text/jscript',
]);

/** sha256 CSP source expressions for every executable inline script in `html`. */
function inlineScriptHashes(html) {
  const hashes = [];
  for (const match of html.matchAll(SCRIPT_RE)) {
    const attrs = match[1] ?? '';
    if (SRC_ATTR_RE.test(attrs)) continue; // external script, covered by 'self'
    const typeMatch = TYPE_ATTR_RE.exec(attrs);
    const type = (typeMatch?.[1] ?? typeMatch?.[2] ?? typeMatch?.[3] ?? '')
      .trim()
      .toLowerCase();
    if (!EXECUTABLE_SCRIPT_TYPES.has(type)) continue;
    const digest = createHash('sha256').update(match[2] ?? '', 'utf8').digest('base64');
    hashes.push(`'sha256-${digest}'`);
  }
  return hashes;
}

/**
 * The policy. Every page carries the same one, including the union of inline
 * script hashes across the build, because the site is a single-page app: after
 * a client-side navigation the ENTRY page's policy is still the one in force,
 * so a per-page policy would not be the policy actually enforced on that page.
 */
function buildPolicy(scriptHashes) {
  return [
    // Everything not named below: same origin only.
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-src 'none'",
    "form-action 'self'",
    `script-src 'self' ${scriptHashes.join(' ')}`,
    `style-src 'self' 'unsafe-inline' ${GOOGLE_FONTS_CSS}`,
    `font-src 'self' data: ${GOOGLE_FONTS_FILES}`,
    // data: for the SVG icons Infima references from CSS backgrounds.
    "img-src 'self' data:",
    "connect-src 'self'",
    'upgrade-insecure-requests',
  ].join('; ');
}

function injectMeta(html, policy, page) {
  const meta = `<meta http-equiv="Content-Security-Policy" content="${policy}">`;
  // After `<meta charset>` so the encoding declaration stays inside the first
  // 1024 bytes, but before any resource the policy has to govern.
  const charset = CHARSET_META_RE.exec(html);
  if (charset) {
    const at = charset.index + charset[0].length;
    return html.slice(0, at) + meta + html.slice(at);
  }
  const head = HEAD_OPEN_RE.exec(html);
  if (head) {
    const at = head.index + head[0].length;
    return html.slice(0, at) + meta + html.slice(at);
  }
  throw new Error(`${LOG_PREFIX}: no <head> to inject the CSP meta into: ${page}`);
}

async function main(outDir) {
  if (!outDir) throw new Error(`${LOG_PREFIX}: usage: node scripts/inject-csp.mjs <build-dir>`);
  const info = await stat(outDir).catch(() => null);
  if (!info?.isDirectory()) throw new Error(`${LOG_PREFIX}: build directory not found: ${outDir}`);

  const entries = await readdir(outDir, { recursive: true });
  const pages = entries
    .filter((entry) => entry.endsWith('.html'))
    .map((entry) => path.join(outDir, entry));
  // An empty directory would "succeed" by injecting nothing.
  if (pages.length === 0) throw new Error(`${LOG_PREFIX}: no HTML pages under ${outDir}`);

  const sources = new Map();
  const hashes = new Set();
  for (const page of pages) {
    const html = await readFile(page, 'utf8');
    // A second run would stack a second policy, and the browser enforces both.
    if (CSP_META_RE.test(html)) {
      throw new Error(`${LOG_PREFIX}: ${page} already carries a CSP; rebuild before injecting`);
    }
    sources.set(page, html);
    for (const hash of inlineScriptHashes(html)) hashes.add(hash);
  }

  const policy = buildPolicy([...hashes].sort());
  await Promise.all(
    [...sources].map(([page, html]) => writeFile(page, injectMeta(html, policy, page), 'utf8')),
  );

  console.log(
    `[${LOG_PREFIX}] CSP injected into ${pages.length} pages ` +
      `(${hashes.size} inline script hashes)`,
  );
}

main(process.argv[2]).catch((err) => {
  console.error(err.message);
  process.exit(1);
});
