/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

import {createHash} from 'node:crypto';
import {readdir, readFile, writeFile} from 'node:fs/promises';
import * as path from 'node:path';
import type {Plugin} from '@docusaurus/types';

/*
 * csp-meta — inject a Content-Security-Policy into every built HTML page.
 *
 * The site is served by GitHub Pages (see static/CNAME), which sends a fixed
 * set of response headers and offers no way to add our own. A `<meta
 * http-equiv>` policy is therefore the only delivery mechanism available
 * short of putting a proxy in front of the apex.
 *
 * Consequences of meta delivery, all deliberate:
 *   - `frame-ancestors`, `report-uri`/`report-to` and `sandbox` are IGNORED in
 *     a meta policy (browsers warn about them on the console), so they are not
 *     emitted. Clickjacking defence still needs a real header — it cannot be
 *     fixed from this repo.
 *   - The policy only governs what the parser reaches AFTER the meta element,
 *     so it is inserted immediately after `<meta charset>` — before the font
 *     stylesheet, before every script.
 *
 * script-src carries hashes rather than 'unsafe-inline': Docusaurus emits two
 * executable inline scripts (the colour-mode initialiser on every page and the
 * base-url misconfiguration banner on the landing page). Hashes are computed
 * from the emitted HTML at postBuild time rather than pinned in the config, so
 * a Docusaurus upgrade that changes either script cannot silently break the
 * site. The `application/ld+json` blocks Docusaurus also emits are data, not
 * script, and are not subject to script-src.
 *
 * style-src keeps 'unsafe-inline' and cannot drop it: prism-react-renderer
 * emits a `style` attribute per syntax-highlighted token (~8k of them across
 * the site) and Mermaid injects a `<style>` element per rendered diagram.
 */

const PLUGIN_NAME = 'csp-meta';

// The one external origin the site loads from: the landing page pulls Inter
// and JetBrains Mono from Google Fonts (stylesheet from googleapis, the font
// files it references from gstatic).
const GOOGLE_FONTS_CSS = 'https://fonts.googleapis.com';
const GOOGLE_FONTS_FILES = 'https://fonts.gstatic.com';

const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
const TYPE_ATTR_RE = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;
const SRC_ATTR_RE = /\bsrc\s*=/i;
const CHARSET_META_RE = /<meta[^>]*\bcharset\s*=[^>]*>/i;
const HEAD_OPEN_RE = /<head\b[^>]*>/i;

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
function inlineScriptHashes(html: string): string[] {
  const hashes: string[] = [];
  for (const match of html.matchAll(SCRIPT_RE)) {
    const attrs = match[1] ?? '';
    if (SRC_ATTR_RE.test(attrs)) continue; // external script — covered by 'self'
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
function buildPolicy(scriptHashes: string[]): string {
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

function injectMeta(html: string, policy: string): string {
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
  throw new Error(`${PLUGIN_NAME}: no <head> to inject the CSP meta into`);
}

export default function cspMetaPlugin(): Plugin {
  return {
    name: PLUGIN_NAME,

    async postBuild({outDir}) {
      const entries = await readdir(outDir, {recursive: true});
      const pages = entries
        .filter((entry) => entry.endsWith('.html'))
        .map((entry) => path.join(outDir, entry));

      const sources = new Map<string, string>();
      const hashes = new Set<string>();
      for (const page of pages) {
        const html = await readFile(page, 'utf8');
        sources.set(page, html);
        for (const hash of inlineScriptHashes(html)) hashes.add(hash);
      }

      const policy = buildPolicy([...hashes].sort());
      await Promise.all(
        [...sources].map(([page, html]) => writeFile(page, injectMeta(html, policy), 'utf8')),
      );

      console.log(
        `[${PLUGIN_NAME}] CSP injected into ${pages.length} pages ` +
          `(${hashes.size} inline script hashes)`,
      );
    },
  };
}
