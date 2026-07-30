/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Fill the two licenses in the product SBOM that no Go module cache can ever
// resolve, because neither package is a downloadable module:
//
//   - the main module (this repository): licenseDeclared Apache-2.0 — the repo
//     literally declares it, via LICENSE and per-file SPDX headers;
//   - stdlib (the Go standard library): licenseConcluded BSD-3-Clause — the
//     SBOM author's conclusion, which is the SPDX field for exactly that.
//
// Everything else in a binary-derived SBOM resolves from the module cache
// (SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES). This script fails loudly if
// either target is missing, so a syft naming change can never silently turn
// the curation into a no-op and re-introduce Undeclared rows.
//
// Usage: node scripts/curate-product-sbom.mjs <sbom.spdx.json>

import { readFileSync, writeFileSync } from "node:fs";

const path = process.argv[2];
if (!path) {
  console.error("usage: curate-product-sbom.mjs <sbom.spdx.json>");
  process.exit(2);
}

const fills = new Map([
  ["github.com/labmonkeys-space/nl6/go", ["licenseDeclared", "Apache-2.0"]],
  ["stdlib", ["licenseConcluded", "BSD-3-Clause"]],
]);

const doc = JSON.parse(readFileSync(path, "utf8"));
const seen = new Set();
for (const pkg of doc.packages ?? []) {
  const fill = fills.get(pkg.name);
  if (!fill) continue;
  const [field, license] = fill;
  pkg[field] = license;
  seen.add(pkg.name);
  console.log(`curated ${pkg.name}: ${field}=${license}`);
}

const missing = [...fills.keys()].filter((name) => !seen.has(name));
if (missing.length > 0) {
  console.error(`curation targets missing from SBOM: ${missing.join(", ")}`);
  process.exit(1);
}

writeFileSync(path, JSON.stringify(doc, null, 1) + "\n");
