/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Fill the licenses in the product SBOM that no Go module cache can ever
// resolve, because none of these packages is a downloadable module:
//
//   - the main module (this repository) and the scanned binary's file-root
//     package: Apache-2.0 — the repo literally declares it, via LICENSE and
//     per-file SPDX headers;
//   - stdlib (the Go standard library): BSD-3-Clause — Go's declared license.
//
// Both licenseDeclared and licenseConcluded are filled, so a maintainer can
// assert the checklist property "no licenseConcluded is NOASSERTION" over the
// whole document (syft fills licenseConcluded for every cache-resolved module;
// these three are the only holdouts). The script fails loudly if any target is
// missing, so a syft naming change or a scan-input change can never silently
// turn the curation into a no-op and re-introduce Undeclared rows.
//
// Usage: node scripts/curate-product-sbom.mjs <sbom.spdx.json>

import { readFileSync, writeFileSync } from "node:fs";

const path = process.argv[2];
if (!path) {
  console.error("usage: curate-product-sbom.mjs <sbom.spdx.json>");
  process.exit(2);
}

const fills = new Map([
  ["github.com/labmonkeys-space/nl6/go", "Apache-2.0"],
  ["nl6-linux-amd64", "Apache-2.0"],
  ["stdlib", "BSD-3-Clause"],
]);

const doc = JSON.parse(readFileSync(path, "utf8"));
const seen = new Set();
for (const pkg of doc.packages ?? []) {
  const license = fills.get(pkg.name);
  if (!license) continue;
  pkg.licenseDeclared = license;
  pkg.licenseConcluded = license;
  seen.add(pkg.name);
  console.log(`curated ${pkg.name}: ${license}`);
}

const missing = [...fills.keys()].filter((name) => !seen.has(name));
if (missing.length > 0) {
  console.error(`curation targets missing from SBOM: ${missing.join(", ")}`);
  process.exit(1);
}

writeFileSync(path, JSON.stringify(doc, null, 1) + "\n");
