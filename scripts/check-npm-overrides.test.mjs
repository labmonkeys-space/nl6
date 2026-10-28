/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Node test for check-npm-overrides.mjs. Run with
 * `node scripts/check-npm-overrides.test.mjs` (or `make docs-audit-overrides-test`).
 *
 * No network: it tests key parsing and classification, the parts that decide
 * which package an entry is compared on. The shipped overrides block uses no
 * selector key today, so this is the only thing exercising that path.
 * Mutation-verify by making packageName() return its input unchanged: the
 * selector cases must fail.
 */

import assert from 'node:assert/strict';
import { classify, overrideEntries, packageName, pathsFor } from './check-npm-overrides.mjs';

// packageName: the selector is cut, a scope is kept.
assert.equal(packageName('undici'), 'undici');
assert.equal(packageName('undici@>=5.15.0 <8.10.2'), 'undici');
assert.equal(packageName('@scope/pkg'), '@scope/pkg');
assert.equal(packageName('@scope/pkg@^1.2.0'), '@scope/pkg');

// overrideEntries: every key form maps to the package it forces.
assert.deepEqual(
  overrideEntries({
    tinypool: '^2.1.2',
    'undici@>=5.15.0 <8.10.2': '8.10.2',
    sockjs: { uuid: '^11.1.1' },
    cheerio: { '.': '1.2.1', 'undici@<8.12.2': '^8.12.2' },
    '@scope/a@^1': { '@scope/b@^2': '2.1.0' },
  }),
  [
    { label: 'tinypool', name: 'tinypool', range: '^2.1.2' },
    { label: 'undici@>=5.15.0 <8.10.2', name: 'undici', range: '8.10.2' },
    { label: 'sockjs>uuid', name: 'uuid', range: '^11.1.1' },
    { label: 'cheerio>.', name: 'cheerio', range: '1.2.1' },
    { label: 'cheerio>undici@<8.12.2', name: 'undici', range: '^8.12.2' },
    { label: '@scope/a@^1>@scope/b@^2', name: '@scope/b', range: '2.1.0' },
  ]
);

// POSITIVE CONTROL: a selector-keyed entry is found in a real-shaped tree.
// Before the fix the raw key matched nothing and this entry read as inert.
const withOv = new Map([['node_modules/undici', '8.10.2']]);
const withoutOv = new Map([['node_modules/undici', '7.30.1']]);
const [entry] = overrideEntries({ 'undici@>=5.15.0 <8.10.2': '8.10.2' });
assert.equal(classify(pathsFor(withOv, entry.name), pathsFor(withoutOv, entry.name)), 'load-bearing');

// classify: the three outcomes.
assert.equal(classify(['node_modules/x@1'], ['node_modules/x@1']), 'inert');
assert.equal(classify(['node_modules/x@2'], ['node_modules/x@1']), 'load-bearing');
assert.equal(classify([], []), 'unresolved');

// pathsFor matches nested copies, not name prefixes.
const tree = new Map([
  ['node_modules/uuid', '14.0.3'],
  ['node_modules/sockjs/node_modules/uuid', '11.1.1'],
  ['node_modules/uuid-extra', '1.0.0'],
]);
assert.deepEqual(pathsFor(tree, 'uuid'), [
  'node_modules/sockjs/node_modules/uuid@11.1.1',
  'node_modules/uuid@14.0.3',
]);

console.log('check-npm-overrides: all tests passed');
