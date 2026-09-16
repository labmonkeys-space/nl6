/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Node test for check-release-integrity.mjs. Run with
 * `node scripts/check-release-integrity.test.mjs` (or `make check-release-integrity-test`).
 *
 * The POSITIVE CONTROL is the load-bearing test here, and it is written
 * first deliberately. This repo currently has zero tag/release drift, so a
 * run against the real repository is satisfied by a check that reports
 * nothing whatever its input — the clean run is the negative control, never
 * the proof. Mutation-verify by making reconcile() return empty lists: the
 * control must fail.
 */

import assert from 'node:assert/strict';
import {
  reconcile,
  planIssueAction,
  renderBody,
  hasFindings,
  ReconcileError,
  VERSION_TAG,
  ISSUE_MARKER,
  GRACE_MS,
} from './check-release-integrity.mjs';

const NOW = Date.parse('2026-09-16T12:00:00Z');
const OLD = '2026-09-01T12:00:00Z';

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`ok - ${name}`);
  } catch (err) {
    console.error(`FAIL - ${name}\n  ${err.message}`);
    process.exitCode = 1;
  }
}

// --- positive control -------------------------------------------------------

test('POSITIVE CONTROL: one planted finding of each type is reported', () => {
  const f = reconcile({
    now: NOW,
    tags: [
      { name: 'v1.0.0', createdAt: OLD }, // fine
      { name: 'v1.0.1', createdAt: OLD }, // planted: no release
      { name: 'v1.0.2', createdAt: OLD }, // planted: release has no assets
      { name: 'not-a-version', createdAt: OLD }, // ignored
    ],
    releases: [
      { tagName: 'v1.0.0', draft: false, assetCount: 16 },
      { tagName: 'v1.0.2', draft: false, assetCount: 0 }, // planted: assetless
      { tagName: 'v0.9.9', draft: false, assetCount: 16 }, // planted: tag gone
    ],
  });
  assert.deepEqual(f.tagsWithoutRelease, ['v1.0.1'], 'orphan tag not reported');
  assert.deepEqual(f.releasesWithoutTag, ['v0.9.9'], 'tagless release not reported');
  assert.deepEqual(f.releasesWithoutAssets, ['v1.0.2'], 'assetless release not reported');
  assert.ok(hasFindings(f));
});

test('POSITIVE CONTROL: the three findings stay separate, not merged into one count', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v2.0.0', createdAt: OLD }, { name: 'v2.0.1', createdAt: OLD }],
    releases: [
      { tagName: 'v2.0.0', draft: false, assetCount: 0 },
      { tagName: 'v1.9.0', draft: false, assetCount: 3 },
    ],
  });
  assert.deepEqual(f.tagsWithoutRelease, ['v2.0.1']);
  assert.deepEqual(f.releasesWithoutAssets, ['v2.0.0']);
  assert.deepEqual(f.releasesWithoutTag, ['v1.9.0']);
});

// --- negative control -------------------------------------------------------

test('a fully reconciled set produces no findings', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v1.0.0', createdAt: OLD }, { name: 'v1.0.1', createdAt: OLD }],
    releases: [
      { tagName: 'v1.0.0', draft: false, assetCount: 16 },
      { tagName: 'v1.0.1', draft: false, assetCount: 16 },
    ],
  });
  assert.equal(hasFindings(f), false);
  assert.deepEqual(f.tagsWithoutRelease, []);
});

// --- drafts -----------------------------------------------------------------

test('a draft release does not satisfy the assertion for its tag', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v1.0.0', createdAt: OLD }],
    releases: [
      { tagName: 'v1.0.0', draft: true, assetCount: 16 },
      { tagName: 'v0.1.0', draft: false, assetCount: 1 },
    ],
  });
  assert.deepEqual(f.tagsWithoutRelease, ['v1.0.0'], 'a draft publishes nothing and must not count');
});

test('a draft release is not reported as an assetless or tagless release', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v1.0.0', createdAt: OLD }],
    releases: [
      { tagName: 'v1.0.0', draft: false, assetCount: 5 },
      { tagName: 'v9.9.9', draft: true, assetCount: 0 },
    ],
  });
  assert.deepEqual(f.releasesWithoutTag, [], 'a draft is not a published release');
  assert.deepEqual(f.releasesWithoutAssets, []);
});

// --- grace window -----------------------------------------------------------

test('a tag younger than the grace window is skipped, the same tag past it is reported', () => {
  const young = new Date(NOW - (GRACE_MS - 60_000)).toISOString();
  const old = new Date(NOW - (GRACE_MS + 60_000)).toISOString();
  const releases = [{ tagName: 'v0.1.0', draft: false, assetCount: 1 }];

  const a = reconcile({ now: NOW, tags: [{ name: 'v1.0.0', createdAt: young }], releases });
  assert.deepEqual(a.tagsWithoutRelease, [], 'in-flight release must not be reported');
  assert.deepEqual(a.skippedYoung, ['v1.0.0']);

  const b = reconcile({ now: NOW, tags: [{ name: 'v1.0.0', createdAt: old }], releases });
  assert.deepEqual(b.tagsWithoutRelease, ['v1.0.0'], 'past the window it must be reported');
  assert.deepEqual(b.skippedYoung, []);
});

test('an unknown tag date fails toward reporting, not toward silence', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v1.0.0', createdAt: null }],
    releases: [{ tagName: 'v0.1.0', draft: false, assetCount: 1 }],
  });
  assert.deepEqual(f.tagsWithoutRelease, ['v1.0.0'],
    'a spurious report self-clears; a spurious skip hides a real orphan');
});

// --- matching rules ---------------------------------------------------------

test('a re-pushed tag is matched by name, whatever commit the release records', () => {
  // Recovering a failed release required deleting v0.29.1 and re-pushing it at
  // a different commit. A commit-based comparison would report that release as
  // broken forever.
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v0.29.1', createdAt: OLD }],
    releases: [{ tagName: 'v0.29.1', draft: false, assetCount: 16, targetCommitish: 'some-other-sha' }],
  });
  assert.deepEqual(f.tagsWithoutRelease, []);
});

test('non-version tags are ignored', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'nightly', createdAt: OLD }, { name: 'v1.0.0', createdAt: OLD }],
    releases: [{ tagName: 'v1.0.0', draft: false, assetCount: 2 }],
  });
  assert.deepEqual(f.tagsWithoutRelease, []);
  assert.equal(f.counts.versionTags, 1);
});

test('prerelease-shaped tags are in scope, not exempted', () => {
  assert.ok(VERSION_TAG.test('v1.2.3-rc1'), 'this repo cuts no prereleases; such a tag is an anomaly either way');
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v1.2.3-rc1', createdAt: OLD }],
    releases: [{ tagName: 'v1.0.0', draft: false, assetCount: 1 }],
  });
  assert.deepEqual(f.tagsWithoutRelease, ['v1.2.3-rc1']);
});

// --- silent-failure guards --------------------------------------------------

test('an empty release list is an error, not "every tag is an orphan"', () => {
  assert.throws(
    () => reconcile({ now: NOW, tags: [{ name: 'v1.0.0', createdAt: OLD }], releases: [] }),
    ReconcileError,
  );
});

test('an empty tag list is an error, not a clean result', () => {
  assert.throws(
    () => reconcile({ now: NOW, tags: [], releases: [{ tagName: 'v1.0.0', draft: false, assetCount: 1 }] }),
    ReconcileError,
  );
});

test('counts are reported so a truncated listing is visible', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v1.0.0', createdAt: OLD }, { name: 'nightly', createdAt: OLD }],
    releases: [{ tagName: 'v1.0.0', draft: false, assetCount: 1 }, { tagName: 'v0.9.0', draft: true, assetCount: 0 }],
  });
  assert.deepEqual(f.counts, { tags: 2, versionTags: 1, releases: 2, published: 1 });
});

// --- issue lifecycle --------------------------------------------------------

const DIRTY = { tagsWithoutRelease: ['v1.0.1'], releasesWithoutTag: [], releasesWithoutAssets: [], skippedYoung: [], counts: {} };
const CLEAN = { tagsWithoutRelease: [], releasesWithoutTag: [], releasesWithoutAssets: [], skippedYoung: [], counts: {} };

test('findings with no open issue open one', () => {
  assert.deepEqual(planIssueAction({ findings: DIRTY, existingIssueNumber: null }), { action: 'open' });
});

test('findings with an open issue update it in place, never open a second', () => {
  assert.deepEqual(planIssueAction({ findings: DIRTY, existingIssueNumber: 42 }), { action: 'update', number: 42 });
});

test('cleared findings close the open issue', () => {
  assert.deepEqual(planIssueAction({ findings: CLEAN, existingIssueNumber: 42 }), { action: 'close', number: 42 });
});

test('a clean repo with no open issue does nothing', () => {
  assert.deepEqual(planIssueAction({ findings: CLEAN, existingIssueNumber: null }), { action: 'none' });
});

// --- report body ------------------------------------------------------------

test('the body carries the marker, the counts and a timestamp', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v1.0.0', createdAt: OLD }, { name: 'v1.0.1', createdAt: OLD }],
    releases: [{ tagName: 'v1.0.0', draft: false, assetCount: 16 }],
  });
  const body = renderBody({ findings: f, now: NOW, repo: 'o/r' });
  assert.ok(body.startsWith(ISSUE_MARKER), 'the issue is located by this marker, not by title');
  assert.match(body, /v1\.0\.1/);
  assert.match(body, /Compared \*\*2 version tags\*\* \(of 2 tags\).*\*\*1 published releases\*\* \(of 1\)/s);
  assert.match(body, /2026-09-16T12:00:00\.000Z/, 'a stale report must read as stale');
});

test('the body names each finding type only when that type has findings', () => {
  const f = reconcile({
    now: NOW,
    tags: [{ name: 'v1.0.0', createdAt: OLD }],
    releases: [{ tagName: 'v1.0.0', draft: false, assetCount: 0 }, { tagName: 'v0.0.1', draft: false, assetCount: 1 }],
  });
  const body = renderBody({ findings: f, now: NOW, repo: 'o/r' });
  assert.ok(body.includes('no assets'), 'assetless finding missing');
  assert.ok(body.includes('whose tag is gone'), 'tagless finding missing');
  assert.ok(!body.includes('Tags with no published release'), 'reported a type with no findings');
});

console.log(`\n${passed} checks passed.`);
