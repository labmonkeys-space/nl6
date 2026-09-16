#!/usr/bin/env node
/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * check-release-integrity.mjs — reconcile the version tags on origin against
 * the releases they were supposed to produce, and report any disagreement as
 * a single GitHub issue.
 *
 * Why this exists: when a tag push fails a release gate, the publish jobs are
 * SKIPPED and no release object is created. The tag is the only trace, and
 * `releases/tag/vX.Y.Z` renders a normal-looking page for it, so the failure
 * is invisible everywhere a maintainer looks — the Releases list only shows
 * release objects, and `git describe` on a fresh clone happily reports the
 * orphan as the latest version. Three tags (v0.28.1, v0.29.1, v0.29.2) sat in
 * that state for up to two weeks before anyone noticed.
 *
 * The comparison itself is trivial. Nearly all the care here is in the two
 * ways this check could join the class of failure it exists to catch:
 *
 *   1. Reporting nothing when it could not answer. An empty tag list or an
 *      empty release list is treated as an ERROR, never as a clean result —
 *      a repo with tags returning none is an API failure, not good news.
 *   2. Reporting garbage from a truncated listing. Every query paginates
 *      explicitly; unpaginated, the API default of 30 against this repo's 49
 *      releases would report 19 released tags as orphans on the first run.
 *
 * The reconciliation, the rendering and the issue-lifecycle decision are pure
 * functions so they can be tested against planted findings. A rule that
 * asserts the absence of something cannot fail on its own, and this repo
 * currently has zero drift, so a run against the real repo proves nothing on
 * its own — see check-release-integrity.test.mjs.
 */

import { execFileSync } from 'node:child_process';

/** Tags this check governs. Prerelease shapes are deliberately INCLUDED: this
 * repo cuts none (RELEASING.md), so such a tag is an anomaly either way. */
export const VERSION_TAG = /^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/** A release takes ~10-15 min end to end and the draft appears near the end,
 * so anything younger than this is still in flight rather than broken. */
export const GRACE_MS = 30 * 60 * 1000;

/** The issue is found by this marker in its BODY, never by title — titles get
 * edited, and a retitled issue would orphan itself and get duplicated. */
export const ISSUE_MARKER = '<!-- release-integrity-report -->';

export class ReconcileError extends Error {}

/**
 * Compare tags against releases.
 *
 * @param {{name: string, createdAt?: string|null}[]} tags   tags on origin
 * @param {{tagName: string, draft: boolean, assetCount: number}[]} releases
 * @param {number} now        epoch ms
 * @param {number} graceMs
 *
 * A tag whose createdAt is unknown is NOT skipped by the grace window. That
 * fails toward reporting, which is the safe direction: a spurious report
 * clears itself on the next run, whereas a spurious skip hides a real orphan.
 */
export function reconcile({ tags, releases, now, graceMs = GRACE_MS }) {
  if (!Array.isArray(tags) || !Array.isArray(releases)) {
    throw new ReconcileError('tags and releases must be arrays');
  }
  // Empty is an ERROR, not a pass. This is the check's own silent-failure
  // guard: without it, an API hiccup that returns [] reports either "all
  // clean" or "every tag is an orphan", and both are confident nonsense.
  if (tags.length === 0) {
    throw new ReconcileError('no tags returned — refusing to report a clean result from an empty listing');
  }
  if (releases.length === 0) {
    throw new ReconcileError('no releases returned — refusing to report every tag as an orphan from an empty listing');
  }

  const versionTags = tags.filter((t) => VERSION_TAG.test(t.name));
  // Only PUBLISHED releases count. A draft publishes nothing, so a tag whose
  // only release object is a draft has still shipped nothing.
  const published = releases.filter((r) => !r.draft);
  const publishedByTag = new Map(published.map((r) => [r.tagName, r]));
  const tagNames = new Set(tags.map((t) => t.name));

  const tagsWithoutRelease = [];
  const skippedYoung = [];
  for (const tag of versionTags) {
    // Matched by NAME, never by target commit: recovering a failed release
    // can require deleting and re-pushing the tag at a different commit, and
    // a commit comparison would report that release as broken forever.
    if (publishedByTag.has(tag.name)) continue;
    const created = tag.createdAt ? Date.parse(tag.createdAt) : NaN;
    if (Number.isFinite(created) && now - created < graceMs) {
      skippedYoung.push(tag.name);
      continue;
    }
    tagsWithoutRelease.push(tag.name);
  }

  const releasesWithoutTag = published
    .filter((r) => !tagNames.has(r.tagName))
    .map((r) => r.tagName);

  // Reported separately from the orphan list on purpose: "no release" and "a
  // release that published nothing" have different causes (gate failed vs
  // upload failed) and different remedies (re-tag vs re-upload).
  const releasesWithoutAssets = published
    .filter((r) => tagNames.has(r.tagName) && r.assetCount === 0)
    .map((r) => r.tagName);

  return {
    tagsWithoutRelease,
    releasesWithoutTag,
    releasesWithoutAssets,
    skippedYoung,
    counts: { tags: tags.length, versionTags: versionTags.length, releases: releases.length, published: published.length },
  };
}

export function hasFindings(f) {
  return f.tagsWithoutRelease.length > 0 || f.releasesWithoutTag.length > 0 || f.releasesWithoutAssets.length > 0;
}

/**
 * Decide what to do with the report issue. Kept separate from the API calls
 * so the open -> update -> close lifecycle is testable without a network.
 */
export function planIssueAction({ findings, existingIssueNumber }) {
  const any = hasFindings(findings);
  if (any && existingIssueNumber == null) return { action: 'open' };
  if (any) return { action: 'update', number: existingIssueNumber };
  if (existingIssueNumber != null) return { action: 'close', number: existingIssueNumber };
  return { action: 'none' };
}

export function renderBody({ findings, now, repo }) {
  const { counts } = findings;
  const lines = [ISSUE_MARKER, ''];
  lines.push('A version tag and the release it was supposed to produce disagree.');
  lines.push('');
  lines.push('When a tag push fails a release gate the publish jobs are skipped and **no release object is created**, but `releases/tag/<tag>` still renders a normal-looking page — so the failure is invisible in the Releases list, on the tag page, and to `git describe`. This issue is the reconciliation that catches it.');
  lines.push('');

  if (findings.tagsWithoutRelease.length) {
    lines.push('### Tags with no published release');
    lines.push('');
    lines.push('The tag exists on origin but nothing shipped: no release, no image, no artifacts. Check the tag\'s Release workflow run — if the run history has aged out, re-cutting the release is the remedy.');
    lines.push('');
    for (const t of findings.tagsWithoutRelease) {
      lines.push(`- \`${t}\` — https://github.com/${repo}/actions?query=branch%3A${encodeURIComponent(t)}`);
    }
    lines.push('');
  }
  if (findings.releasesWithoutTag.length) {
    lines.push('### Published releases whose tag is gone');
    lines.push('');
    lines.push('The release is published but its tag no longer exists on origin, so the artifacts cannot be traced to a commit.');
    lines.push('');
    for (const t of findings.releasesWithoutTag) lines.push(`- \`${t}\``);
    lines.push('');
  }
  if (findings.releasesWithoutAssets.length) {
    lines.push('### Published releases with no assets');
    lines.push('');
    lines.push('The release object exists but carries zero artifacts — the other shape this failure takes, where the release was created and the upload did not finish.');
    lines.push('');
    for (const t of findings.releasesWithoutAssets) lines.push(`- \`${t}\``);
    lines.push('');
  }
  if (findings.skippedYoung.length) {
    lines.push(`_Skipped as still in flight (younger than ${Math.round(GRACE_MS / 60000)} min): ${findings.skippedYoung.map((t) => `\`${t}\``).join(', ')}._`);
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(`Compared **${counts.versionTags} version tags** (of ${counts.tags} tags) against **${counts.published} published releases** (of ${counts.releases}) at ${new Date(now).toISOString()}.`);
  lines.push('');
  lines.push('This issue is maintained by `.github/workflows/release-integrity.yml`; it updates in place and closes itself when the findings clear.');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

function fetchReleases(repo) {
  // --paginate is load-bearing: the API default of 30 against 49 releases
  // would report 19 released tags as orphans.
  const out = gh(['api', `repos/${repo}/releases`, '--paginate', '--jq',
    '.[] | {tagName: .tag_name, draft: .draft, assetCount: (.assets | length)}']);
  return out.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

function fetchTags(repo) {
  const out = gh(['api', `repos/${repo}/tags`, '--paginate', '--jq', '.[] | {name: .name, sha: .commit.sha}']);
  return out.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

/** Dates are fetched only for tags that look like orphans — a handful at
 * most — rather than for all of them, to keep this to a couple of API calls. */
function fetchTagDate(repo, sha) {
  try {
    return gh(['api', `repos/${repo}/commits/${sha}`, '--jq', '.commit.committer.date']).trim();
  } catch {
    return null; // unknown date => not skipped, see reconcile()
  }
}

function findExistingIssue(repo) {
  const out = gh(['api', `repos/${repo}/issues?state=open&per_page=100`, '--paginate', '--jq',
    '.[] | select(.pull_request == null) | {number: .number, body: .body}']);
  for (const line of out.trim().split('\n').filter(Boolean)) {
    const issue = JSON.parse(line);
    if (issue.body && issue.body.includes(ISSUE_MARKER)) return issue.number;
  }
  return null;
}

function main() {
  const repo = process.env.GITHUB_REPOSITORY || 'labmonkeys-space/nl6';
  const dryRun = process.argv.includes('--dry-run');
  const now = Date.now();

  const rawTags = fetchTags(repo);
  const releases = fetchReleases(repo);

  const published = new Set(releases.filter((r) => !r.draft).map((r) => r.tagName));
  const tags = rawTags.map((t) => ({
    name: t.name,
    createdAt: VERSION_TAG.test(t.name) && !published.has(t.name) ? fetchTagDate(repo, t.sha) : null,
  }));

  const findings = reconcile({ tags, releases, now });
  const { counts } = findings;
  console.log(`compared ${counts.versionTags} version tags (of ${counts.tags}) against ${counts.published} published releases (of ${counts.releases})`);
  for (const [label, list] of [
    ['tag with no published release', findings.tagsWithoutRelease],
    ['published release with no tag', findings.releasesWithoutTag],
    ['published release with no assets', findings.releasesWithoutAssets],
  ]) {
    for (const item of list) console.log(`FINDING: ${label}: ${item}`);
  }
  for (const item of findings.skippedYoung) console.log(`skipped (in flight): ${item}`);

  if (dryRun) {
    console.log(hasFindings(findings) ? 'dry-run: findings present, issue NOT touched' : 'dry-run: clean');
    return;
  }

  const plan = planIssueAction({ findings, existingIssueNumber: findExistingIssue(repo) });
  const body = renderBody({ findings, now, repo });
  const title = 'Release integrity: a tag and its release disagree';

  switch (plan.action) {
    case 'open':
      gh(['issue', 'create', '--repo', repo, '--title', title, '--body', body]);
      console.log('opened the report issue');
      break;
    case 'update':
      gh(['issue', 'edit', String(plan.number), '--repo', repo, '--body', body]);
      console.log(`updated report issue #${plan.number}`);
      break;
    case 'close':
      gh(['issue', 'comment', String(plan.number), '--repo', repo, '--body',
        'Findings cleared — every version tag now has a published release. Closing.']);
      gh(['issue', 'close', String(plan.number), '--repo', repo]);
      console.log(`closed report issue #${plan.number}`);
      break;
    default:
      console.log('clean: no findings, no issue');
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (err) {
    console.error(`check-release-integrity: ${err.message}`);
    process.exit(1);
  }
}
