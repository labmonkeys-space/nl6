/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Node test for scripts/fleet.sh import. Run with
 * `node scripts/fleet.test.mjs` (or `make test-fleet`).
 *
 * It runs the real script against a stub server on 127.0.0.1 that records
 * every POST /api/v1/devices body, so the jq filter under test is the shipped
 * one. Needs sh, curl and jq, the script's own runtime dependencies.
 * Mutation-verify by removing one field from the GET-response constructor in
 * fleet.sh: the deepEqual below must fail.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = join(dirname(fileURLToPath(import.meta.url)), 'fleet.sh');

// One device as GET /api/v1/devices lists it: the creatable fields plus
// listing-only fields that a create request rejects.
const listed = {
  ip: '10.42.0.7',
  interface: 'sim7',
  snmp_port: 161,
  ssh_port: 22,
  running: true,
  resource_file: 'juniper_mx10004.json',
  device_type: 'Juniper MX10004',
  flow: { collector: '10.0.0.1:2055', protocol: 'ipfix' },
  traps: { collector: '10.0.0.1:162', mode: 'trap' },
  syslog: { collector: '10.0.0.1:514', format: '5424' },
  gnmi_dialout: { collector: '10.0.0.1:50051', flavor: 'gnmireverse' },
  effective_intervals: { syslog_interval: '10s' },
  if_error_scenario: 'degraded',
  if_flap_scenario: 'typical',
  optical_scenario: 'failing',
  location: 'Fulda',
};

// A plain device: no export blocks, no scenarios. Most real inventory entries
// look like this, and the absent fields must reach the server as null, which
// it reads as unset.
const plain = {
  ip: '10.42.0.8',
  snmp_port: 161,
  ssh_port: 22,
  running: true,
  resource_file: 'asr9k.json',
  device_type: 'Cisco ASR 9000',
};

// runImport runs `fleet.sh import` against a stub server. respond(res, n)
// answers the n-th POST /api/v1/devices (0-based). RETRY_409_DELAY=0 and the
// kill timer bound the run, so a stub or curl problem fails the test instead of
// hanging make test.
async function runImport(respond, retryLimit) {
  const posted = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'POST' && req.url === '/api/v1/devices') {
        posted.push(JSON.parse(body));
        respond(res, posted.length - 1);
        return;
      }
      res.end('{"success":true}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;

  const dir = mkdtempSync(join(tmpdir(), 'nl6-fleet-test-'));
  const file = join(dir, 'inventory.json');
  writeFileSync(file, JSON.stringify({ success: true, data: [listed, plain] }));

  try {
    const env = { ...process.env, NO_PROXY: '127.0.0.1', no_proxy: '127.0.0.1', RETRY_409_LIMIT: String(retryLimit), RETRY_409_DELAY: '0' };
    const child = spawn('sh', [script, 'import', url, file], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    const timer = setTimeout(() => child.kill('SIGKILL'), 30_000);
    let output = '';
    child.stdout.on('data', (d) => { output += d; });
    child.stderr.on('data', (d) => { output += d; });
    const code = await new Promise((resolve) => child.on('close', resolve));
    clearTimeout(timer);
    return { code, output, posted };
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const ok = (res) => res.end('{"success":true}');

// The jq filter turns listed devices into create requests.
{
  const { code, output, posted } = await runImport(ok, 1);
  assert.equal(code, 0, `fleet.sh import exited ${code}:\n${output}`);

  assert.equal(posted.length, 2, 'one create request per listed device');
  assert.deepEqual(posted[0], {
    start_ip: '10.42.0.7',
    device_count: 1,
    netmask: '16',
    resource_file: 'juniper_mx10004.json',
    snmp_port: 161,
    flow: listed.flow,
    traps: listed.traps,
    syslog: listed.syslog,
    gnmi_dialout: listed.gnmi_dialout,
    if_error_scenario: 'degraded',
    if_flap_scenario: 'typical',
    optical_scenario: 'failing',
  });
  assert.deepEqual(posted[1], {
    start_ip: '10.42.0.8',
    device_count: 1,
    netmask: '16',
    resource_file: 'asr9k.json',
    snmp_port: 161,
    flow: null,
    traps: null,
    syslog: null,
    gnmi_dialout: null,
    if_error_scenario: null,
    if_flap_scenario: null,
    optical_scenario: null,
  });
}

// A 409 without Retry-After is a fleet frozen by a running scenario (nl6#1115).
// It lasts as long as the scenario, so import fails on the first attempt even
// with retries left. The refusal carries a header whose name only ends in
// Retry-After, as a proxy may add one. A match that is not anchored to the
// start of the line takes it for the real header and retries.
{
  const frozen = '{"success":false,"message":"fleet membership is frozen by running scenario(s) s-000001: device create/delete is rejected until they finish"}';
  const refuse = (res) => {
    res.statusCode = 409;
    res.setHeader('X-Upstream-Retry-After', '5');
    res.end(frozen);
  };
  const { code, output, posted } = await runImport(refuse, 5);
  assert.notEqual(code, 0, `a frozen fleet must fail the import:\n${output}`);
  assert.equal(posted.length, 1, `a frozen fleet must not be retried:\n${output}`);
  assert.match(output, /s-000001/, 'the failure names the freezing scenario');
  assert.doesNotMatch(output, /BUSY/, 'a frozen fleet is not reported as a busy batch');
}

// A 409 with Retry-After is a concurrent creation batch: wait and retry. The
// first refusal spells the header as Go's net/http writes it, the second in
// lowercase as HTTP/2 and some proxies deliver it. A case-sensitive match
// fails one of the two, whichever case its pattern is written in.
{
  const busy = (res, n) => {
    if (n < 2) {
      res.statusCode = 409;
      res.setHeader(n === 0 ? 'Retry-After' : 'retry-after', '5');
      res.end('{"success":false,"message":"another device creation batch is in progress (2000 devices); retry once it finishes"}');
      return;
    }
    ok(res);
  };
  const { code, output, posted } = await runImport(busy, 3);
  assert.equal(code, 0, `a busy batch must be waited out:\n${output}`);
  assert.equal(posted.length, 4, 'the first device is posted three times, the second once');
  assert.match(output, /BUSY/, 'the retry is reported');
}

console.log('fleet.test.mjs: ok');
