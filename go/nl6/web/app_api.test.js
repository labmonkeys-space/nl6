/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Node test for the console's profile-download buttons (nl6#635). app_api.js
 * is a browser script that reads its collaborators (fetch, document,
 * showAlert, setLoading) from the global scope, so it is evaluated inside a
 * vm context whose globals are stubs. Run with `node app_api.test.js`.
 *
 * What is pinned: with profiling off the server answers 503 with a JSON
 * envelope, and the button must show THAT message rather than a silent empty
 * download; with profiling on the button fetches the real pprof paths.
 */
'use strict';
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadAppApi(fetchImpl) {
    const alerts = [];
    const loading = [];
    const clicks = [];
    const ctx = {
        console,
        URL: { createObjectURL: () => 'blob:stub', revokeObjectURL: () => {} },
        document: {
            createElement: () => ({ style: {}, click() { clicks.push(this.href + ' -> ' + this.download); } }),
            body: { appendChild() {}, removeChild() {} },
            getElementById: () => null,
        },
        window: {},
        fetch: fetchImpl,
        showAlert: (message, type) => alerts.push({ message, type }),
        setLoading: (id, on) => loading.push({ id, on }),
        setTimeout,
        clearTimeout,
    };
    vm.createContext(ctx);
    const src = fs.readFileSync(path.join(__dirname, 'app_api.js'), 'utf8');
    vm.runInContext(src, ctx, { filename: 'app_api.js' });
    return { ctx, alerts, loading, clicks };
}

let checks = 0;

(async () => {
    // Profiling off: the server's 503 envelope message reaches the operator.
    {
        const serverMessage = 'profiling is off; enable it with POST /api/v1/profiling';
        const urls = [];
        const { ctx, alerts, clicks } = loadAppApi(async (url) => {
            urls.push(url);
            return {
                ok: false, status: 503, statusText: 'Service Unavailable',
                text: async () => JSON.stringify({ success: false, message: serverMessage }),
            };
        });
        await ctx.downloadPprofMemory();
        assert.deepStrictEqual(urls, ['/debug/pprof/heap']);
        assert.strictEqual(clicks.length, 0, 'no download link must be clicked on a 503');
        const err = alerts.find((a) => a.type === 'error');
        assert.ok(err && err.message.includes(serverMessage),
            'the 503 body message must surface in the alert, got ' + JSON.stringify(alerts));
        checks += 3;

        await ctx.downloadCpuProfile();
        assert.strictEqual(urls[1], '/debug/pprof/profile?seconds=5');
        assert.ok(alerts.filter((a) => a.type === 'error').length === 2);
        checks += 2;
    }

    // net/http/pprof's own refusal is text/plain, not the JSON envelope: the
    // 500 "cpu profiling already in use" (the SDK holds the one CPU-profile
    // slot) must reach the operator verbatim, not as "HTTP 500".
    {
        const pprofText = 'Could not enable CPU profiling: cpu profiling already in use\n';
        const { ctx, alerts, clicks } = loadAppApi(async () => ({
            ok: false, status: 500, statusText: 'Internal Server Error',
            text: async () => pprofText,
        }));
        await ctx.downloadCpuProfile();
        assert.strictEqual(clicks.length, 0);
        const err = alerts.find((a) => a.type === 'error');
        assert.ok(err && err.message.includes('cpu profiling already in use') && !err.message.includes('HTTP 500'),
            'a text/plain pprof error must surface verbatim, got ' + JSON.stringify(alerts));
        checks += 2;
    }

    // An empty error body falls back to the status line.
    {
        const { ctx, alerts } = loadAppApi(async () => ({
            ok: false, status: 502, statusText: 'Bad Gateway',
            text: async () => '',
        }));
        await ctx.downloadPprofMemory();
        const err = alerts.find((a) => a.type === 'error');
        assert.ok(err && err.message.includes('HTTP 502: Bad Gateway'), JSON.stringify(alerts));
        checks += 1;
    }

    // Profiling on: the body is downloaded under the documented filenames.
    {
        const revoked = [];
        const { ctx, alerts, clicks } = loadAppApi(async () => ({
            ok: true, status: 200, statusText: 'OK',
            blob: async () => ({}),
        }));
        ctx.URL.revokeObjectURL = (u) => revoked.push(u);
        await ctx.downloadPprofMemory();
        await ctx.downloadCpuProfile();
        assert.deepStrictEqual(clicks, [
            'blob:stub -> nl6_heap.pprof.gz',
            'blob:stub -> nl6_cpu.pprof.gz',
        ]);
        assert.strictEqual(alerts.filter((a) => a.type === 'error').length, 0);
        // The object URL is revoked LATER, never synchronously after click():
        // a synchronous revoke can cancel the download it just started.
        assert.deepStrictEqual(revoked, [], 'revoked synchronously');
        await new Promise((r) => setTimeout(r, 1100));
        assert.deepStrictEqual(revoked, ['blob:stub', 'blob:stub'], 'not revoked after the grace period');
        checks += 4;
    }

    // The retired handlers are gone from the console for good.
    {
        const src = fs.readFileSync(path.join(__dirname, 'app_api.js'), 'utf8');
        assert.ok(!src.includes('pprof-memory') && !src.includes('cpu-profile'));
        checks += 1;
    }

    console.log(`app_api.test.js: ${checks} checks passed`);
})().catch((e) => { console.error(e); process.exit(1); });
