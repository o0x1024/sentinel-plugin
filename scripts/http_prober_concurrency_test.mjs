// Run with Node 24: node --test scripts/http_prober_concurrency_test.mjs
// Both source and published bundle use local fetch stubs; no network is used.
import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { monitorExecution } from './monitor_stream_fixture.ts';
import * as source from '../source/bounty/http_prober/index.ts';
import * as published from '../plugins/bounty/http_prober.ts';

for (const [name, plugin] of Object.entries({ source, published })) {
  test(`${name}: concurrency schema exposes the existing integer form with default and bounds`, () => {
    const field = plugin.get_input_schema().properties.concurrency;
    assert.equal(field?.type, 'integer');
    assert.equal(field.default, 32);
    assert.equal(field.minimum, 1);
    assert.equal(field.maximum, 1000);
    assert.match(field.description, /host global direct-fetch concurrency limit/);
  });

  for (const monitor of [false, true]) {
    const mode = monitor ? 'monitor' : 'ordinary';
    for (const [label, concurrency, count, expectedPeak] of [
      ['default', undefined, 65, 32],
      ['serial', 1, 9, 1],
      ['custom', 4, 13, 4],
      ['above old limit', 64, 80, 64],
      ['fewer tasks than workers', 1000, 7, 7],
    ]) {
      test(`${name} ${mode}: ${label} bounds active requests and completes every target`, async t => {
        const targets = Array.from({ length: count }, (_, index) => `https://owned${index}.test/`);
        let active = 0;
        let peak = 0;
        const requested = [];
        const commits = [];
        t.mock.method(globalThis, 'fetch', async (url, init) => {
          assert.equal(init.method, 'GET');
          assert.equal(init.timeout, 3000);
          requested.push(String(url));
          active++;
          peak = Math.max(peak, active);
          try {
            await setImmediate();
            return new Response('<title>Owned fixture</title>', {
              headers: { 'content-type': 'text/html' },
            });
          } finally {
            active--;
          }
        });
        const previousSentinel = globalThis.Sentinel;
        t.after(() => { globalThis.Sentinel = previousSentinel; });
        globalThis.Sentinel = {
          Monitor: {
            reportProgress: () => true,
            commitResults: async request => {
              commits.push(request);
              return { ok: true, sequence: request.sequence };
            },
          },
        };
        const output = await plugin.analyze({
          targets,
          ...(concurrency === undefined ? {} : { concurrency }),
          ...(monitor ? { __monitorExecution: monitorExecution(targets, { pluginId: 'http_prober' }) } : {}),
        });
        assert.equal(output.success, true, output.error);
        assert.equal(peak, expectedPeak);
        assert.equal(active, 0);
        assert.deepEqual(requested.sort(), [...targets].sort());
        if (monitor) {
          assert.equal(output.data.stream_complete, true);
          const completed = commits.flatMap(batch => batch.work).filter(item => item.complete);
          assert.equal(completed.length, count);
          assert.deepEqual(completed.map(item => item.target).sort(), [...targets].sort());
        } else {
          assert.equal(output.data.results.length, count);
          assert.equal(output.data.summary.total, count);
        }
      });
    }

    test(`${name} ${mode}: invalid concurrency fails before requests or result commits`, async t => {
      const fetch = t.mock.method(globalThis, 'fetch', async () => {
        throw new Error('Invalid concurrency must not issue a request');
      });
      const previousSentinel = globalThis.Sentinel;
      t.after(() => { globalThis.Sentinel = previousSentinel; });
      const commits = [];
      globalThis.Sentinel = { Monitor: {
        reportProgress: () => true,
        commitResults: async request => {
          commits.push(request);
          return { ok: true, sequence: request.sequence };
        },
      } };
      const targets = ['https://owned.test/'];
      for (const concurrency of [0, -1, 1.5, 1001, NaN, Infinity, '4', null, true]) {
        const output = await plugin.analyze({ targets, concurrency,
          ...(monitor ? { __monitorExecution: monitorExecution(targets, { pluginId: 'http_prober' }) } : {}),
        });
        assert.equal(output.success, false, `concurrency=${String(concurrency)}`);
        assert.match(output.error, /concurrency must be an integer between 1 and 1000/);
      }
      assert.equal(fetch.mock.callCount(), 0);
      assert.equal(commits.length, 0);
    });
  }
}
