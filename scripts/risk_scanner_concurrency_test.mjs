// Run with Node 24: node --test scripts/risk_scanner_concurrency_test.mjs
// Both implementations use local fetch stubs; no network is used.
import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { monitorExecution } from './monitor_stream_fixture.ts';
import * as source from '../source/bounty/risk_scanner/index.ts';
import * as published from '../plugins/bounty/risk_scanner.ts';

function rules(count, steps = 1) {
  return Array.from({ length: count }, (_, index) => ({
    word: `owned-rule-${index}`,
    metadata: {
      requests: Array.from({ length: steps }, (_, step) => ({
        method: 'GET', path: `/rule-${index}/step-${step}`,
      })),
      matchers: [{ part: 'status', type: 'equals', value: 200 }],
    },
  }));
}

function fixture(t, responder = () => new Response('', { status: 404 })) {
  const requests = [], commits = [];
  let active = 0, peak = 0;
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    requests.push({ url: String(url), init });
    active++;
    peak = Math.max(peak, active);
    try {
      await setImmediate();
      return await responder(String(url), init);
    } finally {
      active--;
    }
  });
  const previousSentinel = globalThis.Sentinel;
  t.after(() => { globalThis.Sentinel = previousSentinel; });
  globalThis.Sentinel = { Monitor: {
    reportProgress: () => true,
    commitResults: async request => {
      commits.push(request);
      return { ok: true, sequence: request.sequence };
    },
  } };
  return { requests, commits, get active() { return active; }, get peak() { return peak; } };
}

async function scan(plugin, input, monitor) {
  const output = await plugin.analyze({ ...input,
    ...(monitor ? { __monitorExecution: monitorExecution(input.targets, { pluginId: 'risk_scanner' }) } : {}),
  });
  assert.equal(output.success, true, output.error);
  return output;
}

function assertComplete(output, f, targets, count, monitor) {
  assert.equal(f.active, 0);
  assert.ok(f.requests.every(({ init }) => init.method === 'GET' && init.timeout === 10000));
  if (monitor) {
    assert.equal(output.data.stream_complete, true);
    const work = f.commits.flatMap(batch => batch.work);
    assert.deepEqual(work.filter(item => item.complete).map(item => item.target).sort(), [...targets].sort());
    assert.equal(work.filter(item => /^rule:[^:]+$/.test(item.key)).length, count);
    assert.ok(work.every(item => item.status !== 'failed'));
  } else {
    assert.equal(output.data.summary.totalTargets, targets.length);
    assert.equal(output.data.summary.executedRules, count);
    assert.equal(output.data.evidence.length, count);
    assert.ok(output.data.evidence.every(item => !item.error));
  }
}

for (const [name, plugin] of Object.entries({ source, published })) {
  test(`${name}: existing integer form exposes concurrency and explains maxRules`, () => {
    const schema = plugin.get_input_schema();
    const field = schema.properties.concurrency;
    assert.equal(field?.type, 'integer');
    assert.equal(field.default, 32);
    assert.equal(field.minimum, 1);
    assert.equal(field.maximum, 1000);
    assert.match(field.description, /host global direct-fetch concurrency limit/);
    assert.equal(schema.properties.maxRules.default, 20);
    assert.match(schema.properties.maxRules.description, /each target/);
  });

  for (const monitor of [false, true]) {
    const mode = monitor ? 'monitor' : 'ordinary';
    for (const [label, concurrency, ruleCount, targetCount, expectedPeak] of [
      ['default', undefined, 20, 3, 32],
      ['serial', 1, 4, 2, 1],
      ['custom', 4, 6, 3, 4],
      ['above old limit', 64, 40, 2, 64],
      ['fewer tasks than workers', 1000, 2, 3, 6],
    ]) {
      test(`${name} ${mode}: ${label} limits the shared target/rule worker pool`, async t => {
        const f = fixture(t);
        const targets = Array.from({ length: targetCount }, (_, index) => `https://owned${index}.test/`);
        const dictionaryEntries = rules(ruleCount);
        const output = await scan(plugin, { targets, dictionaryEntries, maxRules: ruleCount,
          ...(concurrency === undefined ? {} : { concurrency }),
        }, monitor);
        assert.equal(f.peak, expectedPeak);
        const expected = targets.flatMap(target => dictionaryEntries.map(rule => target.slice(0, -1) + rule.metadata.requests[0].path));
        assert.deepEqual(f.requests.map(item => item.url).sort(), expected.sort());
        assertComplete(output, f, targets, ruleCount * targetCount, monitor);
      });
    }

    test(`${name} ${mode}: invalid concurrency fails before requests or commits`, async t => {
      const f = fixture(t);
      const targets = ['https://owned.test/'];
      for (const concurrency of [0, -1, 1.5, 1001, NaN, Infinity, '4', null, true]) {
        const output = await plugin.analyze({ targets, dictionaryEntries: rules(1), concurrency,
          ...(monitor ? { __monitorExecution: monitorExecution(targets, { pluginId: 'risk_scanner' }) } : {}),
        });
        assert.equal(output.success, false, `concurrency=${String(concurrency)}`);
        assert.match(output.error, /concurrency must be an integer between 1 and 1000/);
      }
      assert.equal(f.requests.length, 0);
      assert.equal(f.commits.length, 0);
    });

    for (const maxRules of [undefined, 2]) {
      test(`${name} ${mode}: maxRules=${maxRules ?? 'default 20'} selects rules after filtering for every target`, async t => {
        const f = fixture(t);
        const targets = ['https://one.test/', 'https://two.test/'];
        const valid = rules(25);
        const dictionaryEntries = [
          { word: 'disabled', metadata: { ...valid[0].metadata, enabled: false } },
          { word: 'unsafe', metadata: { ...valid[0].metadata, safe_mode: false } },
          { word: 'other-scope', metadata: { ...valid[0].metadata, match_scope: { fingerprints: ['other-product'] } } },
          valid[0], { ...valid[0], word: valid[0].word.toUpperCase() }, ...valid.slice(1),
        ];
        const output = await scan(plugin, { targets, dictionaryEntries, concurrency: 64,
          ...(maxRules === undefined ? {} : { maxRules }),
        }, monitor);
        const selected = valid.slice(0, maxRules ?? 20);
        const expected = targets.flatMap(target => selected.map(rule => target.slice(0, -1) + rule.metadata.requests[0].path));
        assert.deepEqual(f.requests.map(item => item.url).sort(), expected.sort());
        assertComplete(output, f, targets, selected.length * targets.length, monitor);
      });
    }

    test(`${name} ${mode}: maxRules counts rules while chained requests stay sequential inside each worker`, async t => {
      const completedFirstSteps = new Set();
      const f = fixture(t, url => {
        if (url.endsWith('/step-0')) completedFirstSteps.add(url.slice(0, -1));
        else assert.ok(completedFirstSteps.has(url.slice(0, -1)), 'step 0 completes before step 1 starts');
        return new Response('', { status: 200 });
      });
      const targets = ['https://one.test/', 'https://two.test/'];
      const output = await scan(plugin, { targets, dictionaryEntries: rules(5, 2), maxRules: 2, concurrency: 4 }, monitor);
      assert.equal(f.peak, 4);
      assert.equal(f.requests.length, 8);
      assertComplete(output, f, targets, 4, monitor);
    });

    test(`${name} ${mode}: serial stopOnFirstHit starts no later rule`, async t => {
      const f = fixture(t, () => new Response('', { status: 200 }));
      const targets = ['https://one.test/', 'https://two.test/'];
      const output = await scan(plugin, { targets, dictionaryEntries: rules(5), concurrency: 1, stopOnFirstHit: true }, monitor);
      assert.equal(f.requests.length, 1);
      assertComplete(output, f, targets, 1, monitor);
    });
  }
}
