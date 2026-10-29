// Node 24. All dictionary, HTTP and persistence operations use owned local stubs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { monitorExecution } from './monitor_stream_fixture.ts';
import * as source from '../source/bounty/risk_scanner/index.ts';
import * as published from '../plugins/bounty/risk_scanner.ts';
import { runTaskPool } from '../source/bounty/risk_scanner/task_pool.ts';

const targets = ['https://owned.test/'];
function rules(count) {
  const metadata = { requests: [{ method: 'GET', path: '/probe/{{rule_id}}' }],
    matchers: [{ part: 'status', type: 'equals', value: 200 }] };
  return Array.from({ length: count }, (_, index) => ({ word: `rule-${index}`, metadata }));
}
function fixture(t, dictionary, commit) {
  let requests = 0, completions = 0;
  const requested = new Set(), progress = [];
  t.mock.method(globalThis, 'fetch', async url => {
    requests++;
    requested.add(String(url));
    await setImmediate();
    return new Response('', { status: 404 });
  });
  const previous = globalThis.Sentinel;
  t.after(() => { globalThis.Sentinel = previous; });
  globalThis.Sentinel = { Dictionary: dictionary, Monitor: {
    reportProgress: update => { progress.push(update); return true; },
    commitResults: async request => {
      if (commit) await commit(request);
      completions += request.work.filter(item => item.complete).length;
      return { ok: true, sequence: request.sequence };
    },
  } };
  return { requested, progress, get requests() { return requests; }, get completions() { return completions; } };
}
const context = () => monitorExecution(targets, { pluginId: 'risk_scanner' });

for (const [name, plugin] of Object.entries({ source, published })) {
  test(`${name}: explicit dictionary reads and executes every rule beyond 10000`, async t => {
    const entries = rules(10005), calls = [];
    let defaultCalls = 0;
    const f = fixture(t, {
      getDefaultId: () => { defaultCalls++; return 'unexpected-default'; },
      getEntries: (id, limit) => {
        assert.equal(limit, null, 'the native JSON bridge requires an explicit unbounded limit');
        calls.push({ id, limit });
        return limit === null ? entries : entries.slice(0, limit);
      },
    });
    const output = await plugin.analyze({ targets, dictionaryId: 'owned-rules', __monitorExecution: context() });
    assert.equal(output.success, true, output.error);
    assert.equal(output.data.stream_complete, true);
    assert.deepEqual(calls, [{ id: 'owned-rules', limit: null }]);
    assert.equal(defaultCalls, 0);
    assert.equal(f.requests, 10005);
    assert.ok(f.requested.has('https://owned.test/probe/rule-10004'));
    assert.equal(f.completions, 1);
    assert.equal(output.data.summary.diagnostics.loaded_rules, 10005);
    assert.equal(output.data.summary.diagnostics.completed_rule_tasks, 10005);
  });

  test(`${name}: configured default dictionary supplies all of its rules`, async t => {
    const calls = [];
    const f = fixture(t, {
      getDefaultId: type => { assert.equal(type, 'poc_rule'); return 'configured-default'; },
      getEntries: (id, limit) => {
        assert.equal(limit, null);
        calls.push({ id, limit }); return rules(201);
      },
    });
    const output = await plugin.analyze({ targets });
    assert.equal(output.success, true, output.error);
    assert.deepEqual(calls, [{ id: 'configured-default', limit: null }]);
    assert.equal(f.requests, 201);
    assert.equal(output.data.summary.executedRules, 201);
  });

  for (const scenario of ['failed read', 'empty dictionary', 'invalid response']) {
    test(`${name}: ${scenario} does not scan another dictionary or claim completion`, async t => {
      const calls = [];
      let defaultCalls = 0;
      const f = fixture(t, {
        getDefaultId: () => { defaultCalls++; return 'other-dictionary'; },
        getEntries: id => {
          calls.push(id);
          if (scenario === 'failed read') throw new Error('Owned dictionary read failure');
          return scenario === 'empty dictionary' ? [] : {};
        },
      });
      const output = await plugin.analyze({ targets, dictionaryId: 'chosen-dictionary', __monitorExecution: context() });
      assert.equal(output.success, false);
      assert.ok(output.error.length > 0);
      if (scenario === 'failed read') assert.match(output.error, /Owned dictionary read failure/);
      assert.deepEqual(calls, ['chosen-dictionary']);
      assert.equal(defaultCalls, 0);
      assert.equal(f.requests, 0);
      assert.equal(f.completions, 0);
    });
  }

  test(`${name}: empty inline rules and a missing default remain explicit failures`, async t => {
    let reads = 0;
    const f = fixture(t, { getDefaultId: () => null, getEntries: () => { reads++; return rules(1); } });
    for (const input of [{ dictionaryEntries: [] }, {}]) {
      const output = await plugin.analyze({ targets, ...input });
      assert.equal(output.success, false);
      assert.ok(output.error.length > 0);
    }
    assert.equal(reads, 0);
    assert.equal(f.requests, 0);
  });

  test(`${name}: an entirely filtered dictionary completes with zero HTTP work`, async t => {
    const f = fixture(t, {});
    const entry = rules(1)[0];
    const output = await plugin.analyze({ targets, dictionaryEntries: [{ ...entry,
      metadata: { ...entry.metadata, enabled: false } }], __monitorExecution: context() });
    assert.equal(output.success, true, output.error);
    assert.equal(output.data.stream_complete, true);
    assert.equal(f.requests, 0);
    assert.equal(f.completions, 1);
    assert.equal(output.data.summary.diagnostics.applicable_rules, 0);
    assert.equal(output.data.summary.diagnostics.planned_rule_tasks, 0);
    assert.equal(output.data.summary.diagnostics.completed_rule_tasks, 0);
  });

  test(`${name}: UI progress is coalesced while every rule receives durable evidence`, async t => {
    t.mock.method(Date, 'now', () => 1000);
    let ruleRecords = 0;
    const f = fixture(t, {}, request => {
      ruleRecords += request.work.filter(item => /^rule:[^:]+$/.test(item.key)).length;
    });
    const output = await plugin.analyze({ targets, dictionaryEntries: rules(1000), __monitorExecution: context() });
    assert.equal(output.success, true, output.error);
    assert.equal(f.requests, 1000);
    assert.equal(ruleRecords, 1000);
    assert.equal(f.progress.length, 4);
    assert.equal(f.progress.at(-1).current, 1002);
    assert.ok(f.progress.every((item, index) => index === 0 || item.current >= f.progress[index - 1].current));
  });

  test(`${name}: rejected persistence stops new HTTP work and drains started requests`, async t => {
    let releaseFirst, releaseRest, notifyStarted, notifyRejected;
    const first = new Promise(resolve => { releaseFirst = resolve; });
    const rest = new Promise(resolve => { releaseRest = resolve; });
    const started = new Promise(resolve => { notifyStarted = resolve; });
    const rejected = new Promise(resolve => { notifyRejected = resolve; });
    let active = 0, requests = 0, settled = false;
    const f = fixture(t, {}, () => { notifyRejected(); throw new Error('Owned persistence rejected'); });
    globalThis.fetch = async () => {
      const index = requests++;
      active++;
      if (requests === 4) notifyStarted();
      try {
        await (index === 0 ? first : rest);
        return new Response('', { status: 404 });
      } finally { active--; }
    };
    const pending = plugin.analyze({ targets, dictionaryEntries: rules(1000), concurrency: 4,
      __monitorExecution: monitorExecution(targets, { pluginId: 'risk_scanner', maxWorkItems: 1 }),
    }).then(output => { settled = true; return output; });
    await started;
    releaseFirst();
    await rejected;
    await setImmediate();
    assert.equal(settled, false, 'started requests are drained before analyze returns');
    releaseRest();
    const output = await pending;
    assert.equal(output.success, false);
    assert.match(output.error, /Owned persistence rejected/);
    assert.equal(requests, 4);
    assert.equal(active, 0);
    assert.equal(f.completions, 0);
  });
}

test('indexed scheduling starts bounded work for a trillion combinations and stops immediately', async () => {
  const seen = [];
  let stop = false;
  await runTaskPool(1_000_000_000_000, 8, async index => { seen.push(index); stop = true; }, () => stop);
  assert.deepEqual(seen, [0]);
});

test('indexed scheduling latches the first failure, drains peers, and claims no later task', async () => {
  let releaseFailure, releasePeers;
  const failure = new Promise(resolve => { releaseFailure = resolve; });
  const peers = new Promise(resolve => { releasePeers = resolve; });
  const seen = [];
  let settled = false;
  const running = runTaskPool(1000000, 4, async index => {
    seen.push(index);
    if (index === 0) { await failure; throw new Error('Owned failure'); }
    await peers;
  }, () => false).finally(() => { settled = true; });
  const assertion = assert.rejects(running, /Owned failure/);
  releaseFailure();
  await setImmediate();
  assert.equal(settled, false);
  assert.deepEqual(seen, [0, 1, 2, 3]);
  releasePeers();
  await assertion;
  assert.deepEqual(seen, [0, 1, 2, 3]);
});

test('a fast worker refills its slot while a slow peer is still pending', async () => {
  let releaseSlow, notifyRefill;
  const slow = new Promise(resolve => { releaseSlow = resolve; });
  const refilled = new Promise(resolve => { notifyRefill = resolve; });
  let slowCompleted = false;
  const seen = [];
  const running = runTaskPool(4, 2, async index => {
    seen.push(index);
    if (index === 0) { await slow; slowCompleted = true; }
    if (index === 2) notifyRefill();
  }, () => false);
  await refilled;
  assert.equal(slowCompleted, false);
  assert.ok(seen.includes(2));
  releaseSlow();
  await running;
  assert.deepEqual([...seen].sort(), [0, 1, 2, 3]);
});

test('an empty indexed workload creates no work', async () => {
  await runTaskPool(0, 32, async () => { assert.fail('Unexpected work'); }, () => false);
});
