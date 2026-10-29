import { requestData } from './monitor_request_test_support.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../source/bounty/api_monitor/index.ts';
import { discoverJavascriptAssets } from '../source/bounty/api_monitor/discovery.ts';

let handleFetch;
globalThis.fetch = (url, init) => handleFetch(String(url), init);
const html = text => new Response(text, { headers: { 'content-type': 'text/html' } });
const javascript = text => new Response(text, { headers: { 'content-type': 'application/javascript' } });
function fixture(targets, { chunk = 32, commit } = {}) {
  const requests = [], batches = [], progress = [];
  globalThis.Sentinel = { Monitor: {
    reportProgress: update => { progress.push(update); return true; },
    commitResults: async request => {
      if (commit) await commit(request);
      batches.push(structuredClone(request));
      return { ok: true, sequence: request.sequence };
    },
  } };
  handleFetch = async () => { throw new Error('Unexpected owned fixture request'); };
  return { requests, batches, progress,
    context: { task_id: 'owned', task_name: 'Owned API fixture', program_id: 'owned',
      execution_mode: 'test', started_at: '2026-10-28T00:00:00Z', current_plugin: 'api_monitor',
      current_plugin_index: 1, completed_steps: 0, total_steps: 1,
      result_stream: { protocol: 'monitor-results-v2', targets, max_work_items: chunk,
        max_pending_commits: 1, max_bytes: 2 * 1024 * 1024 } },
    fetch(handler) { handleFetch = (url, init) => { requests.push({ url, init }); return handler(url, init); }; },
  };
}
const data = f => f.batches.map(batch => requestData(batch));
const work = f => f.batches.flatMap(batch => batch.work);
const previous = root => ({ [root]: { baseUrl: root,
  apiEndpoints: [{ path: '/api/historical', source: 'previous' }],
  htmlRoutes: [{ path: '/historical', source: 'previous' }], lastChecked: '2026-10-27T00:00:00Z' } });

test('one root publishes more than 32 real resource results before its slow last script finishes', async () => {
  const target = 'https://owned.test/';
  let firstCommit, release;
  const committed = new Promise(resolve => { firstCommit = resolve; });
  const blocked = new Promise(resolve => { release = resolve; });
  const f = fixture([target], { commit: async () => firstCommit() });
  f.fetch(async url => {
    if (url === target) return html(Array.from({ length: 40 }, (_, index) => `<script src="/file${index}.js"></script>`).join(''));
    const index = Number(new URL(url).pathname.match(/file(\d+)/)?.[1]);
    if (index === 39) await blocked;
    return javascript(`fetch("/api/items${index}");`);
  });
  let finished = false;
  const pending = analyze({ targets: [target], maxJsFiles: 50, __monitorExecution: f.context }).then(result => { finished = true; return result; });
  await committed;
  assert.equal(finished, false);
  assert.ok(work(f).every(item => !item.complete));
  release();
  const output = await pending;
  assert.equal(output.success, true, output.error);
  assert.equal(output.data.stream_complete, true);
  assert.equal(f.requests.length, 41);
  assert.equal(data(f).flatMap(delta => delta.resourceResults || []).length, 41);
  assert.equal(work(f).filter(item => item.complete).length, 1);
  const terminal = data(f).flatMap(delta => delta.results || []);
  assert.equal(terminal.length, 1);
  assert.equal(terminal[0].snapshot.apiEndpoints.length, 40);
  assert.equal(output.data.results, undefined);
  assert.ok(f.batches.every(batch => batch.work.length <= 32));
});

test('partial script failure keeps the previous complete inventory and emits no removed changes', async () => {
  const target = 'https://owned.test/';
  const baseline = previous(target), untouched = structuredClone(baseline);
  const f = fixture([target], { chunk: 1 });
  f.fetch(async url => {
    if (url === target) return html('<script src="/good.js"></script><script src="/broken.js"></script>');
    if (url.endsWith('/broken.js')) return new Response('', { status: 503 });
    return javascript('fetch("/api/current");');
  });
  const output = await analyze({ targets: [target], previousSnapshots: baseline, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.deepEqual(baseline, untouched);
  assert.deepEqual(data(f).flatMap(delta => Object.keys(delta.snapshots || {})), []);
  assert.deepEqual(data(f).flatMap(delta => delta.changeEvents || []), []);
  assert.deepEqual(data(f).flatMap(delta => delta.surface_artifacts?.changes || []), []);
  assert.equal(work(f).find(item => item.complete).status, 'failed');
  assert.ok(data(f).flatMap(delta => delta.resourceResults || []).some(result =>
    result.apiEndpoints.some(endpoint => endpoint.path === '/api/current')));
});

test('a linked page HTTP error leaves root inventory incomplete while optional missing manifests are negative results', async () => {
  const target = 'https://owned.test/';
  const f = fixture([target]);
  f.fetch(async url => url === target ? html('<a href="/missing-page">Missing page</a>') : new Response('', { status: 404 }));
  const failed = await analyze({ targets: [target], crawlDepth: 2, previousSnapshots: previous(target), __monitorExecution: f.context });
  assert.equal(failed.success, true, failed.error);
  assert.equal(work(f).find(item => item.complete).status, 'failed');
  assert.deepEqual(data(f).flatMap(delta => Object.keys(delta.snapshots || {})), []);

  const optional = fixture([target]);
  optional.fetch(async url => url === target ? html('<script src="/good.js"></script>')
    : url.endsWith('/good.js') ? javascript('fetch("/api/current");') : new Response('', { status: 404 }));
  const success = await analyze({ targets: [target], probeSpaManifests: true, __monitorExecution: optional.context });
  assert.equal(success.success, true, success.error);
  assert.equal(work(optional).find(item => item.complete).status, 'ok');
  assert.ok(data(optional).flatMap(delta => delta.resourceResults || []).some(result => result.role === 'manifest' && result.status === 404));
});

test('a rejected root request receipt propagates before script discovery starts', async () => {
  const target = 'https://owned.test/';
  let attemptedCommits = 0;
  const f = fixture([target], { chunk: 1, commit: () => { attemptedCommits++; throw new Error('Owned API receipt rejected'); } });
  f.fetch(async () => html('<script src="/must-not-start.js"></script>'));
  const output = await analyze({ targets: [target], __monitorExecution: f.context });
  assert.equal(output.success, false);
  assert.match(output.error, /API receipt rejected/);
  assert.equal(attemptedCommits, 1);
  assert.equal(f.requests.length, 1);
  assert.equal(f.batches.length, 0);
});

test('root fetch early return still completes once and non-monitor failure counters remain exclusive', async () => {
  const target = 'https://owned.test/';
  const f = fixture([target], { chunk: 1 });
  f.fetch(async () => { throw new Error('Owned API root failure'); });
  const output = await analyze({ targets: [target], __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(work(f).filter(item => item.complete).length, 1);
  assert.equal(work(f).find(item => item.complete).status, 'failed');
  assert.ok(f.progress.some(update => update.phase === 'discover' && update.current === 1));
  const ordinary = await analyze({ targets: [target] });
  assert.equal(ordinary.success, true, ordinary.error);
  assert.equal(ordinary.data.summary.successfulChecks, 0);
  assert.equal(ordinary.data.summary.failedChecks, 1);
  assert.equal(ordinary.data.results.length, 1);
});

test('repeated target identities are scanned and completed once', async () => {
  const target = 'https://owned.test/';
  const f = fixture([target]);
  f.fetch(async () => html('<script>fetch("/api/owned");</script>'));
  const output = await analyze({ targets: [target, target], __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(f.requests.length, 1);
  assert.equal(work(f).filter(item => item.complete).length, 1);
  assert.equal(data(f).flatMap(delta => delta.results || [])[0].snapshot.apiEndpoints[0].path, '/api/owned');
});

test('concurrent roots retain their own events, snapshots, and target receipts', async () => {
  const targets = ['https://one.test/', 'https://two.test/'];
  const f = fixture(targets, { chunk: 1 });
  f.fetch(async url => html(`<script>fetch("/api/${new URL(url).hostname.split('.')[0]}");</script>`));
  const output = await analyze({ targets, previousSnapshots: { ...previous(targets[0]), ...previous(targets[1]) }, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  for (const batch of f.batches) {
    if (!requestData(batch).changeEvents?.length) continue;
    assert.equal(batch.work.length, 1);
    assert.ok(requestData(batch).changeEvents.every(event => event.assetId === batch.work[0].target));
    assert.deepEqual(Object.keys(requestData(batch).snapshots), [batch.work[0].target]);
    assert.equal(requestData(batch).surface_artifacts.changes.length, requestData(batch).changeEvents.length);
    assert.ok(requestData(batch).surface_artifacts.changes.every(change =>
      change.asset_key === batch.work[0].target && change.asset_type === 'web' && change.source === 'api_monitor'));
  }
  assert.deepEqual(work(f).filter(item => item.complete).map(item => item.target).sort(), [...targets].sort());
});

test('ordinary execution retains complete API inventories and streamed execution releases raw script bodies', async () => {
  const target = 'https://owned.test/';
  const f = fixture([target]);
  f.fetch(async url => url === target ? html('<a href="/dashboard">Dashboard</a><script src="/app.js"></script>')
    : javascript('fetch("/api/users");'));
  const output = await analyze({ targets: [target] });
  assert.equal(output.success, true, output.error);
  assert.equal(output.data.results[0].success, true);
  assert.deepEqual(output.data.snapshots[target].apiEndpoints.map(endpoint => endpoint.path), ['/api/users']);
  assert.ok(output.data.snapshots[target].htmlRoutes.some(route => route.path === '/dashboard'));
  assert.equal(f.batches.length, 0);

  const body = 'fetch("/api/retained");' + ' '.repeat(128 * 1024);
  f.fetch(async () => javascript(body));
  const discovery = await discoverJavascriptAssets(target, '<script src="/large.js"></script>',
    'Owned', 1, 10, 20, true, false, false, async () => {}, () => {}, false);
  assert.equal(discovery.scriptContents.length, 1);
  assert.equal(discovery.scriptContents[0].content.length, 0);
});

test('source-map embedded sources are extracted before their raw bodies are released', async () => {
  const target = 'https://owned.test/';
  const f = fixture([target]);
  f.fetch(async url => url === target ? html('<script src="/app.js"></script>')
    : url.endsWith('.map') ? Response.json({ version: 3, sources: ['source.js'], sourcesContent: ['fetch("/api/from-map");'] })
      : javascript('fetch("/api/from-js");\n//# sourceMappingURL=app.js.map'));
  const output = await analyze({ targets: [target], followSourceMaps: true, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  const paths = data(f).flatMap(delta => delta.results || [])[0].snapshot.apiEndpoints.map(endpoint => endpoint.path);
  assert.ok(paths.includes('/api/from-js'));
  assert.ok(paths.includes('/api/from-map'));
});

test('monitor execution rejects a missing protocol without HTTP requests', async () => {
  const target = 'https://owned.test/';
  const f = fixture([target]);
  const output = await analyze({ targets: [target], __monitorExecution: {} });
  assert.equal(output.success, false);
  assert.match(output.error, /monitor-results-v2/);
  assert.equal(f.requests.length, 0);
});

async function apiSubmissionBytes(count) {
  const targets = Array.from({ length: count }, (_, index) => `https://bulk${String(index).padStart(4, '0')}.owned.test/`);
  const f = fixture(targets);
  let workItems = 0, bytes = 0, maxBytes = 0, requests = 0;
  globalThis.Sentinel.Monitor.commitResults = async request => {
    const delta = requestData(request);
    for (const forbidden of ['targets', 'urls', 'target_objects', 'service_targets', 'previousSnapshots', 'dictionaryEntries']) {
      assert.equal(Object.hasOwn(delta, forbidden), false, `API delta contains ${forbidden}`);
    }
    for (const field of ['results', 'resourceResults']) if (delta[field]) {
      assert.ok(delta[field].length <= request.work.length, `${field} contains previous targets' results`);
    }
    if (delta.snapshots) assert.ok(Object.keys(delta.snapshots).length <= request.work.length);
    const serialized = JSON.stringify(request);
    assert.ok(!serialized.includes('UNRELATED_HISTORY_MUST_STAY_AT_INPUT'));
    const size = Buffer.byteLength(serialized);
    assert.ok(size <= request.work.length * 12000 + 1024);
    workItems += request.work.length;
    bytes += size;
    maxBytes = Math.max(maxBytes, size);
    return { ok: true, sequence: request.sequence };
  };
  handleFetch = async url => {
    requests++;
    return String(url).endsWith('.js') ? javascript('fetch("/api/owned");') : html('<script src="/source.js"></script>');
  };
  const output = await analyze({ targets, previousSnapshots: { 'https://unrelated.owned.test/': {
    marker: 'UNRELATED_HISTORY_MUST_STAY_AT_INPUT',
  } }, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(workItems, count * 3);
  assert.equal(requests, count * 2);
  assert.equal(output.data.summary.diagnostics.completed_targets, count);
  return { targets: count, workItems, bytes, maxBytes };
}

test('API committed bytes scale with current resources and completed roots, without repeated input or history', async t => {
  const small = await apiSubmissionBytes(128);
  const large = await apiSubmissionBytes(256);
  assert.ok(large.bytes <= small.bytes * 2.1 + 2048, `API submissions grew superlinearly: ${small.bytes} -> ${large.bytes}`);
  assert.ok(large.maxBytes <= small.maxBytes * 1.15 + 2048);
  t.diagnostic(JSON.stringify({ plugin: 'api_monitor', samples: [small, large] }));
});
