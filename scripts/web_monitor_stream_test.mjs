import test from 'node:test';
import assert from 'node:assert/strict';

const ids = ['http_prober', 'directory_bruteforcer', 'risk_scanner', 'sensitive_file_scanner',
  'actuator_scanner', 'js_analyzer', 'content_monitor', 'favicon_fingerprinter', 'subdomain_takeover'];
const plugins = Object.fromEntries(await Promise.all(ids.map(async id =>
  [id, await import(`../source/bounty/${id}/index.ts`)])));
let handleFetch;
globalThis.fetch = (url, init) => handleFetch(String(url), init);

function fixture(targets, { chunk = 2, commit } = {}) {
  const batches = [], requests = [];
  globalThis.Sentinel = {
    Dictionary: { getEntries: async () => [], getDefaultId: async () => null },
    AST: { parse: () => ({ literals: [], errors: [] }) },
    Monitor: { reportProgress: () => true, commitResults: async request => {
      if (commit) await commit(request);
      batches.push(structuredClone(request));
      return { ok: true, sequence: request.sequence };
    } },
  };
  handleFetch = async (url, init) => {
    requests.push({ url, init });
    throw new Error('Unexpected owned fixture request');
  };
  const context = { task_id: 'owned', task_name: 'Owned fixture', program_id: 'owned',
    execution_mode: 'test', started_at: '2026-10-28T00:00:00Z', current_plugin: 'fixture',
    current_plugin_index: 1, completed_steps: 0, total_steps: 1,
    result_stream: { protocol: 'monitor-results-v1', targets, max_work_items: chunk,
      max_pending_commits: 1, max_bytes: 2 * 1024 * 1024 } };
  return { batches, requests, context,
    fetch(handler) { handleFetch = (url, init) => { requests.push({ url, init }); return handler(url, init); }; } };
}
const work = f => f.batches.flatMap(batch => batch.work);
const data = f => f.batches.map(batch => batch.output.data);
const html = body => new Response(body, { headers: { 'content-type': 'text/html' } });
function complete(f, targets) {
  assert.deepEqual(work(f).filter(item => item.complete).map(item => item.target).sort(), [...targets].sort());
  assert.deepEqual(f.batches.map(batch => batch.sequence), f.batches.map((_, index) => index + 1));
}
function confirmedFindings(f) {
  let count = 0;
  for (const delta of data(f)) {
    if (!Object.hasOwn(delta, 'findings')) continue;
    assert.equal(Object.hasOwn(delta.surface_artifacts || {}, 'findings'), false,
      'the host importer accepts findings in exactly one canonical location');
    for (const finding of delta.findings) {
      count++;
      for (const field of ['finding_type', 'title', 'description', 'affected_url']) {
        assert.equal(typeof finding[field], 'string', field);
        assert.ok(finding[field].length > 0 && finding[field] === finding[field].trim(), field);
      }
      assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity));
      assert.equal(finding.confidence, 'high');
      assert.ok(Object.hasOwn(finding, 'evidence'));
      assert.ok(!Object.hasOwn(finding, 'url') && !Object.hasOwn(finding, 'target')
        && !Object.hasOwn(finding, 'vulnerability_type'));
    }
  }
  assert.ok(count > 0);
}

test('HTTP domains expand to four independent endpoints and persist failures without replacing baselines', async () => {
  const targets = Array.from({ length: 9 }, (_, index) => `owned${index}.test`);
  const f = fixture(targets);
  f.fetch(async url => {
    if (url.endsWith(':8080')) throw new Error('Owned connection failure');
    return html('<title>Owned</title><h1>Endpoint</h1>');
  });
  const output = await plugins.http_prober.analyze({ targets, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(output.data.stream_complete, true);
  assert.equal(f.requests.length, 36);
  assert.ok(f.requests.every(request => request.init.method === 'GET' && request.init.timeout === 3000));
  assert.equal(work(f).length, 36);
  assert.equal(work(f).filter(item => item.status === 'failed').length, 9);
  assert.ok(f.batches.every(batch => batch.work.length <= 2));
  for (const delta of data(f)) {
    assert.ok(Object.keys(delta.snapshots || {}).every(url => !url.endsWith(':8080')));
    assert.ok((delta.changeEvents || []).every(event => event.eventType !== 'asset_removed'));
  }
  assert.equal(output.data.surface_artifacts, undefined);
  complete(f, targets);
});

test('HTTP shared endpoint is probed once and all original target identities complete', async () => {
  const targets = ['owned.test', 'https://owned.test'];
  const f = fixture(targets);
  f.fetch(async () => html('<title>Owned</title>'));
  const output = await plugins.http_prober.analyze({ targets, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(f.requests.length, 4);
  assert.equal(work(f).length, 5);
  complete(f, targets);
});

test('ordinary HTTP output retains the complete target inventory while monitor deltas omit input inventories', async () => {
  const targets = ['one.owned.test', 'two.owned.test'];
  const f = fixture(targets);
  f.fetch(async () => html('<title>Owned</title>'));
  const ordinary = await plugins.http_prober.analyze({ targets });
  assert.equal(ordinary.success, true, ordinary.error);
  assert.deepEqual(ordinary.data.targets, targets);
  assert.equal(ordinary.data.results.length, 8);
  assert.equal(ordinary.data.summary.total, 8);
  assert.equal(f.batches.length, 0);
  const monitor = await plugins.http_prober.analyze({ targets, __monitorExecution: f.context });
  assert.equal(monitor.success, true, monitor.error);
  assert.ok(f.batches.length > 0);
  assert.ok(data(f).every(delta => !Object.hasOwn(delta, 'targets')));
});

test('HTTP typed service batches preserve endpoint owners without expanding service targets into all default ports', async () => {
  const targets = Array.from({ length: 256 }, (_, index) => `service${String(index).padStart(4, '0')}.owned.test:443/tcp`);
  const f = fixture(targets, { chunk: 32 });
  f.fetch(async () => html('<title>Owned service</title>'));
  const output = await plugins.http_prober.analyze({ targets,
    target_objects: targets.map((value, index) => ({ type: 'service', value, source: 'surface_asset',
      asset_id: `service-${index}`, protocol: 'https' })), __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(f.requests.length, targets.length);
  assert.equal(new Set(f.requests.map(request => request.url)).size, targets.length);
  assert.ok(f.requests.every(request => request.url.startsWith('https://') && !request.url.includes(':8080')));
  complete(f, targets);
});

test('directory scan shares one prepared wordlist across every host target and records negative paths', async () => {
  const targets = ['https://one.test/', 'https://two.test/'];
  const f = fixture(targets);
  f.fetch(async url => new Response(url.endsWith('/hit') ? 'owned' : '', { status: url.endsWith('/hit') ? 200 : 404 }));
  const output = await plugins.directory_bruteforcer.analyze({ targets,
    customWordlist: ['hit', 'miss', 'other'], concurrency: 1, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(f.requests.length, 6);
  assert.equal(work(f).length, 6);
  assert.equal(data(f).flatMap(delta => delta.discovered || []).length, 2);
  complete(f, targets);
});

test('directory commit failure stops before starting another path', async () => {
  const targets = ['https://owned.test/'];
  const f = fixture(targets, { chunk: 1, commit: () => { throw new Error('Owned database write failed'); } });
  f.fetch(async () => new Response('', { status: 404 }));
  const output = await plugins.directory_bruteforcer.analyze({ targets,
    customWordlist: ['one', 'two', 'three'], concurrency: 1, __monitorExecution: f.context });
  assert.equal(output.success, false);
  assert.match(output.error, /database write failed/);
  assert.equal(f.requests.length, 1);
});

test('risk stopOnFirstHit is shared across targets and rules while all targets receive terminal receipts', async () => {
  const targets = ['https://one.test/', 'https://two.test/'];
  const f = fixture(targets);
  f.fetch(async () => html('owned'));
  const rules = Array.from({ length: 40 }, (_, index) => ({ word: `owned-${index}`, metadata: {
    requests: [{ path: `/probe${index}`, method: 'GET' }],
    matchers: [{ part: 'status', type: 'equals', value: 200 }],
  } }));
  const output = await plugins.risk_scanner.analyze({ targets, dictionaryEntries: rules,
    maxRules: 40, stopOnFirstHit: true, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.ok(f.requests.length > 0 && f.requests.length <= 32);
  assert.ok(f.requests.every(request => new URL(request.url).hostname === 'one.test'));
  assert.ok(data(f).flatMap(delta => delta.findings || []).length > 0);
  confirmedFindings(f);
  const evidence = data(f).flatMap(delta => delta.surface_artifacts?.evidences || []);
  assert.ok(evidence.length > 0);
  assert.ok(evidence.every(item => item.asset_key === targets[0]), 'existing Web references keep the original trailing slash');
  complete(f, targets);
});

test('a multi-request risk rule persists real steps and never swallows a rejected ACK', async () => {
  const targets = ['https://owned.test/'];
  const f = fixture(targets, { chunk: 1, commit: () => { throw new Error('Owned risk commit rejected'); } });
  f.fetch(async () => html('owned'));
  const output = await plugins.risk_scanner.analyze({ targets,
    dictionaryEntries: [{ word: 'steps', metadata: {
      requests: [{ path: '/first', method: 'GET' }, { path: '/second', method: 'GET' }],
      matchers: [{ part: 'status', type: 'equals', value: 200 }],
    } }], __monitorExecution: f.context });
  assert.equal(output.success, false);
  assert.match(output.error, /risk commit rejected/);
  assert.equal(f.requests.length, 1);
});

test('sensitive scan retains its baseline and stops remaining rules after the first network failure', async () => {
  const targets = ['https://one.test/', 'https://two.test/'];
  const f = fixture(targets);
  f.fetch(async url => {
    if (url.includes('.sentinel-soft404-')) return new Response('', { status: 404 });
    if (url.endsWith('/broken')) throw new Error('Owned request timed out');
    return html('owned explicit match');
  });
  const rules = ['hit', 'broken', 'never'].map(word => ({ word, metadata: { path: `/${word}`,
    matchers: [{ part: 'body', type: 'contains', value: 'explicit match' }] } }));
  const output = await plugins.sensitive_file_scanner.analyze({ targets, maxTargets: 1,
    dictionaryEntries: rules, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(f.requests.filter(request => request.url.includes('.sentinel-soft404-')).length, 1);
  assert.ok(f.requests.every(request => !request.url.endsWith('/never')));
  assert.equal(data(f).flatMap(delta => delta.findings || []).length, 1);
  confirmedFindings(f);
  assert.equal(work(f).find(item => item.target === targets[1]).status, 'skipped');
  assert.equal(work(f).find(item => item.target === targets[0] && item.complete).status, 'failed');
  complete(f, targets);
});

test('content failure is durable and omits the failed target snapshot', async () => {
  const targets = ['https://one.test/', 'https://two.test/'];
  const f = fixture(targets);
  f.fetch(async url => { if (url.includes('two.test')) throw new Error('Owned connection failure'); return html('<title>Owned</title>'); });
  const output = await plugins.content_monitor.analyze({ targets, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(work(f).filter(item => item.status === 'failed').length, 1);
  assert.deepEqual(data(f).flatMap(delta => Object.keys(delta.snapshots || {})), [targets[0]]);
  const changes = data(f).flatMap(delta => delta.surface_artifacts?.changes || []);
  assert.ok(changes.length > 0);
  assert.ok(changes.every(change => change.asset_key === targets[0] && change.source === 'content_monitor'));
  complete(f, targets);
});

test('favicon scan persists real page and icon attempts and keeps the original host identity', async () => {
  const targets = ['https://owned.test/'];
  const f = fixture(targets);
  f.fetch(async url => url.endsWith('.ico')
    ? new Response(new Uint8Array([0, 0, 1, 0, 1, 0, 4, 4]), { headers: { 'content-type': 'image/x-icon' } })
    : html('<title>Owned</title><link rel="icon" href="/favicon.ico">'));
  const output = await plugins.favicon_fingerprinter.analyze({ targets,
    target_objects: [{ type: 'web', value: targets[0], source: 'surface_asset', asset_id: 'owned-web' }],
    dictionaryEntries: [{ word: '-597389481', metadata: { product: 'Owned', asset_category: 'web_server' } }],
    __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(work(f).length, 3);
  assert.equal(data(f).flatMap(delta => delta.surface_artifacts?.fingerprints || []).length, 1);
  assert.deepEqual(data(f).flatMap(delta => delta.surface_artifacts?.webs || []), [], 'existing Web enrichment must not rediscover a normalized alias');
  for (const delta of data(f)) for (const item of [
    ...(delta.surface_artifacts?.fingerprints || []), ...(delta.surface_artifacts?.evidences || []),
  ]) assert.equal(item.asset_key, targets[0]);
  complete(f, targets);
});

test('favicon domain discovery retains canonical new Web URLs', async () => {
  const targets = ['owned.test'];
  const f = fixture(targets);
  f.fetch(async url => url.endsWith('.ico')
    ? new Response(new Uint8Array([0, 0, 1, 0, 1, 0, 4, 4]), { headers: { 'content-type': 'image/x-icon' } })
    : html('<title>Owned</title><link rel="icon" href="/favicon.ico">'));
  const output = await plugins.favicon_fingerprinter.analyze({ targets, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.deepEqual(data(f).flatMap(delta => delta.surface_artifacts?.webs || []).map(item => item.canonical_url), ['https://owned.test']);
  assert.ok(data(f).flatMap(delta => delta.surface_artifacts?.evidences || []).every(item => item.asset_key === 'https://owned.test'));
  complete(f, targets);
});

test('shared normalized Web identities enrich both exact stored assets without repeating requests or findings', async () => {
  const targets = ['https://owned.test', 'https://owned.test/'];
  const f = fixture(targets, { chunk: 1 });
  f.fetch(async () => html('OWNED_EXPLICIT_MATCH'));
  const risk = await plugins.risk_scanner.analyze({ targets, dictionaryEntries: [{ word: 'owned', metadata: {
    requests: [{ method: 'GET', path: '/check' }],
    matchers: [{ part: 'body', type: 'contains', value: 'OWNED_EXPLICIT_MATCH' }],
  } }], __monitorExecution: f.context });
  assert.equal(risk.success, true, risk.error);
  assert.equal(f.requests.length, 1);
  assert.equal(data(f).flatMap(delta => delta.findings || []).length, 1);
  assert.deepEqual(data(f).flatMap(delta => delta.surface_artifacts?.evidences || []).map(item => item.asset_key).sort(), [...targets].sort());
  complete(f, targets);

  const icons = fixture(targets, { chunk: 1 });
  icons.fetch(async url => url.endsWith('.ico')
    ? new Response(new Uint8Array([0, 0, 1, 0, 1, 0, 4, 4]), { headers: { 'content-type': 'image/x-icon' } })
    : html('<title>Owned</title><link rel="icon" href="/favicon.ico">'));
  const favicon = await plugins.favicon_fingerprinter.analyze({ targets,
    target_objects: targets.map((value, index) => ({ type: 'web', value, source: 'surface_asset', asset_id: `owned-${index}` })),
    dictionaryEntries: [{ word: '-597389481', metadata: { product: 'Owned', asset_category: 'web_server' } }],
    __monitorExecution: icons.context });
  assert.equal(favicon.success, true, favicon.error);
  assert.equal(icons.requests.length, 2, 'the shared page and icon are each fetched once');
  assert.deepEqual(data(icons).flatMap(delta => delta.surface_artifacts?.webs || []), []);
  for (const kind of ['evidences', 'fingerprints']) assert.deepEqual(
    data(icons).flatMap(delta => delta.surface_artifacts?.[kind] || []).map(item => item.asset_key).sort(), [...targets].sort());
  assert.equal(data(icons).flatMap(delta => delta.results || []).filter(result => result.faviconHash).length, 1);
  complete(icons, targets);
});

test('actuator probes keep shared baselines and persist each confirmed endpoint once', async () => {
  const targets = ['https://one.test/', 'https://two.test/'];
  const f = fixture(targets);
  f.fetch(async url => url.endsWith('/info') ? Response.json({ app: 'Owned', build: '1' }) : new Response('', { status: 404 }));
  const output = await plugins.actuator_scanner.analyze({ targets, actuator_endpoints: ['info'],
    include_actuator_prefix: false, concurrency: 1, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(f.requests.length, 4);
  assert.equal(data(f).flatMap(delta => delta.findings || []).length, 2);
  confirmedFindings(f);
  complete(f, targets);
});

test('JavaScript analysis persists each real file during discovery and does not replay files on completion', async () => {
  const targets = ['https://owned.test/'];
  const f = fixture(targets);
  f.fetch(async url => url.endsWith('.js') ? new Response('const owned = 1;', { headers: { 'content-type': 'application/javascript' } })
    : html(Array.from({ length: 40 }, (_, index) => `<script src="/file${index}.js"></script>`).join('')));
  const output = await plugins.js_analyzer.analyze({ urls: targets, maxFiles: 40, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(f.requests.length, 41);
  assert.equal(data(f).flatMap(delta => delta.files || []).length, 40);
  assert.equal(output.data.files, undefined);
  complete(f, targets);
});

test('takeover DNS transport failure remains failed evidence and never becomes NXDOMAIN vulnerability', async () => {
  const targets = ['owned.test'];
  const f = fixture(targets);
  f.fetch(async () => new Response('', { status: 503 }));
  const output = await plugins.subdomain_takeover.analyze({ domains: targets, __monitorExecution: f.context });
  assert.equal(output.success, true, output.error);
  assert.equal(work(f)[0].status, 'failed');
  assert.equal(data(f)[0].results[0].vulnerable, false);
  assert.match(data(f)[0].results[0].error, /DNS query failed/);
  assert.equal(f.requests.length, 1);
  complete(f, targets);
});

test('all web plugins reject a missing monitor protocol before any network work', async () => {
  const f = fixture([]);
  for (const id of ids) {
    const output = await plugins[id].analyze({ __monitorExecution: {} });
    assert.equal(output.success, false, id);
    assert.match(output.error, /monitor-results-v1/, id);
  }
  assert.equal(f.requests.length, 0);
});

test('large streamed HTTP, directory, rule and JavaScript scans acknowledge every result and return only bounded completion metrics', async () => {
  for (const kind of ['http', 'directory', 'risk', 'javascript']) {
    const targets = kind === 'http' ? Array.from({ length: 300 }, (_, index) => `bulk${index}.test`)
      : kind === 'risk' ? Array.from({ length: 20 }, (_, index) => `https://bulk${index}.test/`)
        : ['https://bulk.test/'];
    const f = fixture(targets, { chunk: 32 });
    let savedWork = 0, savedProducts = 0, commits = 0, requestCount = 0;
    // Count receipts without retaining their payloads in this fixture.
    globalThis.Sentinel.Monitor.commitResults = async request => {
      savedWork += request.work.length;
      commits++;
      assert.ok(request.work.length <= 32);
      const delta = request.output.data;
      savedProducts += kind === 'javascript' ? (delta.files || []).length
        : kind === 'directory' ? (delta.discovered || []).length
          : kind === 'risk' ? (delta.findings || []).length : (delta.results || []).length;
      return { ok: true, sequence: request.sequence };
    };
    handleFetch = async url => {
      requestCount++;
      if (kind === 'javascript' && String(url) === targets[0]) {
        return html(Array.from({ length: 128 }, (_, index) => `<script src="/file${index}.js"></script>`).join(''));
      }
      return html('<title>Owned bulk result</title><h1>Explicit owned result</h1>');
    };
    let output;
    if (kind === 'http') output = await plugins.http_prober.analyze({ targets, __monitorExecution: f.context });
    else if (kind === 'directory') output = await plugins.directory_bruteforcer.analyze({ targets,
      customWordlist: Array.from({ length: 1000 }, (_, index) => `path${index}`), __monitorExecution: f.context });
    else if (kind === 'risk') output = await plugins.risk_scanner.analyze({ targets, maxRules: 65,
      dictionaryEntries: Array.from({ length: 65 }, (_, index) => ({ word: `rule${index}`, metadata: {
        requests: [{ method: 'GET', path: `/rule${index}` }], matchers: [{ part: 'status', type: 'equals', value: 200 }],
      } })), __monitorExecution: f.context });
    else output = await plugins.js_analyzer.analyze({ urls: targets, maxFiles: 128, __monitorExecution: f.context });
    assert.equal(output.success, true, `${kind}: ${output.error}`);
    assert.equal(output.data.stream_complete, true);
    assert.equal(output.data.summary.diagnostics.committed_work_items, savedWork);
    assert.equal(output.data.summary.diagnostics.completed_targets, targets.length);
    assert.ok(commits > 3, kind);
    assert.equal(savedProducts, kind === 'http' ? 1200 : kind === 'directory' ? 1000 : kind === 'risk' ? 1300 : 128);
    assert.equal(requestCount, kind === 'http' ? 1200 : kind === 'directory' ? 1000 : kind === 'risk' ? 1300 : 129);
    assert.ok(JSON.stringify(output).length < 1000, `${kind}: final output must not retain full scan products`);
    assert.equal(f.batches.length, 0);
  }
});

const linearCases = {
  http_prober: {
    domain: true, workPerTarget: 4, requestsPerTarget: 4,
    input: () => ({}), fetch: async () => html('<title>Owned</title><h1>Owned result</h1>'),
  },
  directory_bruteforcer: {
    workPerTarget: 2, requestsPerTarget: 2,
    input: () => ({ customWordlist: ['first', 'second'] }), fetch: async () => new Response('Owned result'),
  },
  risk_scanner: {
    workPerTarget: 3, requestsPerTarget: 1,
    input: () => ({ dictionaryEntries: [{ word: 'owned', metadata: {
      requests: [{ method: 'GET', path: '/check' }],
      matchers: [{ part: 'body', type: 'contains', value: 'OWNED_EXPLICIT_MATCH' }],
    } }] }), fetch: async () => html('OWNED_EXPLICIT_MATCH'),
  },
  sensitive_file_scanner: {
    workPerTarget: 3, requestsPerTarget: 2,
    input: () => ({ dictionaryEntries: [{ word: 'owned', metadata: { path: '/check',
      matchers: [{ part: 'body', type: 'contains', value: 'OWNED_EXPLICIT_MATCH' }],
    } }] }), fetch: async url => url.includes('.sentinel-soft404-') ? new Response('', { status: 404 }) : html('OWNED_EXPLICIT_MATCH'),
  },
  actuator_scanner: {
    workPerTarget: 3, requestsPerTarget: 2,
    input: () => ({ actuator_endpoints: ['info'], include_actuator_prefix: false }),
    fetch: async url => url.endsWith('/info') ? Response.json({ app: 'Owned', build: '1' }) : new Response('', { status: 404 }),
  },
  js_analyzer: {
    workPerTarget: 3, requestsPerTarget: 2,
    input: targets => ({ urls: targets }),
    fetch: async url => url.endsWith('.js') ? new Response('const owned = 1;', { headers: { 'content-type': 'application/javascript' } })
      : html('<script src="/source.js"></script>'),
  },
  content_monitor: {
    workPerTarget: 1, requestsPerTarget: 1,
    input: () => ({}), fetch: async () => html('<title>Owned</title><h1>Owned result</h1>'),
  },
  favicon_fingerprinter: {
    workPerTarget: 3, requestsPerTarget: 2,
    input: targets => ({
      target_objects: targets.map((value, index) => ({ type: 'web', value, source: 'surface_asset', asset_id: `web-${index}` })),
      dictionaryEntries: [{ word: '-597389481', metadata: { product: 'Owned', asset_category: 'web_server' } }],
    }),
    fetch: async url => url.endsWith('.ico')
      ? new Response(new Uint8Array([0, 0, 1, 0, 1, 0, 4, 4]), { headers: { 'content-type': 'image/x-icon' } })
      : html('<title>Owned</title><link rel="icon" href="/favicon.ico">'),
  },
  subdomain_takeover: {
    domain: true, workPerTarget: 1, requestsPerTarget: 1,
    input: targets => ({ domains: targets, checkCname: false, checkHttp: true }),
    fetch: async () => html('<title>Owned</title><h1>Owned result</h1>'),
  },
};

async function linearSubmission(id, count) {
  const spec = linearCases[id];
  const targets = Array.from({ length: count }, (_, index) => {
    const host = `bulk${String(index).padStart(4, '0')}.owned.test`;
    return spec.domain ? host : `https://${host}/`;
  });
  const f = fixture(targets, { chunk: 32 });
  let workItems = 0, bytes = 0, maxBytes = 0, requests = 0, batches = 0;
  globalThis.Sentinel.Monitor.commitResults = async request => {
    const delta = request.output.data;
    for (const forbidden of ['targets', 'urls', 'domains', 'ips', 'target_objects', 'service_targets', 'previousSnapshots', 'dictionaryEntries']) {
      assert.equal(Object.hasOwn(delta, forbidden), false, `${id}: delta contains ${forbidden} input inventory`);
    }
    for (const key of ['results', 'files', 'discovered', 'findings']) {
      if (Array.isArray(delta[key])) assert.ok(delta[key].length <= request.work.length,
        `${id}: ${key} must contain current work, not the cumulative scan`);
    }
    if (delta.snapshots) assert.ok(Object.keys(delta.snapshots).length <= request.work.length,
      `${id}: snapshot delta must not contain the historical inventory`);
    const serialized = JSON.stringify(request);
    assert.ok(!serialized.includes('UNRELATED_HISTORY_MUST_STAY_AT_INPUT'), `${id}: unrelated baseline was submitted`);
    const size = Buffer.byteLength(serialized);
    assert.ok(size <= request.work.length * 12000 + 1024, `${id}: current-work payload grew with all targets`);
    workItems += request.work.length;
    bytes += size;
    maxBytes = Math.max(maxBytes, size);
    batches++;
    return { ok: true, sequence: request.sequence };
  };
  handleFetch = async url => { requests++; return spec.fetch(String(url)); };
  const output = await plugins[id].analyze({ targets, ...spec.input(targets),
    previousSnapshots: { 'https://unrelated.owned.test/': { marker: 'UNRELATED_HISTORY_MUST_STAY_AT_INPUT' } },
    __monitorExecution: f.context });
  assert.equal(output.success, true, `${id}: ${output.error}`);
  assert.equal(workItems, count * spec.workPerTarget, id);
  assert.equal(requests, count * spec.requestsPerTarget, id);
  assert.equal(output.data.summary.diagnostics.completed_targets, count, id);
  return { targets: count, workItems, bytes, maxBytes, batches };
}

for (const id of Object.keys(linearCases)) test(`${id}: doubling target count keeps total committed JSON linear`, async t => {
  const small = await linearSubmission(id, 128);
  const large = await linearSubmission(id, 256);
  assert.ok(large.bytes <= small.bytes * 2.1 + 2048,
    `${id}: submissions grew superlinearly (${small.bytes} -> ${large.bytes} bytes)`);
  assert.ok(large.maxBytes <= small.maxBytes * 1.15 + 2048,
    `${id}: batch bytes must stay bounded by work count, not the full inventory`);
  t.diagnostic(JSON.stringify({ plugin: id, samples: [small, large] }));
});
