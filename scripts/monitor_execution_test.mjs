// Run with Node 24: node --test scripts/monitor_execution_test.mjs
// All requests are local stubs; no network and no credentials are used.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
const originalFetch = globalThis.fetch;
const originalSentinel = globalThis.Sentinel;
let handleFetch;
globalThis.fetch = (...args) => handleFetch(...args);
globalThis.Sentinel = { log() {}, Monitor: { reportProgress() { return true; } } };
const subdomain = await import('../plugins/bounty/subdomain_enumerator.ts');
const fofa = await import('../plugins/bounty/fofa_asset_monitor.ts');
after(() => { globalThis.fetch = originalFetch; globalThis.Sentinel = originalSentinel; });
const ok = (body) => new Response(JSON.stringify(body), { status: 200 });

test('enumerates every unique domain, keeps aliases from truncating input, and merges snapshots', async () => {
  const requested = [];
  handleFetch = async (url) => { const domain = new URL(url).searchParams.get('q').replace(/^%\./, ''); requested.push(domain); return ok([{ name_value: 'api.' + domain }]); };
  const output = await subdomain.analyze({ domains: ['one.test', 'two.test', 'ONE.TEST'], domain: 'one.test', sources: ['crtsh'], previousSnapshots: { 'old.test': { domain: 'old.test', subdomains: [], lastChecked: 'old' } } });
  assert.equal(output.success, true);
  assert.deepEqual(requested.sort(), ['one.test', 'two.test']);
  assert.deepEqual(output.data.subdomains, ['api.one.test', 'api.two.test']);
  assert.equal(output.data.summary.totalTargets, 2);
  assert.deepEqual(Object.keys(output.data.snapshots).sort(), ['old.test', 'one.test', 'two.test']);
});

test('all failed sources propagate failure and retain the previous snapshot', async () => {
  handleFetch = async () => new Response('denied', { status: 401 });
  const previous = { 'one.test': { domain: 'one.test', subdomains: ['api.one.test'], lastChecked: 'old' } };
  const output = await subdomain.analyze({ domains: ['one.test', 'two.test'], sources: ['crtsh', 'alienvault'], previousSnapshots: previous });
  assert.equal(output.success, false);
  assert.equal(output.data.summary.failedTargets, 2);
  assert.match(output.error, /HTTP 401/);
  assert.deepEqual(output.data.snapshots, previous);
  assert.deepEqual(output.data.changeEvents, []);
});

test('a failed domain does not prevent subsequent domains from being enumerated', async () => {
  handleFetch = async (url) => String(url).includes('bad.test') ? new Response('denied', { status: 401 }) : ok([{ name_value: 'api.good.test' }]);
  const output = await subdomain.analyze({ domains: ['bad.test', 'good.test'], sources: ['crtsh'] });
  assert.equal(output.success, false);
  assert.equal(output.data.summary.successfulTargets, 1);
  assert.ok(output.data.subdomains.includes('api.good.test'));
});

test('FOFA HTTP failures and partial target failures propagate with diagnostics', async () => {
  for (const partial of [false, true]) {
    handleFetch = async (url) => partial && atob(new URL(url).searchParams.get('qbase64')).includes('good.test') ? ok({ error: false, size: 0, results: [] }) : new Response('denied', { status: 401 });
    const output = await fofa.analyze({ fofaKey: 'stub', domains: ['bad.test', 'good.test'], maxPages: 1 });
    assert.equal(output.success, false);
    assert.equal(output.data.summary.failedQueries, partial ? 1 : 2);
    assert.match(output.error, /HTTP 401/);
  }
});

test('FOFA successful zero-result queries remain successful', async () => {
  handleFetch = async () => ok({ error: false, size: 0, results: [] });
  const output = await fofa.analyze({ fofaKey: 'stub', domains: ['one.test', 'two.test'], maxPages: 1 });
  assert.equal(output.success, true);
  assert.equal(output.data.summary.successfulQueries, 2);
});

test('bounds concurrent domains and reports monotonic completion for the whole list', async () => {
  let active = 0, peak = 0;
  const updates = [];
  globalThis.Sentinel.Monitor.reportProgress = update => { updates.push(update.current); return true; };
  handleFetch = async (url) => {
    active += 1; peak = Math.max(peak, active);
    await new Promise(resolve => setImmediate(resolve));
    active -= 1;
    const domain = new URL(url).searchParams.get('q').slice(2);
    return ok([{ name_value: 'api.' + domain }]);
  };
  const output = await subdomain.analyze({ domains: Array.from({ length: 9 }, (_, i) => `target${i}.test`), sources: ['crtsh'], __monitorExecution: {} });
  assert.equal(output.success, true);
  assert.equal(output.data.summary.successfulTargets, 9);
  assert.equal(peak, 4);
  assert.equal(updates.at(-1), 9);
  assert.ok(updates.every((value, index) => index === 0 || value >= updates[index - 1]));
});

test('partial source failure exposes warnings without replacing the complete snapshot or removing assets', async () => {
  const previous = { 'one.test': { domain: 'one.test', subdomains: ['old.one.test'], lastChecked: 'old' } };
  handleFetch = async url => String(url).includes('crt.sh') ? ok([{ name_value: 'api.one.test' }]) : new Response('denied', { status: 401 });
  const output = await subdomain.analyze({ domains: ['one.test'], sources: ['crtsh', 'alienvault'], previousSnapshots: previous });
  assert.equal(output.success, true);
  assert.equal(output.data.summary.sourcesFailed, 1);
  assert.ok(output.data.warnings.length > 0);
  assert.deepEqual(output.data.snapshots, previous);
  assert.ok(output.data.changeEvents.every(event => event.eventType !== 'asset_removed'));
});
