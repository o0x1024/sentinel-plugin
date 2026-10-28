// Node 24; deterministic native/HTTP fixtures only. No external network calls.
import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
const previous = { Sentinel: globalThis.Sentinel, fetch: globalThis.fetch, Deno: globalThis.Deno };
let fixtureFetch = async () => { throw new Error("Unconfigured fixture network call"); };
globalThis.fetch = (...args) => fixtureFetch(...args);
const modules = {};
for (const id of ['dns_resolver', 'cidr_mapper', 'cert_monitor', 'service_probe', 'service_monitor', 'port_monitor', 'fofa_asset_monitor', 'subdomain_enumerator', 'subdomain_brute']) {
  modules[id] = await import(`../source/bounty/${id}/index.ts`);
}
let commits, requests;
const ctx = targets => ({ task_id: 'owned', task_name: 'Owned fixture', program_id: 'p', execution_mode: 'test', started_at: '2026-10-28T00:00:00Z', current_plugin: 'fixture', current_plugin_index: 1, completed_steps: 0, total_steps: 1,
  result_stream: { protocol: 'monitor-results-v1', targets, max_work_items: 1, max_pending_commits: 1, max_bytes: 2 * 1024 * 1024 } });
const ok = body => new Response(JSON.stringify(body), { status: 200 });
beforeEach(() => {
  commits = []; requests = [];
  globalThis.Sentinel = { log() {}, Monitor: { reportProgress: () => true, commitResults: async request => { commits.push(structuredClone(request)); return { ok: true, sequence: request.sequence }; } },
    Dictionary: { getDefaultId: () => 'owned-rules', getEntries: () => [] } };
  fixtureFetch = async () => { throw new Error('Unconfigured fixture network call'); };
  globalThis.Deno = { resolveDns: async (_, type) => type === 'A' ? ['192.0.2.1'] : [] };
});
after(() => Object.assign(globalThis, previous));

test('DNS stores successful host groups and preserves failed baselines', async () => {
  globalThis.Deno.resolveDns = async (host, type) => { if (host === 'bad.test') throw new Error('DNS timeout'); return type === 'A' ? ['192.0.2.1'] : []; };
  const output = await modules.dns_resolver.analyze({ targets: ['good.test', 'bad.test'], recordTypes: ['A'], previousSnapshots: { 'bad.test': { target: 'bad.test', records: [{ recordType: 'A', value: '192.0.2.2' }] } }, __monitorExecution: ctx(['good.test', 'bad.test']) });
  assert.equal(output.success, true); assert.equal(output.data.stream_complete, true);
  assert.equal(commits.length, 2);
  const failed = commits.find(commit => commit.work[0].target === 'bad.test');
  assert.equal(failed.work[0].status, 'failed'); assert.deepEqual(failed.output.data.snapshots, {});
});

test('CIDR output is bounded and every input completes exactly once', async () => {
  const output = await modules.cidr_mapper.analyze({ targets: ['192.0.2.0/23'], maxHosts: 510, __monitorExecution: ctx(['192.0.2.0/23']) });
  assert.equal(output.success, true); assert.equal(commits.length, 3);
  assert.deepEqual(commits.map(commit => commit.work[0].complete), [false, false, true]);
  assert.equal(commits.flatMap(commit => commit.output.data.surface_artifacts?.ips || []).length, 510);
});

test('certificate aliases stay attached to their original Web identities', async () => {
  globalThis.Sentinel.TLS = { getCertificate: async domain => ({ success: true, cert: { subject: `CN=${domain}`, issuer: 'Owned CA', validFrom: '2026-01-01T00:00:00Z', validTo: '2027-01-01T00:00:00Z', fingerprintSha256: 'ab'.repeat(32), serialNumber: '01', tlsVersion: 'TLSv1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256', subjectAltNames: [domain] } }) };
  const output = await modules.cert_monitor.analyze({ targets: ['https://one.test/path'], __monitorExecution: ctx(['https://one.test/path']) });
  assert.equal(output.success, true); assert.equal(commits[0].work[0].target, 'https://one.test/path');
  assert.equal(commits[0].output.data.surface_artifacts.certificates.length, 1);
});

test('service plugins require native results and never execute a JS alternate probe', async () => {
  let http = 0; fixtureFetch = async () => { http++; throw new Error('Unexpected alternate HTTP path'); };
  globalThis.Sentinel.Network = { probeServices: async request => { requests.push(request); return { success: false, results: [], error: 'native unavailable' }; } };
  for (const id of ['service_probe', 'service_monitor']) {
    const result = await modules[id].analyze({ targets: ['one.test:443/tcp'], dictionaryEntries: [{ word: 'owned', metadata: {} }], __monitorExecution: ctx(['one.test:443/tcp']) });
    assert.equal(result.success, false); assert.match(result.error, /native unavailable/);
  }
  assert.equal(http, 0); assert.equal(commits.length, 0);
});

test('service endpoints commit independent native results, without failed snapshot replacement', async () => {
  globalThis.Sentinel.Network = { probeServices: async ({ targets }) => ({ success: true, results: targets.map(target => ({ ...target, target: `${target.host}:${target.port}`, success: target.host !== 'bad.test', available: target.host !== 'bad.test', serviceName: 'https', error: target.host === 'bad.test' ? 'connect failure' : undefined })), ruleCount: 1 }) };
  const targets = ['good.test:443/tcp', 'bad.test:443/tcp'];
  const output = await modules.service_monitor.analyze({ targets, dictionaryEntries: [{ word: 'owned', metadata: {} }], __monitorExecution: ctx(targets) });
  assert.equal(output.success, true); assert.equal(commits.length, 2);
  assert.deepEqual(commits.find(commit => commit.work[0].target === 'bad.test:443/tcp').output.data.snapshots, {});
});

test('port batches publish observations before one authoritative complete host snapshot', async () => {
  globalThis.Sentinel.Network = { scanPorts: async request => { requests.push(request); return { success: true, results: [{ host: request.targets[0].host, resolved_ips: ['127.0.0.1'], open_ports: [request.ports[0]] }] }; } };
  const ports = Array.from({ length: 512 }, (_, index) => index + 1);
  const output = await modules.port_monitor.analyze({ targets: ['127.0.0.1'], ports, __monitorExecution: ctx(['127.0.0.1']) });
  assert.equal(output.success, true); assert.equal(requests.length, 2);
  assert.equal(new Set(requests.flatMap(request => request.ports)).size, 512);
  assert.ok(commits.slice(0, 2).every(commit => !('snapshots' in commit.output.data)));
  assert.equal(commits.at(-1).output.data.snapshots['127.0.0.1'].openPorts.length, 2);
});

test('FOFA stores page assets immediately and replaces a query snapshot only at complete query', async () => {
  fixtureFetch = async raw => { const page = Number(new URL(raw).searchParams.get('page')); return ok({ error: false, size: 2, results: [[`https://page${page}.one.test`, '127.0.0.1', '443', 'https', 'owned', `page${page}.one.test`, 'now']] }); };
  const result = await modules.fofa_asset_monitor.analyze({ fofaKey: 'fixture', domains: ['one.test'], pageSize: 1, maxPages: 3, __monitorExecution: ctx(['one.test']) });
  assert.equal(result.success, true); assert.equal(commits.length, 3);
  assert.ok(commits.slice(0, 2).every(commit => !('snapshots' in commit.output.data)));
  const final = commits.at(-1); assert.match(final.work[0].key, /^query:.+:complete$/);
  assert.equal(Object.keys(final.output.data.snapshots).length, 1);
});

test('FOFA later-page failure keeps the saved page and never changes its baseline', async () => {
  fixtureFetch = async raw => Number(new URL(raw).searchParams.get('page')) === 1 ? ok({ error: false, size: 2, results: [['https://api.one.test', '127.0.0.1', '443', 'https', 'owned', 'api.one.test', 'now']] }) : new Response('denied', { status: 401 });
  const output = await modules.fofa_asset_monitor.analyze({ fofaKey: 'fixture', domains: ['one.test'], pageSize: 1, maxPages: 3, __monitorExecution: ctx(['one.test']) });
  assert.equal(output.success, false); assert.match(output.error, /401/);
  assert.equal(commits[0].output.data.surface_artifacts.webs.length, 1);
  assert.ok(commits.every(commit => Object.keys(commit.output.data.snapshots || {}).length === 0));
});

test('FOFA page limit is not an authoritative empty/removal baseline', async () => {
  fixtureFetch = async () => ok({ error: false, size: 3, results: [['https://api.one.test', '127.0.0.1', '443', 'https', 'owned', 'api.one.test', 'now']] });
  const output = await modules.fofa_asset_monitor.analyze({ fofaKey: 'fixture', domains: ['one.test'], pageSize: 1, maxPages: 1, __monitorExecution: ctx(['one.test']) });
  assert.equal(output.success, true); assert.ok(commits.every(commit => Object.keys(commit.output.data.snapshots || {}).length === 0));
  assert.equal(commits.at(-1).work[0].status, 'failed');
  assert.match(commits.at(-1).work[0].error, /page limit reached/);
});

test('subdomain source deltas never turn a partial source set into a removed-domain snapshot', async () => {
  fixtureFetch = async raw => String(raw).includes('crt.sh') ? ok([{ name_value: 'api.one.test' }]) : new Response('denied', { status: 401 });
  const result = await modules.subdomain_enumerator.analyze({ domains: ['one.test'], sources: ['crtsh', 'alienvault'], previousSnapshots: { 'one.test': { domain: 'one.test', subdomains: ['old.one.test'], lastChecked: 'old' } }, __monitorExecution: ctx(['one.test']) });
  assert.equal(result.success, true); assert.equal(commits.length, 3);
  assert.ok(commits.every(commit => Object.keys(commit.output.data.snapshots || {}).length === 0));
  assert.ok(commits.some(commit => commit.work[0].status === 'failed'));
});

test('failed result persistence stops producers before another native work unit', async () => {
  globalThis.Sentinel.Monitor.commitResults = async () => { throw new Error('owned persistence failure'); };
  globalThis.Sentinel.Network = { scanPorts: async request => { requests.push(request); return { success: true, results: [{ host: '127.0.0.1', resolved_ips: ['127.0.0.1'], open_ports: [] }] }; } };
  const output = await modules.port_monitor.analyze({ targets: ['127.0.0.1'], ports: Array.from({ length: 512 }, (_, i) => i + 1), __monitorExecution: ctx(['127.0.0.1']) });
  assert.equal(output.success, false); assert.match(output.error, /persistence failure/); assert.equal(requests.length, 1);
});

test('certificate fields cannot be synthesized from an incomplete native response', async () => {
  globalThis.Sentinel.TLS = { getCertificate: async () => ({ success: true, cert: { subject: 'CN=one.test', issuer: 'Owned CA' } }) };
  const output = await modules.cert_monitor.analyze({ targets: ['one.test'], __monitorExecution: ctx(['one.test']) });
  assert.equal(output.success, true); assert.equal(commits[0].work[0].status, 'failed');
  assert.deepEqual(commits[0].output.data.snapshots, {});
  assert.deepEqual(commits[0].output.data.surface_artifacts.certificates, []);
});

test('FOFA streaming failures never persist the API credential or authenticated URL', async () => {
  const key = 'owned-secret-not-a-real-key';
  fixtureFetch = async () => { throw new Error(`request failed: https://fofa.test/api?key=${key}`); };
  const output = await modules.fofa_asset_monitor.analyze({ fofaKey: key, domains: ['one.test'], __monitorExecution: ctx(['one.test']) });
  assert.equal(output.success, false); assert.ok(!JSON.stringify({ output, commits }).includes(key));
});

test('service snapshots use exactly the canonical endpoint key', async () => {
  globalThis.Sentinel.Network = { probeServices: async ({ targets }) => ({ success: true, results: targets.map(target => ({ ...target, target: `${target.host}:${target.port}`, success: true, available: true, serviceName: 'https', productName: 'new' })) }) };
  const result = await modules.service_monitor.analyze({ targets: ['one.test:443/tcp'], dictionaryEntries: [{ word: 'owned', metadata: {} }], previousSnapshots: { 'one.test:443/https': { available: true, serviceName: 'old', productName: 'old' } }, __monitorExecution: ctx(['one.test:443/tcp']) });
  assert.equal(result.success, true); assert.deepEqual(commits[0].output.data.changeEvents, []);
});

test('TLS bridge options and result projection match the native Rust DTO exactly', async () => {
  let requested;
  globalThis.Sentinel.TLS = { getCertificate: async (hostname, options) => { requested = { hostname, options }; return { success: true, cert: { subject: 'CN=one.test', issuer: 'Owned CA', serialNumber: '01', validFrom: '2026-01-01T00:00:00Z', validTo: '2027-01-01T00:00:00Z', fingerprintSha256: 'ab'.repeat(32), subjectAltNames: ['one.test', 'email:owned@one.test'] } }; } };
  const output = await modules.cert_monitor.analyze({ targets: ['https://one.test:8443/'], __monitorExecution: ctx(['https://one.test:8443/']) });
  assert.equal(output.success, true); assert.deepEqual(requested, { hostname: 'one.test', options: { port: 8443, timeoutMs: 3000 } });
  const data = commits[0].output.data; assert.equal(data.results[0].certInfo.fingerprint, 'ab'.repeat(32));
  assert.ok(!('protocol' in data.results[0].certInfo)); assert.ok(!('cipher' in data.results[0].certInfo));
  assert.deepEqual(data.surface_artifacts.domains.map(domain => domain.fqdn), ['one.test']);
  assert.ok(data.snapshots['one.test:8443']);
});

test('unknown port reachability retains confirmed open ports without replacing a host baseline', async () => {
  globalThis.Sentinel.Network = { scanPorts: async () => ({ success: false, results: [{ host: '127.0.0.1', resolved_ips: ['127.0.0.1'], open_ports: [80], error: '1 port(s) have unknown reachability; complete port snapshot is unavailable' }] }) };
  const result = await modules.port_monitor.analyze({ targets: ['127.0.0.1'], ports: [80, 443], previousSnapshots: { '127.0.0.1': { host: '127.0.0.1', openPorts: [{ port: 443, protocol: 'tcp', state: 'open' }], lastChecked: 'old' } }, __monitorExecution: ctx(['127.0.0.1']) });
  assert.equal(result.success, true);
  assert.ok(commits.every(request => Object.keys(request.output.data.snapshots || {}).length === 0));
  assert.ok(commits.every(request => (request.output.data.changeEvents || []).length === 0));
  assert.ok(commits.some(request => request.output.data.surface_artifacts?.ports?.some(port => port.port === 80)));
  assert.ok(commits.every(request => request.work[0].status === 'failed'));
});

test('certificate typed artifacts share one normalized SHA-256 identity', async () => {
  const rawFingerprint = Array.from({ length: 32 }, () => 'AB').join(':');
  globalThis.Sentinel.TLS = { getCertificate: async () => ({ success: true, cert: { subject: 'CN=one.test', issuer: 'Owned CA', serialNumber: '01', validFrom: '2026-01-01T00:00:00Z', validTo: '2027-01-01T00:00:00Z', fingerprintSha256: rawFingerprint, subjectAltNames: ['one.test'] } }) };
  const output = await modules.cert_monitor.analyze({ targets: ['one.test'], __monitorExecution: ctx(['one.test']) });
  assert.equal(output.success, true);
  const data = commits[0].output.data, expected = 'ab'.repeat(32);
  assert.equal(data.results[0].certInfo.fingerprint, rawFingerprint);
  assert.equal(data.surface_artifacts.certificates[0].sha256, expected);
  assert.ok(data.surface_artifacts.evidences.every(evidence => evidence.asset_key === expected));
  assert.ok(data.surface_artifacts.relations.every(relation => relation.to_key === expected));
});

test('service HTTP hints survive typed identity while artifacts use canonical TCP refs including IPv6', async () => {
  const owner = '[::1]:8443/tcp'; let request;
  globalThis.Sentinel.Network = { probeServices: async input => { request = input; return { success: true, results: input.targets.map(target => ({ ...target, target: '::1:8443', success: true, available: true, serviceName: 'https', productName: 'Owned', banner: 'owned native service' })) }; } };
  const output = await modules.service_probe.analyze({ targets: [owner], target_objects: [{ type: 'service', value: owner, host: '::1', port: 8443, transport_protocol: 'tcp', protocol: 'https', service_name: 'https' }],
    dictionaryEntries: [{ word: 'owned', metadata: { product: 'Owned', asset_category: 'web_server', matchers: [{ part: 'banner', type: 'contains', value: 'owned' }] } }], __monitorExecution: ctx([owner]) });
  assert.equal(output.success, true); assert.equal(request.targets.length, 1);
  assert.deepEqual(request.targets[0], { host: '::1', port: 8443, protocol: 'https' });
  const data = commits[0].output.data;
  assert.ok(data.snapshots['[::1]:8443']);
  assert.ok(data.surface_artifacts.fingerprints.length > 0);
  assert.ok(data.surface_artifacts.fingerprints.every(item => item.asset_key === owner));
  assert.ok(data.surface_artifacts.evidences.every(item => item.asset_key === owner));
  assert.ok(data.surface_artifacts.relations.every(item => item.to_key === owner));
});

test('subdomain source failure records redact configured provider credentials', async () => {
  const secret = 'owned-test-provider-key';
  fixtureFetch = async () => { throw new Error(`request failed: https://provider.test/query?key=${secret}`); };
  await assert.rejects(modules.subdomain_enumerator.analyze({ domains: ['one.test'], sources: ['crtsh'], apiConfig: { shodan_key: secret }, __monitorExecution: ctx(['one.test']) }), error => !error.message.includes(secret));
  assert.ok(!JSON.stringify(commits).includes(secret));
  assert.ok(JSON.stringify(commits).includes('[REDACTED]'));
});
