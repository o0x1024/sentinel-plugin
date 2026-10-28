// Node 24+; all native calls are fixtures, with no network or platform dictionary reads.
import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { analyze, get_input_schema, get_output_schema } from '../plugins/bounty/subdomain_brute.ts';
import { nativeSubdomainBruteFixture } from './subdomain_brute_fixture.ts';
const originalSentinel = globalThis.Sentinel;
const originalFetch = globalThis.fetch;
let requests;
let native;
beforeEach(() => {
    requests = [];
    native = request => nativeSubdomainBruteFixture(request);
    globalThis.fetch = () => { throw new Error('No HTTP or DNS fallback is permitted in this fixture'); };
    globalThis.Sentinel = {
        Network: { async bruteForceSubdomains(request) { requests.push(request); return native(request); } },
        Dictionary: { getWords() { throw new Error('Platform wordlists must remain in the native runtime'); } },
    };
});
after(() => { globalThis.Sentinel = originalSentinel; globalThis.fetch = originalFetch; });

test('catalog, metadata header, seed bindings and typed schema agree', async () => {
    const catalog = JSON.parse(await readFile(new URL('../plugins.json', import.meta.url), 'utf8'));
    const contracts = JSON.parse(await readFile(new URL('./monitor_plugin_contracts.json', import.meta.url), 'utf8'));
    const entry = catalog.plugins.find(plugin => plugin.id === 'subdomain_brute');
    const contract = contracts.plugins.find(plugin => plugin.id === 'subdomain_brute');
    assert.equal(entry.version, '1.0.0');
    for (const field of ['id', 'monitor_type', 'input_mode', 'target_asset_types', 'seed_bindings']) assert.deepEqual(entry[field], contract[field]);
    assert.deepEqual(entry.tags.filter(tag => tag.startsWith('capability:')), contract.capability_tags);
    const source = await readFile(new URL('../plugins/bounty/subdomain_brute.ts', import.meta.url), 'utf8');
    assert.equal(source.match(/@version\s+(\S+)/)?.[1], entry.version);
    assert.deepEqual(JSON.parse(source.match(/@seed_bindings ([^\n]+)/)[1]), entry.seed_bindings);
    const schema = get_input_schema();
    assert.equal(schema.type, 'object');
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.properties.targets.type, 'array');
    assert.equal(schema.properties.targets.items.type, 'string');
    assert.equal(schema.properties.transport.default, 'udp');
    assert.deepEqual(schema.properties.transport.enum, ['udp', 'ethernet']);
    assert.equal(schema.properties.dns_timeout_seconds.type, 'integer');
    assert.equal(schema.properties.max_wait_seconds.maximum, 3600);
    assert.equal(schema.properties.__monitorExecution.readOnly, true);
    assert.equal(schema.properties.previousSnapshots.readOnly, true);
    assert.ok(!('previous_snapshots' in schema.properties));
    assert.ok(get_output_schema().properties.data.properties.surface_artifacts);
});

test('forwards a complete multi-target batch and dictionary configuration in exactly one native call', async () => {
    const dictionary = ['api', 'www', 'dev'];
    const resolvers = ['127.0.0.1:5353'];
    const monitor = Object.freeze({ task_id: 'monitor-1', program_id: 'program-1', plugin_run_id: 'native-run-1' });
    const input = Object.freeze({ targets: ['one.test', 'two.test'], dictionary_id: 'custom-dict-id', dictionary, resolvers, skip_wildcard: false, bandwidth_limit: '2M', dns_timeout_seconds: 3, max_wait_seconds: 30, max_retries: 2, query_types: ['a', 'aaaa'], resolve_records: false, raw_records: true, verify_mode: false, __monitorExecution: monitor });
    const output = await analyze(input);
    assert.equal(output.success, true);
    assert.equal(requests.length, 1);
    assert.deepEqual(requests[0].targets, ['one.test', 'two.test']);
    assert.equal(requests[0].dictionary, dictionary);
    assert.equal(requests[0].resolvers, resolvers);
    assert.equal(requests[0].dictionary_id, 'custom-dict-id');
    assert.equal(requests[0].transport, 'udp');
    assert.equal(requests[0].__monitorExecution, monitor);
    for (const key of ['skip_wildcard', 'bandwidth_limit', 'dns_timeout_seconds', 'max_wait_seconds', 'max_retries', 'query_types', 'resolve_records', 'raw_records']) assert.deepEqual(requests[0][key], input[key]);
    assert.equal(output.data.summary.total_targets, 2);
    assert.equal(output.data.changeEvents, output.data.change_events);
    assert.equal(output.data.surface_artifacts.domains.length, 2);
    assert.equal(output.data.surface_artifacts.changes, output.data.change_events);
});

test('keeps explicit ethernet selection and reports unsupported native transport without falling back', async () => {
    native = () => { throw new Error('ETHERNET_UNAVAILABLE: raw packet permission denied'); };
    const output = await analyze({ targets: ['one.test'], transport: 'ethernet', device: 'en0' });
    assert.equal(output.success, false);
    assert.match(output.error, /ETHERNET_UNAVAILABLE/);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].transport, 'ethernet');
    assert.equal(requests[0].device, 'en0');
});

test('maps legacy snapshots and aliases without mutating monitor-owned input', async () => {
    const snapshots = Object.freeze({ 'old.test': Object.freeze({ domain: 'old.test', subdomains: ['api.old.test'], lastChecked: 'old-time' }) });
    const result = await analyze({ targets: ['one.test', 'two.test'], domains: ['three.test'], domain: 'four.test', previousSnapshots: snapshots });
    assert.equal(result.success, true);
    assert.deepEqual(requests[0].targets, ['one.test', 'two.test', 'three.test', 'four.test']);
    assert.deepEqual(requests[0].previous_snapshots, { 'old.test': { domain: 'old.test', subdomains: ['api.old.test'], last_checked: 'old-time' } });
    assert.equal(snapshots['old.test'].lastChecked, 'old-time');
    assert.ok(!('previousSnapshots' in requests[0]));
    assert.ok(!('domain' in requests[0]));
    assert.equal(result.data.snapshots['old.test'].last_checked, 'old-time');
});

test('missing native bridge fails explicitly without any alternate network path', async () => {
    globalThis.Sentinel = {};
    const result = await analyze({ targets: ['one.test'] });
    assert.equal(result.success, false);
    assert.match(result.error, /bruteForceSubdomains.*unavailable/);
    assert.equal(requests.length, 0);
});

test('native errors, timeouts and cancellation never become successful empty snapshots', async () => {
    for (const message of ['DNS timeout before complete result', 'CANCELLED: monitor stopped', 'dictionary was not found']) {
        native = () => { throw new Error(message); };
        const output = await analyze({ targets: ['one.test'] });
        assert.equal(output.success, false);
        assert.equal(output.error, message);
        assert.equal(output.data, undefined);
    }
    native = () => ({ success: false, cancelled: true, error: 'cancelled by native host' });
    const cancelled = await analyze({ targets: ['one.test'] });
    assert.equal(cancelled.success, false);
    assert.equal(cancelled.cancelled, true);
    native = () => ({ success: true, cancelled: true });
    assert.equal((await analyze({ targets: ['one.test'] })).success, false);
});

test('invalid inputs or incomplete native results cannot silently pass', async () => {
    for (const input of [{ targets: [] }, { targets: ['one.test'], transport: 'auto' }, { targets: ['one.test'], monitor_context: { task_id: 'forged' } }, { targets: [12] }]) {
        assert.equal((await analyze(input)).success, false);
    }
    assert.equal(requests.length, 0);
    native = () => ({ success: true, data: {} });
    const malformed = await analyze({ targets: ['one.test'] });
    assert.equal(malformed.success, false);
    assert.match(malformed.error, /missing standard result fields/);
});
