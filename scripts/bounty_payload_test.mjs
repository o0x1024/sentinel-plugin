// Node 24; controlled producer/durable-payload contracts, with no real network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { monitorExecution } from './monitor_stream_fixture.ts';
import { createMonitorResultStream } from '../source/shared/monitor_results.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalSentinel = globalThis.Sentinel;
test.afterEach(() => { globalThis.Sentinel = originalSentinel; });

async function runReport(args) {
    const directory = await mkdtemp('/private/tmp/sentinel-bounty-payload-contract-');
    const output = `${directory}/report.json`;
    execFileSync('rtk', ['proxy', 'node', '--disable-warning=ExperimentalWarning', 'scripts/bounty_payload_benchmark.mjs',
        ...args, '--output', output], { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024 });
    return JSON.parse(await readFile(output, 'utf8'));
}

test('each forbidden input echo fails before the first write and latches the error', async () => {
    for (const field of ['targets', 'target_objects', 'service_targets', '__monitorExecution',
        'previousSnapshots', 'previous_snapshots', 'dictionaryEntries', 'dictionary']) {
        let writes = 0;
        globalThis.Sentinel = { Monitor: { commitResults: async request => { writes++; return { ok: true, sequence: request.sequence }; } } };
        const stream = createMonitorResultStream({ __monitorExecution: monitorExecution(['one']) });
        const value = field.includes('napshot') || field === '__monitorExecution' ? { one: { old: true } } : ['old-whole-input'];
        await assert.rejects(stream.record('one', 'probe', { success: true, data: { [field]: value, results: [] } }));
        assert.equal(writes, 0, `${field} must not reach persistence`);
        assert.throws(() => stream.assertHealthy());
    }
});

test('a single excessive UTF-8 result fails without a partial persistence operation', async () => {
    let writes = 0;
    globalThis.Sentinel = { Monitor: { commitResults: async request => { writes++; return { ok: true, sequence: request.sequence }; } } };
    const stream = createMonitorResultStream({ __monitorExecution: monitorExecution(['one'], { maxBytes: 1024 }) });
    await assert.rejects(stream.record('one', 'probe', { success: true, data: { results: [{ text: '漢😀'.repeat(1024) }] } }), /byte|size|limit/i);
    assert.equal(writes, 0);
});

test('a v1 producer rejects a v2 host before performing HTTP work', async () => {
    const code=execFileSync('rtk',['proxy','git','show','d92c508:plugins/bounty/http_prober.ts'],{cwd:root,encoding:'utf8'});
    const {analyze}=await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
    const savedFetch=globalThis.fetch;let calls=0;
    globalThis.fetch=async()=>{calls++;throw new Error('Unexpected network work');};
    try {
        const result=await analyze({targets:['owned.test'],__monitorExecution:monitorExecution(['owned.test'])});
        assert.equal(result.success,false);assert.match(result.error,/monitor-results-v1/);assert.equal(calls,0);
    } finally {globalThis.fetch=savedFetch;}
});

test('all twenty repaired producers keep 4x input growth within linear payload bounds', async () => {
    const report = await runReport(['--variant', 'current', '--sizes', '64,256', '--assert-linear']);
    assert.equal(new Set(report.rows.map(row => row.plugin)).size, 20);
    assert.equal(report.rows.length, 40);
    assert.equal(report.comparisons.length, 20);
    assert(report.comparisons.every(comparison => comparison.linear));
    for (const row of report.rows) {
        assert.equal(row.completed_targets, row.targets);
        assert.deepEqual(row.forbidden_fields, {});
        assert(row.max_package_bytes <= 2 * 1024 * 1024);
    }
});
