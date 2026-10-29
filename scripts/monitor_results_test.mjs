import { requestData } from './monitor_request_test_support.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { createMonitorResultStream } from '../source/shared/monitor_results.ts';

const originalSentinel = globalThis.Sentinel;
const originalNow = Date.now;
test.afterEach(() => { globalThis.Sentinel = originalSentinel; Date.now = originalNow; });

function input(targets, limits = {}) {
    return { __monitorExecution: { result_stream: {
        protocol: 'monitor-results-v2', targets, max_work_items: 32,
        max_pending_commits: 2, max_bytes: 2 * 1024 * 1024, ...limits,
    } } };
}

function commitFixture(implementation) {
    const requests = [];
    globalThis.Sentinel = { Monitor: { async commitResults(request) {
        requests.push(structuredClone(request));
        return implementation ? implementation(request) : { ok: true, sequence: request.sequence };
    } } };
    return requests;
}

const output = (data = {}) => ({ success: true, data });
const intermediate = { complete: false };

test('ordinary tools preserve output and require no monitor host', async () => {
    delete globalThis.Sentinel;
    const stream = createMonitorResultStream({ targets: ['ordinary'] });
    assert.equal(stream.enabled, false);
    await stream.record('', '', null);
    const original = { success: false, error: 'ordinary tool error' };
    assert.equal(await stream.finish(original), original);
});

test('monitor context requires the exact protocol, explicit limits and commit API', () => {
    commitFixture();
    assert.throws(() => createMonitorResultStream({ __monitorExecution: {} }), /monitor-results-v2/);
    assert.throws(() => createMonitorResultStream({ __monitorExecution: null }), /monitor-results-v2/);
    assert.throws(() => createMonitorResultStream(input([], { protocol: 'technology-v1' })), /monitor-results-v2/);
    assert.throws(() => createMonitorResultStream(input([], { max_work_items: 33 })), /max_work_items/);
    assert.throws(() => createMonitorResultStream(input([], { max_bytes: 0 })), /max_bytes/);
    assert.throws(() => createMonitorResultStream(input([], { max_pending_commits: 3 })), /max_pending_commits/);
    delete globalThis.Sentinel;
    assert.throws(() => createMonitorResultStream(input([])), /commitResults/);
});

test('batches retain independent outputs while their validated projection merges consistently', async () => {
    const requests = commitFixture();
    const stream = createMonitorResultStream(input(['one', 'two']));
    const first = output({ results: [{ url: 'one' }], findings: [{ id: 1 }], snapshots: { one: { version: 1 } },
        surface_artifacts: { webs: [{ canonical_url: 'one' }] }, summary: { total: 1, byStatus: { '200': 1 } } });
    await stream.record('one', 'request', first, { snapshot_complete: true });
    first.data.results.length = 0;
    await stream.record('two', 'request', output({ results: [{ url: 'two' }], findings: [{ id: 2 }],
        snapshots: { two: { version: 2 } }, surface_artifacts: { webs: [{ canonical_url: 'two' }] },
        summary: { total: 1, byStatus: { '200': 1, '404': 1 } } }), { snapshot_complete: true });
    const final = await stream.finish(output({ results: ['must not replay'], snapshots: { stale: {} } }));
    assert.equal(requests.length, 1);
    assert.equal(Object.hasOwn(requests[0], 'output'), false);
    assert.deepEqual(requests[0].work.map(work => work.output.data.results), [[{ url:'one' }],[{ url:'two' }]]);
    assert.deepEqual(requestData(requests[0]).results, [{ url: 'one' }, { url: 'two' }]);
    assert.deepEqual(requestData(requests[0]).findings, [{ id: 1 }, { id: 2 }]);
    assert.deepEqual(requestData(requests[0]).snapshots, { one: { version: 1 }, two: { version: 2 } });
    assert.deepEqual(requestData(requests[0]).summary, { total: 2, byStatus: { '200': 2, '404': 1 } });
    assert.equal(requestData(requests[0]).surface_artifacts.webs.length, 2);
    assert.equal(final.data.stream_complete, true);
    assert.equal(final.data.results, undefined);
    assert.equal(final.data.summary.diagnostics.committed_work_items, 2);
});

test('flushes at work count and retains no prior batch results', async () => {
    const requests = commitFixture();
    const stream = createMonitorResultStream(input(['one'], { max_work_items: 2 }));
    await stream.record('one', 'a', output({ results: ['a'] }), intermediate);
    await stream.record('one', 'b', output({ results: ['b'] }), intermediate);
    await stream.record('one', 'c', output({ results: ['c'] }));
    await stream.finish();
    assert.deepEqual(requests.map(item => [item.sequence, requestData(item).results]), [[1, ['a', 'b']], [2, ['c']]]);
    assert.deepEqual(requests.map(item => item.work.map(work => work.complete)), [[false, false], [true]]);
});

test('flushes completed work when five seconds have elapsed', async () => {
    let now = 100;
    Date.now = () => now;
    const requests = commitFixture();
    const stream = createMonitorResultStream(input(['one']));
    await stream.record('one', 'a', output(), intermediate);
    now += 5001;
    await stream.record('one', 'b', output());
    assert.equal(requests.length, 1);
    assert.equal(requests[0].work.length, 2);
    await stream.finish();
});

test('splits by actual UTF-8 JSON bytes before reaching the work count', async () => {
    const requests = commitFixture();
    const maxBytes = 2000;
    const stream = createMonitorResultStream(input(['one'], { max_bytes: maxBytes }));
    for (const key of ['a', 'b', 'c']) {
        await stream.record('one', key, output({ results: [{ text: '漢😀'.repeat(160) }] }), { complete: key === 'c' });
    }
    await stream.finish();
    assert.equal(requests.length, 3);
    assert(requests.every(request => Buffer.byteLength(JSON.stringify(request), 'utf8') <= maxBytes));
    assert.deepEqual(requests.map(request => request.sequence), [1, 2, 3]);
});

test('rejects a single oversized result without submitting it', async () => {
    const requests = commitFixture();
    const stream = createMonitorResultStream(input(['one'], { max_bytes: 1000 }));
    await assert.rejects(stream.record('one', 'large', output({ results: ['😀'.repeat(1000)] })), /single.*byte limit/);
    assert.equal(requests.length, 0);
    assert.throws(() => stream.assertHealthy(), /single.*byte limit/);
});

test('ownership, duplicate work, terminal targets and key bounds fail explicitly', async () => {
    commitFixture();
    await assert.rejects(createMonitorResultStream(input(['one'])).record('other', 'a', output()), /owned/);
    await assert.rejects(createMonitorResultStream(input(['one'])).record('one', 'x'.repeat(2049), output()), /2048/);
    const duplicate = createMonitorResultStream(input(['one']));
    await duplicate.record('one', 'a', output(), intermediate);
    await assert.rejects(duplicate.record('one', 'a', output(), intermediate), /repeats/);
    const terminal = createMonitorResultStream(input(['one']));
    await terminal.record('one', 'a', output());
    await assert.rejects(terminal.record('one', 'b', output()), /completed target/);
});

test('commit rejection and mismatched acknowledgements latch and stop later submissions', async () => {
    for (const implementation of [() => { throw new Error('disk save failed'); }, request => ({ ok: true, sequence: request.sequence + 1 })]) {
        const requests = commitFixture(implementation);
        const stream = createMonitorResultStream(input(['one'], { max_work_items: 1, max_pending_commits: 1 }));
        await assert.rejects(stream.record('one', 'a', output(), intermediate), /disk save failed|not acknowledged/);
        await assert.rejects(stream.record('one', 'b', output()), /disk save failed|not acknowledged/);
        await assert.rejects(stream.finish(), /disk save failed|not acknowledged/);
        assert.equal(requests.length, 1);
    }
});

test('backpressure allows at most two unacknowledged commits', async () => {
    const releases = [];
    const requests = commitFixture(request => new Promise(resolve => releases.push(() => resolve({ ok: true, sequence: request.sequence }))));
    const stream = createMonitorResultStream(input(['one'], { max_work_items: 1 }));
    await stream.record('one', 'a', output(), intermediate);
    let settled = false;
    const second = stream.record('one', 'b', output(), intermediate).then(() => { settled = true; });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(requests.length, 2);
    assert.equal(settled, false);
    releases.shift()();
    await second;
    const third = stream.record('one', 'c', output());
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(requests.length, 3);
    releases.shift()();
    await third;
    const done = stream.finish();
    releases.shift()();
    const final = await done;
    assert.equal(final.data.summary.diagnostics.max_pending_commits, 2);
});

test('finish saves valid partial results then preserves plugin failure', async () => {
    const requests = commitFixture();
    const stream = createMonitorResultStream(input(['one', 'two']));
    await stream.record('one', 'a', output({ results: ['saved'] }));
    await assert.rejects(stream.finish({ success: false, error: 'FOFA page failed' }), /FOFA page failed/);
    assert.deepEqual(requestData(requests[0]).results, ['saved']);
});

test('finish retains numeric plugin diagnostics and protects acknowledged counters', async () => {
    commitFixture();
    const stream = createMonitorResultStream(input(['one']));
    await stream.record('one', 'a', output());
    const final = await stream.finish(output({ summary: { diagnostics: {
        dictionary_load_ms: 11, matching_ms_sum: 29, scan_wall_ms: 53,
        committed_work_items: 999, submitted_batches: 999, max_pending_commits: 999,
        sensitive_text: 'never copy text', invalid: -1, infinite: Infinity,
    } } }));
    const diagnostics = final.data.summary.diagnostics;
    assert.equal(diagnostics.dictionary_load_ms, 11);
    assert.equal(diagnostics.matching_ms_sum, 29);
    assert.equal(diagnostics.scan_wall_ms, 53);
    assert.equal(diagnostics.committed_work_items, 1);
    assert.equal(diagnostics.submitted_batches, 1);
    assert.equal(diagnostics.max_pending_commits, 1);
    for (const field of ['sensitive_text', 'invalid', 'infinite']) assert.equal(diagnostics[field], undefined);
});

test('finish rejects omitted targets, and a finished stream rejects later work', async () => {
    const requests = commitFixture();
    const stream = createMonitorResultStream(input(['one', 'two']));
    await stream.record('one', 'a', output());
    await assert.rejects(stream.finish(), /all targets completed \(1\/2\)/);
    assert.equal(requests.length, 1);
    const finished = createMonitorResultStream(input([]));
    await finished.finish();
    await assert.rejects(finished.record('one', 'a', output()), /already finished/);
});


test('snapshots keep stable state keys independent of work IDs, and failed work cannot publish them', async () => {
    const packets=commitFixture();
    const stream=createMonitorResultStream(input(['query']));
    await stream.record('query','page:7:inventory-complete',output({snapshots:{stableQueryId:{assets:[]}}}),{snapshot_complete:true});
    await stream.finish();
    assert.deepEqual(packets[0].work[0].output.data.snapshots,{stableQueryId:{assets:[]}});
    const rejected=createMonitorResultStream(input(['query']));
    await assert.rejects(rejected.record('query','failed',output({snapshots:{stableQueryId:{assets:[]}}}),{status:'failed',snapshot_complete:true}),/successful work/);
});

test('partial observations cannot silently replace a retained snapshot', async () => {
    commitFixture();
    const stream=createMonitorResultStream(input(['query']));
    await assert.rejects(stream.record('query','page',output({snapshots:{query:{partial:true}}}),{complete:false}),/complete observation/);
});
