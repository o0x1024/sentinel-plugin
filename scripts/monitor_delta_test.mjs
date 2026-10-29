import { requestData } from './monitor_request_test_support.mjs';
// Independent JSON/Buffer oracles for the incremental size tree. Node 24, no I/O.
import test from 'node:test';
import assert from 'node:assert/strict';
import { copyMonitorDelta, mergeMonitorDelta, monitorRequestBytes, jsonBytes,
    MONITOR_DELTA_INPUT_FIELDS } from '../source/shared/monitor_delta.ts';
import { createMonitorResultStream } from '../source/shared/monitor_results.ts';
import { monitorExecution } from './monitor_stream_fixture.ts';

const canonical = value => JSON.parse(JSON.stringify(value));
const byteOracle = value => Buffer.byteLength(JSON.stringify(value), 'utf8');
const output = data => ({ success: true, data });
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/** Contract-level merge oracle: native cloning/property assignment, no byte tree. */
function mergeReference(left, right, path = []) {
    if (left === undefined) return structuredClone(right);
    if (path.length === 1 && path[0] === 'snapshots') {
        return Object.fromEntries([...Object.entries(left), ...Object.entries(right)]);
    }
    if (Array.isArray(left) && Array.isArray(right)) return left.concat(right);
    if (path[0] === 'summary' && typeof left === 'number' && typeof right === 'number') return left + right;
    if (!plain(left) || !plain(right)) return structuredClone(right);
    const result = structuredClone(left);
    for (const key of Object.keys(right)) {
        const value = own(left, key) ? mergeReference(left[key], right[key], [...path, key]) : structuredClone(right[key]);
        Object.defineProperty(result, key, { value, enumerable: true, writable: true, configurable: true });
    }
    return result;
}

function seeded(seed) {
    let state = seed >>> 0;
    return maximum => {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        return maximum ? state % maximum : state;
    };
}
const strings = ['', 'ASCII', 'quote"slash\\', '\u0000\b\f\n\r\t', '汉字😀𠜎', '\u2028\u2029', '\ud800', '\udfff', 'a\ud800b\udfffc', '😀\ud800'];
const numbers = [0, -0, 1, -1, 9, 99, 0.1, 0.2, 1e-7, 1e21, 9.999e20,
    Number.MAX_VALUE, Number.MIN_VALUE, 1e308, -1e308, NaN, Infinity, -Infinity];
const keys = ['0', '1', '10', '00', '4294967294', '4294967295', '__proto__', 'constructor', 'prototype', '汉😀', 'quote"\\\n'];

function randomValue(next, depth = 0) {
    const kind = next(depth < 3 ? 7 : 4);
    if (kind === 0) return strings[next(strings.length)];
    if (kind === 1) return numbers[next(numbers.length)];
    if (kind === 2) return next(2) === 0;
    if (kind === 3) return null;
    if (kind === 4) return Array.from({ length: next(4) }, () => randomValue(next, depth + 1));
    if (kind === 5) return undefined;
    return Object.fromEntries(Array.from({ length: next(4) }, () => [keys[next(keys.length)], randomValue(next, depth + 1)]));
}

function randomDelta(next, index) {
    return {
        results: Array.from({ length: next(3) }, () => randomValue(next)),
        snapshots: Object.fromEntries(Array.from({ length: next(3) }, () => [keys[next(keys.length)], randomValue(next)])),
        summary: { count: numbers[next(numbers.length)], nested: { total: numbers[next(numbers.length)] },
            labels: next(2) ? [] : [strings[next(strings.length)]] },
        surface_artifacts: { evidences: next(2) ? [{ content_json: randomValue(next), index }] : [] },
        payload: randomValue(next),
        [keys[next(keys.length)]]: randomValue(next),
    };
}

function workSample(next, index) {
    return { target: `https://owned.test/${strings[next(strings.length)]}`, key: `${index}:${strings[next(strings.length)]}`,
        status: 'ok', complete: next(2) === 0, ...(next(2) ? { error: strings[next(strings.length)] } : {}) };
}

test('native JSON oracle covers Unicode, escapes, lone surrogates, numeric keys and JSON coercions', () => {
    for (const value of [...strings, ...numbers, [], [undefined, NaN, Infinity, ...strings],
        Object.fromEntries(keys.map((key, index) => [key, strings[index % strings.length]])),
        { omitted: undefined, retained: null, date: new Date('2026-10-29T00:00:00Z'), nested: { notFinite: Infinity } }]) {
        assert.equal(jsonBytes(value), byteOracle(value));
        const tree = copyMonitorDelta(output({ payload: value }));
        assert.deepEqual(tree.value, canonical({ payload: value }));
        assert.equal(tree.bytes, byteOracle(tree.value));
    }
    assert.throws(() => copyMonitorDelta(output({ payload: 1n })), /BigInt/i);
    const cyclic = {}; cyclic.self = cyclic;
    assert.throws(() => copyMonitorDelta(output(cyclic)), /circular/i);
});

test('snapshot replacement and summary number formatting preserve native JSON semantics', () => {
    const first = Object.fromEntries([
        ['snapshots', Object.fromEntries([['__proto__', { old: ['retain-no-fields'], nested: { a: 1 } }], ['1', { stale: true }]])],
        ['summary', { fraction: 0.1, exponent: 9e20, overflow: 1e308, nested: { value: 99 } }],
        ['results', []], ['__proto__', { marker: 'left' }],
    ]);
    const second = Object.fromEntries([
        ['snapshots', Object.fromEntries([['__proto__', { fresh: '😀' }], ['1', []]])],
        ['summary', { fraction: 0.2, exponent: 2e20, overflow: 1e308, nested: { value: 1 } }],
        ['results', [{ value: '\ud800' }]], ['__proto__', { marker: 'right', own: true }],
    ]);
    const merged = mergeMonitorDelta(copyMonitorDelta(output(first)), copyMonitorDelta(output(second)));
    const reference = mergeReference(canonical(first), canonical(second));
    assert.deepEqual(canonical(merged.value), canonical(reference));
    assert.deepEqual(merged.value.snapshots.__proto__, { fresh: '😀' });
    assert.deepEqual(merged.value.snapshots['1'], []);
    assert.equal(merged.value.summary.fraction, 0.1 + 0.2);
    assert.equal(merged.value.summary.exponent, 1.1e21);
    assert.equal(canonical(merged.value).summary.overflow, null);
    assert.equal(Object.getPrototypeOf(merged.value), Object.prototype);
    assert.equal(Object.prototype.marker, undefined);
    assert.equal(merged.bytes, byteOracle(merged.value));
});

test('deterministic generated merges and request envelopes agree with an independent Buffer oracle', () => {
    const next = seeded(0xc0dec0de);
    let merges = 0;
    for (let round = 0; round < 96; round++) {
        let tree;
        let reference;
        for (let step = 0; step < 18; step++) {
            const incoming = randomDelta(next, step);
            const copied = copyMonitorDelta(output(incoming));
            assert.equal(copied.bytes, byteOracle(canonical(incoming)), `copy ${round}/${step}`);
            const previousTree = tree;
            const previousJson = previousTree && JSON.stringify(previousTree.value);
            const copiedJson = JSON.stringify(copied.value);
            tree = mergeMonitorDelta(tree, copied);
            if (previousTree) assert.equal(JSON.stringify(previousTree.value), previousJson, `left ownership ${round}/${step}`);
            assert.equal(JSON.stringify(copied.value), copiedJson, `right ownership ${round}/${step}`);
            reference = mergeReference(reference, canonical(incoming));
            assert.deepEqual(canonical(tree.value), canonical(reference), `value ${round}/${step}`);
            assert.equal(tree.bytes, byteOracle(reference), `data bytes ${round}/${step}`);
            const work = Array.from({ length: next(5) }, (_, index) => ({ ...workSample(next, index), output: output(index === 0 ? reference : {}) }));
            const workContentsBytes = byteOracle(work) - 2;
            for (const sequence of [9, 10, 99, 100]) {
                const request = { sequence, work };
                assert.equal(monitorRequestBytes(sequence, workContentsBytes), byteOracle(request), `envelope ${round}/${step}/${sequence}`);
            }
            merges++;
        }
    }
    assert.equal(merges, 1728);
});

test('all eight reserved data fields reject even empty or undefined own properties', () => {
    assert.equal(MONITOR_DELTA_INPUT_FIELDS.length, 8);
    for (const field of MONITOR_DELTA_INPUT_FIELDS) for (const value of [undefined, null, '', [], {}, 0, false]) {
        const data = { results: [] };
        Object.defineProperty(data, field, { value, enumerable: true });
        assert.throws(() => copyMonitorDelta(output(data)), error => error.message.includes(`data.${field}`));
    }
});

test('JSON conversion cannot introduce a reserved field or turn data into a scalar container', () => {
    for (const field of MONITOR_DELTA_INPUT_FIELDS) {
        const data = { toJSON: () => ({ [field]: [] }) };
        assert.throws(() => copyMonitorDelta(output(data)), `JSON-generated ${field} must also be rejected`);
    }
    for (const value of [null, [], 'not an object', 1, undefined]) {
        assert.throws(() => copyMonitorDelta(output({ toJSON: () => value })), 'Serialized data must remain an object');
    }
    for (const value of [null, [], 'not a snapshot dictionary', 1]) {
        assert.throws(() => copyMonitorDelta(output({ snapshots: { toJSON: () => value } })), 'Serialized snapshots must remain an object');
        assert.throws(() => copyMonitorDelta(output({ toJSON: () => ({ snapshots: value }) })), 'JSON-generated snapshots must remain an object');
    }
});

test('real stream crosses sequence 9 to 10 within a small byte budget with exact immutable receipts', async () => {
    const original = globalThis.Sentinel;
    const snapshots = [];
    const items = Array.from({ length: 40 }, (_, index) => ({
        results: [{ index, text: `${strings[index % strings.length]}漢😀`.repeat(6) }],
        snapshots: { one: { revision: index, text: strings[(index + 1) % strings.length] } },
        summary: { total: 1, fractional: 0.1 },
    }));
    const key = index => `work:${index}:😀`;
    const requestFor = index => ({ sequence: 40, work: [{ target: 'one', key: key(index), status: 'ok', complete: index === 39, snapshot_complete: true, output: output(items[index]) }] });
    const byteLimit = Math.max(...items.map((_, index) => byteOracle(requestFor(index)))) + 8;
    let actualTotal = 0;
    let actualMaximum = 0;
    try {
        globalThis.Sentinel = { Monitor: { commitResults: async request => {
            const bytes = byteOracle(request);
            assert(bytes <= byteLimit);
            assert.equal(request.sequence, snapshots.length + 1);
            actualTotal += bytes;
            actualMaximum = Math.max(actualMaximum, bytes);
            snapshots.push(canonical(request));
            return { ok: true, sequence: request.sequence };
        } } };
        const stream = createMonitorResultStream({ __monitorExecution: monitorExecution(['one'], { maxBytes: byteLimit }) });
        const expected = items.map(canonical);
        for (const [index, data] of items.entries()) {
            await stream.record('one', key(index), output(data), { complete: index === 39, snapshot_complete: true });
            data.results[0].text = 'CALLER_MUTATED';
            data.snapshots.one.revision = -999;
            data.summary.total = -100;
        }
        const final = await stream.finish();
        assert(snapshots.length >= 10);
        assert.equal(snapshots[8].sequence, 9);
        assert.equal(snapshots[9].sequence, 10);
        const received = snapshots.flatMap(request => requestData(request).results);
        assert.deepEqual(received, expected.flatMap(data => data.results));
        for (const request of snapshots) {
            const index = Number(request.work.at(-1).key.match(/^work:(\d+):/)[1]);
            assert.deepEqual(requestData(request).snapshots.one, expected[index].snapshots.one);
        }
        const diagnostics = final.data.summary.diagnostics;
        assert.equal(diagnostics.submitted_json_bytes, actualTotal);
        assert.equal(diagnostics.committed_json_bytes, actualTotal);
        assert.equal(diagnostics.max_batch_json_bytes, actualMaximum);
        assert.equal(diagnostics.committed_work_items, items.length);
        assert.equal(diagnostics.completed_targets, 1);
        assert(snapshots.every(request => requestData(request).summary.total === request.work.length));
    } finally { globalThis.Sentinel = original; }
});
