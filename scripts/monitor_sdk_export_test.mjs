import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { stripTypeScriptTypes } from 'node:module';
import { createMonitorResultStream } from '../source/shared/monitor_results.ts';
import { MONITOR_DELTA_INPUT_FIELDS } from '../source/shared/monitor_delta.ts';

const authoring = new URL('../../sentinel-ai-pro/src-tauri/sentinel-plugin-authoring/', import.meta.url);
const sdk = await readFile(new URL('resources/monitor_result_sdk.js', authoring), 'utf8');
const manifest = JSON.parse(await readFile(new URL('resources/monitor_result_sdk.manifest.json', authoring), 'utf8'));
const contract = await readFile(new URL('src/monitor_contract.rs', authoring), 'utf8');
const rawString = name => {
  const match = contract.match(new RegExp(`const ${name}: &str = r#"([\\s\\S]*?)"#;`));
  assert.ok(match, `${name} must be a renderer-owned raw string`);
  return match[1];
};
const prefix = rawString('MONITOR_ANALYZE_PREFIX'), suffix = rawString('MONITOR_ANALYZE_SUFFIX');
const limit = name => {
  const expression = contract.match(new RegExp(`const ${name}: (?:usize|u64) = ([^;]+);`))?.[1];
  assert.ok(expression && /^[\d_\s*]+$/.test(expression), name);
  return expression.replaceAll('_', '').split('*').map(value => Number(value.trim())).reduce((left, right) => left * right, 1);
};
function context(targets, overrides = {}) {
  return { __monitorExecution: { result_stream: { protocol: 'monitor-results-v2', targets,
    max_work_items: 32, max_pending_commits: 2, max_bytes: 2 * 1024 * 1024, ...overrides } } };
}
function embedded(commit = async request => ({ ok: true, sequence: request.sequence })) {
  const sandbox = vm.createContext({ Sentinel: { Monitor: { commitResults: commit } }, Error, console });
  vm.runInContext(sdk, sandbox);
  return { sandbox, factory: sandbox.SENTINEL_MONITOR_RESULT_SDK.createMonitorResultStream };
}
function renderedBody(body, commit, nativeOperation) {
  const runtime = embedded(commit);
  if (nativeOperation) runtime.sandbox.Sentinel.Network = {
    bruteForceSubdomains: input => nativeOperation(input, runtime.sandbox.Sentinel.Monitor.commitResults),
  };
  const source = `interface ToolInput { [key:string]:any }\ninterface ToolOutput { success:boolean;data?:any;error?:string }\nasync function analyze(input:ToolInput):Promise<ToolOutput> {\n${prefix}${body}\n${suffix}\n}\nglobalThis.analyze=analyze;`;
  vm.runInContext(stripTypeScriptTypes(source), runtime.sandbox);
  return runtime.sandbox.analyze;
}
const plain = value => JSON.parse(JSON.stringify(value));

test('embedded SDK source hashes, entry contract and reproducible check match canonical modules', async () => {
  const combined = createHash('sha256');
  for (const source of manifest.sources) {
    const bytes = await readFile(new URL(`../${source.path}`, import.meta.url));
    assert.equal(bytes.length, source.bytes);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), source.sha256);
    combined.update(source.path).update('\0').update(bytes).update('\0');
  }
  assert.equal(combined.digest('hex'), manifest.sources_sha256);
  assert.equal(createHash('sha256').update(sdk).digest('hex'), manifest.sdk_sha256);
  assert.ok(sdk.includes(`canonical_sources_sha256: ${manifest.sources_sha256}`));
  assert.equal(manifest.esbuild, '0.21.5');
  const fields = contract.match(/const MONITOR_DELTA_INPUT_FIELDS:[^=]*=\s*\[([\s\S]*?)\];/)[1];
  assert.deepEqual([...fields.matchAll(/"([^"]+)"/g)].map(match => match[1]), [...MONITOR_DELTA_INPUT_FIELDS]);
  assert.deepEqual(plain(embedded().sandbox.SENTINEL_MONITOR_RESULT_SDK.MONITOR_DELTA_INPUT_FIELDS), [...MONITOR_DELTA_INPUT_FIELDS]);
  assert.match(execFileSync(process.execPath, [fileURLToPath(new URL('export_monitor_sdk.mjs', import.meta.url)), '--check'], { encoding: 'utf8' }), /reproducible/);
});

test('Rust documented SDK limits equal the canonical runtime boundaries', () => {
  for (const [name, option] of [['MONITOR_MAX_WORK_ITEMS', 'max_work_items'],
    ['MONITOR_MAX_PENDING_COMMITS', 'max_pending_commits'], ['MONITOR_MAX_JSON_BYTES', 'max_bytes']]) {
    const value = limit(name), { factory } = embedded();
    assert.doesNotThrow(() => factory(context([], { [option]: value })));
    assert.throws(() => factory(context([], { [option]: value + 1 })), /must be an integer/);
  }
  assert.equal(limit('MONITOR_COMMIT_INTERVAL_MS'), 5000);
});

async function trace(factory, chunks) {
  const stream = factory(context(['one', 'two'], { max_work_items: 2, max_pending_commits: 1 }));
  await stream.record('one', 'first', { success: true, data: { results: [{ text: '跨域🚀\ud800' }], snapshots: { one: { title: 'first' } } } }, { complete: false, snapshot_complete: true });
  await stream.record('one', 'complete', { success: true, data: { results: [{ text: 'second' }], snapshots: { one: { title: 'new' } } } }, { snapshot_complete: true });
  await stream.record('two', 'failure', { success: true, data: { results: [{ error: 'owned failure' }] } }, { status: 'failed' });
  const output = await stream.finish({ success: true, data: { ordinaryOnly: true } });
  const result = plain(output);
  delete result.data.summary.diagnostics.backpressure_ms_sum;
  return { chunks: plain(chunks), output: result };
}
test('exported SDK keeps canonical per-work deltas, Unicode byte accounting and terminal behavior', async () => {
  const canonicalChunks = [], exportedChunks = [];
  const previous = globalThis.Sentinel;
  try {
    globalThis.Sentinel = { Monitor: { commitResults: async request => {
      canonicalChunks.push(plain(request)); return { ok: true, sequence: request.sequence };
    } } };
    const canonical = await trace(createMonitorResultStream, canonicalChunks);
    const runtime = embedded(async request => { exportedChunks.push(plain(request)); return { ok: true, sequence: request.sequence }; });
    const exported = await trace(runtime.factory, exportedChunks);
    assert.deepEqual(exported, canonical);
    assert.equal(exported.output.data.summary.diagnostics.committed_json_bytes,
      exportedChunks.reduce((bytes, request) => bytes + Buffer.byteLength(JSON.stringify(request)), 0));
  } finally { globalThis.Sentinel = previous; }
});

test('every reserved input field is rejected by the exported SDK without sending a commit', async () => {
  for (const field of MONITOR_DELTA_INPUT_FIELDS) {
    let commits = 0;
    const { factory } = embedded(async () => { commits++; throw new Error('must not commit'); });
    const stream = factory(context(['owned']));
    await assert.rejects(stream.record('owned', 'bad', { success: true, data: { [field]: [] } }), /must not repeat execution input field/);
    await assert.rejects(stream.finish({ success: true }), /must not repeat execution input field/);
    assert.equal(commits, 0);
  }
});

test('exported SDK applies backpressure and latches failed acknowledgements', async () => {
  const releases = [];
  const { factory } = embedded(request => new Promise(resolve => releases.push(() => resolve({ ok: true, sequence: request.sequence }))));
  const stream = factory(context(['one', 'two'], { max_work_items: 1, max_pending_commits: 2 }));
  await stream.record('one', 'complete', { success: true, data: {} });
  let completed = false;
  const pending = stream.record('two', 'complete', { success: true, data: {} }).then(() => { completed = true; });
  await new Promise(setImmediate);
  assert.equal(releases.length, 2);
  assert.equal(completed, false);
  releases[0]();
  await pending;
  releases[1]();
  assert.equal((await stream.finish({ success: true })).data.stream_complete, true);

  let failedCommits = 0;
  const bad = embedded(async request => { failedCommits++; return { ok: true, sequence: request.sequence + 1 }; }).factory(
    context(['owned'], { max_work_items: 1, max_pending_commits: 1 }));
  await assert.rejects(bad.record('owned', 'complete', { success: true, data: {} }), /not acknowledged/);
  await assert.rejects(bad.finish({ success: false, error: 'body must not replace commit failure' }), /not acknowledged/);
  assert.equal(failedCommits, 1);
});

test('renderer wrapper flushes buffered valid work before returning a thrown business failure', async () => {
  const commits = [];
  const analyze = renderedBody(`await stream.record(input.targets[0], 'owned', {success:true,data:{results:[{owned:true}]}}, {complete:true}); throw new Error('owned business failure');`, async request => {
    commits.push(plain(request)); return { ok: true, sequence: request.sequence };
  });
  const result = await analyze({ targets: ['one', 'two'], ...context(['one', 'two']) });
  assert.equal(result.success, false);
  assert.equal(result.error, 'owned business failure');
  assert.equal(commits.length, 1);
  assert.equal(commits[0].work[0].target, 'one');
});

test('renderer wrapper exposes readonly business methods and retains ordinary full outputs', async () => {
  const analyze = renderedBody(`if (!Object.isFrozen(stream) || 'finish' in stream) throw new Error('invalid facade');
    if(stream.enabled) { await stream.record('one','complete',{success:true,data:{results:[1]}}); }
    return {success:true,data:{targets:input.targets,results:[1]}};`);
  assert.deepEqual(plain(await analyze({ targets: ['one'] })), { success: true, data: { targets: ['one'], results: [1] } });
  const monitored = await analyze({ targets: ['one'], ...context(['one']) });
  assert.equal(monitored.success, true);
  assert.equal(monitored.data.stream_complete, true);
  assert.equal(monitored.data.targets, undefined);
});

test('renderer returns explicit SDK failures for missing protocol, computed input echo and incomplete work', async () => {
  const missing = renderedBody(`throw new Error('business body must not start');`);
  assert.match((await missing({ __monitorExecution: {} })).error, /requires the monitor-results-v2/);
  const echo = renderedBody(`await stream.record('one','bad',{success:true,data:{[input.field]:input.targets}});return {success:true};`);
  assert.match((await echo({ targets: ['one'], field: 'targets', ...context(['one']) })).error, /must not repeat execution input field/);
  const incomplete = renderedBody(`await stream.record('one','partial',{success:true,data:{results:[1]}},{complete:false});return {success:true};`);
  assert.match((await incomplete({ ...context(['one']) })).error, /before all targets completed/);
});

const nativeBody = 'return await stream.delegateNative(() => Sentinel.Network.bruteForceSubdomains(input));';
async function simulatedNative(input, commit) {
  if (!input.__monitorExecution) return { success: true, data: { targets: input.targets, results: [{ native: true }] } };
  await commit({ sequence: 1, work: input.targets.map(target => ({ target, key: 'native', status: 'ok', complete: true, output: { success: true, data: { results: [{ target, native: true }] } } })) });
  return { success: true, data: { stream_complete: true, ordinaryMustNotLeak: input.targets } };
}

test('explicit native delegation uses the same simulated sink and bypasses unused JS-stream completion', async () => {
  const commits = [];
  const analyze = renderedBody(nativeBody, async request => {
    commits.push(plain(request)); return { ok: true, sequence: request.sequence };
  }, simulatedNative);
  const output = plain(await analyze({ targets: ['one', 'two'], ...context(['one', 'two']) }));
  assert.deepEqual(output, { success: true, data: { stream_complete: true, summary: { diagnostics: { native_delegated: 1 } } } });
  assert.equal(commits.length, 1);
  assert.deepEqual(commits[0].work.map(work => work.target), ['one', 'two']);
});

test('ordinary native delegation preserves the complete native ToolOutput', async () => {
  let commits = 0;
  const analyze = renderedBody(nativeBody, async () => { commits++; throw new Error('ordinary must not commit'); }, simulatedNative);
  assert.deepEqual(plain(await analyze({ targets: ['one'] })), { success: true, data: { targets: ['one'], results: [{ native: true }] } });
  assert.equal(commits, 0);
});

test('native throw, failed result and missing completion marker remain latched after body catches them', async () => {
  const body = `try { await stream.delegateNative(() => Sentinel.Network.bruteForceSubdomains(input)); } catch (_) {}
    return {success:true,data:{stream_complete:true}};`;
  for (const [operation, expected] of [
    [async () => { throw new Error('owned native transport failure'); }, 'owned native transport failure'],
    [async () => ({ success: false, error: 'owned native result failure' }), 'owned native result failure'],
    [async () => ({ success: true, data: {} }), 'native delegation requires a successful stream_complete result'],
    [async () => null, 'native delegation must return a ToolOutput result'],
  ]) {
    const analyze = renderedBody(body, undefined, operation);
    const output = await analyze({ targets: ['one'], ...context(['one']) });
    assert.equal(output.success, false);
    assert.equal(output.error, expected);
  }
});

test('a partial native failure keeps its simulated ACK prefix and cannot become success', async () => {
  const commits = [];
  const analyze = renderedBody(`try { await stream.delegateNative(() => Sentinel.Network.bruteForceSubdomains(input)); } catch (_) {}
    return {success:true};`, async request => {
    commits.push(plain(request)); return { ok: true, sequence: request.sequence };
  }, async (input, commit) => {
    await commit({ sequence: 1, work: [{ target: input.targets[0], key: 'native-first', status: 'ok', complete: true, output: { success: true, data: { results: [{ native: true }] } } }] });
    throw new Error('owned native failed after first ACK');
  });
  const output = await analyze({ targets: ['one', 'two'], ...context(['one', 'two']) });
  assert.equal(output.success, false);
  assert.equal(output.error, 'owned native failed after first ACK');
  assert.equal(commits.length, 1);
});

test('JS records followed by delegation reject the native operation before side effects and flush valid JS prefix', async () => {
  const commits = []; let nativeCalls = 0;
  const analyze = renderedBody(`await stream.record('one','js-first',{success:true,data:{results:[1]}});
    try { await stream.delegateNative(() => Sentinel.Network.bruteForceSubdomains(input)); } catch (_) {}
    return {success:true};`, async request => { commits.push(plain(request)); return { ok: true, sequence: request.sequence }; },
  async () => { nativeCalls++; return { success: true, data: { stream_complete: true } }; });
  const output = await analyze({ targets: ['one'], ...context(['one']) });
  assert.equal(output.success, false);
  assert.match(output.error, /native delegation/);
  assert.equal(nativeCalls, 0);
  assert.equal(commits.length, 1);
  assert.equal(commits[0].work[0].key, 'js-first');
});

test('native delegation followed by JS record or a second delegation cannot replay another producer', async () => {
  for (const second of ["await stream.record('one','bad-js',{success:true,data:{results:[1]}});",
    'await stream.delegateNative(() => Sentinel.Network.bruteForceSubdomains(input));']) {
    const commits = []; let nativeCalls = 0;
    const analyze = renderedBody(`await stream.delegateNative(() => Sentinel.Network.bruteForceSubdomains(input));
      try { ${second} } catch (_) {} return {success:true};`, async request => {
      commits.push(plain(request)); return { ok: true, sequence: request.sequence };
    }, async (input, commit) => { nativeCalls++; return simulatedNative(input, commit); });
    const output = await analyze({ targets: ['one'], ...context(['one']) });
    assert.equal(output.success, false);
    assert.match(output.error, /native delegation/);
    assert.equal(nativeCalls, 1);
    assert.equal(commits.length, 1);
  }
});

test('a native completion marker without simulated ACKs is not evidence of host acceptance', async () => {
  let commits = 0;
  const analyze = renderedBody(nativeBody, async () => { commits++; throw new Error('must not fabricate commits'); },
    async () => ({ success: true, data: { stream_complete: true, committedTargets: 9999 } }));
  const output = await analyze({ targets: ['one'], ...context(['one']) });
  assert.equal(output.data.summary.diagnostics.native_delegated, 1);
  assert.equal(output.data.committedTargets, undefined);
  assert.equal(commits, 0);
  // The real host/authoring sink must independently reject these missing ACKs.
});

test('pending native delegation cannot finish early, and ordinary failure output cannot be masked', async () => {
  let release;
  const analyze = renderedBody('stream.delegateNative(() => Sentinel.Network.bruteForceSubdomains(input)); return {success:true};', undefined,
    () => new Promise(resolve => { release = resolve; }));
  const output = await analyze({ targets: ['one'], ...context(['one']) });
  assert.equal(output.success, false);
  assert.match(output.error, /native delegation must be awaited/);
  release({ success: true, data: { stream_complete: true } });
  await new Promise(setImmediate);
  const failure = { success: false, error: 'owned ordinary native failure', data: { partialResults: [1] } };
  const ordinary = renderedBody(`await stream.delegateNative(() => Sentinel.Network.bruteForceSubdomains(input)); return {success:true};`, undefined,
    async () => failure);
  assert.deepEqual(plain(await ordinary({ targets: ['one'] })), failure);
});
