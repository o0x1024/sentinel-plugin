/** Compare real published producers in isolated Node processes; no network. */
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setImmediate } from 'node:timers/promises';
import { monitorExecution } from './monitor_stream_fixture.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = fileURLToPath(import.meta.url);
const baselineRef = '23853f6112ea8c6fea3b2ee9ee9bdc5396a78662';
const args = process.argv.slice(2);
const concurrency = 32;

async function measure(variant, targetCount, ruleCount, bundlePath) {
  assert.equal(typeof globalThis.gc, 'function', 'Run child with --expose-gc');
  let code;
  if (variant === 'baseline') {
    const result = spawnSync('git', ['show', `${baselineRef}:plugins/bounty/risk_scanner.ts`], { cwd: root, encoding: 'utf8' });
    if (result.status !== 0) throw new Error(result.stderr);
    code = result.stdout;
  } else {
    code = await readFile(bundlePath, 'utf8');
  }
  const plugin = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
  const targets = Array.from({ length: targetCount }, (_, index) => `https://owned${index}.test/`);
  const metadata = { requests: [{ method: 'GET', path: '/probe' }],
    matchers: [{ part: 'status', type: 'equals', value: 200 }] };
  const dictionaryEntries = Array.from({ length: ruleCount }, (_, index) => ({ word: `rule-${index}`, metadata }));
  const input = { targets, dictionaryEntries, concurrency,
    __monitorExecution: monitorExecution(targets, { pluginId: 'risk_scanner', maxWorkItems: 1 }) };
  // The previous published version needs its explicit limit raised for equal
  // coverage. The current producer receives no removed parameter.
  if (variant === 'baseline') {
    input.maxRules = ruleCount;
    // The pinned historical producer is measured with its own original protocol.
    input.__monitorExecution.result_stream.protocol='monitor-results-v1';
  }
  let release, notifySaturated;
  const gate = new Promise(resolve => { release = resolve; });
  const saturated = new Promise(resolve => { notifySaturated = resolve; });
  let requests = 0;
  globalThis.fetch = async () => {
    requests++;
    if (requests === concurrency) notifySaturated();
    await gate;
    return new Response('', { status: 404 });
  };
  globalThis.Sentinel = { Monitor: {
    reportProgress: () => true,
    commitResults: () => { throw new Error('Owned benchmark stop'); },
  } };
  globalThis.gc();
  const before = process.memoryUsage();
  const start = performance.now();
  const pending = plugin.analyze(input);
  await Promise.race([saturated, pending.then(output => { throw new Error(`Producer ended before saturation: ${output.error}`); })]);
  const saturatedAt = performance.now();
  await setImmediate();
  globalThis.gc();
  const during = process.memoryUsage();
  release();
  const output = await pending;
  await setImmediate();
  assert.equal(output.success, false);
  assert.match(output.error, /Owned benchmark stop/);
  assert.equal(requests, concurrency, 'no additional HTTP work starts after failed persistence');
  return {
    variant, version: code.match(/@version\s+(\S+)/)?.[1],
    bundle_sha256: createHash('sha256').update(code).digest('hex'),
    targets: targetCount, rules: ruleCount, planned_rule_tasks: targetCount * ruleCount,
    concurrency, started_requests: requests,
    prepare_and_saturate_ms: Number((saturatedAt - start).toFixed(3)),
    heap_growth_at_worker_saturation_bytes: during.heapUsed - before.heapUsed,
    rss_growth_at_worker_saturation_bytes: during.rss - before.rss,
  };
}

if (args[0] === '--child') {
  console.log(JSON.stringify(await measure(args[1], Number(args[2]), Number(args[3]), args[4])));
} else {
  const outputIndex = args.indexOf('--output');
  const outputPath = outputIndex < 0 ? undefined : args[outputIndex + 1];
  if (outputIndex >= 0 && !outputPath) throw new Error('--output requires a path');
  const bundleIndex = args.indexOf('--bundle');
  const bundleOption = bundleIndex < 0 ? undefined : args[bundleIndex + 1];
  if (bundleIndex >= 0 && !bundleOption) throw new Error('--bundle requires a path');
  const bundlePath = bundleOption ? resolve(bundleOption) : fileURLToPath(new URL('../plugins/bounty/risk_scanner.ts', import.meta.url));
  const allowed = new Set(['--assert-memory', '--output', outputPath, '--bundle', bundleOption]);
  if (args.some(arg => !allowed.has(arg))) throw new Error('Unknown benchmark argument');
  const rows = [];
  for (const targetCount of [500, 5000]) {
    for (const variant of ['baseline', 'current']) {
      const child = spawnSync(process.execPath,
        ['--expose-gc', '--disable-warning=ExperimentalWarning', script, '--child', variant, String(targetCount), '200', bundlePath],
        { cwd: root, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 });
      if (child.status !== 0) throw new Error(child.stderr || child.error?.message || child.stdout);
      rows.push(JSON.parse(child.stdout));
    }
  }
  const baseline = rows.find(row => row.variant === 'baseline' && row.targets === 5000);
  const current = rows.find(row => row.variant === 'current' && row.targets === 5000);
  const reduction = baseline.heap_growth_at_worker_saturation_bytes / Math.max(current.heap_growth_at_worker_saturation_bytes, 1);
  if (args.includes('--assert-memory')) {
    assert.ok(current.heap_growth_at_worker_saturation_bytes < 12 * 1024 * 1024,
      'one million planned tasks must not allocate a task matrix');
    assert.ok(reduction > 8, 'indexed producer should use at least 8x less preparation heap for this fixture');
  }
  const report = { baseline_ref: baselineRef, methodology: {
    execution: 'Node 24; real published plugins in isolated child processes; 200 rules per target in both versions',
    measurement: 'Inputs allocated before measurement; sample live heap after GC while the first 32 fetches are gated; fail the first result commit to stop',
    scope: 'Producer preparation and scheduling memory only; excludes real network, QuickJS, SQLite and desktop acceptance',
  }, rows, largest_case_heap_reduction_factor: Number(reduction.toFixed(2)) };
  if (outputPath) await writeFile(outputPath, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
}
