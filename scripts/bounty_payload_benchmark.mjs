import { requestData } from './monitor_request_test_support.mjs';
/** Node 24 producer/serialization benchmark. All network and native APIs are fixtures. */
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createPayloadCase } from './bounty_payload_fixtures.mjs';

const root = new URL('../', import.meta.url);
const forbidden = ['targets', 'target_objects', 'service_targets', '__monitorExecution',
    'previousSnapshots', 'previous_snapshots', 'dictionaryEntries', 'dictionary'];
const argv = process.argv.slice(2);
function option(name, fallback) { const index = argv.indexOf(name); return index < 0 ? fallback : argv[index + 1]; }
const sizes = option('--sizes', '64,256,1024').split(',').map(Number);
const variant = option('--variant', 'current');
const outputPath = option('--output', undefined);
const selected = option('--plugins', '').split(',').filter(Boolean);
const assertLinear = argv.includes('--assert-linear');
if (sizes.some(size => !Number.isInteger(size) || size < 1 || size > 4096)) throw new Error('Sizes must be integers between 1 and 4096');
if (variant !== 'current' || argv.includes('--baseline-ref')) throw new Error('This benchmark measures current v2 producers only; historical measurements use their original checkout');
const manifest = JSON.parse(await readFile(new URL('plugins.json', root), 'utf8'));
const plugins = manifest.plugins.filter(plugin => plugin.main_category === 'bounty' && (!selected.length || selected.includes(plugin.id)));
if (selected.some(id => !plugins.some(plugin => plugin.id === id))) throw new Error('Unknown bounty plugin selection');
const variants = ['current'];
const original = { Sentinel: globalThis.Sentinel, fetch: globalThis.fetch, Deno: globalThis.Deno };
// Some real plugins capture fetch when their module loads. Keep one forwarding
// function so every measurement uses its own fixture and counters.
let activeFetch = async () => { throw new Error('No controlled fetch fixture is active'); };
globalThis.fetch = (...args) => activeFetch(...args);
const rows = [];
const comparisons = [];

function metrics() {
    return { submitted_bytes: 0, work_items: 0, completed_targets: 0, commits: 0, max_package_bytes: 0,
        fetches: 0, native_calls: 0, progress_events: 0, progress_bytes: 0, output_array_items: 0, snapshot_entries: 0,
        surface_artifact_items: 0, failed_work_items: 0, failed_completed_targets: 0, skipped_work_items: 0,
        forbidden_fields: {}, forbidden_input_items: 0 };
}

function collector(stats) {
    return async request => {
        if (request.sequence !== stats.commits + 1) throw new Error('Fixture received an out-of-order result sequence');
        const bytes = Buffer.byteLength(JSON.stringify(request), 'utf8');
        stats.submitted_bytes += bytes;
        stats.max_package_bytes = Math.max(stats.max_package_bytes, bytes);
        stats.commits++;
        stats.work_items += request.work.length;
        stats.completed_targets += request.work.filter(work => work.complete).length;
        stats.failed_work_items += request.work.filter(work => work.status === 'failed').length;
        stats.failed_completed_targets += request.work.filter(work => work.status === 'failed' && work.complete).length;
        stats.skipped_work_items += request.work.filter(work => work.status === 'skipped').length;
        const data = requestData(request);
        for (const key of forbidden) if (Object.hasOwn(data, key)) {
            stats.forbidden_fields[key] = (stats.forbidden_fields[key] || 0) + 1;
            const value = data[key];
            stats.forbidden_input_items += Array.isArray(value) ? value.length : value && typeof value === 'object' ? Object.keys(value).length : 1;
        }
        for (const value of Object.values(data)) if (Array.isArray(value)) stats.output_array_items += value.length;
        stats.snapshot_entries += Object.keys(data.snapshots || {}).length;
        for (const value of Object.values(data.surface_artifacts || {})) if (Array.isArray(value)) stats.surface_artifact_items += value.length;
        return { ok: true, sequence: request.sequence };
    };
}

async function execute(module, id, count) {
    const stats = metrics();
    const fixture = createPayloadCase(id, count, stats);
    activeFetch = fixture.fetch;
    fixture.install(collector(stats));
    const start = performance.now();
    const result = await module.analyze(fixture.input);
    const elapsed = performance.now() - start;
    if (result?.success !== true || result.data?.stream_complete !== true) {
        throw new Error(`${id}/${count}: ${result?.error || 'monitor did not complete its result stream'}`);
    }
    if (stats.completed_targets !== fixture.targets.length) throw new Error(`${id}: completed ${stats.completed_targets}/${fixture.targets.length} targets`);
    const diagnostics = result.data?.summary?.diagnostics;
    const helperMetricsPresent = diagnostics && Object.hasOwn(diagnostics, 'committed_json_bytes');
    if (helperMetricsPresent && (diagnostics.committed_json_bytes !== stats.submitted_bytes
        || diagnostics.submitted_json_bytes !== stats.submitted_bytes
        || diagnostics.max_batch_json_bytes !== stats.max_package_bytes)) {
        throw new Error(`${id}: helper JSON byte metrics disagree with the independently serialized sink`);
    }
    return { targets: count, scenario: fixture.scenario, ...stats, wall_ms: Number(elapsed.toFixed(3)),
        work_records_per_second: Math.round(stats.work_items * 1000 / Math.max(elapsed, 0.001)),
        bytes_per_work: Number((stats.submitted_bytes / stats.work_items).toFixed(3)),
        helper_byte_metrics_verified: Boolean(helperMetricsPresent),
        final_output_bytes: Buffer.byteLength(JSON.stringify(result), 'utf8') };
}

try {
    for (const plugin of plugins) {
        for (const label of variants) {
            const code = await readFile(new URL(`plugins/bounty/${plugin.id}.ts`, root), 'utf8');
            const version = manifest.plugins.find(item => item.id === plugin.id).version;
            if (code.match(/@version\s+(\S+)/)?.[1] !== version) throw new Error(`${plugin.id}: published version differs from ${label} manifest`);
            const hash = createHash('sha256').update(code).digest('hex');
            const module = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
            await execute(module, plugin.id, Math.min(4, sizes[0]));
            for (const size of sizes) {
                const row = { plugin: plugin.id, variant: label, version, bundle_sha256: hash, ...await execute(module, plugin.id, size) };
                rows.push(row);
                console.log(`${label.padEnd(8)} ${plugin.id.padEnd(24)} N=${String(size).padStart(4)} work=${String(row.work_items).padStart(5)} bytes=${String(row.submitted_bytes).padStart(10)} max=${String(row.max_package_bytes).padStart(7)} ${String(row.work_records_per_second).padStart(7)} work/s`);
                if (label === 'current' && (row.max_package_bytes > 2 * 1024 * 1024 || Object.keys(row.forbidden_fields).length)) {
                    throw new Error(`${plugin.id}: repaired stream echoed monitor inputs or exceeded the package bound`);
                }
                if (label === 'current' && plugin.id !== 'subdomain_brute' && !row.helper_byte_metrics_verified) {
                    throw new Error(`${plugin.id}: current bundle is missing exact byte accounting diagnostics`);
                }
            }
        }
    }
    for (const plugin of plugins) {
        const current = rows.filter(row => row.plugin === plugin.id && row.variant === 'current').sort((a, b) => a.targets - b.targets);
        for (let index = 1; index < current.length; index++) {
            const previous = current[index - 1], next = current[index];
            const targetRatio = next.targets / previous.targets;
            const byteRatio = next.submitted_bytes / previous.submitted_bytes;
            const workRatio = next.work_items / previous.work_items;
            const progressRatio = previous.progress_bytes ? next.progress_bytes / previous.progress_bytes : next.progress_bytes ? Infinity : 0;
            const linear = byteRatio <= targetRatio * 1.15 && workRatio <= targetRatio * 1.05 && progressRatio <= targetRatio * 1.15;
            comparisons.push({ plugin: plugin.id, from: previous.targets, to: next.targets,
                target_ratio: targetRatio, submitted_byte_ratio: Number(byteRatio.toFixed(4)),
                work_ratio: Number(workRatio.toFixed(4)), progress_byte_ratio: Number(progressRatio.toFixed(4)), linear });
            if (assertLinear && !linear) throw new Error(`${plugin.id}: non-linear submitted payload growth ${byteRatio.toFixed(3)} for ${targetRatio}x inputs`);
        }
    }
    const report = { protocol: 'monitor-results-v2', sizes, methodology: {
        execution: 'Node 24 real published plugin producers and embedded shared helper; every HTTP, DNS, TLS, AST, dictionary and native operation is a deterministic fixture',
        native_subdomain_brute: 'Native engine work is emitted by a fixture; this does not measure Rust DNS/verification throughput',
        record_unit: 'One committed work item; records/s is not database row throughput',
        bytes: 'UTF-8 bytes of every commitResults request, serialized once in the sink; progress messages serialized separately; no requests are retained',
        scope: 'JavaScript producer/serialization cost and submitted write volume; excludes real network, QuickJS and SQLite costs',
    }, rows, comparisons };
    const json = JSON.stringify(report, null, 2) + '\n';
    if (Buffer.byteLength(json) >= 1024 * 1024) throw new Error('Benchmark report exceeds the 1 MiB report bound');
    if (outputPath) await writeFile(outputPath, json);
    console.log(`Completed ${rows.length} measured cases; ${comparisons.length} current-payload growth comparisons${outputPath ? `; report ${outputPath}` : ''}.`);
} finally { Object.assign(globalThis, original); }
