/** Bounded, acknowledged monitor deltas; ordinary tool calls retain their output. */
type JsonObject = Record<string, any>;
type WorkStatus = "ok" | "failed" | "skipped";

export interface MonitorResultOptions {
    status?: WorkStatus;
    /** False for intermediate work; a target accepts no work after completion. */
    complete?: boolean;
    error?: string;
    failure_category?: string;
}

interface WorkItem {
    target: string;
    key: string;
    status: WorkStatus;
    complete: boolean;
    error?: string;
    failure_category?: string;
}

interface ResultRequest {
    sequence: number;
    work: WorkItem[];
    output: { success: true; data: JsonObject };
}

const MAX_WORK_ITEMS = 32;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const COMMIT_INTERVAL_MS = 5000;

function object(value: unknown): value is JsonObject {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** JSON.stringify escapes lone surrogates; count the UTF-8 encoding of its text. */
function jsonBytes(value: unknown): number {
    const text = JSON.stringify(value);
    let bytes = 0;
    for (let index = 0; index < text.length; index++) {
        const code = text.charCodeAt(index);
        if (code < 0x80) bytes++;
        else if (code < 0x800) bytes += 2;
        else if (code >= 0xd800 && code <= 0xdbff) { bytes += 4; index++; }
        else bytes += 3;
    }
    return bytes;
}

/** Inputs are copied before buffering, so callers may release/reset their arrays. */
function copyOutput(output: unknown): { success: true; data: JsonObject } {
    if (!object(output) || output.success !== true || !object(output.data)) {
        throw new Error("Monitor result delta must contain success:true and an object data");
    }
    return JSON.parse(JSON.stringify({ success: true, data: output.data }));
}

function mergeValue(left: any, right: any, summary = false): any {
    if (Array.isArray(left) && Array.isArray(right)) return [...left, ...right];
    if (summary && typeof left === "number" && typeof right === "number") return left + right;
    if (object(left) && object(right)) {
        const merged: JsonObject = { ...left };
        for (const [key, value] of Object.entries(right)) {
            merged[key] = key in merged ? mergeValue(merged[key], value, summary) : value;
        }
        return merged;
    }
    return right;
}

function mergeData(left: JsonObject, right: JsonObject): JsonObject {
    const data: JsonObject = { ...left };
    for (const [key, value] of Object.entries(right)) {
        if (key === "snapshots") {
            if (!object(value)) throw new Error("Monitor snapshot delta must be an object");
            data.snapshots = { ...data.snapshots, ...value };
        } else {
            data[key] = key in data ? mergeValue(data[key], value, key === "summary") : value;
        }
    }
    return data;
}

function positiveLimit(value: unknown, maximum: number, label: string): number {
    if (!Number.isInteger(value) || Number(value) < 1 || Number(value) > maximum) {
        throw new Error(`Monitor result stream ${label} must be an integer between 1 and ${maximum}`);
    }
    return Number(value);
}

export function createMonitorResultStream(input: unknown) {
    const context = object(input) ? input.__monitorExecution : undefined;
    if (context === undefined) {
        return {
            enabled: false,
            assertHealthy() {},
            async record(_target: string, _key: string, _output: unknown, _options?: MonitorResultOptions) {},
            async finish<T = unknown>(finalOutput?: T): Promise<T> { return finalOutput as T; },
        };
    }
    if (!object(context) || !object(context.result_stream)
        || context.result_stream.protocol !== "monitor-results-v1") {
        throw new Error("Monitor execution requires the monitor-results-v1 result stream");
    }
    const monitor = (globalThis as any).Sentinel?.Monitor;
    if (typeof monitor?.commitResults !== "function") {
        throw new Error("Monitor execution requires Sentinel.Monitor.commitResults");
    }
    const stream = context.result_stream;
    if (!Array.isArray(stream.targets) || stream.targets.some((target: unknown) => typeof target !== "string" || !target)) {
        throw new Error("Monitor result stream requires the host-owned targets array");
    }
    const expected = new Set<string>(stream.targets);
    const chunkSize = positiveLimit(stream.max_work_items, MAX_WORK_ITEMS, "max_work_items");
    const maxPending = positiveLimit(stream.max_pending_commits, 2, "max_pending_commits");
    const byteLimit = positiveLimit(stream.max_bytes, MAX_JSON_BYTES, "max_bytes");
    const completed = new Set<string>();
    const pending = new Set<Promise<void>>();
    // Only unacknowledged work keys live here. The host owns durable duplicate detection.
    const bufferedKeys = new Set<string>();
    let buffered: WorkItem[] = [];
    let data: JsonObject = {};
    let sequence = 0;
    let lastCommitAt = Date.now();
    let failed: Error | undefined;
    let finished = false;
    let serialization: Promise<void> = Promise.resolve();
    let committedItems = 0;
    let submittedBatches = 0;
    let maxPendingObserved = 0;
    let backpressureMs = 0;

    function assertHealthy(): void {
        if (failed) throw failed;
        if (finished) throw new Error("Monitor result stream is already finished");
    }

    function latch(error: unknown): Error {
        failed ||= error instanceof Error ? error : new Error(String(error));
        return failed;
    }

    async function capacity(): Promise<void> {
        const start = Date.now();
        while (pending.size >= maxPending) {
            await Promise.race(pending);
            if (failed) throw failed;
        }
        backpressureMs += Date.now() - start;
        if (failed) throw failed;
    }

    async function flush(): Promise<void> {
        assertHealthy();
        if (!buffered.length) return;
        await capacity();
        const request: ResultRequest = { sequence: sequence + 1, work: buffered, output: { success: true, data } };
        if (jsonBytes(request) > byteLimit) throw new Error("Monitor result batch exceeds the JSON byte limit");
        sequence++;
        const keys = buffered.map(item => JSON.stringify([item.target, item.key]));
        buffered = [];
        data = {};
        lastCommitAt = Date.now();
        submittedBatches++;
        let commit: Promise<void>;
        commit = Promise.resolve().then(async () => {
            const ack = await monitor.commitResults(request);
            if (ack?.ok !== true || ack.sequence !== request.sequence) {
                throw new Error(`Monitor result commit ${request.sequence} was not acknowledged`);
            }
            committedItems += request.work.length;
        }).catch(error => { latch(error); }).finally(() => {
            for (const key of keys) bufferedKeys.delete(key);
            pending.delete(commit);
        });
        pending.add(commit);
        maxPendingObserved = Math.max(maxPendingObserved, pending.size);
        // Hold producers at the configured bound, including the currently saving batch.
        await capacity();
    }

    function exclusive<T>(action: () => Promise<T>): Promise<T> {
        const operation = serialization.then(action).catch(error => { throw latch(error); });
        serialization = operation.then(() => {}, () => {});
        return operation;
    }

    async function record(target: string, key: string, output: unknown, options: MonitorResultOptions = {}): Promise<void> {
        return exclusive(async () => {
            assertHealthy();
            if (typeof target !== "string" || !expected.has(target)) throw new Error("Monitor work target is not owned by this execution");
            if (typeof key !== "string" || !key || key.length > 2048) throw new Error("Monitor work key must contain 1 to 2048 characters");
            if (completed.has(target)) throw new Error("Monitor work cannot follow a completed target");
            const identity = JSON.stringify([target, key]);
            if (bufferedKeys.has(identity)) throw new Error("Monitor work repeats an unacknowledged target/key");
            const status = options.status ?? "ok";
            if (!["ok", "failed", "skipped"].includes(status)) throw new Error("Invalid monitor work status");
            const item: WorkItem = { target, key, status, complete: options.complete !== false };
            if (options.error !== undefined) item.error = options.error;
            if (options.failure_category !== undefined) item.failure_category = options.failure_category;
            const delta = copyOutput(output);
            const single: ResultRequest = { sequence: sequence + 1, work: [item], output: delta };
            if (jsonBytes(single) > byteLimit) throw new Error("A single monitor work result exceeds the JSON byte limit");
            let combined = mergeData(data, delta.data);
            const candidate: ResultRequest = { sequence: sequence + 1, work: [...buffered, item], output: { success: true, data: combined } };
            if (buffered.length && jsonBytes(candidate) > byteLimit) {
                await flush();
                combined = delta.data;
            }
            buffered.push(item);
            data = combined;
            bufferedKeys.add(identity);
            if (item.complete) completed.add(target);
            if (buffered.length >= chunkSize || Date.now() - lastCommitAt >= COMMIT_INTERVAL_MS) await flush();
        });
    }

    async function finish<T = unknown>(finalOutput?: T): Promise<T> {
        return exclusive(async () => {
            assertHealthy();
            await flush();
            await Promise.all(pending);
            if (failed) throw failed;
            const finalRecord = object(finalOutput) ? finalOutput as JsonObject : undefined;
            if (finalRecord?.success === false) {
                throw new Error(typeof finalRecord.error === "string" && finalRecord.error
                    ? finalRecord.error : "Monitor plugin reported an unsuccessful execution");
            }
            if (completed.size !== expected.size) {
                throw new Error(`Monitor result stream ended before all targets completed (${completed.size}/${expected.size})`);
            }
            const finalDiagnostics = finalRecord && object(finalRecord.data)
                && object(finalRecord.data.summary) && object(finalRecord.data.summary.diagnostics)
                ? finalRecord.data.summary.diagnostics : {};
            const pluginMetrics = Object.fromEntries(Object.entries(finalDiagnostics)
                .filter(([, value]) => typeof value === "number" && Number.isFinite(value) && value >= 0));
            finished = true;
            return { success: true, data: { stream_complete: true, summary: { diagnostics: {
                ...pluginMetrics,
                committed_work_items: committedItems,
                completed_targets: completed.size,
                submitted_batches: submittedBatches,
                max_pending_commits: maxPendingObserved,
                backpressure_ms_sum: backpressureMs,
            } } } } as T;
        });
    }

    return { enabled: true, assertHealthy, record, finish };
}
