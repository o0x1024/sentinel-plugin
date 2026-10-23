// Deterministic input/failure isolation tests. No network permission is granted.
import { deepEqual, equal, ok } from "node:assert/strict";
import { analyze } from "../plugins/bounty/tech_fingerprinter.ts";
const rule = { word: "php", metadata: { name: "PHP", product: "PHP", asset_category: "programming_language", matchers: [{ part: "header", key: "x-powered-by", type: "contains", value: "PHP" }] } };
function fixture() {
    const requests: string[] = [];
    globalThis.fetch = async input => {
        const url = String(input); requests.push(url);
        if (url.endsWith("/fail")) throw new Error("Connection refused");
        return new Response("<h1>Portal</h1>", { headers: { "x-powered-by": "PHP/8.2.12" } });
    };
    return requests;
}
Deno.test("one invalid URL and one fetch failure do not block later valid targets", async () => {
    const original = globalThis.fetch;
    try {
        const requests = fixture();
        const output = await analyze({ targets: ["https://example.test/first", "ED:9D:47:BE:EE:16:EF:76", "https://example.test/fail", "https://example.test/last"], concurrency: 1, dictionaryEntries: [rule] });
        equal(output.success, true);
        equal(output.data!.summary.totalTargets, 3);
        equal(output.data!.summary.skippedTargets, 1);
        equal(output.data!.summary.failedTargets, 1);
        equal(output.data!.summary.matchedTargets, 2);
        deepEqual(requests, ["https://example.test/first", "https://example.test/fail", "https://example.test/last"]);
        equal(output.data!.results.filter(r => r.status === "failed").length, 1);
        equal(output.data!.surface_artifacts!.evidences.length, 3);
    } finally { globalThis.fetch = original; }
});
Deno.test("all-invalid input makes no requests and never leaks URL credentials", async () => {
    const original = globalThis.fetch;
    try {
        const requests = fixture();
        const output = await analyze({ targets: ["example.test", "ftp://example.test/", "https://person:PRIVATE_TEST_VALUE@example.test/", "https://example.test:99999/", "https://example.test/#fragment", "https://*.example.test/", "https://bad_host.example.test/", "https:///example.test/", "https://-bad.example.test/"], dictionaryEntries: [rule] });
        equal(output.success, true); equal(output.data!.summary.skippedTargets, 9);
        equal(output.data!.summary.failedTargets, 0); equal(output.data!.summary.totalTargets, 0);
        deepEqual(output.data!.results, []);
        deepEqual(requests, []); equal(output.data!.surface_artifacts!.evidences.length, 0);
        ok(!JSON.stringify(output).includes("PRIVATE_TEST_VALUE"));
    } finally { globalThis.fetch = original; }
});
Deno.test("malformed rules fail configuration before any network request", async () => {
    const original = globalThis.fetch;
    try {
        const requests = fixture();
        const output = await analyze({ targets: ["https://example.test/"], dictionaryEntries: [{ word: "broken", metadata: { matchers: [{ part: "header", key: "server", type: "regex", value: "[" }] } }] });
        equal(output.success, false); deepEqual(requests, []);
        equal((await analyze({ targets: [], dictionaryEntries: [rule] })).success, false);
    } finally { globalThis.fetch = original; }
});
Deno.test("dictionary access errors remain explicit configuration failures", async () => {
    const globals = globalThis as Record<string, unknown>;
    const old = globals.Sentinel;
    try {
        globals.Sentinel = { Dictionary: { getDefaultId: async () => "rules", getEntries: async () => { throw new Error("PermissionDenied: dictionary"); } } };
        const output = await analyze({ targets: ["https://example.test/"], dictionaryId: "rules" });
        equal(output.success, false); ok(output.error!.includes("PermissionDenied"));
    } finally { globals.Sentinel = old; }
});

Deno.test("scope-only URL is filtered before requests and rule loading", async () => {
    const original = globalThis.fetch;
    try {
        const requests = fixture();
        const output = await analyze({ url: "http://127.0.0.1:18765/", targets: ["http://127.0.0.1:18765/"],
            target_objects: [{ type: "web", value: "http://127.0.0.1:18765/", source: "scope" }] });
        equal(output.success, true); equal(output.data!.summary.totalTargets, 0);
        equal(output.data!.summary.failedTargets, 0); equal(output.data!.summary.skippedTargets, 1);
        deepEqual(requests, []); deepEqual(output.data!.surface_artifacts!.evidences, []);
    } finally { globalThis.fetch = original; }
});

Deno.test("monitor queue contains only valid existing Web assets", async () => {
    const original = globalThis.fetch;
    try {
        const requests = fixture();
        const targets = ["http://127.0.0.1:18765/", "*.example.test", "https://example.test/first", "https://example.test/fail", "https://example.test/last"];
        const output = await analyze({ targets, concurrency: 1, dictionaryEntries: [rule],
            target_objects: targets.map((value, index) => ({ type: "web", value,
                source: index === 0 ? "scope" : "surface_asset", asset_id: index === 0 ? undefined : `web-${index}` })) });
        equal(output.success, true); equal(output.data!.summary.totalTargets, 3);
        equal(output.data!.summary.skippedTargets, 2); equal(output.data!.summary.failedTargets, 1);
        equal(output.data!.summary.matchedTargets, 2);
        deepEqual(requests, targets.slice(2));
        ok(output.data!.surface_artifacts!.evidences.every(e => targets.slice(2).includes(e.asset_key)));
    } finally { globalThis.fetch = original; }
});

function streamInput(targets: string[]) {
    return {
        targets, concurrency: 4, dictionaryEntries: [rule],
        target_objects: targets.map((value, index) => ({ type: "web", value, source: "surface_asset", asset_id: `web-${index}` })),
        __monitorExecution: { task_id: "t", task_name: "stream", program_id: "p", execution_mode: "test", started_at: "2026-10-23T00:00:00Z",
            current_plugin: "tech_fingerprinter", current_plugin_index: 1, completed_steps: 0, total_steps: 1,
            result_stream: { protocol: "technology-v1" as const, max_targets: 3 } },
    };
}
Deno.test("stream submits bounded deltas, retains failed baseline and releases acknowledged payloads", async () => {
    const originalFetch = globalThis.fetch;
    const globals = globalThis as Record<string, unknown>;
    const originalSentinel = globals.Sentinel;
    try {
        fixture();
        const chunks: any[] = [];
        globals.Sentinel = { Monitor: { commitResults: async (request: any) => {
            chunks.push(structuredClone(request));
            return { ok: true, sequence: request.sequence };
        } } };
        const targets = Array.from({length: 10}, (_, i) => `https://example.test/${i === 5 ? "fail" : i}`);
        const output = await analyze(streamInput(targets));
        equal(output.success, true); equal(output.data!.stream_complete, true);
        equal(chunks.length, 4);
        deepEqual(chunks.map(chunk => chunk.sequence), [1, 2, 3, 4]);
        equal(chunks.flatMap(chunk => chunk.output.data.results).length, 10);
        equal(output.data!.summary.failedTargets, 1); equal(output.data!.summary.matchedTargets, 9);
        equal(output.data!.results.length, 0); equal(output.data!.surface_artifacts!.evidences.length, 0);
        deepEqual(output.data!.snapshots, {});
        for (const chunk of chunks) {
            ok(chunk.output.data.results.length <= 3);
            ok(!Object.hasOwn(chunk.output.data.snapshots, targets[5]));
            for (const evidence of chunk.output.data.surface_artifacts.evidences) {
                ok(chunk.output.data.results.some((result: any) => result.url === evidence.asset_key));
            }
        }
    } finally { globalThis.fetch = originalFetch; globals.Sentinel = originalSentinel; }
});
Deno.test("stream commit rejection and wrong acknowledgement cannot turn into request failures or success", async () => {
    const originalFetch = globalThis.fetch;
    const globals = globalThis as Record<string, unknown>;
    const originalSentinel = globals.Sentinel;
    try {
        for (const wrongAck of [false, true]) {
            const requests = fixture(); let commits = 0;
            globals.Sentinel = { Monitor: { commitResults: (request: any) => {
                commits++;
                if (!wrongAck) throw new Error("database write failed");
                return { ok: true, sequence: request.sequence + 1 };
            } } };
            const input = streamInput(Array.from({length: 20}, (_, i) => `https://example.test/${i}`));
            input.concurrency = 1;
            const output = await analyze(input);
            equal(output.success, false); equal(commits, 1); equal(requests.length, 3);
            ok(output.error!.includes(wrongAck ? "acknowledged" : "database write failed"));
        }
    } finally { globalThis.fetch = originalFetch; globals.Sentinel = originalSentinel; }
});

Deno.test("slow low-concurrency scans commit progress before a full chunk accumulates", async () => {
    const originalFetch = globalThis.fetch;
    const originalNow = Date.now;
    const globals = globalThis as Record<string, unknown>;
    const originalSentinel = globals.Sentinel;
    try {
        let now = 0; Date.now = () => now;
        globalThis.fetch = async () => { now += 6000; return new Response("ok"); };
        const sizes: number[] = [];
        globals.Sentinel = { Monitor: { commitResults: (request: any) => {
            sizes.push(request.output.data.results.length);
            return { ok: true, sequence: request.sequence };
        } } };
        const input = streamInput(["https://example.test/1", "https://example.test/2"]);
        input.concurrency = 1;
        const result = await analyze(input);
        equal(result.success, true); deepEqual(sizes, [1, 1]);
    } finally { globalThis.fetch = originalFetch; Date.now = originalNow; globals.Sentinel = originalSentinel; }
});
