/** Compare module sources and published bundles using deterministic local fixtures.
 * Optional --baseline-dir compares pre-refactor source copies in the same run.
 * Usage: deno run --allow-read scripts/verify_monitor_bundles.ts
 */
const root = new URL("../", import.meta.url);
const baselineIndex = Deno.args.indexOf("--baseline-dir");
const baselineDirectory = baselineIndex >= 0 ? Deno.args[baselineIndex + 1] : undefined;
if (baselineIndex >= 0 && !baselineDirectory) throw new Error("Missing --baseline-dir path");
type Plugin = {
    get_input_schema(): unknown;
    get_output_schema(): unknown;
    analyze(input: Record<string, unknown>): Promise<unknown>;
};
let requests: string[] = [];
const fixedTime = Date.parse("2026-10-18T02:00:00.000Z");
const RealDate = Date;
const originalRandom = Math.random;
const originalPerformanceNow = performance.now;
const originalFetch = globalThis.fetch;
const originalSentinel = (globalThis as Record<string, unknown>).Sentinel;
class FixedDate extends RealDate {
    constructor(value?: string | number) { super(value === undefined ? fixedTime : value); }
    static override now() { return fixedTime; }
}
globalThis.Date = FixedDate as DateConstructor;
Math.random = () => 0.25;
Object.defineProperty(performance, "now", { configurable: true, value: () => 100 });
(globalThis as Record<string, unknown>).Sentinel = {
    log() {},
    Monitor: { reportProgress: async () => true },
};
globalThis.fetch = async (input: RequestInfo | URL): Promise<Response> => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    requests.push(raw);
    const url = new URL(raw);
    if (url.hostname === "crt.sh") {
        return Response.json([{ name_value: "app.example.test\napi.example.test" }]);
    }
    if (url.hostname === "api.hackertarget.com") {
        return new Response("app.example.test,192.0.2.1\ncdn.example.test,192.0.2.2");
    }
    if (url.hostname !== "app.example.test") throw new Error(`Unexpected fixture request: ${raw}`);
    if (url.pathname === "/assets/app.js") {
        return new Response('fetch("/api/users"); fetch("/api/profile"); const route="/dashboard";', { headers: { "content-type": "application/javascript" } });
    }
    if (url.pathname === "/" || url.pathname === "/dashboard") {
        return new Response('<html><head><script src="/assets/app.js"></script></head><body><a href="/dashboard">Dashboard</a></body></html>', { headers: { "content-type": "text/html" } });
    }
    return new Response("Not found", { status: 404 });
};

function assertEqual(actual: unknown, expected: unknown, label: string): void {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${label}: output differs`);
}

try {
    let assertions = 0;
    for (const id of ["api_monitor", "subdomain_enumerator"]) {
        const source = await import(new URL(`source/bounty/${id}/index.ts`, root).href) as Plugin;
        const bundle = await import(new URL(`plugins/bounty/${id}.ts`, root).href) as Plugin;
        const variants: Array<[string, Plugin]> = [["source", source], ["bundle", bundle]];
        if (baselineDirectory) {
            const baseline = await import(new URL(`${id}.ts`, `file://${baselineDirectory.replace(/\/$/, "")}/`).href) as Plugin;
            variants.push(["baseline", baseline]);
        }
        for (const [label, plugin] of variants.slice(1)) {
            assertEqual(plugin.get_input_schema(), source.get_input_schema(), `${id}/${label}/input schema`);
            assertEqual(plugin.get_output_schema(), source.get_output_schema(), `${id}/${label}/output schema`);
            assertions += 2;
        }
        const scenarios = id === "subdomain_enumerator" ? [
            { domains: ["example.test"], sources: ["crtsh", "hackertarget"], removeDuplicates: true },
            { domains: ["example.test"], sources: ["crtsh"], previousSnapshots: { "example.test": { domain: "example.test", subdomains: ["old.example.test"], lastChecked: "2026-10-17T00:00:00Z" } } },
            { domains: [] },
        ] : [
            { targets: ["https://app.example.test/"], crawlDepth: 1, followSourceMaps: false, probeSpaManifests: false },
            { targets: ["https://app.example.test/assets/app.js"], followSourceMaps: false, probeSpaManifests: false },
            { targets: [] },
        ];
        for (let index = 0; index < scenarios.length; index++) {
            let reference: unknown;
            for (const [label, plugin] of variants) {
                requests = [];
                const result = await plugin.analyze(structuredClone(scenarios[index]));
                const observed = { result, requests: [...requests] };
                if (label === "source") reference = observed;
                else {
                    assertEqual(observed, reference, `${id}/${label}/scenario ${index}`);
                    assertions++;
                }
            }
        }
        console.log(`${id}: schemas, results, snapshots, events, and request sequences identical across ${variants.map(([label]) => label).join(" / ")}`);
    }
    console.log(`Passed ${assertions} deterministic equivalence comparisons; network permissions were not granted.`);
} finally {
    globalThis.Date = RealDate;
    Math.random = originalRandom;
    Object.defineProperty(performance, "now", { configurable: true, value: originalPerformanceNow });
    globalThis.fetch = originalFetch;
    (globalThis as Record<string, unknown>).Sentinel = originalSentinel;
}
