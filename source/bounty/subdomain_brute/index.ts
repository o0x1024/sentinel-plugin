/**
 * Native Dictionary Subdomain Brute Force
 *
 * @plugin subdomain_brute
 * @name Subdomain Brute Force
 * @version 1.0.1
 * @author Sentinel Team
 * @main_category bounty
 * @category recon
 * @monitor_type dns
 * @input_mode seed
 * @target_asset_types []
 * @seed_bindings [{"seed_type":"root_domain","input_key":"targets"},{"seed_type":"domain","input_key":"targets"}]
 * @default_severity info
 * @tags subdomain, dns, bruteforce, dictionary, native, asm, surface, capability:network-scan, capability:monitor-events, monitor:results-stream-v1
 * @description Batch dictionary-based DNS discovery through the native Rust engine; defaults to UDP and reports transport failures explicitly
 */
import { createMonitorResultStream } from "../../shared/monitor_results.ts";

type QueryType = "a" | "aaaa" | "cname" | "mx" | "ns" | "txt";
type Transport = "udp" | "ethernet";
interface Snapshot {
    domain: string;
    subdomains: string[];
    last_checked?: string;
    lastChecked?: string;
}
interface ToolInput {
    targets?: string[];
    domain?: string;
    domains?: string[];
    dictionary_id?: string;
    dictionary?: string[];
    resolvers?: string[];
    skip_wildcard?: boolean;
    bandwidth_limit?: string | null;
    verify_mode?: boolean;
    max_retries?: number;
    dns_timeout_seconds?: number;
    max_wait_seconds?: number;
    verify_timeout_seconds?: number;
    verify_concurrency?: number;
    resolve_records?: boolean;
    query_types?: QueryType[];
    raw_records?: boolean;
    device?: string | null;
    transport?: Transport;
    previous_snapshots?: Record<string, Snapshot>;
    previousSnapshots?: Record<string, Snapshot>;
    __monitorExecution?: Record<string, unknown>;
}
interface NativeData {
    targets: string[];
    subdomains: string[];
    results: unknown[];
    change_events: unknown[];
    snapshots: Record<string, unknown>;
    summary: Record<string, unknown>;
    surface_artifacts: Record<string, unknown>;
    [key: string]: unknown;
}
interface ToolOutput {
    success: boolean;
    data?: NativeData & { changeEvents?: unknown[] };
    error?: string;
    cancelled?: boolean;
    [key: string]: unknown;
}
declare const Sentinel: {
    Network?: {
        bruteForceSubdomains?: (request: Record<string, unknown>) => Promise<ToolOutput>;
    };
};

const nativeKeys = [
    "dictionary_id", "dictionary", "resolvers", "skip_wildcard", "bandwidth_limit", "verify_mode",
    "max_retries", "dns_timeout_seconds", "max_wait_seconds", "verify_timeout_seconds", "verify_concurrency",
    "resolve_records", "query_types", "raw_records", "device", "__monitorExecution",
] as const;
const acceptedKeys = new Set<string>([...nativeKeys, "targets", "domain", "domains", "transport", "previous_snapshots", "previousSnapshots"]);
const stringArray = (description: string) => ({ type: "array", items: { type: "string" }, description });

export function get_input_schema() {
    const snapshot = {
        type: "object", required: ["domain", "subdomains"],
        properties: { domain: { type: "string" }, subdomains: stringArray("Previously discovered subdomains"), last_checked: { type: "string" }, lastChecked: { type: "string", description: "Legacy monitor timestamp alias" } },
    };
    return {
        type: "object", additionalProperties: false,
        anyOf: [{ required: ["targets"] }, { required: ["domain"] }, { required: ["domains"] }],
        properties: {
            targets: { ...stringArray("Root domains supplied by monitor seed bindings; the complete batch runs in one native call"), minItems: 1 },
            domain: { type: "string", minLength: 1, description: "Single-domain compatibility alias; merged with the target list" },
            domains: stringArray("Legacy monitor domain-list alias; merged without truncating targets"),
            dictionary_id: { type: "string", minLength: 1, description: "Platform subdomain dictionary ID. The native host reads its complete wordlist; the plugin never transfers platform dictionary words into JavaScript." },
            dictionary: stringArray("Optional inline subdomain prefixes, forwarded unchanged. Native selection uses inline entries, the selected platform dictionary, or the configured default dictionary."),
            resolvers: stringArray("DNS resolver IPs or IP:port values; native engine validates and normalizes them"),
            skip_wildcard: { type: "boolean", default: true },
            bandwidth_limit: { type: ["string", "null"], default: "3M", description: "Global native engine bandwidth limit, for example 3M" },
            verify_mode: { type: "boolean", default: false, description: "Enable native HTTP verification of discovered subdomains" },
            max_retries: { type: "integer", minimum: 1, maximum: 10, default: 5 },
            dns_timeout_seconds: { type: "integer", minimum: 1, maximum: 300, default: 10 },
            max_wait_seconds: { type: "integer", minimum: 1, maximum: 3600, default: 10, description: "Response wait window after the initial batch has been sent. The host execution deadline covers the complete run. Unanswered queries fail rather than producing a successful empty snapshot." },
            verify_timeout_seconds: { type: "integer", minimum: 1, maximum: 300, default: 10 },
            verify_concurrency: { type: "integer", minimum: 1, maximum: 1000, default: 50 },
            resolve_records: { type: "boolean", default: true },
            query_types: { type: "array", items: { type: "string", enum: ["a", "aaaa", "cname", "mx", "ns", "txt"] }, default: ["a"] },
            raw_records: { type: "boolean", default: false },
            device: { type: ["string", "null"], description: "Explicit network device for ethernet transport where supported" },
            transport: { type: "string", enum: ["udp", "ethernet"], default: "udp", description: "UDP works with normal desktop permissions. Ethernet is an explicit raw-packet choice and must be supported; failures are not silently downgraded." },
            previousSnapshots: { type: "object", additionalProperties: snapshot, readOnly: true, description: "Host-injected previous snapshots; adapted to native previous_snapshots internally" },
            __monitorExecution: { type: "object", readOnly: true, description: "Host-injected monitor context. Passed through unchanged and checked by the native host; plugins cannot impersonate another monitor task." },
        },
    };
}

export function get_output_schema() {
    return {
        type: "object", required: ["success"],
        properties: {
            success: { type: "boolean" }, error: { type: "string" }, cancelled: { type: "boolean" },
            data: {
                type: "object", required: ["targets", "subdomains", "results", "change_events", "changeEvents", "snapshots", "summary", "surface_artifacts"],
                properties: {
                    stream_complete: { type: "boolean" },
                    targets: stringArray("Complete native batch"), subdomains: stringArray("Native discovered domains"),
                    results: { type: "array", items: { type: "object" } },
                    change_events: { type: "array", items: { type: "object" } },
                    changeEvents: { type: "array", items: { type: "object" }, description: "Monitor-compatible alias referencing the same native change_events array" },
                    snapshots: { type: "object", description: "Native snapshots keyed by root domain, retaining snake_case last_checked" },
                    summary: { type: "object", properties: { total_targets: { type: "integer" }, dictionary_size: { type: "integer" }, dictionary_source: { type: "string" }, total_discovered: { type: "integer" } } },
                    surface_artifacts: { type: "object", properties: Object.fromEntries(["domains", "ips", "relations", "evidences", "changes"].map(key => [key, { type: "array", items: { type: "object" } }])) },
                },
            },
        },
    };
}

function previousSnapshots(input: ToolInput): Record<string, unknown> | undefined {
    const snapshots = input.previous_snapshots ?? input.previousSnapshots;
    if (snapshots === undefined) return undefined;
    if (!snapshots || typeof snapshots !== "object" || Array.isArray(snapshots)) throw new Error("previous_snapshots must be an object");
    return Object.fromEntries(Object.entries(snapshots).map(([domain, snapshot]) => {
        if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) throw new Error(`Invalid previous snapshot for ${domain}`);
        const { lastChecked, ...native } = snapshot;
        return [domain, { ...native, ...(native.last_checked === undefined && lastChecked !== undefined ? { last_checked: lastChecked } : {}) }];
    }));
}

function buildRequest(input: ToolInput): Record<string, unknown> {
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Input must be an object");
    const unknownKeys = Object.keys(input).filter(key => !acceptedKeys.has(key));
    if (unknownKeys.length) throw new Error(`Unsupported subdomain_brute input fields: ${unknownKeys.join(", ")}`);
    if (input.transport !== undefined && input.transport !== "udp" && input.transport !== "ethernet") throw new Error("transport must be udp or ethernet");
    if (input.targets !== undefined && !Array.isArray(input.targets) || input.domains !== undefined && !Array.isArray(input.domains)) throw new Error("targets and domains must be string arrays");
    if (input.domain !== undefined && typeof input.domain !== "string") throw new Error("domain must be a string");
    const targets = [...(input.targets ?? []), ...(input.domains ?? []), ...(input.domain === undefined ? [] : [input.domain])];
    if (!targets.length || targets.some(target => typeof target !== "string" || !target.trim())) throw new Error("Provide at least one root domain in targets");
    const request: Record<string, unknown> = { targets, transport: input.transport ?? "udp" };
    for (const key of nativeKeys) if (input[key] !== undefined) request[key] = input[key];
    const snapshots = previousSnapshots(input);
    if (snapshots !== undefined) request.previous_snapshots = snapshots;
    return request;
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const stream = createMonitorResultStream(input);
        const request = buildRequest(input);
        const network = typeof Sentinel === "undefined" ? undefined : Sentinel.Network;
        if (typeof network?.bruteForceSubdomains !== "function") throw new Error("Native Sentinel.Network.bruteForceSubdomains is unavailable; update the Sentinel host. No JavaScript DNS fallback was used.");
        const output = await network.bruteForceSubdomains(request);
        if (!output || typeof output !== "object" || typeof output.success !== "boolean") throw new Error("Invalid native subdomain brute force response");
        if (!output.success || output.cancelled === true) return { ...output, success: false, error: output.error || (output.cancelled ? "Native subdomain brute force was cancelled" : "Native subdomain brute force failed") };
        const data = output.data;
        if (!data || !Array.isArray(data.targets) || !Array.isArray(data.subdomains) || !Array.isArray(data.results) || !Array.isArray(data.change_events) || !data.snapshots || !data.summary || !data.surface_artifacts) throw new Error("Native subdomain brute force response is missing standard result fields");
        if (stream.enabled && data.stream_complete !== true) throw new Error("Native subdomain monitor did not acknowledge a complete result stream");
        return { ...output, data: { ...data, changeEvents: data.change_events } };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
}

const pluginGlobals = globalThis as typeof globalThis & { get_input_schema?: typeof get_input_schema; get_output_schema?: typeof get_output_schema; analyze?: typeof analyze };
pluginGlobals.get_input_schema = get_input_schema;
pluginGlobals.get_output_schema = get_output_schema;
pluginGlobals.analyze = analyze;
