/**
 * Service Probe Tool
 *
 * @plugin service_probe
 * @name Service Probe
 * @version 1.2.9
 * @author Sentinel Team
 * @main_category bounty
 * @monitor_type service
 * @input_mode asset
 * @target_asset_types ["service"]
 * @category recon
 * @seed_bindings []
 * @default_severity info
 * @tags service, probe, fingerprint, banner, asm, network, dictionary, normalized, native, capability:network-scan, capability:dictionary, capability:monitor-events, monitor:results-stream-v1
 * @description Identify exposed services from host/port targets with the native Rust service identification engine, normalized fingerprint artifacts, and structured service evidence
 */
import { createMonitorResultStream } from "../../shared/monitor_results.ts";
import { createMonitorTargetWriter } from "../../shared/monitor_target_writer.ts";

declare const Sentinel: {
    Dictionary?: {
        getEntries?(idOrName: string, limit?: number): Promise<any[]>;
        getDefaultId?(dictType: string): Promise<string | null>;
    };
    Network?: {
        probeServices?(request: {
            targets: Array<{ host: string; port: number; protocol: string }>;
            rules?: Array<{ id?: string; word: string; category?: string | null; metadata?: any }>;
            dictionaryId?: string;
            followHttpRedirects?: boolean;
            readBanner?: boolean;
            engine?: string;
            monitorProgress?: MonitorExecutionContext;
        }): Promise<{
            success: boolean;
            results: Array<ProbeResult>;
            ruleCount?: number;
            engineRequested: string;
            engineUsed: string;
            engineExperimental: boolean;
            fallbackReason?: string;
            error?: string;
        }>;
        getServiceProbeCapabilities?(): Promise<{
            default_engine: string;
            engines: Array<{
                id: string;
                experimental: boolean;
                available: boolean;
                implemented: boolean;
            }>;
        }>;
    };
};

interface PortLikeTarget {
    host_key?: string;
    ip_or_host?: string;
    host?: string;
    port?: number;
    port_number?: number;
    transport_protocol?: string;
    protocol?: string;
    value?: string;
    type?: string;
    service_name?: string;
}

interface ToolInput {
    targets?: Array<string | PortLikeTarget>;
    target_objects?: Array<string | PortLikeTarget>;
    service_targets?: Array<string | PortLikeTarget>;
    dictionaryId?: string;
    dictionaryEntries?: RuleEntry[];
    followHttpRedirects?: boolean;
    readBanner?: boolean;
    serviceProbeEngine?: string;
    __monitorExecution?: MonitorExecutionContext;
}

interface RuleEntry {
    id?: string;
    word: string;
    category?: string | null;
    metadata?: any;
}

interface ProbeResult {
    target: string;
    success: boolean;
    available: boolean;
    host: string;
    port: number;
    protocol: string;
    serviceName?: string;
    productName?: string;
    vendor?: string;
    version?: string;
    banner?: string;
    serverHeader?: string;
    title?: string;
    statusCode?: number;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: ProbeResult[];
        snapshots: Record<string, ServiceSnapshot>;
        summary: {
            totalTargets: number;
            successfulChecks: number;
            failedChecks: number;
            reachableServices: number;
            unreachableServices: number;
            identifiedProducts: number;
            matchedFingerprints: number;
            scannedRules: number;
            probeEngineRequested: string;
            probeEngineUsed: string;
            probeEngineExperimental: boolean;
            probeEngineFallbackReason?: string;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

interface ServiceProbeEngineCapability {
    id: string;
    experimental: boolean;
    available: boolean;
    implemented: boolean;
}

interface ServiceProbeCapabilitiesResponse {
    default_engine: string;
    engines: ServiceProbeEngineCapability[];
}

interface ResolvedServiceProbeEngine {
    requested: string;
    used: string;
    experimental: boolean;
    fallbackReason?: string;
}

interface NativeServiceProbeResponse {
    success: boolean;
    results: ProbeResult[];
    ruleCount?: number;
    engineRequested: string;
    engineUsed: string;
    engineExperimental: boolean;
    fallbackReason?: string;
    error?: string;
}

interface MonitorExecutionContext {
    task_id: string;
    task_name: string;
    program_id: string;
    execution_mode: string;
    started_at: string;
    current_plugin: string;
    current_plugin_index: number;
    completed_steps: number;
    total_steps: number;
    imported_assets?: number;
}

async function reportMonitorProgress(
    monitorExecution: MonitorExecutionContext | undefined,
    update: Record<string, unknown>,
): Promise<boolean> {
    if (!monitorExecution) return false;
    try {
        return Boolean(await Sentinel.Monitor?.reportProgress?.({
            monitorProgress: {
                taskId: monitorExecution.task_id,
                taskName: monitorExecution.task_name,
                programId: monitorExecution.program_id,
                executionMode: monitorExecution.execution_mode,
                startedAt: monitorExecution.started_at,
                currentPlugin: monitorExecution.current_plugin,
                currentPluginIndex: monitorExecution.current_plugin_index,
                completedSteps: monitorExecution.completed_steps,
                totalSteps: monitorExecution.total_steps,
                importedAssets: monitorExecution.imported_assets,
            },
            ...update,
        }));
    } catch {
        return false;
    }
}

const HTTP_PORTS = new Set([80, 81, 443, 8000, 8080, 8081, 8443, 8888, 9000]);
const TLS_PORTS = new Set([443, 8443, 9443]);

const DEFAULT_SERVICE_NAMES: Record<number, string> = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
    9200: "elasticsearch",
    27017: "mongodb",
};

const pluginGlobals = globalThis as typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

function parseMetadata(value: any): Record<string, any> {
    if (!value) return {};
    if (typeof value === "string") {
        try {
            return JSON.parse(value);
        } catch {
            return {};
        }
    }
    return typeof value === "object" ? value : {};
}

async function loadDictionaryEntries(idOrName: string): Promise<RuleEntry[]> {
    if (typeof Sentinel?.Dictionary?.getEntries !== "function") throw new Error("Native service rule dictionary API is unavailable");
    const entries = await Sentinel.Dictionary.getEntries(idOrName, 10000);
    if (!Array.isArray(entries) || !entries.length) throw new Error("Service rule dictionary is empty or invalid");
    return entries.map((entry: any) => {
        if (!entry || typeof entry.word !== "string" || !entry.word.trim()) throw new Error("Service rule dictionary contains an invalid entry");
        return { id: entry.id, word: entry.word, category: entry.category, metadata: parseMetadata(entry.metadata) };
    });
}

async function loadRules(input: ToolInput): Promise<RuleEntry[]> {
    if (Array.isArray(input.dictionaryEntries) && input.dictionaryEntries.length) {
        return input.dictionaryEntries.map(entry => ({ ...entry, metadata: parseMetadata(entry.metadata) }));
    }
    return await loadDictionaryEntries(await resolveRuleDictionaryId(input));
}

async function resolveRuleDictionaryId(input: ToolInput): Promise<string> {
    if (input.dictionaryId !== undefined) {
        if (typeof input.dictionaryId !== "string" || !input.dictionaryId || input.dictionaryId.trim() !== input.dictionaryId) throw new Error("Service rule dictionary ID must be an unpadded string");
        return input.dictionaryId;
    }
    if (typeof Sentinel?.Dictionary?.getDefaultId !== "function") throw new Error("Native service rule default dictionary API is unavailable");
    const id = await Sentinel.Dictionary.getDefaultId("service_probe_rule");
    if (typeof id !== "string" || !id || id.trim() !== id) throw new Error("No default service rule dictionary is configured");
    return id;
}

function normalizeTarget(raw: string | PortLikeTarget): { host: string; port: number; protocol: string } | null {
    if (typeof raw === "string") {
        if (!raw || raw.trim() !== raw) return null;
        try {
            const explicitUrl = raw.includes("://");
            const suffix = !explicitUrl ? raw.match(/\/(tcp|udp)$/)?.[1] : undefined;
            const value = suffix ? raw.slice(0, -(suffix.length + 1)) : raw;
            const parsed = new URL(explicitUrl ? value : `tcp://${value}`);
            const protocol = suffix || parsed.protocol.slice(0, -1);
            const port = Number(parsed.port || (protocol === "https" ? 443 : protocol === "http" ? 80 : 0));
            if (!parsed.hostname || !["tcp", "http", "https"].includes(protocol) || !Number.isInteger(port) || port <= 0 || port > 65535 || parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname && parsed.pathname !== "/")) return null;
            return { host: parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase(), port, protocol };
        } catch { return null; }
    }
    if (!raw || typeof raw !== "object") return null;
    const hostValue = raw.ip_or_host ?? raw.host ?? raw.host_key;
    const portValue = raw.port ?? raw.port_number;
    let identity: { host: string; port: number; protocol: string } | null;
    if (hostValue !== undefined || portValue !== undefined) {
        const host = String(hostValue || "").trim().replace(/^\[|\]$/g, "").toLowerCase();
        const port = Number(portValue);
        if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) return null;
        identity = { host, port, protocol: "tcp" };
    } else { identity = typeof raw.value === "string" ? normalizeTarget(raw.value) : null; }
    if (!identity) return null;
    const transport = raw.transport_protocol ?? (raw.protocol === "tcp" || raw.protocol === "udp" ? raw.protocol : "tcp");
    if (transport !== "tcp") return null;
    const application = [raw.protocol, raw.service_name].find(value => value === "http" || value === "https");
    return { ...identity, protocol: application || identity.protocol };
}

function collectRawTargets(input: ToolInput): Array<string | PortLikeTarget> {
    const rawTargets = [
        ...(Array.isArray(input.service_targets) ? input.service_targets : []),
        ...(Array.isArray(input.target_objects) ? input.target_objects : []),
        ...(Array.isArray(input.targets) ? input.targets : []),
    ];

    return rawTargets.filter((target) => {
        if (typeof target === "string") {
            return target.trim().length > 0;
        }
        if (!target || typeof target !== "object") {
            return false;
        }
        return !target.type || target.type === "service";
    });
}

function serviceKey(host: string, port: number): string {
    return `${host.includes(":") ? `[${host}]` : host}:${port}`;
}

function serviceArtifactKey(host: string, port: number): string { return `${serviceKey(host, port)}/tcp`; }

function dedupeTargets(targets: Array<{ host: string; port: number; protocol: string }>): Array<{ host: string; port: number; protocol: string }> {
    const deduped = new Map<string, { host: string; port: number; protocol: string }>();
    for (const target of targets) {
        const key = serviceKey(target.host, target.port);
        const existing = deduped.get(key);
        if (!existing) {
            deduped.set(key, target);
            continue;
        }

        const existingPriority = existing.protocol === "https" ? 3 : existing.protocol === "http" ? 2 : 1;
        const currentPriority = target.protocol === "https" ? 3 : target.protocol === "http" ? 2 : 1;
        if (currentPriority > existingPriority) {
            deduped.set(key, target);
        }
    }

    return Array.from(deduped.values());
}

function inferServiceName(port: number, protocol: string, banner?: string, serverHeader?: string): string {
    const normalizedBanner = `${banner || ""} ${serverHeader || ""}`.toLowerCase();
    if (normalizedBanner.includes("ssh")) return "ssh";
    if (normalizedBanner.includes("smtp")) return "smtp";
    if (normalizedBanner.includes("redis")) return "redis";
    if (normalizedBanner.includes("mysql")) return "mysql";
    if (normalizedBanner.includes("postgres")) return "postgresql";
    if (normalizedBanner.includes("mongodb")) return "mongodb";
    if (normalizedBanner.includes("elasticsearch")) return "elasticsearch";
    if (HTTP_PORTS.has(port) || normalizedBanner.includes("http")) {
        return TLS_PORTS.has(port) || protocol === "https" ? "https" : "http";
    }
    return DEFAULT_SERVICE_NAMES[port] || protocol || "unknown";
}

function extractProductInfo(banner?: string, serverHeader?: string): {
    productName?: string;
    vendor?: string;
    version?: string;
} {
    const source = `${serverHeader || ""} ${banner || ""}`.trim();
    if (!source) return {};

    const patterns = [
        /(?<product>nginx)\/(?<version>[\d.]+)/i,
        /(?<product>apache(?: httpd)?)\/(?<version>[\d.]+)/i,
        /(?<product>microsoft-iis)\/(?<version>[\d.]+)/i,
        /(?<product>openssh)[-_](?<version>[\d.p]+)/i,
        /(?<product>redis)[-_ ]server v=(?<version>[\d.]+)/i,
        /(?<product>postgres(?:ql)?)\s+(?<version>[\d.]+)/i,
        /(?<product>mysql)[-_ ](?<version>[\d.]+)/i,
        /(?<product>elasticsearch)\/(?<version>[\d.]+)/i,
    ];

    for (const pattern of patterns) {
        const match = source.match(pattern);
        if (!match?.groups?.product) continue;
        const productName = match.groups.product.toLowerCase();
        let vendor: string | undefined;
        if (productName.includes("nginx")) vendor = "NGINX";
        if (productName.includes("apache")) vendor = "Apache";
        if (productName.includes("iis")) vendor = "Microsoft";
        if (productName.includes("openssh")) vendor = "OpenSSH";
        if (productName.includes("redis")) vendor = "Redis";
        if (productName.includes("mysql")) vendor = "Oracle";
        if (productName.includes("postgres")) vendor = "PostgreSQL";
        if (productName.includes("elasticsearch")) vendor = "Elastic";
        return {
            productName,
            vendor,
            version: match.groups.version,
        };
    }

    return {
        productName: source.split(/[ /]/)[0]?.toLowerCase(),
    };
}

const SERVICE_FETCH_TIMEOUT_MS = 3000;

async function runSequentially<T>(tasks: Array<() => Promise<T>>): Promise<T[]> {
    const results = new Array<T>(tasks.length);
    let nextIndex = 0;
    const workers = Array.from({ length: Math.min(16, tasks.length) }, async () => {
        while (nextIndex < tasks.length) {
            const currentIndex = nextIndex++;
            results[currentIndex] = await tasks[currentIndex]();
        }
    });
    await Promise.all(workers);
    return results;
}

function isIpLiteral(value: string): boolean {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
}

function buildServiceSnapshot(result: ProbeResult, timestamp: string): ServiceSnapshot {
    return {
        target: result.target,
        host: result.host,
        port: result.port,
        protocol: result.protocol,
        serviceName: result.serviceName || "unknown",
        productName: result.productName,
        vendor: result.vendor,
        version: result.version,
        banner: result.banner,
        serverHeader: result.serverHeader,
        title: result.title,
        statusCode: result.statusCode,
        lastChecked: timestamp,
    };
}

function serviceMatcherHit(ctx: Record<string, any>, matcher: any): boolean {
    const part = String(matcher?.part || "banner").toLowerCase();
    const type = String(matcher?.type || "contains").toLowerCase();
    const value = String(matcher?.value || "");

    const source = part === "header"
        ? String(ctx.serverHeader || "")
        : part === "product"
            ? String(ctx.productName || "")
            : part === "service"
                ? String(ctx.serviceName || "")
                : String(ctx.banner || "");

    if (type === "equals") return source.toLowerCase() === value.toLowerCase();
    if (type === "regex") {
        try {
            return new RegExp(value, "i").test(source);
        } catch {
            return false;
        }
    }
    return source.toLowerCase().includes(value.toLowerCase());
}

function matchServiceRule(result: ProbeResult, rules: RuleEntry[]): RuleEntry | undefined {
    for (const rule of rules) {
        const metadata = parseMetadata(rule.metadata);
        const matchers = Array.isArray(metadata.matchers) ? metadata.matchers : [];
        if (matchers.length > 0) {
            const operator = String(metadata.operator || "or").toLowerCase();
            const matched = operator === "and"
                ? matchers.every((matcher: any) => serviceMatcherHit(result, matcher))
                : matchers.some((matcher: any) => serviceMatcherHit(result, matcher));
            if (matched) {
                return rule;
            }
            continue;
        }

        const probe = `${result.productName || ""} ${result.serviceName || ""} ${result.serverHeader || ""} ${result.banner || ""}`.toLowerCase();
        if (probe.includes(rule.word.toLowerCase())) {
            return rule;
        }
    }

    return undefined;
}

async function resolveServiceProbeEngine(requestedEngine?: string): Promise<ResolvedServiceProbeEngine> {
    const requested = requestedEngine ?? "native";
    if (requested !== "native") throw new Error(`Unsupported service probe engine: ${requested}`);
    return { requested, used: "native", experimental: false };
}

async function probeServicesWithNativeEngine(
    targets: Array<{ host: string; port: number; protocol: string }>,
    dictionaryId: string | null,
    rules: RuleEntry[],
    followHttpRedirects: boolean,
    readBanner: boolean,
    engine: string,
    monitorExecution?: MonitorExecutionContext,
): Promise<NativeServiceProbeResponse | null> {
    if (
        typeof Sentinel === "undefined"
        || !Sentinel.Network
        || typeof Sentinel.Network.probeServices !== "function"
    ) {
        throw new Error("Native service probing engine is not available");
    }

    return await Sentinel.Network.probeServices({
        targets,
        rules,
        dictionaryId: dictionaryId || undefined,
        followHttpRedirects,
        readBanner,
        engine,
        monitorProgress: monitorExecution ? {
            taskId: monitorExecution.task_id,
            taskName: monitorExecution.task_name,
            programId: monitorExecution.program_id,
            executionMode: monitorExecution.execution_mode,
            startedAt: monitorExecution.started_at,
            currentPlugin: monitorExecution.current_plugin,
            currentPluginIndex: monitorExecution.current_plugin_index,
            completedSteps: monitorExecution.completed_steps,
            totalSteps: monitorExecution.total_steps,
            importedAssets: monitorExecution.imported_assets ?? 0,
        } : undefined,
    }) as NativeServiceProbeResponse;
}

export function get_input_schema() {
    return {
        type: "object",
        properties: {
            targets: {
                type: "array",
                description: "Port targets as strings like host:port or surface service objects",
            },
            target_objects: {
                type: "array",
                description: "Structured monitor targets. Service entries are preferred when present.",
            },
            service_targets: {
                type: "array",
                description: "Structured service endpoints with host, port, and protocol fields",
            },
            dictionaryId: {
                type: "string",
                "x-control": "dictionary-picker",
                "x-dictionary-type": "service_probe_rule",
                description: "Structured service fingerprint dictionary ID or name",
            },
            dictionaryEntries: {
                type: "array",
                description: "Structured service fingerprint rule entries injected by workflow",
            },
            followHttpRedirects: {
                type: "boolean",
                default: true,
            },
            readBanner: {
                type: "boolean",
                default: false,
            },
            serviceProbeEngine: {
                type: "string",
                enum: ["native"],
                default: "native",
                description: "Service probe engine. Native is the built-in Rust service identification engine.",
            },
        },
    };
}

pluginGlobals.get_input_schema = get_input_schema;

export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean" },
            data: {
                type: "object",
                properties: {
                    results: { type: "array" },
                    snapshots: { type: "object" },
                    summary: { type: "object" },
                    surface_artifacts: {
                        type: "object",
                        description: "Structured service probe and fingerprint artifacts",
                        properties: {
                            services: { type: "array" },
                            fingerprints: { type: "array" },
                            evidences: { type: "array" },
                            relations: { type: "array" },
                        },
                    },
                },
            },
            error: { type: "string" },
        },
    };
}

pluginGlobals.get_output_schema = get_output_schema;

function projectServiceProbeOutput(results: ProbeResult[], rules: RuleEntry[], timestamp: string, probeEngine: ResolvedServiceProbeEngine, ruleCount: number): ToolOutput {

        let successfulChecks = 0;
        let failedChecks = 0;
        let reachableServices = 0;
        let unreachableServices = 0;
        const snapshots: Record<string, ServiceSnapshot> = {};

        for (const result of results) {
            if (result.available) {
                successfulChecks += 1;
                reachableServices += 1;
            } else {
                failedChecks += 1;
                unreachableServices += 1;
            }
            if (result.success) snapshots[result.target] = buildServiceSnapshot(result, timestamp);
        }

        const successfulResults = results.filter((result) => result.available);
        const services = successfulResults.map((result) => ({
            host_key: result.host,
            ip_or_host: result.host,
            port: result.port,
            transport_protocol: "tcp",
            protocol_name: result.protocol,
            application_service_name: result.serviceName,
            product_name: result.productName,
            vendor: result.vendor,
            version: result.version,
            banner: result.banner || result.serverHeader,
            source: "service_probe",
            confidence: 0.92,
            experimental: probeEngine.experimental,
            probe_engine: probeEngine.used,
        }));

        const fingerprints = successfulResults.flatMap((result) => {
            const key = serviceArtifactKey(result.host, result.port);
            const matchedRule = matchServiceRule(result, rules);
            if (!matchedRule) {
                return [];
            }

            const ruleMetadata = parseMetadata(matchedRule.metadata);
            const normalizedProduct = ruleMetadata.product || result.productName;
            const normalizedCategory = ruleMetadata.asset_category;
            if (!normalizedProduct || !normalizedCategory) {
                return [];
            }

            const normalizedVendor = ruleMetadata.vendor || result.vendor;
            const normalizedFamily = ruleMetadata.asset_family || undefined;
            const ruleBase = (matchedRule.word || normalizedProduct)
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, "_")
                .replace(/^_+|_+$/g, "") || "unknown";
            const ruleId = ruleMetadata.rule_id || matchedRule.id || `service_rule:${ruleBase}`;
            const ruleWord = matchedRule.word || ruleBase;
            const ruleName = ruleMetadata.name || matchedRule.word || normalizedProduct;
            const fingerprintItems: any[] = [];

            if (result.banner) {
                fingerprintItems.push({
                    asset_type: "service",
                    asset_key: key,
                    fingerprint_type: "banner",
                    fingerprint_key: "banner",
                    fingerprint_value: result.banner,
                    rule_id: ruleId,
                    rule_word: ruleWord,
                    rule_name: ruleName,
                    normalized_product: normalizedProduct,
                    normalized_vendor: normalizedVendor,
                    normalized_category: normalizedCategory,
                    normalized_family: normalizedFamily,
                    version: result.version,
                    confidence: 0.88,
                    evidence: result.banner,
                    source: "service_probe",
                });
            }

            if (result.productName) {
                fingerprintItems.push({
                    asset_type: "service",
                    asset_key: key,
                    fingerprint_type: "product",
                    fingerprint_key: "product_name",
                    fingerprint_value: `${result.productName}${result.version ? ` ${result.version}` : ""}`,
                    rule_id: ruleId,
                    rule_word: ruleWord,
                    rule_name: ruleName,
                    normalized_product: normalizedProduct,
                    normalized_vendor: normalizedVendor,
                    normalized_category: normalizedCategory,
                    normalized_family: normalizedFamily,
                    version: result.version,
                    confidence: 0.9,
                    source: "service_probe",
                });
            }

            if (fingerprintItems.length === 0) {
                fingerprintItems.push({
                    asset_type: "service",
                    asset_key: key,
                    fingerprint_type: "service",
                    fingerprint_key: "service_name",
                    fingerprint_value: result.serviceName || "unknown",
                    rule_id: ruleId,
                    rule_word: ruleWord,
                    rule_name: ruleName,
                    normalized_product: normalizedProduct,
                    normalized_vendor: normalizedVendor,
                    normalized_category: normalizedCategory,
                    normalized_family: normalizedFamily,
                    version: result.version,
                    confidence: 0.86,
                    source: "service_probe",
                });
            }

            return fingerprintItems;
        });

        const evidences = results.map((result) => ({
            asset_type: "service",
            asset_key: serviceArtifactKey(result.host, result.port),
            evidence_type: "service_probe_snapshot",
            title: `Service Probe Snapshot: ${result.target}`,
            content_text: result.available
                ? `${result.serviceName || "unknown"} ${result.productName || ""} ${result.version || ""}`.trim()
                : (result.error || "Service unreachable"),
            content_json: {
                ...result,
                probe_engine: probeEngine.used,
                probe_engine_requested: probeEngine.requested,
                probe_engine_experimental: probeEngine.experimental,
                probe_engine_fallback_reason: probeEngine.fallbackReason,
            },
            source: "service_probe",
        }));

        const relations = successfulResults.map((result) => ({
            from_type: isIpLiteral(result.host) ? "ip" : "domain",
            from_key: result.host,
            to_type: "service",
            to_key: serviceArtifactKey(result.host, result.port),
            relation_type: "exposes_service",
            source: "service_probe",
            confidence: 0.92,
        }));


        return {
            success: true,
            data: {
                results,
                snapshots,
                summary: {
                    totalTargets: results.length,
                    successfulChecks,
                    failedChecks,
                    reachableServices,
                    unreachableServices,
                    identifiedProducts: successfulResults.filter((result) => Boolean(result.productName)).length,
                    matchedFingerprints: fingerprints.length,
                    scannedRules: ruleCount,
                    probeEngineRequested: probeEngine.requested,
                    probeEngineUsed: probeEngine.used,
                    probeEngineExperimental: probeEngine.experimental,
                    probeEngineFallbackReason: probeEngine.fallbackReason,
                },
                surface_artifacts: {
                    services,
                    fingerprints,
                    evidences,
                    relations,
                },
            },
        };
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const stream = createMonitorResultStream(input);
        const writeTarget = createMonitorTargetWriter(input, stream, value => { const parsed = normalizeTarget(value); return parsed ? serviceKey(parsed.host, parsed.port) : ""; });
        const rawTargets = collectRawTargets(input);
        if (rawTargets.length === 0) {
            return {
                success: false,
                error: "Invalid input: service targets are required",
            };
        }

        const normalizedTargets = dedupeTargets(rawTargets
            .map(normalizeTarget)
            .filter((target): target is NonNullable<typeof target> => Boolean(target)));

        if (normalizedTargets.length === 0) {
            return {
                success: false,
                error: "No valid service targets provided",
            };
        }

        const followHttpRedirects = input.followHttpRedirects !== false;
        const readBanner = input.readBanner === true;
        const monitorExecution = input.__monitorExecution;
        const explicitRules = Array.isArray(input.dictionaryEntries) && input.dictionaryEntries.length > 0
            ? await loadRules(input)
            : [];
        const dictionaryId = explicitRules.length ? null : await resolveRuleDictionaryId(input);
        const timestamp = new Date().toISOString();
        const requestedProbeEngine = await resolveServiceProbeEngine(input.serviceProbeEngine);
        const rules = explicitRules.length ? explicitRules : await loadRules({ ...input, dictionaryId: dictionaryId || input.dictionaryId });
        const probeEngine = requestedProbeEngine;
        let ruleCount = rules.length;
        const results: ProbeResult[] = [];
        await runSequentially(normalizedTargets.map((target, index) => async (): Promise<void> => {
            stream.assertHealthy();
            const nativeProbe = await probeServicesWithNativeEngine([target], null, rules, followHttpRedirects, readBanner, requestedProbeEngine.used, monitorExecution);
            if (!nativeProbe || !Array.isArray(nativeProbe.results) || nativeProbe.results.length !== 1) {
                throw new Error(nativeProbe?.error || "Native service probe returned no authoritative endpoint result");
            }
            const result = { ...nativeProbe.results[0], target: serviceKey(nativeProbe.results[0].host, nativeProbe.results[0].port), title: undefined };
            if (result.host !== target.host || result.port !== target.port || result.target !== serviceKey(target.host, target.port)) throw new Error("Native service probe returned an unrelated endpoint");
            ruleCount = nativeProbe.ruleCount ?? rules.length;
            await writeTarget(serviceKey(target.host, target.port), "native-service-endpoint", projectServiceProbeOutput([result], rules, timestamp, probeEngine, ruleCount) as any, { status: result.success ? "ok" : "failed", error: result.error });
            if (!stream.enabled) results[index] = result;
        }));
        return await stream.finish(stream.enabled ? { success: true } : projectServiceProbeOutput(results, rules, timestamp, probeEngine, ruleCount));

    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
