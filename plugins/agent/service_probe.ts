/**
 * Service Probe Tool
 *
 * @plugin service_probe
 * @name Service Probe
 * @version 1.2.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags service, probe, fingerprint, banner, asm
 * @description Identify exposed services from host/port targets with the native Rust service identification engine, normalized fingerprint artifacts, and structured service evidence
 */

import { reportMonitorProgress } from "./monitor_progress.ts";

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
            timeoutMs?: number;
            concurrency?: number;
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
    timeout?: number;
    concurrency?: number;
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
    if (!Sentinel?.Dictionary?.getEntries) return [];
    try {
        const entries = await Sentinel.Dictionary.getEntries(idOrName, 10000);
        return entries
            .filter((item: any) => item && typeof item.word === "string")
            .map((item: any) => ({
                id: typeof item.id === "string" ? item.id : undefined,
                word: item.word,
                category: typeof item.category === "string" ? item.category : null,
                metadata: parseMetadata(item.metadata),
            }));
    } catch {
        return [];
    }
}

async function loadRules(input: ToolInput): Promise<RuleEntry[]> {
    if (Array.isArray(input.dictionaryEntries) && input.dictionaryEntries.length > 0) {
        return input.dictionaryEntries.map((entry) => ({
            ...entry,
            metadata: parseMetadata(entry.metadata),
        }));
    }

    const resolvedDictionaryId = await resolveRuleDictionaryId(input);
    const candidates = [
        input.dictionaryId,
        resolvedDictionaryId,
        "builtin_service_fingerprint_rules",
        "Service Fingerprint Rules",
    ].filter((value, index, array): value is string =>
        typeof value === "string"
        && value.trim().length > 0
        && array.indexOf(value) === index
    );

    for (const candidate of candidates) {
        const rules = await loadDictionaryEntries(candidate);
        if (rules.length > 0) {
            return rules;
        }
    }

    return [];
}

async function resolveRuleDictionaryId(input: ToolInput): Promise<string | null> {
    if (typeof input.dictionaryId === "string" && input.dictionaryId.trim()) {
        return input.dictionaryId.trim();
    }

    try {
        const defaultId = await Sentinel?.Dictionary?.getDefaultId?.("service_probe_rule");
        if (typeof defaultId === "string" && defaultId.trim()) {
            return defaultId.trim();
        }
    } catch {
        // ignore and keep fallback chain below
    }

    try {
        const fallbackId = await Sentinel?.Dictionary?.getDefaultId?.("fingerprint_rule");
        if (typeof fallbackId === "string" && fallbackId.trim()) {
            return fallbackId.trim();
        }
    } catch {
        // ignore and keep fallback chain below
    }

    return "builtin_service_fingerprint_rules";
}

function normalizeTarget(raw: string | PortLikeTarget): { host: string; port: number; protocol: string } | null {
    if (typeof raw === "string") {
        const trimmed = raw.trim();
        if (!trimmed) return null;

        try {
            const normalized = trimmed.includes("://") ? trimmed : `tcp://${trimmed}`;
            const parsed = new URL(normalized);
            const protocol = parsed.protocol.replace(":", "") || "tcp";
            const port = Number(parsed.port || (protocol === "https" ? 443 : protocol === "http" ? 80 : 0));
            if (!parsed.hostname || !port) return null;
            return { host: parsed.hostname, port, protocol };
        } catch {
            const [hostPart, portPart] = trimmed.split(":");
            const port = Number(portPart || 0);
            if (!hostPart || !port) return null;
            return { host: hostPart, port, protocol: "tcp" };
        }
    }

    if (typeof raw.value === "string" && raw.value.trim()) {
        return normalizeTarget(raw.value);
    }

    const host = String(raw.ip_or_host || raw.host || raw.host_key || "").trim();
    const port = Number(raw.port ?? raw.port_number ?? 0);
    const protocol = String(raw.transport_protocol || raw.protocol || "tcp").trim().toLowerCase();
    if (!host || !port) return null;
    return { host, port, protocol };
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
    return `${host}:${port}`;
}

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

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, {
            ...init,
            signal: controller.signal,
        });
    } finally {
        clearTimeout(timeoutId);
    }
}

async function fingerprintHttp(
    host: string,
    port: number,
    timeout: number,
    followHttpRedirects: boolean,
): Promise<Partial<ProbeResult>> {
    const protocol = TLS_PORTS.has(port) ? "https" : "http";
    const url = `${protocol}://${host}:${port}/`;
    const response = await fetchWithTimeout(
        url,
        {
            method: "HEAD",
            redirect: followHttpRedirects ? "follow" : "manual",
        },
        timeout,
    );

    return {
        protocol,
        statusCode: response.status,
    };
}

async function fingerprintTcp(
    host: string,
    port: number,
    timeout: number,
    readBanner: boolean,
): Promise<Partial<ProbeResult>> {
    // @ts-ignore
    const conn = await Deno.connect({ hostname: host, port, transport: "tcp" });
    try {
        const buffer = new Uint8Array(512);
        // @ts-ignore
        conn.setReadDeadline(Date.now() + timeout);

        if (!readBanner) {
            return {};
        }

        const bytesRead = await conn.read(buffer);
        if (!bytesRead || bytesRead <= 0) {
            return {};
        }

        const banner = new TextDecoder().decode(buffer.subarray(0, bytesRead))
            .replace(/[\x00-\x08\x0b-\x1f]/g, " ")
            .trim()
            .slice(0, 240);

        return { banner };
    } finally {
        conn.close();
    }
}

async function runWithConcurrency<T>(tasks: Array<() => Promise<T>>, concurrency: number): Promise<T[]> {
    const results: T[] = [];
    const workers = Array.from({ length: Math.max(1, concurrency) }, async () => {
        while (tasks.length > 0) {
            const task = tasks.shift();
            if (!task) break;
            results.push(await task());
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
    const normalizedRequested = String(requestedEngine || "native").trim().toLowerCase() || "native";
    if (normalizedRequested === "native") {
        return {
            requested: normalizedRequested,
            used: "native",
            experimental: false,
        };
    }

    if (normalizedRequested === "builtin" || normalizedRequested === "pistol") {
        return {
            requested: normalizedRequested,
            used: "native",
            experimental: false,
            fallbackReason: `Legacy service probe engine '${normalizedRequested}' was migrated to native`,
        };
    }

    return {
        requested: normalizedRequested,
        used: "native",
        experimental: false,
        fallbackReason: `Unknown service probe engine: ${normalizedRequested}; using native`,
    };
}

async function probeServicesWithNativeEngine(
    targets: Array<{ host: string; port: number; protocol: string }>,
    dictionaryId: string | null,
    rules: RuleEntry[],
    timeout: number,
    concurrency: number,
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
        return null;
    }

    return await Sentinel.Network.probeServices({
        targets,
        rules,
        dictionaryId: dictionaryId || undefined,
        timeoutMs: timeout,
        concurrency,
        followHttpRedirects,
        readBanner,
        engine,
        monitorProgress: monitorExecution ? {
            task_id: monitorExecution.task_id,
            task_name: monitorExecution.task_name,
            program_id: monitorExecution.program_id,
            execution_mode: monitorExecution.execution_mode,
            started_at: monitorExecution.started_at,
            current_plugin: monitorExecution.current_plugin,
            current_plugin_index: monitorExecution.current_plugin_index,
            completed_steps: monitorExecution.completed_steps,
            total_steps: monitorExecution.total_steps,
            imported_assets: monitorExecution.imported_assets ?? 0,
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
                description: "Structured service fingerprint dictionary ID or name",
            },
            dictionaryEntries: {
                type: "array",
                description: "Structured service fingerprint rule entries injected by workflow",
            },
            timeout: {
                type: "integer",
                default: 5000,
                minimum: 1000,
                maximum: 30000,
            },
            concurrency: {
                type: "integer",
                default: 10,
                minimum: 1,
                maximum: 50,
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

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
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

        const timeout = Math.max(1000, Math.min(input.timeout || 5000, 30000));
        const concurrency = Math.max(1, Math.min(input.concurrency || 10, 50));
        const followHttpRedirects = input.followHttpRedirects !== false;
        const readBanner = input.readBanner === true;
        const monitorExecution = input.__monitorExecution;
        const dictionaryId = await resolveRuleDictionaryId(input);
        const explicitRules = Array.isArray(input.dictionaryEntries) && input.dictionaryEntries.length > 0
            ? await loadRules(input)
            : [];
        const timestamp = new Date().toISOString();
        const requestedProbeEngine = await resolveServiceProbeEngine(input.serviceProbeEngine);
        const nativeProbe = await probeServicesWithNativeEngine(
            normalizedTargets,
            dictionaryId,
            explicitRules,
            timeout,
            concurrency,
            followHttpRedirects,
            readBanner,
            requestedProbeEngine.used,
            monitorExecution,
        ).catch(() => null);
        const probeEngine = nativeProbe
            ? {
                requested: nativeProbe.engineRequested || requestedProbeEngine.requested,
                used: nativeProbe.engineUsed || requestedProbeEngine.used,
                experimental: nativeProbe.engineExperimental ?? requestedProbeEngine.experimental,
                fallbackReason: nativeProbe.fallbackReason || requestedProbeEngine.fallbackReason,
            }
            : requestedProbeEngine;
        const sanitizedResults = (nativeProbe?.results?.length ? nativeProbe.results : []).map((result) => ({
            ...result,
            title: undefined,
        }));
        const rules = sanitizedResults.length > 0
            ? explicitRules
            : await loadRules({
                ...input,
                dictionaryId: dictionaryId || input.dictionaryId,
            });

        let results: ProbeResult[];
        if (sanitizedResults.length > 0) {
            results = sanitizedResults;
        } else {
            const tasks = normalizedTargets.map((target) => async (): Promise<ProbeResult> => {
                const key = serviceKey(target.host, target.port);
                try {
                    let details: Partial<ProbeResult>;
                    if (HTTP_PORTS.has(target.port) || target.protocol === "http" || target.protocol === "https") {
                        details = await fingerprintHttp(target.host, target.port, timeout, followHttpRedirects);
                    } else {
                        details = await fingerprintTcp(target.host, target.port, timeout, readBanner);
                    }

                    const protocol = String(details.protocol || target.protocol || "tcp");
                    const serviceName = inferServiceName(
                        target.port,
                        protocol,
                        details.banner,
                        details.serverHeader,
                    );
                    const productInfo = extractProductInfo(details.banner, details.serverHeader);

                    return {
                        target: key,
                        success: true,
                        available: true,
                        host: target.host,
                        port: target.port,
                        protocol,
                        serviceName,
                        banner: details.banner,
                        serverHeader: details.serverHeader,
                        statusCode: details.statusCode,
                        productName: productInfo.productName,
                        vendor: productInfo.vendor,
                        version: productInfo.version,
                    };
                } catch (error: any) {
                    return {
                        target: key,
                        success: false,
                        available: false,
                        host: target.host,
                        port: target.port,
                        protocol: target.protocol,
                        serviceName: DEFAULT_SERVICE_NAMES[target.port] || target.protocol || "unknown",
                        error: error instanceof Error ? error.message : String(error),
                    };
                }
            });

            results = await runWithConcurrency(tasks, concurrency);
        }

        await reportMonitorProgress(monitorExecution, {
            current: normalizedTargets.length + 1,
            total: normalizedTargets.length + 2,
            phase: "compare",
            message: "Comparing probe results",
        });

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
            snapshots[result.target] = buildServiceSnapshot(result, timestamp);
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
            const key = serviceKey(result.host, result.port);
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
            asset_key: result.target,
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
            to_key: result.target,
            relation_type: "exposes_service",
            source: "service_probe",
            confidence: 0.92,
        }));

        await reportMonitorProgress(monitorExecution, {
            current: normalizedTargets.length + 2,
            total: normalizedTargets.length + 2,
            phase: "build",
            message: "Building service probe results",
        });

        return {
            success: true,
            data: {
                results,
                snapshots,
                summary: {
                    totalTargets: normalizedTargets.length,
                    successfulChecks,
                    failedChecks,
                    reachableServices,
                    unreachableServices,
                    identifiedProducts: successfulResults.filter((result) => Boolean(result.productName)).length,
                    matchedFingerprints: fingerprints.length,
                    scannedRules: nativeProbe?.ruleCount ?? rules.length,
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
    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
