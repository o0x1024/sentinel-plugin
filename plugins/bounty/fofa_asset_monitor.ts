/**
 * FOFA Asset Monitor
 *
 * @plugin fofa_asset_monitor
 * @name FOFA Asset Monitor
 * @version 1.0.0
 * @author Sentinel Team
 * @main_category bounty
 * @category monitor
 * @default_severity medium
 * @tags fofa, asset, monitor, reconnaissance, osint, surface, change-detection
 * @description Query FOFA Search API for scoped domains or explicit FOFA syntax, normalize discovered hosts, IPs, services, and web assets, and emit asset change events for monitoring workflows.
 */

interface ToolInput {
    fofaKey: string;
    domains?: string[] | string;
    targets?: string[] | string;
    target_objects?: MonitorTargetObject[];
    targetObjects?: MonitorTargetObject[];
    queries?: string[] | string;
    fields?: string[] | string;
    pageSize?: number;
    maxPages?: number;
    full?: boolean;
    timeout?: number;
    fofaBaseUrl?: string;
    previousSnapshots?: Record<string, FofaQuerySnapshot>;
    includeRemovedAssets?: boolean;
    __monitorExecution?: MonitorExecutionContext;
}

interface MonitorTargetObject {
    type?: string;
    value?: string;
    source?: string;
    host?: string;
    port?: number | string;
    protocol?: string;
    service_name?: string;
    asset_id?: string;
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

interface FofaApiResponse {
    error?: boolean;
    errmsg?: string;
    consumed_fpoint?: number;
    required_fpoints?: number;
    size?: number;
    page?: number;
    mode?: string;
    query?: string;
    results?: string[][];
}

interface FofaAsset {
    assetKey: string;
    host: string;
    ip: string;
    port: number | null;
    protocol: string;
    title: string;
    domain: string;
    countryName: string;
    region: string;
    city: string;
    server: string;
    product: string;
    productCategory: string;
    version: string;
    cname: string;
    lastUpdateTime: string;
    url: string | null;
    hostname: string;
    raw: Record<string, string>;
}

interface FofaQueryPlan {
    id: string;
    query: string;
    source: "domain" | "ip" | "service" | "web" | "explicit";
    target: string;
}

interface FofaQueryResult {
    id: string;
    query: string;
    source: string;
    target: string;
    success: boolean;
    totalReported: number;
    pagesFetched: number;
    assets: FofaAsset[];
    error?: string;
}

interface FofaQuerySnapshot {
    id: string;
    query: string;
    assetKeys: string[];
    totalReported: number;
    lastChecked: string;
}

interface ChangeEvent {
    id: string;
    assetId: string;
    eventType: string;
    severity: "low" | "medium" | "high" | "critical";
    title: string;
    description: string;
    oldValue?: string;
    newValue?: string;
    detectionMethod: string;
    tags: string[];
    autoTriggerEnabled: boolean;
    riskScore: number;
    metadata: Record<string, any>;
}

interface ToolOutput {
    success: boolean;
    data?: {
        queries: FofaQueryPlan[];
        results: FofaQueryResult[];
        subdomains: string[];
        urls: string[];
        ips: string[];
        assets: Array<{ type: string; value: string; metadata: Record<string, any> }>;
        changeEvents: ChangeEvent[];
        snapshots: Record<string, FofaQuerySnapshot>;
        summary: {
            totalQueries: number;
            successfulQueries: number;
            failedQueries: number;
            totalReported: number;
            totalAssets: number;
            uniqueHosts: number;
            uniqueIps: number;
            uniqueUrls: number;
            assetChanges: number;
        };
        surface_artifacts: Record<string, any[]>;
    };
    error?: string;
}

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

type FetchInitWithTimeout = RequestInit & { timeout?: number };

const pluginGlobals = globalThis as PluginGlobals;

const PLUGIN_ID = "fofa_asset_monitor";
const DEFAULT_BASE_URL = "https://fofa.info";
const DEFAULT_TIMEOUT = 5000;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 5;
const MAX_PAGE_SIZE = 10000;
const DEFAULT_FIELDS = [
    "host",
    "ip",
    "port",
    "protocol",
    "title",
    "domain",
    "lastupdatetime",
    "country_name",
    "region",
    "city",
    "server",
    "product",
    "product_category",
    "version",
    "cname",
];

export function get_input_schema() {
    return {
        type: "object",
        required: ["fofaKey"],
        properties: {
            fofaKey: {
                type: "string",
                description: "FOFA API key used with /api/v1/search/all",
            },
            domains: {
                type: "array",
                items: { type: "string" },
                description: "Root domains or scoped domains. Monitor tasks inject this automatically.",
                default: [],
            },
            queries: {
                type: "array",
                items: { type: "string" },
                description: "Explicit FOFA query syntax. Example: domain=\"example.com\" && protocol=\"https\"",
                default: [],
            },
            fields: {
                type: "array",
                items: { type: "string" },
                description: "FOFA result fields in response order",
                default: DEFAULT_FIELDS,
            },
            pageSize: {
                type: "integer",
                description: "FOFA result page size",
                default: DEFAULT_PAGE_SIZE,
                minimum: 1,
                maximum: MAX_PAGE_SIZE,
            },
            maxPages: {
                type: "integer",
                description: "Maximum FOFA pages to fetch per query",
                default: DEFAULT_MAX_PAGES,
                minimum: 1,
                maximum: 100,
            },
            full: {
                type: "boolean",
                description: "Request FOFA full-history search instead of the default recent-data window",
                default: false,
            },
            timeout: {
                type: "integer",
                description: "HTTP request timeout in milliseconds",
                default: DEFAULT_TIMEOUT,
                minimum: 5000,
                maximum: 120000,
            },
            fofaBaseUrl: {
                type: "string",
                description: "FOFA API base URL",
                default: DEFAULT_BASE_URL,
            },
            includeRemovedAssets: {
                type: "boolean",
                description: "Emit change events for assets no longer returned by FOFA",
                default: true,
            },
            previousSnapshots: {
                type: "object",
                description: "Previous FOFA snapshots keyed by query id",
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
                    queries: { type: "array" },
                    results: { type: "array" },
                    subdomains: { type: "array", items: { type: "string" } },
                    urls: { type: "array", items: { type: "string" } },
                    ips: { type: "array", items: { type: "string" } },
                    assets: { type: "array" },
                    changeEvents: { type: "array" },
                    snapshots: { type: "object" },
                    summary: { type: "object" },
                    surface_artifacts: { type: "object" },
                },
            },
            error: { type: "string" },
        },
    };
}

pluginGlobals.get_output_schema = get_output_schema;

async function reportMonitorProgress(
    monitorExecution: MonitorExecutionContext | undefined,
    update: Record<string, unknown>,
): Promise<boolean> {
    if (!monitorExecution) return false;
    const sentinel = (globalThis as any).Sentinel;
    try {
        return Boolean(await sentinel?.Monitor?.reportProgress?.({
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

function normalizeStringList(value: unknown): string[] {
    if (Array.isArray(value)) {
        return value.map(item => String(item || "").trim()).filter(Boolean);
    }
    if (typeof value === "string") {
        return value
            .split(/[,\n]/)
            .map(item => item.trim())
            .filter(Boolean);
    }
    return [];
}

function normalizeFields(value: unknown): string[] {
    const fields = normalizeStringList(value);
    return fields.length > 0 ? fields : DEFAULT_FIELDS;
}

function clampInteger(value: unknown, fallback: number, min: number, max: number): number {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function normalizeBaseUrl(value: unknown): string {
    const baseUrl = String(value || DEFAULT_BASE_URL).trim().replace(/\/+$/, "");
    if (!/^https?:\/\//i.test(baseUrl)) {
        throw new Error("fofaBaseUrl must start with http:// or https://");
    }
    return baseUrl;
}

function normalizeTargetValue(value: string): string {
    let normalized = value.trim();
    normalized = normalized.replace(/^https?:\/\//i, "");
    normalized = normalized.replace(/^wss?:\/\//i, "");
    normalized = normalized.split("/")[0] || normalized;
    normalized = normalized.replace(/^\*\./, "");
    normalized = normalized.replace(/^\./, "");
    return normalized.trim().toLowerCase();
}

function extractHost(value: string): string {
    const trimmed = value.trim();
    if (!trimmed) return "";
    try {
        const parsed = new URL(trimmed);
        return parsed.hostname.toLowerCase();
    } catch {
        return normalizeTargetValue(trimmed).split(":")[0] || "";
    }
}

function extractPort(value: string): number | null {
    const trimmed = value.trim();
    try {
        const parsed = new URL(trimmed);
        if (parsed.port) return Number(parsed.port);
        if (parsed.protocol === "https:") return 443;
        if (parsed.protocol === "http:") return 80;
    } catch {
        const withoutPath = trimmed.replace(/^https?:\/\//i, "").split("/")[0] || "";
        const parts = withoutPath.split(":");
        if (parts.length > 1) {
            const parsed = Number(parts[parts.length - 1]);
            return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
        }
    }
    return null;
}

function isIpLiteral(value: string): boolean {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(":");
}

function guessRootDomain(hostname: string): string {
    const parts = hostname.toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    return parts.slice(-2).join(".");
}

function stableHash(value: string): string {
    let hash = 2166136261;
    for (let index = 0; index < value.length; index++) {
        hash ^= value.charCodeAt(index);
        hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
}

function generateId(): string {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (char) => {
        const random = Math.random() * 16 | 0;
        const value = char === "x" ? random : (random & 0x3 | 0x8);
        return value.toString(16);
    });
}

function encodeBase64Utf8(value: string): string {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

function buildQueryPlans(input: ToolInput): FofaQueryPlan[] {
    const plans = new Map<string, FofaQueryPlan>();
    const explicitQueries = normalizeStringList(input.queries);

    for (const query of explicitQueries) {
        const normalized = query.trim();
        const id = `query-${stableHash(normalized)}`;
        plans.set(id, { id, query: normalized, source: "explicit", target: normalized });
    }

    const targetObjects = Array.isArray(input.target_objects)
        ? input.target_objects
        : Array.isArray(input.targetObjects)
          ? input.targetObjects
          : [];

    for (const targetObject of targetObjects) {
        const type = String(targetObject.type || "").toLowerCase();
        const rawValue = String(targetObject.value || targetObject.host || "").trim();
        if (!rawValue) continue;

        if (type === "ip") {
            const ip = normalizeTargetValue(rawValue);
            const query = `ip="${ip}"`;
            plans.set(`ip-${stableHash(query)}`, { id: `ip-${stableHash(query)}`, query, source: "ip", target: ip });
            continue;
        }

        if (type === "service") {
            const host = normalizeTargetValue(String(targetObject.host || rawValue));
            const port = Number(targetObject.port || extractPort(rawValue));
            if (host && Number.isInteger(port) && port > 0) {
                const field = isIpLiteral(host) ? "ip" : "host";
                const query = `${field}="${host}" && port="${port}"`;
                plans.set(`service-${stableHash(query)}`, { id: `service-${stableHash(query)}`, query, source: "service", target: `${host}:${port}` });
            }
            continue;
        }

        if (type === "web") {
            const host = extractHost(rawValue);
            if (host) {
                const query = `host="${host}"`;
                plans.set(`web-${stableHash(query)}`, { id: `web-${stableHash(query)}`, query, source: "web", target: host });
            }
            continue;
        }

        const domain = normalizeTargetValue(rawValue);
        if (domain && !isIpLiteral(domain)) {
            const query = `domain="${domain}"`;
            plans.set(`domain-${stableHash(query)}`, { id: `domain-${stableHash(query)}`, query, source: "domain", target: domain });
        }
    }

    const domains = [...normalizeStringList(input.domains), ...normalizeStringList(input.targets)];
    for (const value of domains) {
        const target = normalizeTargetValue(value);
        if (!target) continue;
        const query = isIpLiteral(target) ? `ip="${target}"` : `domain="${target}"`;
        const source = isIpLiteral(target) ? "ip" : "domain";
        const id = `${source}-${stableHash(query)}`;
        plans.set(id, { id, query, source, target });
    }

    return Array.from(plans.values());
}

async function fetchJson(url: string, timeoutMs: number): Promise<FofaApiResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const init: FetchInitWithTimeout = {
            method: "GET",
            signal: controller.signal,
            headers: { accept: "application/json" },
            timeout: timeoutMs,
        };
        const response = await fetch(url, init);
        const text = await response.text();
        let payload: any;
        try {
            payload = JSON.parse(text);
        } catch {
            throw new Error(`FOFA returned non-JSON response with HTTP ${response.status}`);
        }
        if (!response.ok) {
            throw new Error(payload?.errmsg || `FOFA HTTP ${response.status}`);
        }
        return payload as FofaApiResponse;
    } finally {
        clearTimeout(timeoutId);
    }
}

async function searchFofa(
    plan: FofaQueryPlan,
    fofaKey: string,
    baseUrl: string,
    fields: string[],
    pageSize: number,
    maxPages: number,
    full: boolean,
    timeoutMs: number,
): Promise<FofaQueryResult> {
    const assets = new Map<string, FofaAsset>();
    let totalReported = 0;
    let pagesFetched = 0;

    for (let page = 1; page <= maxPages; page++) {
        const params = new URLSearchParams();
        params.set("key", fofaKey);
        params.set("qbase64", encodeBase64Utf8(plan.query));
        params.set("fields", fields.join(","));
        params.set("page", String(page));
        params.set("size", String(pageSize));
        params.set("full", full ? "true" : "false");
        params.set("r_type", "json");

        const payload = await fetchJson(`${baseUrl}/api/v1/search/all?${params.toString()}`, timeoutMs);
        if (payload.error) {
            throw new Error(payload.errmsg || "FOFA API returned error=true");
        }

        const rows = Array.isArray(payload.results) ? payload.results : [];
        totalReported = Number(payload.size || totalReported || rows.length);
        pagesFetched = page;

        for (const row of rows) {
            const asset = parseFofaRow(row, fields);
            if (asset.assetKey) {
                assets.set(asset.assetKey, asset);
            }
        }

        if (rows.length < pageSize) break;
    }

    return {
        id: plan.id,
        query: plan.query,
        source: plan.source,
        target: plan.target,
        success: true,
        totalReported,
        pagesFetched,
        assets: Array.from(assets.values()),
    };
}

function parseFofaRow(row: string[], fields: string[]): FofaAsset {
    const raw: Record<string, string> = {};
    fields.forEach((field, index) => {
        raw[field] = row[index] === undefined || row[index] === null ? "" : String(row[index]);
    });

    const host = raw.host || raw.link || "";
    const ip = raw.ip || "";
    const portValue = Number(raw.port || 0);
    const port = Number.isInteger(portValue) && portValue > 0 ? portValue : extractPort(host);
    const protocol = (raw.protocol || raw.base_protocol || "").toLowerCase();
    const hostname = extractHost(host || raw.domain || ip);
    const url = buildWebUrl(host, protocol, port);
    const assetKey = buildAssetKey(host, ip, port, protocol);

    return {
        assetKey,
        host,
        ip,
        port,
        protocol,
        title: raw.title || "",
        domain: raw.domain || "",
        countryName: raw.country_name || raw.country || "",
        region: raw.region || raw.province || "",
        city: raw.city || "",
        server: raw.server || "",
        product: raw.product || "",
        productCategory: raw.product_category || raw.category || "",
        version: raw.version || "",
        cname: raw.cname || "",
        lastUpdateTime: raw.lastupdatetime || "",
        url,
        hostname,
        raw,
    };
}

function buildAssetKey(host: string, ip: string, port: number | null, protocol: string): string {
    const hostPart = host.trim().toLowerCase() || ip.trim().toLowerCase();
    const portPart = port ? `:${port}` : "";
    const protocolPart = protocol ? `/${protocol}` : "";
    return `${hostPart}${portPart}${protocolPart}`;
}

function buildWebUrl(host: string, protocol: string, port: number | null): string | null {
    const trimmed = host.trim();
    if (!trimmed) return null;
    if (/^https?:\/\//i.test(trimmed)) return trimmed;

    const webProtocol = protocol === "https" || port === 443
        ? "https"
        : protocol === "http" || port === 80
          ? "http"
          : "";
    if (!webProtocol) return null;

    return `${webProtocol}://${trimmed}`;
}

function createChangeEvent(
    plan: FofaQueryPlan,
    eventType: "asset_discovered" | "asset_removed",
    assetKeys: string[],
    timestamp: string,
): ChangeEvent {
    const discovered = eventType === "asset_discovered";
    return {
        id: generateId(),
        assetId: plan.target || plan.id,
        eventType,
        severity: discovered ? "medium" : "low",
        title: discovered
            ? `FOFA discovered ${assetKeys.length} new asset(s) for ${plan.target}`
            : `FOFA no longer returns ${assetKeys.length} asset(s) for ${plan.target}`,
        description: discovered
            ? `FOFA query ${plan.query} returned new assets: ${assetKeys.slice(0, 10).join(", ")}`
            : `FOFA query ${plan.query} stopped returning assets: ${assetKeys.slice(0, 10).join(", ")}`,
        newValue: discovered ? assetKeys.join("\n") : undefined,
        oldValue: discovered ? undefined : assetKeys.join("\n"),
        detectionMethod: PLUGIN_ID,
        tags: ["fofa", "asset-monitor", eventType],
        autoTriggerEnabled: discovered,
        riskScore: discovered ? 45 : 15,
        metadata: {
            queryId: plan.id,
            query: plan.query,
            source: plan.source,
            target: plan.target,
            count: assetKeys.length,
            detectedAt: timestamp,
        },
    };
}

function buildArtifacts(allAssets: FofaAsset[], changeEvents: ChangeEvent[]) {
    const domains = new Map<string, any>();
    const ips = new Map<string, any>();
    const services = new Map<string, any>();
    const webs = new Map<string, any>();
    const evidences: any[] = [];
    const relations = new Map<string, any>();

    for (const asset of allAssets) {
        if (asset.hostname && !isIpLiteral(asset.hostname)) {
            domains.set(asset.hostname, {
                fqdn: asset.hostname,
                root_domain: guessRootDomain(asset.hostname),
                main_domain: guessRootDomain(asset.hostname),
                source: PLUGIN_ID,
                confidence: 0.9,
                metadata: {
                    fofa_domain: asset.domain,
                    cname: asset.cname,
                    lastupdatetime: asset.lastUpdateTime,
                },
            });
        }

        if (asset.domain && !isIpLiteral(asset.domain)) {
            domains.set(asset.domain, {
                fqdn: asset.domain,
                root_domain: guessRootDomain(asset.domain),
                main_domain: guessRootDomain(asset.domain),
                source: PLUGIN_ID,
                confidence: 0.85,
            });
        }

        if (asset.ip) {
            ips.set(asset.ip, {
                ip_address: asset.ip,
                ip_version: asset.ip.includes(":") ? "IPv6" : "IPv4",
                country: asset.countryName,
                region: asset.region,
                city: asset.city,
                source: PLUGIN_ID,
                confidence: 0.9,
            });
        }

        if (asset.ip && asset.port) {
            const serviceKey = `${asset.ip}:${asset.port}/${asset.protocol || "tcp"}`;
            services.set(serviceKey, {
                host: asset.hostname || asset.ip,
                ip_address: asset.ip,
                port_number: asset.port,
                protocol_name: asset.protocol || "tcp",
                service_name: asset.protocol || asset.product || "",
                service_product: asset.product,
                service_version: asset.version,
                banner: asset.server,
                source: PLUGIN_ID,
                confidence: 0.82,
                last_seen_at: asset.lastUpdateTime,
                metadata: asset.raw,
            });
            relations.set(`${asset.ip}->${serviceKey}`, {
                from_type: "ip",
                from_key: asset.ip,
                to_type: "service",
                to_key: serviceKey,
                relation_type: "exposes_service",
                source: PLUGIN_ID,
                confidence: 0.82,
            });
        }

        if (asset.url) {
            const parsed = new URL(asset.url);
            webs.set(asset.url, {
                canonical_url: asset.url,
                scheme: parsed.protocol.replace(":", ""),
                site_title: asset.title || null,
                http_status_code: 0,
                server_header: asset.server || null,
                response_headers: {},
                page_fingerprint: asset.product || null,
                favicon_hash: null,
                framework: asset.productCategory || null,
                cms: null,
                waf_flag: null,
                cdn_flag: null,
                login_flag: null,
                api_flag: null,
                openapi_url: null,
                business_type: null,
                language: null,
                filing_info: null,
                content_summary: [asset.title, asset.product, asset.version].filter(Boolean).join(" / "),
                last_accessed_at: asset.lastUpdateTime || null,
            });

            if (asset.hostname && !isIpLiteral(asset.hostname)) {
                relations.set(`${asset.hostname}->${asset.url}`, {
                    from_type: "domain",
                    from_key: asset.hostname,
                    to_type: "web",
                    to_key: asset.url,
                    relation_type: "hosts_web",
                    source: PLUGIN_ID,
                    confidence: 0.85,
                });
            }
        }

        if (asset.hostname && asset.ip && !isIpLiteral(asset.hostname)) {
            relations.set(`${asset.hostname}->${asset.ip}`, {
                from_type: "domain",
                from_key: asset.hostname,
                to_type: "ip",
                to_key: asset.ip,
                relation_type: "resolves_to",
                source: PLUGIN_ID,
                confidence: 0.75,
            });
        }

        evidences.push({
            asset_type: asset.url ? "web" : asset.ip ? "service" : "domain",
            asset_key: asset.url || asset.assetKey,
            evidence_type: "fofa_search_result",
            title: `FOFA asset: ${asset.host || asset.ip}`,
            content_json: asset.raw,
            source: PLUGIN_ID,
        });
    }

    return {
        domains: Array.from(domains.values()),
        ips: Array.from(ips.values()),
        services: Array.from(services.values()),
        webs: Array.from(webs.values()),
        changes: changeEvents.map(event => ({
            asset_key: event.assetId,
            asset_type: "domain",
            change_type: event.eventType,
            severity: event.severity,
            title: event.title,
            description: event.description,
            old_value: event.oldValue,
            new_value: event.newValue,
            risk_score: event.riskScore,
            source: PLUGIN_ID,
            metadata: event.metadata,
        })),
        evidences,
        relations: Array.from(relations.values()),
    };
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const fofaKey = String(input.fofaKey || "").trim();
        if (!fofaKey) {
            throw new Error("fofaKey is required");
        }

        const plans = buildQueryPlans(input);
        if (plans.length === 0) {
            throw new Error("At least one domain, target, target_object, or explicit FOFA query is required");
        }

        const fields = normalizeFields(input.fields);
        const pageSize = clampInteger(input.pageSize, DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE);
        const maxPages = clampInteger(input.maxPages, DEFAULT_MAX_PAGES, 1, 100);
        const timeoutMs = clampInteger(input.timeout, DEFAULT_TIMEOUT, 5000, 120000);
        const baseUrl = normalizeBaseUrl(input.fofaBaseUrl);
        const full = input.full === true;
        const includeRemovedAssets = input.includeRemovedAssets !== false;
        const previousSnapshots = input.previousSnapshots || {};
        const timestamp = new Date().toISOString();

        await reportMonitorProgress(input.__monitorExecution, {
            current: 0,
            total: plans.length,
            phase: "query",
            message: `Querying FOFA for ${plans.length} target set(s)`,
        });

        const results: FofaQueryResult[] = [];
        for (let index = 0; index < plans.length; index++) {
            const plan = plans[index];
            await reportMonitorProgress(input.__monitorExecution, {
                current: index,
                total: plans.length,
                currentTarget: plan.target,
                phase: "query",
                message: `Querying FOFA: ${plan.target}`,
            });

            try {
                results.push(await searchFofa(plan, fofaKey, baseUrl, fields, pageSize, maxPages, full, timeoutMs));
            } catch (error) {
                results.push({
                    id: plan.id,
                    query: plan.query,
                    source: plan.source,
                    target: plan.target,
                    success: false,
                    totalReported: 0,
                    pagesFetched: 0,
                    assets: [],
                    error: error instanceof Error ? error.message : String(error),
                });
            }
        }

        await reportMonitorProgress(input.__monitorExecution, {
            current: plans.length,
            total: plans.length,
            phase: "build",
            message: "Building FOFA asset artifacts",
        });

        const changeEvents: ChangeEvent[] = [];
        const snapshots: Record<string, FofaQuerySnapshot> = {};
        const allAssetsMap = new Map<string, FofaAsset>();

        for (const result of results) {
            if (!result.success) continue;
            const plan = plans.find(item => item.id === result.id);
            if (!plan) continue;

            for (const asset of result.assets) {
                allAssetsMap.set(asset.assetKey, asset);
            }

            const currentKeys = result.assets.map(asset => asset.assetKey).sort();
            snapshots[result.id] = {
                id: result.id,
                query: result.query,
                assetKeys: currentKeys,
                totalReported: result.totalReported,
                lastChecked: timestamp,
            };

            const previous = previousSnapshots[result.id];
            if (!previous) {
                if (currentKeys.length > 0) {
                    changeEvents.push(createChangeEvent(plan, "asset_discovered", currentKeys, timestamp));
                }
                continue;
            }

            const previousKeys = new Set(previous.assetKeys || []);
            const currentKeySet = new Set(currentKeys);
            const added = currentKeys.filter(key => !previousKeys.has(key));
            const removed = (previous.assetKeys || []).filter(key => !currentKeySet.has(key));
            if (added.length > 0) {
                changeEvents.push(createChangeEvent(plan, "asset_discovered", added, timestamp));
            }
            if (includeRemovedAssets && removed.length > 0) {
                changeEvents.push(createChangeEvent(plan, "asset_removed", removed, timestamp));
            }
        }

        const allAssets = Array.from(allAssetsMap.values());
        const subdomains = Array.from(new Set(
            allAssets
                .map(asset => asset.hostname || asset.domain)
                .filter(host => host && !isIpLiteral(host))
        )).sort();
        const urls = Array.from(new Set(allAssets.map(asset => asset.url).filter((url): url is string => Boolean(url)))).sort();
        const ips = Array.from(new Set(allAssets.map(asset => asset.ip).filter(Boolean))).sort();
        const standardAssets = [
            ...subdomains.map(value => ({ type: "domain", value, metadata: { source: PLUGIN_ID } })),
            ...urls.map(value => ({ type: "url", value, metadata: { source: PLUGIN_ID } })),
            ...ips.map(value => ({ type: "ip", value, metadata: { source: PLUGIN_ID } })),
            ...allAssets
                .filter(asset => asset.ip && asset.port)
                .map(asset => ({
                    type: "service",
                    value: `${asset.ip}:${asset.port}`,
                    metadata: {
                        source: PLUGIN_ID,
                        host: asset.host,
                        protocol: asset.protocol,
                        product: asset.product,
                        version: asset.version,
                    },
                })),
        ];

        const surfaceArtifacts = buildArtifacts(allAssets, changeEvents);
        const successfulQueries = results.filter(result => result.success).length;

        return {
            success: true,
            data: {
                queries: plans,
                results,
                subdomains,
                urls,
                ips,
                assets: standardAssets,
                changeEvents,
                snapshots,
                summary: {
                    totalQueries: plans.length,
                    successfulQueries,
                    failedQueries: plans.length - successfulQueries,
                    totalReported: results.reduce((sum, result) => sum + result.totalReported, 0),
                    totalAssets: allAssets.length,
                    uniqueHosts: subdomains.length,
                    uniqueIps: ips.length,
                    uniqueUrls: urls.length,
                    assetChanges: changeEvents.length,
                },
                surface_artifacts: surfaceArtifacts,
            },
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
