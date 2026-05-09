/**
 * FOFA Asset Monitor
 *
 * @plugin fofa_asset_monitor
 * @name FOFA Asset Monitor
 * @version 1.2.0
 * @author Sentinel Team
 * @main_category bounty
 * @category monitor
 * @default_severity medium
 * @tags fofa, asset, monitor, reconnaissance, osint, surface, change-detection
 * @description Query FOFA Search API with domain and enterprise website fingerprints such as icon hash, org, ASN, CNAME, title, body, and header clues, then emit website-only monitoring artifacts.
 */

interface ToolInput {
    fofaKey: string;
    domains?: string[] | string;
    targets?: string[] | string;
    target_objects?: MonitorTargetObject[];
    targetObjects?: MonitorTargetObject[];
    queries?: string[] | string;
    iconHashes?: string[] | string;
    brandKeywords?: string[] | string;
    orgNames?: string[] | string;
    asnList?: Array<string | number> | string;
    cnameKeywords?: string[] | string;
    titleKeywords?: string[] | string;
    bodyKeywords?: string[] | string;
    headerKeywords?: string[] | string;
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
    results?: Array<string[] | Record<string, unknown>>;
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
    source: "domain" | "ip" | "service" | "web" | "explicit" | "icon" | "org" | "asn" | "cname" | "title" | "body" | "header";
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
            iconHashes: {
                type: "array",
                items: { type: "string" },
                description: "Website favicon hash values used with FOFA icon_hash syntax.",
                default: [],
            },
            brandKeywords: {
                type: "array",
                items: { type: "string" },
                description: "Enterprise brand keywords used to anchor icon/org/asn/cname queries through title/body matching.",
                default: [],
            },
            orgNames: {
                type: "array",
                items: { type: "string" },
                description: "Enterprise organization names for FOFA org queries.",
                default: [],
            },
            asnList: {
                type: "array",
                items: {
                    anyOf: [
                        { type: "integer" },
                        { type: "string" },
                    ],
                },
                description: "Owned ASN values for enterprise web infrastructure.",
                default: [],
            },
            cnameKeywords: {
                type: "array",
                items: { type: "string" },
                description: "CNAME keywords or full CNAME values for website infrastructure.",
                default: [],
            },
            titleKeywords: {
                type: "array",
                items: { type: "string" },
                description: "Website title keywords for direct FOFA title queries.",
                default: [],
            },
            bodyKeywords: {
                type: "array",
                items: { type: "string" },
                description: "HTML body keywords for enterprise website matching.",
                default: [],
            },
            headerKeywords: {
                type: "array",
                items: { type: "string" },
                description: "HTTP header keywords for reverse proxy, CDN, or enterprise gateway matching.",
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

function uniqueStrings(values: string[]): string[] {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const value of values) {
        const normalized = String(value || "").trim();
        if (!normalized || seen.has(normalized)) continue;
        seen.add(normalized);
        result.push(normalized);
    }
    return result;
}

function normalizeAsnList(value: unknown): string[] {
    if (Array.isArray(value)) {
        return uniqueStrings(
            value
                .map(item => String(item ?? "").trim())
                .filter(item => /^\d+$/.test(item)),
        );
    }

    if (typeof value === "string") {
        return uniqueStrings(
            value
                .split(/[,\n]/)
                .map(item => item.trim())
                .filter(item => /^\d+$/.test(item)),
        );
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
    if (/^(https?|wss?):\/\//i.test(trimmed)) {
        try {
            const parsed = new URL(trimmed);
            return parsed.hostname.toLowerCase();
        } catch {
            return "";
        }
    }
    return normalizeTargetValue(trimmed).split(":")[0] || "";
}

function extractPort(value: string): number | null {
    const trimmed = value.trim();
    if (/^(https?|wss?):\/\//i.test(trimmed)) {
        try {
            const parsed = new URL(trimmed);
            if (parsed.port) return Number(parsed.port);
            if (parsed.protocol === "https:") return 443;
            if (parsed.protocol === "http:") return 80;
        } catch {
            return null;
        }
    }

    const withoutPath = trimmed.replace(/^https?:\/\//i, "").split("/")[0] || "";
    const parts = withoutPath.split(":");
    if (parts.length > 1) {
        const parsed = Number(parts[parts.length - 1]);
        return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
    }
    return null;
}

function isIpLiteral(value: string): boolean {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || (/^[0-9a-f:]+$/i.test(value) && value.includes(":"));
}

function guessRootDomain(hostname: string): string {
    const parts = hostname.toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    return parts.slice(-2).join(".");
}

function computeSubdomainLevel(hostname: string): number {
    const parts = hostname.toLowerCase().split(".").filter(Boolean);
    return Math.max(0, parts.length - 2);
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

function escapeQueryValue(value: string): string {
    return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').trim();
}

function addPlan(
    plans: Map<string, FofaQueryPlan>,
    source: FofaQueryPlan["source"],
    target: string,
    query: string,
) {
    const normalizedQuery = query.trim();
    if (!normalizedQuery) return;
    const id = `${source}-${stableHash(normalizedQuery)}`;
    plans.set(id, { id, query: normalizedQuery, source, target: target.trim() || normalizedQuery });
}

function addFieldQueryPlan(
    plans: Map<string, FofaQueryPlan>,
    source: Extract<FofaQueryPlan["source"], "icon" | "org" | "asn" | "cname" | "title" | "body" | "header">,
    field: string,
    value: string,
) {
    const normalized = escapeQueryValue(value);
    if (!normalized) return;
    addPlan(plans, source, normalized, `${field}="${normalized}"`);
}

function addBrandAnchoredFieldQueries(
    plans: Map<string, FofaQueryPlan>,
    source: Extract<FofaQueryPlan["source"], "icon" | "org" | "asn" | "cname">,
    field: string,
    value: string,
    brandKeywords: string[],
) {
    const normalized = escapeQueryValue(value);
    if (!normalized) return;

    if (brandKeywords.length === 0) {
        addPlan(plans, source, normalized, `${field}="${normalized}"`);
        return;
    }

    for (const brandKeyword of brandKeywords) {
        const anchor = escapeQueryValue(brandKeyword);
        if (!anchor) continue;
        addPlan(plans, source, `${normalized} + title:${anchor}`, `${field}="${normalized}" && title="${anchor}"`);
        addPlan(plans, source, `${normalized} + body:${anchor}`, `${field}="${normalized}" && body="${anchor}"`);
    }
}

function buildQueryPlans(input: ToolInput): FofaQueryPlan[] {
    const plans = new Map<string, FofaQueryPlan>();
    const explicitQueries = uniqueStrings(normalizeStringList(input.queries));
    const brandKeywords = uniqueStrings(normalizeStringList(input.brandKeywords));
    const iconHashes = uniqueStrings(normalizeStringList(input.iconHashes));
    const orgNames = uniqueStrings(normalizeStringList(input.orgNames));
    const asnList = normalizeAsnList(input.asnList);
    const cnameKeywords = uniqueStrings(normalizeStringList(input.cnameKeywords));
    const titleKeywords = uniqueStrings(normalizeStringList(input.titleKeywords));
    const bodyKeywords = uniqueStrings(normalizeStringList(input.bodyKeywords));
    const headerKeywords = uniqueStrings(normalizeStringList(input.headerKeywords));

    for (const query of explicitQueries) {
        const normalized = query.trim();
        addPlan(plans, "explicit", normalized, normalized);
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
            addPlan(plans, "ip", ip, `ip="${escapeQueryValue(ip)}"`);
            continue;
        }

        if (type === "service") {
            const host = normalizeTargetValue(String(targetObject.host || rawValue));
            const port = Number(targetObject.port || extractPort(rawValue));
            if (host && Number.isInteger(port) && port > 0) {
                const field = isIpLiteral(host) ? "ip" : "host";
                addPlan(
                    plans,
                    "service",
                    `${host}:${port}`,
                    `${field}="${escapeQueryValue(host)}" && port="${port}"`,
                );
            }
            continue;
        }

        if (type === "web") {
            const host = extractHost(rawValue);
            if (host) {
                addPlan(plans, "web", host, `host="${escapeQueryValue(host)}"`);
            }
            continue;
        }

        if (type === "icon" || type === "icon_hash") {
            addBrandAnchoredFieldQueries(plans, "icon", "icon_hash", rawValue, brandKeywords);
            continue;
        }

        if (type === "org") {
            addBrandAnchoredFieldQueries(plans, "org", "org", rawValue, brandKeywords);
            continue;
        }

        if (type === "asn") {
            addBrandAnchoredFieldQueries(plans, "asn", "asn", rawValue, brandKeywords);
            continue;
        }

        if (type === "cname") {
            addBrandAnchoredFieldQueries(plans, "cname", "cname", rawValue, brandKeywords);
            continue;
        }

        if (type === "title") {
            addFieldQueryPlan(plans, "title", "title", rawValue);
            continue;
        }

        if (type === "body") {
            addFieldQueryPlan(plans, "body", "body", rawValue);
            continue;
        }

        if (type === "header") {
            addFieldQueryPlan(plans, "header", "header", rawValue);
            continue;
        }

        const domain = normalizeTargetValue(rawValue);
        if (domain && !isIpLiteral(domain)) {
            addPlan(plans, "domain", domain, `domain="${escapeQueryValue(domain)}"`);
        }
    }

    const domains = uniqueStrings([...normalizeStringList(input.domains), ...normalizeStringList(input.targets)]);
    for (const value of domains) {
        const target = normalizeTargetValue(value);
        if (!target) continue;
        const escapedTarget = escapeQueryValue(target);
        const query = isIpLiteral(target) ? `ip="${escapedTarget}"` : `domain="${escapedTarget}"`;
        const source = isIpLiteral(target) ? "ip" : "domain";
        addPlan(plans, source, target, query);
    }

    for (const iconHash of iconHashes) {
        addBrandAnchoredFieldQueries(plans, "icon", "icon_hash", iconHash, brandKeywords);
    }

    for (const orgName of orgNames) {
        addBrandAnchoredFieldQueries(plans, "org", "org", orgName, brandKeywords);
    }

    for (const asn of asnList) {
        addBrandAnchoredFieldQueries(plans, "asn", "asn", asn, brandKeywords);
    }

    for (const cnameKeyword of cnameKeywords) {
        addBrandAnchoredFieldQueries(plans, "cname", "cname", cnameKeyword, brandKeywords);
    }

    for (const titleKeyword of titleKeywords) {
        addFieldQueryPlan(plans, "title", "title", titleKeyword);
    }

    for (const bodyKeyword of bodyKeywords) {
        addFieldQueryPlan(plans, "body", "body", bodyKeyword);
    }

    for (const headerKeyword of headerKeywords) {
        addFieldQueryPlan(plans, "header", "header", headerKeyword);
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

function readRowValue(row: string[] | Record<string, unknown>, field: string, index: number): string {
    if (Array.isArray(row)) {
        const value = row[index];
        return value === undefined || value === null ? "" : String(value);
    }

    const record = row as Record<string, unknown>;
    const direct = record[field];
    if (direct !== undefined && direct !== null) {
        return String(direct);
    }

    const aliases: Record<string, string[]> = {
        host: ["url", "link"],
        domain: ["hostname"],
        protocol: ["base_protocol", "scheme"],
        country_name: ["country"],
        region: ["province"],
        product_category: ["category"],
    };

    for (const alias of aliases[field] || []) {
        const aliased = record[alias];
        if (aliased !== undefined && aliased !== null) {
            return String(aliased);
        }
    }

    return "";
}

function parseFofaRow(row: string[] | Record<string, unknown>, fields: string[]): FofaAsset {
    const raw: Record<string, string> = {};
    fields.forEach((field, index) => {
        raw[field] = readRowValue(row, field, index);
    });

    const record = Array.isArray(row) ? null : row as Record<string, unknown>;
    const host = raw.host || raw.link || (record?.url ? String(record.url) : "");
    const ip = raw.ip || (record?.ip ? String(record.ip) : "");
    const portValue = Number(raw.port || 0);
    const objectPort = record?.port === undefined || record?.port === null ? 0 : Number(record.port);
    const port = Number.isInteger(portValue) && portValue > 0
        ? portValue
        : Number.isInteger(objectPort) && objectPort > 0
          ? objectPort
          : extractPort(host);
    const protocol = (raw.protocol || raw.base_protocol || "").toLowerCase();
    const domain = raw.domain || (record?.domain ? String(record.domain) : "");
    const hostname = extractHost(host || domain || ip);
    const canonicalHost = host || domain || hostname || ip;
    const url = buildWebUrl(canonicalHost, protocol, port);
    const assetKey = buildAssetKey(canonicalHost, ip, port, protocol);

    return {
        assetKey,
        host: canonicalHost,
        ip,
        port,
        protocol,
        title: raw.title || "",
        domain,
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

    const resolvedHost = extractHost(trimmed) || trimmed;
    const resolvedPort = port && port > 0 ? port : extractPort(trimmed);
    const needsPort =
        resolvedPort !== null
        && !((webProtocol === "http" && resolvedPort === 80) || (webProtocol === "https" && resolvedPort === 443));
    const hostForUrl =
        isIpLiteral(resolvedHost) && resolvedHost.includes(":")
            ? `[${resolvedHost}]`
            : resolvedHost;

    return `${webProtocol}://${hostForUrl}${needsPort ? `:${resolvedPort}` : ""}`;
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

function buildArtifacts(allAssets: FofaAsset[]) {
    const domains = new Map<string, any>();
    const webs = new Map<string, any>();

    for (const asset of allAssets) {
        const fqdn = asset.hostname && !isIpLiteral(asset.hostname)
            ? asset.hostname
            : asset.domain && !isIpLiteral(asset.domain)
              ? asset.domain
              : "";

        if (fqdn) {
            const rootDomain = guessRootDomain(fqdn);
            domains.set(fqdn, {
                fqdn,
                main_domain: rootDomain,
                root_domain: rootDomain,
                subdomain_level: computeSubdomainLevel(fqdn),
            });
        }

        if (asset.url) {
            const parsed = new URL(asset.url);
            webs.set(asset.url, {
                canonical_url: asset.url,
                url: asset.url,
                scheme: parsed.protocol.replace(":", ""),
                host: asset.host || parsed.host,
                hostname: parsed.hostname || asset.hostname || null,
                ip_address: asset.ip || null,
                port: asset.port,
                site_title: asset.title || null,
                title: asset.title || null,
                http_status_code: 0,
                response_headers: {},
                content_summary: asset.title || parsed.hostname || asset.hostname || asset.host || asset.ip,
                last_accessed_at: asset.lastUpdateTime || null,
                lastUpdateTime: asset.lastUpdateTime || null,
            });
        }
    }

    return {
        domains: Array.from(domains.values()),
        webs: Array.from(webs.values()),
        changes: [],
        evidences: [],
        relations: [],
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
            throw new Error("At least one domain, target, target_object, explicit FOFA query, or enterprise website fingerprint input is required");
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
        const surfaceArtifacts = buildArtifacts(allAssets);
        const successfulQueries = results.filter(result => result.success).length;

        return {
            success: true,
            data: {
                queries: plans,
                results,
                subdomains: [],
                urls: [],
                ips: [],
                assets: [],
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
