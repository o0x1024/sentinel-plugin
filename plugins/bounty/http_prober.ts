/**
 * HTTP Prober Tool
 * 
 * @plugin http_prober
 * @name HTTP Prober
 * @version 1.4.2
 * @author Sentinel Team
 * @main_category bounty
 * @category recon
 * @default_severity info
 * @tags http, probe, alive, discovery, web
 * @description Probe HTTP/HTTPS endpoints from URLs and service endpoints to confirm live websites, collect status code, title, headers, technologies, and structured web artifacts
 */

interface ToolInput {
    targets: string[];
    target_objects?: Array<string | ServiceLikeTarget>;
    service_targets?: Array<string | ServiceLikeTarget>;
    ports?: number[];
    timeout?: number;
    followRedirects?: boolean;
    maxRedirects?: number;
    userAgent?: string;
    extractTitle?: boolean;
    extractHeaders?: boolean;
    checkHttps?: boolean;
    checkHttp?: boolean;
    previousSnapshots?: Record<string, ProbeSnapshot>;
    __monitorExecution?: MonitorExecutionContext;
}

interface ServiceLikeTarget {
    type?: string;
    value?: string;
    host?: string;
    host_key?: string;
    ip_or_host?: string;
    port?: number;
    port_number?: number;
    protocol?: string;
    transport_protocol?: string;
    service_name?: string;
}

interface ProbeResult {
    url: string;
    alive: boolean;
    statusCode?: number;
    statusText?: string;
    title?: string;
    contentLength?: number;
    contentType?: string;
    server?: string;
    headers?: Record<string, string>;
    redirectUrl?: string;
    responseTime?: number;
    error?: string;
    technologies?: string[];
    contentSummary?: string;
}

interface ProbeSnapshot {
    url: string;
    alive: boolean;
    statusCode?: number;
    title?: string;
    contentType?: string;
    server?: string;
    redirectUrl?: string;
    technologies: string[];
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
        targets: string[];
        results: ProbeResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, ProbeSnapshot>;
        summary: {
            total: number;
            alive: number;
            dead: number;
            byStatusCode: Record<string, number>;
            contentChanges: number;
            technologyChanges: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
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

const DEFAULT_TIMEOUT = 3000;
const DEFAULT_CONCURRENCY = 80;
const MAX_CONCURRENCY = 100;
const DEFAULT_MAX_REDIRECTS = 2;
const DEFAULT_PORTS = [80, 443, 8080, 8443];
const DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
const HTTP_PRIMARY_PORTS = new Set([80, 8080]);
const HTTPS_PRIMARY_PORTS = new Set([443, 8443]);
const RESPONSE_PREVIEW_BYTES = 16 * 1024;

function isIpLiteral(value: string): boolean {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
}

const TECH_SIGNATURES: Record<string, { header?: string; pattern: RegExp }[]> = {
    "nginx": [
        { header: "server", pattern: /nginx/i },
    ],
    "apache": [
        { header: "server", pattern: /apache/i },
    ],
    "iis": [
        { header: "server", pattern: /microsoft-iis/i },
    ],
    "cloudflare": [
        { header: "server", pattern: /cloudflare/i },
        { header: "cf-ray", pattern: /.+/ },
    ],
    "aws": [
        { header: "server", pattern: /amazons3/i },
        { header: "x-amz-request-id", pattern: /.+/ },
    ],
    "express": [
        { header: "x-powered-by", pattern: /express/i },
    ],
    "php": [
        { header: "x-powered-by", pattern: /php/i },
    ],
    "asp.net": [
        { header: "x-powered-by", pattern: /asp\.net/i },
        { header: "x-aspnet-version", pattern: /.+/ },
    ],
    "django": [
        { header: "x-frame-options", pattern: /SAMEORIGIN/i },
    ],
    "wordpress": [
        { header: "link", pattern: /wp-json/i },
    ],
    "varnish": [
        { header: "via", pattern: /varnish/i },
        { header: "x-varnish", pattern: /.+/ },
    ],
    "akamai": [
        { header: "x-akamai-transformed", pattern: /.+/ },
    ],
};

const pluginGlobals = globalThis as typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "List of generic targets to probe (domains, IPs, or URLs)"
            },
            target_objects: {
                type: "array",
                description: "Structured target objects, including service endpoint assets",
            },
            service_targets: {
                type: "array",
                description: "Service endpoint targets such as host:port or structured service assets",
            },
            ports: {
                type: "array",
                items: { type: "integer" },
                description: `Ports to probe. Default: ${DEFAULT_PORTS.join(", ")}`,
                default: DEFAULT_PORTS
            },
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: DEFAULT_TIMEOUT,
                minimum: 1000,
                maximum: 60000
            },
            followRedirects: {
                type: "boolean",
                description: "Follow HTTP redirects",
                default: true
            },
            maxRedirects: {
                type: "integer",
                description: "Maximum number of redirects to follow",
                default: DEFAULT_MAX_REDIRECTS
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header",
                default: DEFAULT_USER_AGENT
            },
            extractTitle: {
                type: "boolean",
                description: "Extract page title from HTML",
                default: true
            },
            extractHeaders: {
                type: "boolean",
                description: "Include response headers in results",
                default: false
            },
            checkHttps: {
                type: "boolean",
                description: "Check HTTPS protocol",
                default: true
            },
            checkHttp: {
                type: "boolean",
                description: "Check HTTP protocol",
                default: true
            },
            previousSnapshots: {
                type: "object",
                description: "Previous HTTP snapshots keyed by URL for change detection"
            }
        }
    };
}

pluginGlobals.get_input_schema = get_input_schema;

/**
 * Export output schema
 */
export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean", description: "Whether the operation succeeded" },
            data: {
                type: "object",
                properties: {
                    targets: { type: "array", items: { type: "string" }, description: "Original target list" },
                    results: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                url: { type: "string", description: "Probed URL" },
                                alive: { type: "boolean" },
                                statusCode: { type: "integer" },
                                title: { type: "string" },
                                contentLength: { type: "integer" },
                                server: { type: "string" },
                                technologies: { type: "array", items: { type: "string" } }
                            }
                        },
                        description: "Probe results for alive hosts"
                    },
                    changeEvents: { type: "array", description: "Detected probe change events" },
                    snapshots: { type: "object", description: "HTTP snapshots keyed by URL" },
                    summary: {
                        type: "object",
                        properties: {
                            total: { type: "integer" },
                            alive: { type: "integer" },
                            dead: { type: "integer" }
                        }
                    },
                    surface_artifacts: {
                        type: "object",
                        description: "Typed network surface artifacts for surface graph ingestion",
                        properties: {
                            webs: {
                                type: "array",
                                description: "Strict web assets with canonical_url, scheme, http_status_code, response_headers, and content_summary",
                            },
                            evidences: {
                                type: "array",
                                description: "Strict web evidences such as http_response_headers and http_response_body_summary",
                            },
                        },
                    }
                }
            },
            error: { type: "string", description: "Error message if failed" }
        }
    };
}

pluginGlobals.get_output_schema = get_output_schema;

/**
 * Extract title from HTML content
 */
function extractTitle(html: string): string | undefined {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match ? match[1].trim() : undefined;
}

function buildContentSummary(text: string): string {
    return text
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 500);
}

type ProbeFetchInit = RequestInit & {
    timeout: number;
    maxRedirects: number;
    maxBodyBytes?: number;
};

async function fetchWithTimeout(url: string, init: ProbeFetchInit): Promise<any> {
    const controller = new AbortController();
    const upstreamSignal = init.signal;
    const timeoutMs = Number.isFinite(init.timeout) ? Math.max(0, init.timeout) : 0;
    let timeoutId: ReturnType<typeof setTimeout> | undefined;

    const abortFromUpstream = () => {
        controller.abort();
    };

    if (upstreamSignal) {
        if (upstreamSignal.aborted) {
            controller.abort();
        } else {
            upstreamSignal.addEventListener("abort", abortFromUpstream, { once: true });
        }
    }

    if (timeoutMs > 0) {
        timeoutId = setTimeout(() => {
            controller.abort();
        }, timeoutMs);
    }

    try {
        return await fetch(url, {
            ...init,
            signal: controller.signal,
        });
    } finally {
        if (timeoutId !== undefined) {
            clearTimeout(timeoutId);
        }
        if (upstreamSignal) {
            upstreamSignal.removeEventListener("abort", abortFromUpstream);
        }
    }
}

/**
 * Detect technologies from headers
 */
function detectTechnologies(headers: Record<string, string>): string[] {
    const detected: string[] = [];
    
    for (const [tech, signatures] of Object.entries(TECH_SIGNATURES)) {
        for (const sig of signatures) {
            if (sig.header) {
                const headerValue = headers[sig.header.toLowerCase()];
                if (headerValue && sig.pattern.test(headerValue)) {
                    if (!detected.includes(tech)) {
                        detected.push(tech);
                    }
                    break;
                }
            }
        }
    }
    
    return detected;
}

function isHtmlContentType(contentType?: string): boolean {
    return /(?:text\/html|application\/xhtml\+xml)/i.test(contentType || "");
}

function collectResponseHeaders(response: any): Record<string, string> {
    const headers: Record<string, string> = {};
    response.headers.forEach((value: string, key: string) => {
        headers[key.toLowerCase()] = value;
    });
    return headers;
}

function parseContentLength(headers: Record<string, string>): number {
    const contentRange = headers["content-range"];
    if (contentRange) {
        const match = contentRange.match(/bytes\s+\d+-\d+\/(\d+|\*)/i);
        if (match && match[1] !== "*") {
            const totalLength = parseInt(match[1], 10);
            if (Number.isFinite(totalLength) && totalLength > 0) {
                return totalLength;
            }
        }
    }

    const contentLength = parseInt(headers["content-length"] || "0", 10);
    return Number.isFinite(contentLength) && contentLength > 0 ? contentLength : 0;
}

function shouldFallbackToGet(status: number): boolean {
    return status === 405 || status === 501;
}

function shouldFetchBodyForTitle(
    statusCode: number,
    headers: Record<string, string>,
    extractTitleEnabled: boolean,
): boolean {
    if (!extractTitleEnabled || statusCode >= 400) {
        return false;
    }

    const contentType = headers["content-type"];
    return !contentType || isHtmlContentType(contentType);
}

function resolveRedirectUrl(
    requestedUrl: string,
    response: { redirected?: boolean; url?: string },
    headers: Record<string, string>,
): string | undefined {
    if (response.redirected && response.url && response.url !== requestedUrl) {
        return response.url;
    }

    const location = headers["location"];
    if (!location) {
        return undefined;
    }

    try {
        return new URL(location, requestedUrl).toString();
    } catch {
        return location;
    }
}

/**
 * Normalize target to URL
 */
function normalizeTarget(target: string, port: number, protocol: string): string {
    // If already a full URL, return as is
    if (target.startsWith("http://") || target.startsWith("https://")) {
        return target;
    }
    
    // Build URL from target
    const defaultPort = protocol === "https" ? 443 : 80;
    if (port === defaultPort) {
        return `${protocol}://${target}`;
    }
    return `${protocol}://${target}:${port}`;
}

type NormalizedServiceTarget = {
    host: string;
    port: number;
    protocol?: string;
    serviceName?: string;
};

function normalizeServiceTarget(raw: string | ServiceLikeTarget): NormalizedServiceTarget | null {
    if (typeof raw === "string") {
        const trimmed = raw.trim();
        if (!trimmed) return null;

        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            try {
                const parsed = new URL(trimmed);
                const protocol = parsed.protocol.replace(":", "").toLowerCase();
                const port = Number(parsed.port || (protocol === "https" ? 443 : 80));
                if (!parsed.hostname || !port) return null;
                return { host: parsed.hostname, port, protocol };
            } catch {
                return null;
            }
        }

        const normalized = trimmed.replace(/\/(?:tcp|udp)$/i, "");
        try {
            const parsed = new URL(`tcp://${normalized}`);
            const port = Number(parsed.port || 0);
            if (!parsed.hostname || !port) return null;
            return { host: parsed.hostname, port, protocol: "tcp" };
        } catch {
            const [hostPart, portPart] = normalized.split(":");
            const port = Number(portPart || 0);
            if (!hostPart || !port) return null;
            return { host: hostPart, port, protocol: "tcp" };
        }
    }

    if (!raw || typeof raw !== "object") {
        return null;
    }

    if (raw.type && raw.type !== "service") {
        return null;
    }

    if (typeof raw.value === "string" && raw.value.trim()) {
        const normalized = normalizeServiceTarget(raw.value);
        if (normalized) {
            return {
                ...normalized,
                protocol: raw.protocol || raw.transport_protocol || normalized.protocol,
                serviceName: raw.service_name,
            };
        }
    }

    const host = String(raw.ip_or_host || raw.host || raw.host_key || "").trim();
    const port = Number(raw.port ?? raw.port_number ?? 0);
    const protocol = String(raw.protocol || raw.transport_protocol || "").trim().toLowerCase();
    const serviceName = String(raw.service_name || "").trim().toLowerCase();
    if (!host || !port) return null;
    return {
        host,
        port,
        protocol: protocol || undefined,
        serviceName: serviceName || undefined,
    };
}

function collectServiceTargets(input: ToolInput): NormalizedServiceTarget[] {
    const rawTargets = [
        ...(Array.isArray(input.service_targets) ? input.service_targets : []),
        ...(Array.isArray(input.target_objects) ? input.target_objects : []),
    ];

    const deduped = new Map<string, NormalizedServiceTarget>();
    for (const rawTarget of rawTargets) {
        const normalized = normalizeServiceTarget(rawTarget);
        if (!normalized) continue;

        const key = `${normalized.host}:${normalized.port}`;
        const existing = deduped.get(key);
        if (!existing) {
            deduped.set(key, normalized);
            continue;
        }

        const existingPriority = existing.protocol === "https" ? 3 : existing.protocol === "http" ? 2 : 1;
        const currentPriority = normalized.protocol === "https" ? 3 : normalized.protocol === "http" ? 2 : 1;
        if (currentPriority > existingPriority) {
            deduped.set(key, normalized);
        }
    }

    return Array.from(deduped.values());
}

function buildCandidateUrlsFromServiceTarget(
    target: NormalizedServiceTarget,
    options: {
        checkHttp: boolean;
        checkHttps: boolean;
        probeUnknownPortsWithBoth: boolean;
    }
): string[] {
    const protocols: string[] = [];
    const normalizedProtocol = (target.protocol || "").toLowerCase();
    const normalizedServiceName = (target.serviceName || "").toLowerCase();

    if ((normalizedProtocol === "https" || normalizedServiceName === "https") && options.checkHttps) {
        protocols.push("https");
    } else if ((normalizedProtocol === "http" || normalizedServiceName === "http") && options.checkHttp) {
        protocols.push("http");
    } else {
        const isHttpPrimary = HTTP_PRIMARY_PORTS.has(target.port);
        const isHttpsPrimary = HTTPS_PRIMARY_PORTS.has(target.port);

        if (options.checkHttp && isHttpPrimary) {
            protocols.push("http");
        }
        if (options.checkHttps && isHttpsPrimary) {
            protocols.push("https");
        }

        if (protocols.length === 0 && options.probeUnknownPortsWithBoth) {
            if (options.checkHttps) {
                protocols.push("https");
            }
            if (options.checkHttp) {
                protocols.push("http");
            }
        }
    }

    return protocols.map((protocol) => normalizeTarget(target.host, target.port, protocol));
}

function buildCandidateUrls(
    target: string,
    ports: number[],
    options: {
        checkHttp: boolean;
        checkHttps: boolean;
        probeUnknownPortsWithBoth: boolean;
    }
): string[] {
    if (target.startsWith("http://") || target.startsWith("https://")) {
        return [target];
    }

    const urls: string[] = [];
    for (const port of ports) {
        const protocols: string[] = [];
        const isHttpPrimary = HTTP_PRIMARY_PORTS.has(port);
        const isHttpsPrimary = HTTPS_PRIMARY_PORTS.has(port);

        if (options.checkHttp && isHttpPrimary) {
            protocols.push("http");
        }
        if (options.checkHttps && isHttpsPrimary) {
            protocols.push("https");
        }

        if (protocols.length === 0 && options.probeUnknownPortsWithBoth) {
            if (options.checkHttps) {
                protocols.push("https");
            }
            if (options.checkHttp) {
                protocols.push("http");
            }
        }

        if (protocols.length === 0) {
            if (options.checkHttps && !options.checkHttp) {
                protocols.push("https");
            } else if (options.checkHttp && !options.checkHttps) {
                protocols.push("http");
            }
        }

        for (const protocol of protocols) {
            urls.push(normalizeTarget(target, port, protocol));
        }
    }

    return urls;
}

/**
 * Probe a single URL
 */
async function probeUrl(
    url: string,
    options: {
        timeout: number;
        followRedirects: boolean;
        maxRedirects: number;
        userAgent: string;
        extractTitle: boolean;
        extractHeaders: boolean;
    }
): Promise<ProbeResult> {
    const startTime = performance.now();
    const requestInit = {
        headers: {
            "User-Agent": options.userAgent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
        redirect: options.followRedirects ? "follow" : "manual",
        maxRedirects: options.maxRedirects,
        timeout: options.timeout,
    } satisfies ProbeFetchInit;
    const getRequestInit = {
        ...requestInit,
        method: "GET",
        maxBodyBytes: RESPONSE_PREVIEW_BYTES,
        headers: {
            ...requestInit.headers,
            "Range": `bytes=0-${RESPONSE_PREVIEW_BYTES - 1}`,
        },
    } satisfies ProbeFetchInit;
    
    try {
        let response: any;
        let requestMethod: "HEAD" | "GET" = options.extractTitle ? "GET" : "HEAD";
        if (requestMethod === "GET") {
            response = await fetchWithTimeout(url, getRequestInit);
        } else {
            try {
                response = await fetchWithTimeout(url, {
                    method: "HEAD",
                    ...requestInit,
                });
            } catch {
                requestMethod = "GET";
                response = await fetchWithTimeout(url, getRequestInit);
            }
        }

        let headers = collectResponseHeaders(response);

        if (requestMethod === "HEAD" && shouldFallbackToGet(response.status)) {
            requestMethod = "GET";
            response = await fetchWithTimeout(url, getRequestInit);
            headers = collectResponseHeaders(response);
        }
        
        let title: string | undefined;
        let contentLength = parseContentLength(headers);
        let contentSummary: string | undefined;
        
        if (requestMethod === "HEAD" && shouldFetchBodyForTitle(response.status, headers, options.extractTitle)) {
            response = await fetchWithTimeout(url, getRequestInit);
            headers = collectResponseHeaders(response);
            contentLength = parseContentLength(headers);
            requestMethod = "GET";
        }

        if (requestMethod === "GET" && shouldFetchBodyForTitle(response.status, headers, options.extractTitle)) {
            try {
                const text = await response.text();
                title = extractTitle(text);
                contentSummary = buildContentSummary(text);
                if (!contentLength) {
                    contentLength = text.length;
                }
            } catch {
                // Ignore body read errors
            }
        }
        
        // Detect technologies
        const technologies = detectTechnologies(headers);
        
        const result: ProbeResult = {
            url,
            alive: true,
            responseTime: Math.round(performance.now() - startTime),
            statusCode: response.status,
            statusText: response.statusText,
            title,
            contentLength,
            contentType: headers["content-type"],
            server: headers["server"],
            headers,
            technologies,
            contentSummary,
        };
        
        result.redirectUrl = resolveRedirectUrl(url, response, headers);
        
        return result;
        
    } catch (error: any) {
        const responseTime = Math.round(performance.now() - startTime);
        return {
            url,
            alive: false,
            responseTime,
            error: error.message || String(error),
        };
    }
}

/**
 * Run tasks sequentially through runtime scheduling
 */
async function runSequentially<T>(tasks: Array<() => Promise<T>>): Promise<T[]> {
    // Rust controls request pacing; plugins only submit work to the runtime queue.
    const results: T[] = [];
    for (const task of tasks) {
        results.push(await task());
    }
    return results;
}

function normalizeTechnologyList(technologies?: string[]): string[] {
    return Array.from(new Set((technologies || []).map((item) => String(item || "").trim()).filter(Boolean)))
        .sort((left, right) => left.localeCompare(right));
}

function buildProbeEventId(prefix: string, url: string, timestamp: string): string {
    return `${prefix}-${url}-${timestamp}`.replace(/[^a-zA-Z0-9_-]+/g, "-").slice(0, 120);
}

function buildProbeSnapshot(result: ProbeResult, timestamp: string): ProbeSnapshot {
    return {
        url: result.url,
        alive: result.alive,
        statusCode: result.statusCode,
        title: result.title,
        contentType: result.contentType,
        server: result.server,
        redirectUrl: result.redirectUrl,
        technologies: normalizeTechnologyList(result.technologies),
        lastChecked: timestamp,
    };
}

function createAvailabilityEvent(previous: ProbeSnapshot | null, current: ProbeSnapshot, timestamp: string): ChangeEvent {
    const discovered = current.alive;
    return {
        id: buildProbeEventId(discovered ? "web-discovered" : "web-removed", current.url, timestamp),
        assetId: current.url,
        eventType: discovered ? "asset_discovered" : "asset_removed",
        severity: discovered ? "medium" : "high",
        title: discovered ? `Web endpoint discovered: ${current.url}` : `Web endpoint unreachable: ${current.url}`,
        description: discovered
            ? `A live web endpoint was observed at ${current.url}${current.statusCode ? ` with status ${current.statusCode}` : ""}.`
            : `Previously reachable web endpoint ${current.url} is no longer responding successfully.`,
        oldValue: previous ? JSON.stringify(previous) : undefined,
        newValue: discovered ? JSON.stringify(current) : undefined,
        detectionMethod: "http_prober",
        tags: ["http", discovered ? "discovered" : "removed", "availability"],
        autoTriggerEnabled: true,
        riskScore: discovered ? 52 : 74,
        metadata: {
            previous,
            current,
        },
    };
}

function createContentChangeEvent(url: string, diffs: string[], previous: ProbeSnapshot, current: ProbeSnapshot, timestamp: string): ChangeEvent {
    const statusChanged = previous.statusCode !== current.statusCode;
    const severity: ChangeEvent["severity"] = statusChanged ? "medium" : "low";
    return {
        id: buildProbeEventId("content", url, timestamp),
        assetId: url,
        eventType: "content_change",
        severity,
        title: `HTTP content changed for ${url}`,
        description: diffs.join("; "),
        oldValue: JSON.stringify({
            statusCode: previous.statusCode,
            title: previous.title,
            contentType: previous.contentType,
            server: previous.server,
            redirectUrl: previous.redirectUrl,
        }),
        newValue: JSON.stringify({
            statusCode: current.statusCode,
            title: current.title,
            contentType: current.contentType,
            server: current.server,
            redirectUrl: current.redirectUrl,
        }),
        detectionMethod: "http_prober",
        tags: ["http", "content", ...(statusChanged ? ["status"] : [])],
        autoTriggerEnabled: true,
        riskScore: statusChanged ? 58 : 36,
        metadata: {
            url,
            previous,
            current,
            fields: diffs,
        },
    };
}

function createTechnologyChangeEvent(url: string, added: string[], removed: string[], timestamp: string): ChangeEvent {
    const severity: ChangeEvent["severity"] = removed.length > 0 ? "medium" : "low";
    const parts: string[] = [];
    if (added.length > 0) parts.push(`added ${added.join(", ")}`);
    if (removed.length > 0) parts.push(`removed ${removed.join(", ")}`);
    return {
        id: buildProbeEventId("technology", url, timestamp),
        assetId: url,
        eventType: "technology_change",
        severity,
        title: `Technology footprint changed for ${url}`,
        description: parts.join("; "),
        oldValue: removed.join("\n") || undefined,
        newValue: added.join("\n") || undefined,
        detectionMethod: "http_prober",
        tags: ["http", "technology", "change"],
        autoTriggerEnabled: true,
        riskScore: removed.length > 0 ? 57 : 42,
        metadata: {
            url,
            added,
            removed,
        },
    };
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const rawTargets = Array.isArray(input.targets) ? input.targets : [];
        const validStringTargets = rawTargets.filter(
            target => typeof target === "string" && target.trim().length > 0,
        );

        const inferredServiceTargets = validStringTargets.filter((target) => {
            if (target.startsWith("http://") || target.startsWith("https://")) {
                return false;
            }
            return normalizeServiceTarget(target) !== null;
        });

        const genericTargets = validStringTargets.filter((target) => !inferredServiceTargets.includes(target));
        const structuredServiceTargets = collectServiceTargets({
            ...input,
            service_targets: [
                ...(Array.isArray(input.service_targets) ? input.service_targets : []),
                ...inferredServiceTargets,
            ],
        });

        if (
            genericTargets.length === 0
            && structuredServiceTargets.length === 0
        ) {
            return {
                success: false,
                error: "Invalid input: provide at least one generic target or service endpoint target"
            };
        }

        const timeout = input.timeout || DEFAULT_TIMEOUT;
                const followRedirects = input.followRedirects !== false;
        const maxRedirects = input.maxRedirects || DEFAULT_MAX_REDIRECTS;
        const userAgent = input.userAgent || DEFAULT_USER_AGENT;
        const extractTitle = input.extractTitle !== false;
        const extractHeaders = input.extractHeaders === true;
        const checkHttps = input.checkHttps !== false;
        const checkHttp = input.checkHttp !== false;
        const ports = input.ports || DEFAULT_PORTS;
        const previousSnapshots = input.previousSnapshots || {};
        const monitorExecution = input.__monitorExecution;
        const timestamp = new Date().toISOString();
        
        const probeUnknownPortsWithBoth = Array.isArray(input.ports) && input.ports.length > 0;
        const urls = genericTargets.flatMap(target => buildCandidateUrls(target, ports, {
            checkHttp,
            checkHttps,
            probeUnknownPortsWithBoth,
        }));
        const serviceUrls = structuredServiceTargets.flatMap((target) =>
            buildCandidateUrlsFromServiceTarget(target, {
                checkHttp,
                checkHttps,
                probeUnknownPortsWithBoth: false,
            }),
        );
        
        const uniqueUrls = [...new Set([...urls, ...serviceUrls])];
        const totalProgressUnits = uniqueUrls.length + 2;

        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: totalProgressUnits,
            phase: "prepare",
            message: "Preparing HTTP probes",
        });

        let completedUrls = 0;
        const tasks = uniqueUrls.map(url => async () => {
            try {
                return await probeUrl(url, {
                    timeout,
                    followRedirects,
                    maxRedirects,
                    userAgent,
                    extractTitle,
                    extractHeaders,
                });
            } finally {
                completedUrls += 1;
                await reportMonitorProgress(monitorExecution, {
                    current: completedUrls,
                    total: totalProgressUnits,
                    currentTarget: url,
                    phase: "probe",
                    message: `Probing web endpoint ${url}`,
                });
            }
        });
        
        const results = await runSequentially(tasks);
        await reportMonitorProgress(monitorExecution, {
            current: uniqueUrls.length + 1,
            total: totalProgressUnits,
            phase: "compare",
            message: "Comparing HTTP snapshots",
        });
        const aliveResults = results.filter(r => r.alive);
        const deadResults = results.filter(r => !r.alive);
        const changeEvents: ChangeEvent[] = [];
        const snapshots: Record<string, ProbeSnapshot> = {};

        for (const result of results) {
            const snapshot = buildProbeSnapshot(result, timestamp);
            snapshots[result.url] = snapshot;
            const previous = previousSnapshots[result.url];

            if (!previous) {
                if (snapshot.alive) {
                    changeEvents.push(createAvailabilityEvent(null, snapshot, timestamp));
                }
                continue;
            }

            if (previous.alive !== snapshot.alive) {
                changeEvents.push(createAvailabilityEvent(previous, snapshot, timestamp));
                continue;
            }

            if (!snapshot.alive || !previous.alive) {
                continue;
            }

            const contentDiffs: string[] = [];
            if (previous.statusCode !== snapshot.statusCode) {
                contentDiffs.push(`status ${previous.statusCode || "unknown"} -> ${snapshot.statusCode || "unknown"}`);
            }
            if ((previous.title || "") !== (snapshot.title || "")) {
                contentDiffs.push(`title ${JSON.stringify(previous.title || "")} -> ${JSON.stringify(snapshot.title || "")}`);
            }
            if ((previous.server || "") !== (snapshot.server || "")) {
                contentDiffs.push(`server ${JSON.stringify(previous.server || "")} -> ${JSON.stringify(snapshot.server || "")}`);
            }
            if ((previous.contentType || "") !== (snapshot.contentType || "")) {
                contentDiffs.push(`content-type ${JSON.stringify(previous.contentType || "")} -> ${JSON.stringify(snapshot.contentType || "")}`);
            }
            if ((previous.redirectUrl || "") !== (snapshot.redirectUrl || "")) {
                contentDiffs.push(`redirect ${JSON.stringify(previous.redirectUrl || "")} -> ${JSON.stringify(snapshot.redirectUrl || "")}`);
            }
            if (contentDiffs.length > 0) {
                changeEvents.push(createContentChangeEvent(result.url, contentDiffs, previous, snapshot, timestamp));
            }

            const previousTechnologies = new Set(normalizeTechnologyList(previous.technologies));
            const currentTechnologies = new Set(snapshot.technologies);
            const addedTechnologies = snapshot.technologies.filter(item => !previousTechnologies.has(item));
            const removedTechnologies = [...previousTechnologies].filter(item => !currentTechnologies.has(item));
            if (addedTechnologies.length > 0 || removedTechnologies.length > 0) {
                changeEvents.push(createTechnologyChangeEvent(result.url, addedTechnologies, removedTechnologies, timestamp));
            }
        }

        const surfaceDomains = [...new Set(aliveResults
            .map(result => new URL(result.url).hostname)
            .filter(hostname => hostname.includes(".") && !isIpLiteral(hostname))
        )].map(hostname => ({
            fqdn: hostname,
            main_domain: hostname.split(".").slice(-2).join("."),
            root_domain: hostname.split(".").slice(-2).join("."),
            source: "http_prober",
            confidence: 0.9,
        }));
        const surfaceIps = [...new Set(aliveResults
            .map(result => new URL(result.url).hostname)
            .filter(hostname => isIpLiteral(hostname))
        )].map(ipAddress => ({
            ip_address: ipAddress,
            ip_version: ipAddress.includes(":") ? "IPv6" : "IPv4",
            source: "http_prober",
            confidence: 0.9,
        }));
        const surfaceWebs = aliveResults.map(result => {
            const parsed = new URL(result.url);
            return {
                canonical_url: result.url,
                scheme: parsed.protocol.replace(":", ""),
                hostname: parsed.hostname,
                port: Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80)),
                site_title: result.title,
                http_status_code: result.statusCode,
                server_header: result.server,
                response_headers: result.headers || {},
                content_summary: result.contentSummary || `${result.statusCode || "unknown"} ${result.title || ""}`.trim(),
                source: "http_prober",
                confidence: 0.95,
            };
        });
        const surfaceEvidences = aliveResults.flatMap(result => {
            const parsed = new URL(result.url);
            const evidences: any[] = [{
                asset_type: "web",
                asset_key: result.url,
                evidence_type: "http_response_headers",
                title: `HTTP Response Headers: ${parsed.hostname}`,
                content_json: {
                    url: result.url,
                    headers: result.headers || {},
                },
                source: "http_prober",
            }];

            if (result.contentSummary) {
                evidences.push({
                    asset_type: "web",
                    asset_key: result.url,
                    evidence_type: "http_response_body_summary",
                    title: `HTTP Response Body Summary: ${parsed.hostname}`,
                    content_text: result.contentSummary,
                    content_json: {
                        url: result.url,
                        status_code: result.statusCode,
                        title: result.title,
                        content_type: result.contentType,
                        response_time: result.responseTime,
                        technologies: result.technologies,
                        redirect_url: result.redirectUrl,
                    },
                    source: "http_prober",
                });
            }

            return evidences;
        });
        
        const byStatusCode: Record<string, number> = {};
        for (const result of aliveResults) {
            const code = String(result.statusCode || "unknown");
            byStatusCode[code] = (byStatusCode[code] || 0) + 1;
        }

        await reportMonitorProgress(monitorExecution, {
            current: totalProgressUnits,
            total: totalProgressUnits,
            phase: "build",
            message: "Building web probe results",
        });
        
        return {
            success: true,
            data: {
                targets: input.targets,
                results: aliveResults,
                changeEvents,
                snapshots,
                summary: {
                    total: uniqueUrls.length,
                    alive: aliveResults.length,
                    dead: deadResults.length,
                    byStatusCode,
                    contentChanges: changeEvents.filter(event => event.eventType === "content_change").length,
                    technologyChanges: changeEvents.filter(event => event.eventType === "technology_change").length,
                },
                surface_artifacts: {
                    domains: surfaceDomains,
                    ips: surfaceIps,
                    webs: surfaceWebs,
                    changes: changeEvents.map(event => ({
                        asset_key: event.assetId,
                        asset_type: "web",
                        change_type: event.eventType,
                        severity: event.severity,
                        title: event.title,
                        description: event.description,
                        old_value: event.oldValue,
                        new_value: event.newValue,
                        risk_score: event.riskScore,
                        source: "http_prober",
                        metadata: event.metadata,
                    })),
                    evidences: surfaceEvidences,
                    relations: aliveResults.map(result => {
                        const parsed = new URL(result.url);
                        if (isIpLiteral(parsed.hostname)) {
                            return {
                                from_type: "ip",
                                from_key: parsed.hostname,
                                to_type: "web",
                                to_key: result.url,
                                relation_type: "exposes_web",
                                source: "http_prober",
                                confidence: 0.9,
                            };
                        }
                        return {
                            from_type: "domain",
                            from_key: parsed.hostname,
                            to_type: "web",
                            to_key: result.url,
                            relation_type: "exposes_web",
                            source: "http_prober",
                            confidence: 0.9,
                        };
                    }),
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
