/**
 * API Endpoint Change Monitor
 * 
 * @plugin api_monitor
 * @name API Monitor
 * @version 1.2.0
 * @author Sentinel Team
 * @main_category bounty
 * @category monitor
 * @default_severity high
 * @tags api, endpoint, monitor, change-detection, rest, graphql, javascript, spa
 * @description Monitor API endpoints for changes by discovering JavaScript assets and extracting API paths directly from JS bundles and pages
 */

// Declare Sentinel API for JS analysis
declare const Sentinel: {
    AST: {
        parse: (code: string, filename?: string) => {
            success: boolean;
            literals: Array<{ value: string; line: number; column: number; type: string }>;
            errors: string[];
        };
    };
    Monitor?: {
        reportProgress?: (payload: Record<string, unknown>) => Promise<boolean>;
    };
};

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

interface ToolInput {
    targets: string[];  // Base URLs or JS files to analyze
    timeout?: number;
    userAgent?: string;
    crawlDepth?: number;
    maxJsFiles?: number;
    includeSameOriginOnly?: boolean;
    followSourceMaps?: boolean;
    probeSpaManifests?: boolean;
    includeGraphQL?: boolean;
    includeOpenAPI?: boolean;
    previousSnapshots?: Record<string, ApiSnapshot>;
    __monitorExecution?: MonitorExecutionContext;
}

interface JsLink {
    url: string;
    type: "external" | "inline" | "module" | "dynamic" | "sourcemap" | "webpack" | "manifest";
    source: string;
    size?: number;
    hash?: string;
}

interface ScriptContentSource {
    source: string;
    content: string;
}

interface SourceMapLike {
    version?: number;
    file?: string;
    sourceRoot?: string;
    sources?: string[];
    sourcesContent?: Array<string | null>;
    sections?: Array<{ map?: SourceMapLike }>;
}

interface FetchResult {
    ok: boolean;
    status: number | null;
    text: string;
    size: number;
    contentType: string;
    finalUrl: string;
    error?: string;
}

interface HttpProbeResult {
    ok: boolean;
    status: number;
    text: string;
    size: number;
    contentType: string;
    finalUrl: string;
    fetchedAt: string;
}

interface JsDiscoveryResult {
    jsLinks: JsLink[];
    scriptContents: ScriptContentSource[];
    crawledPages: string[];
}

interface ApiEndpoint {
    path: string;
    method?: string;
    source: string;
    parameters?: string[];
    requestUrl?: string;
    requestMethod?: string;
    responseStatus?: number;
    responseContentType?: string;
    responsePreview?: string;
    responseFetchedAt?: string;
    responseError?: string;
    responseSize?: number;
}

interface ApiSnapshot {
    baseUrl: string;
    endpoints: ApiEndpoint[];
    graphqlEndpoint?: string;
    openApiSpec?: string;
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

interface ApiResult {
    baseUrl: string;
    success: boolean;
    snapshot?: ApiSnapshot;
    addedEndpoints?: ApiEndpoint[];
    removedEndpoints?: ApiEndpoint[];
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: ApiResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, ApiSnapshot>;
        summary: {
            totalTargets: number;
            successfulChecks: number;
            failedChecks: number;
            totalEndpoints: number;
            totalJsFiles: number;
            addedEndpoints: number;
            removedEndpoints: number;
            apiChanges: number;
        };
    };
    error?: string;
}

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;

// Generate UUID
function generateId(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

async function runSequentially<T>(tasks: Array<() => Promise<T>>): Promise<T[]> {
    // Rust controls request pacing; plugins only submit work to the runtime queue.
    const results: T[] = [];
    for (const task of tasks) {
        results.push(await task());
    }
    return results;
}

// API endpoint patterns
const API_PATTERNS = [
    /^\/api\/[a-zA-Z0-9\/_-]+$/,
    /^\/v[0-9]+\/[a-zA-Z0-9\/_-]+$/,
    /^\/rest\/[a-zA-Z0-9\/_-]+$/,
    /^\/graphql\/?$/,
    /^\/gql\/?$/,
    /^\/(?:users?|auth|login|logout|register|signup|profile|account|settings|config|admin|dashboard|data|search|upload|download|export|import|webhook|token|oauth|callback|notify|events?|messages?|posts?|comments?|items?|products?|orders?|payments?|subscriptions?|notifications?)(?:\/[a-zA-Z0-9_-]*)*$/,
];


const DEFAULT_MAX_JS_FILES = 100;
const DEFAULT_PAGE_CRAWL_LIMIT = 20;
const MAX_RESPONSE_PREVIEW_CHARS = 4000;
const MAX_CONSTANT_RESOLUTION_SOURCE_LENGTH = 1_000_000;
const MAX_LITERAL_SCAN_MATCHES = 5000;
const LARGE_BUNDLE_SOURCE_LENGTH = 600_000;
const BUNDLE_SCAN_CHUNK_SIZE = 120_000;
const BUNDLE_SCAN_CHUNK_OVERLAP = 2_048;
const MAX_RESOLVABLE_EXPRESSION_LENGTH = 2_048;
const MAX_RESOLVABLE_CONCAT_PARTS = 64;
const MAX_RESOLVABLE_TEMPLATE_REFERENCES = 32;
const MAX_RESOLVE_DEPTH = 8;
const MAX_CONSTANT_ASSIGNMENTS = 5_000;
const SAFE_RESPONSE_PROBE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function stripQuotes(value: string): string {
    if (value.length >= 2) {
        const first = value[0];
        const last = value[value.length - 1];
        if ((first === "'" && last === "'") || (first === "\"" && last === "\"") || (first === "`" && last === "`")) {
            return value.slice(1, -1);
        }
    }
    return value;
}

function splitConcatenatedExpression(expr: string): string[] {
    const parts: string[] = [];
    let current = "";
    let quote: string | null = null;
    let braceDepth = 0;

    for (let index = 0; index < expr.length; index += 1) {
        const char = expr[index];
        const previous = index > 0 ? expr[index - 1] : "";

        if (quote) {
            current += char;
            if (char === quote && previous !== "\\") {
                quote = null;
            }
            continue;
        }

        if (char === "'" || char === "\"" || char === "`") {
            quote = char;
            current += char;
            continue;
        }

        if (char === "(" || char === "[" || char === "{") {
            braceDepth += 1;
            current += char;
            continue;
        }

        if (char === ")" || char === "]" || char === "}") {
            braceDepth = Math.max(0, braceDepth - 1);
            current += char;
            continue;
        }

        if (char === "+" && braceDepth === 0) {
            const trimmed = current.trim();
            if (trimmed) parts.push(trimmed);
            current = "";
            continue;
        }

        current += char;
    }

    const tail = current.trim();
    if (tail) parts.push(tail);
    return parts;
}

function resolveStringExpression(
    expr: string,
    constants: Map<string, string>,
    depth = 0,
): string | null {
    const normalizedExpr = expr.trim();
    if (!normalizedExpr) return null;
    if (depth > MAX_RESOLVE_DEPTH) return null;
    if (normalizedExpr.length > MAX_RESOLVABLE_EXPRESSION_LENGTH) return null;

    if ((normalizedExpr.startsWith("'") && normalizedExpr.endsWith("'"))
        || (normalizedExpr.startsWith("\"") && normalizedExpr.endsWith("\""))) {
        return stripQuotes(normalizedExpr);
    }

    if (normalizedExpr.startsWith("`") && normalizedExpr.endsWith("`")) {
        const templateBody = stripQuotes(normalizedExpr);
        let interpolationCount = 0;
        return templateBody.replace(/\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g, (_match, name: string) => {
            interpolationCount += 1;
            if (interpolationCount > MAX_RESOLVABLE_TEMPLATE_REFERENCES) {
                return "";
            }
            return constants.get(name) ?? "";
        });
    }

    if (/^[A-Za-z_$][\w$]*$/.test(normalizedExpr)) {
        return constants.get(normalizedExpr) ?? null;
    }

    if (normalizedExpr.includes("+")) {
        const parts = splitConcatenatedExpression(normalizedExpr);
        if (parts.length === 0) return null;
        if (parts.length > MAX_RESOLVABLE_CONCAT_PARTS) return null;
        let resolved = "";
        for (const part of parts) {
            const value = resolveStringExpression(part, constants, depth + 1);
            if (value === null) return null;
            if ((resolved.length + value.length) > MAX_RESOLVABLE_EXPRESSION_LENGTH) {
                return null;
            }
            resolved += value;
        }
        return resolved;
    }

    return null;
}

function collectResolvableConstants(content: string): Map<string, string> {
    if (content.length > MAX_CONSTANT_RESOLUTION_SOURCE_LENGTH) {
        return new Map<string, string>();
    }

    const rawAssignments = new Map<string, string>();
    const resolved = new Map<string, string>();
    const assignmentRegex = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+);?/g;
    let match;

    while ((match = assignmentRegex.exec(content)) !== null && rawAssignments.size < MAX_CONSTANT_ASSIGNMENTS) {
        rawAssignments.set(match[1], match[2].trim());
    }

    for (let iteration = 0; iteration < 5; iteration += 1) {
        let changed = false;
        for (const [name, expression] of rawAssignments.entries()) {
            if (resolved.has(name)) continue;
            const value = safeResolveStringExpression(expression, resolved);
            if (typeof value === "string" && value.length > 0) {
                resolved.set(name, value);
                changed = true;
            }
        }
        if (!changed) break;
    }

    return resolved;
}

function safeResolveStringExpression(expr: string, constants: Map<string, string>): string | null {
    try {
        return resolveStringExpression(expr, constants);
    } catch {
        return null;
    }
}

function normalizeEndpointPath(value: string): string | null {
    const normalizedValue = String(value || "").trim();
    if (!normalizedValue) return null;

    if (/^https?:\/\/[^\/]+\/(?:api|v[0-9]+|rest|graphql)/i.test(normalizedValue)) {
        try {
            return new URL(normalizedValue).pathname;
        } catch {
            return null;
        }
    }

    for (const pattern of API_PATTERNS) {
        if (pattern.test(normalizedValue)) {
            return normalizedValue;
        }
    }

    return null;
}

function pushApiEndpoint(
    endpoints: ApiEndpoint[],
    seen: Set<string>,
    pathCandidate: string,
    source: string,
    method?: string,
) {
    const normalizedPath = normalizeEndpointPath(pathCandidate);
    if (!normalizedPath) return;

    const normalizedMethod = method ? method.toUpperCase() : undefined;
    const key = `${normalizedMethod || ""}:${normalizedPath}`;
    if (seen.has(key)) return;

    seen.add(key);
    endpoints.push({
        path: normalizedPath,
        method: normalizedMethod,
        source,
    });
}

function collectLiteralCandidates(
    content: string,
    limit: number,
): Array<{ value: string; line: number }> {
    const literals: Array<{ value: string; line: number }> = [];
    const stringPattern = /(['"`])([^'"`\n]{3,200})\1/g;
    let match;

    while ((match = stringPattern.exec(content)) !== null && literals.length < limit) {
        literals.push({ value: match[2], line: 0 });
    }

    return literals;
}

function scanDirectApiCallsFromChunk(
    content: string,
    source: string,
    endpoints: ApiEndpoint[],
    seen: Set<string>,
) {
    const emptyConstants = new Map<string, string>();
    const axiosInstances = new Map<string, string>();
    const axiosCreateRegex = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*axios\s*\.\s*create\s*\(\s*\{[\s\S]{0,300}?baseURL\s*:\s*([^,}\n]+)[\s\S]{0,300}?\}\s*\)/g;
    let axiosCreateMatch;
    while ((axiosCreateMatch = axiosCreateRegex.exec(content)) !== null) {
        const baseUrl = safeResolveStringExpression(axiosCreateMatch[2], emptyConstants);
        if (baseUrl) {
            axiosInstances.set(axiosCreateMatch[1], baseUrl);
        }
    }

    const methodCallRegex = /([A-Za-z_$][\w$]*|axios|fetch)\s*(?:\.\s*(get|post|put|delete|patch))?\s*\(\s*([^,\n)]+)(?:,\s*(\{[\s\S]{0,250}?\}))?/g;
    let methodCallMatch;
    while ((methodCallMatch = methodCallRegex.exec(content)) !== null) {
        const clientName = methodCallMatch[1];
        const explicitMethod = methodCallMatch[2];
        const targetExpression = methodCallMatch[3];
        const configExpression = methodCallMatch[4] || "";

        const methodMatch = configExpression.match(/\bmethod\s*:\s*['"`]?([A-Za-z]+)['"`]?/i);
        const method = explicitMethod || methodMatch?.[1] || (clientName === "fetch" ? "GET" : undefined);
        const resolvedTarget = safeResolveStringExpression(targetExpression, emptyConstants);
        if (!resolvedTarget) continue;

        const axiosBase = axiosInstances.get(clientName);
        const combinedTarget = axiosBase && resolvedTarget.startsWith("/")
            ? `${axiosBase.replace(/\/$/, "")}${resolvedTarget}`
            : resolvedTarget;
        pushApiEndpoint(endpoints, seen, combinedTarget, source, method);
    }

    const requestObjectRegex = /([A-Za-z_$][\w$]*(?:\.\s*request)?|axios)\s*\(\s*\{([\s\S]{0,300}?)\}\s*\)/g;
    let requestObjectMatch;
    while ((requestObjectMatch = requestObjectRegex.exec(content)) !== null) {
        const callee = requestObjectMatch[1].replace(/\s+/g, "");
        const objectBody = requestObjectMatch[2];
        const urlMatch = objectBody.match(/\burl\s*:\s*([^,}\n]+)/);
        if (!urlMatch) continue;

        const methodMatch = objectBody.match(/\bmethod\s*:\s*['"`]?([A-Za-z]+)['"`]?/i);
        const resolvedUrl = safeResolveStringExpression(urlMatch[1], emptyConstants);
        if (!resolvedUrl) continue;

        const instanceName = callee.replace(/\.request$/, "");
        const axiosBase = axiosInstances.get(instanceName);
        const combinedTarget = axiosBase && resolvedUrl.startsWith("/")
            ? `${axiosBase.replace(/\/$/, "")}${resolvedUrl}`
            : resolvedUrl;
        pushApiEndpoint(endpoints, seen, combinedTarget, source, methodMatch?.[1]);
    }
}

function extractApisFromJsChunked(content: string, source: string): ApiEndpoint[] {
    const endpoints: ApiEndpoint[] = [];
    const seen = new Set<string>();
    const chunkStep = Math.max(1, BUNDLE_SCAN_CHUNK_SIZE - BUNDLE_SCAN_CHUNK_OVERLAP);
    let collectedLiteralCount = 0;

    for (let start = 0; start < content.length; start += chunkStep) {
        const chunk = content.slice(start, start + BUNDLE_SCAN_CHUNK_SIZE);
        if (!chunk) continue;

        if (collectedLiteralCount < MAX_LITERAL_SCAN_MATCHES) {
            const remaining = MAX_LITERAL_SCAN_MATCHES - collectedLiteralCount;
            const literals = collectLiteralCandidates(chunk, remaining);
            for (const literal of literals) {
                const value = literal.value.trim();
                pushApiEndpoint(endpoints, seen, value, source);
            }
            collectedLiteralCount += literals.length;
        }

        scanDirectApiCallsFromChunk(chunk, source, endpoints, seen);
    }

    return endpoints;
}

// Extract API endpoints from JavaScript content
function extractApisFromJs(content: string, source: string): ApiEndpoint[] {
    const endpoints: ApiEndpoint[] = [];
    const seen = new Set<string>();
    const constants = collectResolvableConstants(content);
    
    // Try to use Sentinel AST API if available
    let literals: Array<{ value: string; line: number }> = [];
    
    try {
        if (typeof Sentinel !== "undefined" && Sentinel.AST) {
            const result = Sentinel.AST.parse(content, source);
            literals = result.literals;
        }
    } catch {
        // Fall back to regex
    }
    
    if (literals.length === 0) {
        literals = collectLiteralCandidates(content, MAX_LITERAL_SCAN_MATCHES);
    }
    
    for (const literal of literals) {
        const value = literal.value.trim();
        pushApiEndpoint(endpoints, seen, value, source);
    }

    for (const value of constants.values()) {
        pushApiEndpoint(endpoints, seen, value, source);
    }
    
    const axiosInstances = new Map<string, string>();
    const axiosCreateRegex = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*axios\s*\.\s*create\s*\(\s*\{[\s\S]{0,300}?baseURL\s*:\s*([^,}\n]+)[\s\S]{0,300}?\}\s*\)/g;
    let axiosCreateMatch;
    while ((axiosCreateMatch = axiosCreateRegex.exec(content)) !== null) {
        const baseUrl = safeResolveStringExpression(axiosCreateMatch[2], constants);
        if (baseUrl) {
            axiosInstances.set(axiosCreateMatch[1], baseUrl);
        }
    }

    const methodCallRegex = /([A-Za-z_$][\w$]*|axios|fetch)\s*(?:\.\s*(get|post|put|delete|patch))?\s*\(\s*([^,\n)]+)(?:,\s*(\{[\s\S]{0,250}?\}))?/g;
    let methodCallMatch;
    while ((methodCallMatch = methodCallRegex.exec(content)) !== null) {
        const clientName = methodCallMatch[1];
        const explicitMethod = methodCallMatch[2];
        const targetExpression = methodCallMatch[3];
        const configExpression = methodCallMatch[4] || "";

        const methodMatch = configExpression.match(/\bmethod\s*:\s*['"`]?([A-Za-z]+)['"`]?/i);
        const method = explicitMethod || methodMatch?.[1] || (clientName === "fetch" ? "GET" : undefined);
        const resolvedTarget = safeResolveStringExpression(targetExpression, constants);
        if (!resolvedTarget) continue;

        const axiosBase = axiosInstances.get(clientName);
        const combinedTarget = axiosBase && resolvedTarget.startsWith("/")
            ? `${axiosBase.replace(/\/$/, "")}${resolvedTarget}`
            : resolvedTarget;
        pushApiEndpoint(endpoints, seen, combinedTarget, source, method);
    }

    const requestObjectRegex = /([A-Za-z_$][\w$]*(?:\.\s*request)?|axios)\s*\(\s*\{([\s\S]{0,300}?)\}\s*\)/g;
    let requestObjectMatch;
    while ((requestObjectMatch = requestObjectRegex.exec(content)) !== null) {
        const callee = requestObjectMatch[1].replace(/\s+/g, "");
        const objectBody = requestObjectMatch[2];
        const urlMatch = objectBody.match(/\burl\s*:\s*([^,}\n]+)/);
        if (!urlMatch) continue;

        const methodMatch = objectBody.match(/\bmethod\s*:\s*['"`]?([A-Za-z]+)['"`]?/i);
        const resolvedUrl = safeResolveStringExpression(urlMatch[1], constants);
        if (!resolvedUrl) continue;

        const instanceName = callee.replace(/\.request$/, "");
        const axiosBase = axiosInstances.get(instanceName);
        const combinedTarget = axiosBase && resolvedUrl.startsWith("/")
            ? `${axiosBase.replace(/\/$/, "")}${resolvedUrl}`
            : resolvedUrl;
        pushApiEndpoint(endpoints, seen, combinedTarget, source, methodMatch?.[1]);
    }
    
    return endpoints;
}

function safeExtractApisFromJs(content: string, source: string): ApiEndpoint[] {
    if (content.length > LARGE_BUNDLE_SOURCE_LENGTH) {
        return extractApisFromJsChunked(content, source);
    }

    try {
        return extractApisFromJs(content, source);
    } catch {
        return extractApisFromJsChunked(content, source);
    }
}

function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, "0");
}

function resolveUrl(base: string, relative: string): string {
    if (!relative || typeof relative !== "string") return "";
    const normalizedRelative = relative.trim();
    if (!normalizedRelative) return "";

    try {
        if (normalizedRelative.startsWith("//")) {
            const baseUrl = new URL(base);
            return `${baseUrl.protocol}${normalizedRelative}`;
        }
        return new URL(normalizedRelative, base).href;
    } catch {
        return "";
    }
}

function isSameOrigin(baseUrl: string, targetUrl: string): boolean {
    try {
        return new URL(baseUrl).origin === new URL(targetUrl).origin;
    } catch {
        return false;
    }
}

function looksLikeJs(path: string): boolean {
    if (!path) return false;
    const clean = path.split("?")[0].split("#")[0];
    if (/\.(?:js|mjs|cjs|jsx|ts|tsx)$/i.test(clean)) return true;
    if (/\.[a-f0-9]{6,10}\.js$/i.test(clean)) return true;
    if (/(?:chunk|bundle|vendor|app|main|index)\.[a-f0-9]+/i.test(clean)) return true;
    return false;
}

async function fetchWithTimeout(
    url: string,
    timeout: number,
    userAgent: string,
    accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,*/*;q=0.8",
): Promise<FetchResult | null> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, {
            headers: {
                "User-Agent": userAgent,
                "Accept": accept,
                "Accept-Language": "en-US,en;q=0.5",
            },
            signal: controller.signal,
            redirect: "follow",
        });

        clearTimeout(timeoutId);
        const text = await response.text();
        return { ok: response.ok, status: response.status, text, size: text.length, contentType: response.headers.get("content-type") || "", finalUrl: response.url || url };
    } catch (error: any) {
        clearTimeout(timeoutId);
        const message = error?.name === "AbortError"
            ? `Request timed out after ${timeout}ms`
            : (error?.message || String(error) || "Unknown fetch error");
        return { ok: false, status: null, text: "", size: 0, contentType: "", finalUrl: url, error: message };
    }
}

function canAnalyzePageResponse(result: FetchResult): boolean {
    const text = String(result.text || "").trim();
    const contentType = String(result.contentType || "").toLowerCase();
    return Boolean(text) && (!contentType || contentType.includes("text/html") || contentType.includes("application/xhtml+xml") || contentType.includes("javascript") || contentType.includes("ecmascript") || contentType.includes("text/plain"));
}
function describeTargetFetchFailure(result: FetchResult | null): string {
    if (!result) return "Failed to fetch target page";
    if (result.error) return `Failed to fetch target page: ${result.error}`;
    if (typeof result.status === "number") return `Target page returned HTTP ${result.status}`;
    return "Failed to fetch target page";
}
function looksLikeHtmlDocument(contentType: string, text: string): boolean {
    const normalized = String(contentType || "").toLowerCase();
    const preview = String(text || "").trim().slice(0, 256).toLowerCase();
    return normalized.includes("text/html") || normalized.includes("application/xhtml+xml")
        || preview.startsWith("<!doctype html") || preview.startsWith("<html")
        || preview.includes("<head") || preview.includes("<body");
}
function isLikelyApiProbeResponse(requestUrl: string, path: string, response: HttpProbeResult): boolean {
    const content = String(response.text || "").trim();
    const contentType = String(response.contentType || "").toLowerCase();
    if (!content || looksLikeHtmlDocument(contentType, content)) return false;
    try {
        const requestedPath = new URL(requestUrl).pathname;
        const finalPath = new URL(response.finalUrl || requestUrl).pathname;
        if (requestedPath !== finalPath && (finalPath === "/" || finalPath === "/index.html")) return false;
    } catch {}
    if (path.includes("swagger") || path.includes("openapi") || path.includes("api-docs")) {
        const lowered = content.toLowerCase();
        return lowered.includes("\"openapi\"") || lowered.includes("\"swagger\"") || lowered.includes("openapi:") || lowered.includes("swagger:");
    }
    return contentType.includes("json") || contentType.includes("xml") || contentType.includes("graphql") || content.startsWith("{") || content.startsWith("[") || content.startsWith("<?xml") || ((response.status === 401 || response.status === 403 || response.status === 405) && !content.includes("<"));
}
function isPreviewableContentType(contentType: string): boolean {
    const normalized = String(contentType || "").toLowerCase();
    if (!normalized) return true;
    return normalized.includes("json") || normalized.includes("text/") || normalized.includes("javascript") || normalized.includes("xml") || normalized.includes("html") || normalized.includes("graphql") || normalized.includes("x-www-form-urlencoded");
}
function normalizeResponsePreview(text: string): string {
    const normalized = String(text || "").replace(/\0/g, "").trim();
    if (normalized.length <= MAX_RESPONSE_PREVIEW_CHARS) return normalized;
    return `${normalized.slice(0, MAX_RESPONSE_PREVIEW_CHARS)}\n...[truncated]`;
}
async function fetchHttpProbe(
    url: string,
    timeout: number,
    userAgent: string,
    method = "GET",
    accept = "application/json,text/plain,*/*",
    body?: string,
): Promise<HttpProbeResult | null> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, {
            method,
            headers: {
                "User-Agent": userAgent,
                "Accept": accept,
                "Accept-Language": "en-US,en;q=0.5",
                ...(body ? { "Content-Type": "application/json" } : {}),
            },
            ...(body ? { body } : {}),
            signal: controller.signal,
            redirect: "follow",
        });

        clearTimeout(timeoutId);

        const contentType = response.headers.get("content-type") || "";
        const previewable = isPreviewableContentType(contentType);
        const text = previewable
            ? await response.text()
            : `[non-text content omitted: ${contentType || "unknown"}]`;

        return {
            ok: response.ok,
            status: response.status,
            text,
            size: Number(response.headers.get("content-length")) || text.length,
            contentType,
            finalUrl: response.url || url,
            fetchedAt: new Date().toISOString(),
        };
    } catch {
        clearTimeout(timeoutId);
        return null;
    }
}

function resolveEndpointRequestUrl(baseUrl: string, path: string): string {
    return resolveUrl(baseUrl, path) || path;
}

function isDynamicEndpointPath(path: string): boolean {
    return /(^|\/)(:\w+|\{\w+\}|\*)/.test(String(path || ""));
}

async function captureEndpointResponse(
    endpoint: ApiEndpoint,
    baseUrl: string,
    timeout: number,
    userAgent: string,
): Promise<ApiEndpoint> {
    const enriched: ApiEndpoint = { ...endpoint };
    const requestUrl = resolveEndpointRequestUrl(baseUrl, endpoint.path);
    const requestMethod = String(endpoint.method || "GET").trim().toUpperCase() || "GET";

    enriched.requestUrl = requestUrl;
    enriched.requestMethod = requestMethod;

    if (
        enriched.responseFetchedAt
        || enriched.responseError
        || typeof enriched.responseStatus === "number"
    ) {
        return enriched;
    }

    if (!SAFE_RESPONSE_PROBE_METHODS.has(requestMethod)) {
        enriched.responseError = `Skipped unsafe method probing for ${requestMethod}`;
        return enriched;
    }

    if (isDynamicEndpointPath(endpoint.path)) {
        enriched.responseError = "Skipped probing dynamic endpoint template";
        return enriched;
    }

    const response = await fetchHttpProbe(
        requestUrl,
        timeout,
        userAgent,
        requestMethod,
        "application/json,text/plain,text/html,application/xml,*/*",
    );

    if (!response) {
        enriched.responseError = "Failed to fetch endpoint response";
        return enriched;
    }

    enriched.responseStatus = response.status;
    enriched.responseContentType = response.contentType;
    enriched.responseSize = response.size;
    enriched.responseFetchedAt = response.fetchedAt;
    enriched.requestUrl = response.finalUrl || requestUrl;
    enriched.responsePreview = normalizeResponsePreview(response.text);
    if (!response.ok) {
        enriched.responseError = `Received HTTP ${response.status}`;
    }

    return enriched;
}

function extractScriptTags(html: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    const scriptTagRegex = /<script\b([^>]*)>/gi;
    let match;

    while ((match = scriptTagRegex.exec(html)) !== null) {
        const attrs = match[1];
        const srcMatch = attrs.match(/\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        if (srcMatch) {
            const src = srcMatch[1] || srcMatch[2] || srcMatch[3];
            if (src) {
                const url = resolveUrl(baseUrl, src);
                if (url && !seenUrls.has(url)) {
                    seenUrls.add(url);
                    links.push({
                        url,
                        type: /\btype\s*=\s*["']?module["']?/i.test(attrs) ? "module" : "external",
                        source: "script_tag",
                    });
                }
            }
        }

        const dataSrcMatch = attrs.match(/\bdata-src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        if (dataSrcMatch) {
            const src = dataSrcMatch[1] || dataSrcMatch[2] || dataSrcMatch[3];
            if (src) {
                const url = resolveUrl(baseUrl, src);
                if (url && !seenUrls.has(url)) {
                    seenUrls.add(url);
                    links.push({ url, type: "external", source: "script_data_src" });
                }
            }
        }
    }

    return links;
}

function extractLinkTags(html: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    const linkTagRegex = /<link\b([^>]*)>/gi;
    let match;

    while ((match = linkTagRegex.exec(html)) !== null) {
        const attrs = match[1];
        const hrefMatch = attrs.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        if (!hrefMatch) continue;

        const href = hrefMatch[1] || hrefMatch[2] || hrefMatch[3];
        if (!href) continue;

        const relMatch = attrs.match(/\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        const rel = (relMatch ? (relMatch[1] || relMatch[2] || relMatch[3]) : "").toLowerCase();
        const asMatch = attrs.match(/\bas\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        const as = (asMatch ? (asMatch[1] || asMatch[2] || asMatch[3]) : "").toLowerCase();

        const url = resolveUrl(baseUrl, href);
        if (!url || seenUrls.has(url)) continue;

        if (rel === "modulepreload") {
            seenUrls.add(url);
            links.push({ url, type: "module", source: "modulepreload" });
        } else if ((rel === "preload" || rel === "prefetch") && as === "script") {
            seenUrls.add(url);
            links.push({ url, type: "module", source: rel });
        } else if (looksLikeJs(href)) {
            seenUrls.add(url);
            links.push({ url, type: "dynamic", source: "link_tag" });
        }
    }

    return links;
}

function extractInlineScripts(html: string): Array<{ content: string; hash: string }> {
    const scripts: Array<{ content: string; hash: string }> = [];
    const inlineRegex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
    let match;

    while ((match = inlineRegex.exec(html)) !== null) {
        const attrs = match[1];
        const content = match[2];
        if (/\bsrc\s*=/i.test(attrs)) continue;
        if (!content || content.trim().length < 10) continue;

        scripts.push({
            content: content.trim(),
            hash: simpleHash(content),
        });
    }

    return scripts;
}

function pushDiscoveredJsLink(
    links: JsLink[],
    seenUrls: Set<string>,
    baseUrl: string,
    candidate: string,
    type: JsLink["type"],
    source: string,
) {
    const normalizedCandidate = String(candidate || "")
        .trim()
        .replace(/\\u002F/gi, "/")
        .replace(/\\\//g, "/");
    if (!normalizedCandidate || normalizedCandidate.startsWith("data:") || normalizedCandidate.includes("{{")) {
        return;
    }

    const url = resolveUrl(baseUrl, normalizedCandidate);
    if (!url || seenUrls.has(url)) return;
    if (type !== "sourcemap" && !looksLikeJs(url)) return;

    seenUrls.add(url);
    links.push({ url, type, source });
}

function extractJsFromContent(content: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    let match;

    const esImportRegex = /import\s+(?:[\w\s{},*]+\s+from\s+)?["']([^"']+)["']/g;
    while ((match = esImportRegex.exec(content)) !== null) {
        const path = match[1];
        if (looksLikeJs(path) || !path.startsWith(".")) {
            pushDiscoveredJsLink(links, seenUrls, baseUrl, path, "module", "es_import");
        }
    }

    const dynamicImportRegex = /import\s*\(\s*["']([^"']+)["']\s*\)/g;
    while ((match = dynamicImportRegex.exec(content)) !== null) {
        pushDiscoveredJsLink(links, seenUrls, baseUrl, match[1], "dynamic", "dynamic_import");
    }

    const requireRegex = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
    while ((match = requireRegex.exec(content)) !== null) {
        pushDiscoveredJsLink(links, seenUrls, baseUrl, match[1], "dynamic", "require");
    }

    const sourceMapRegex = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
    while ((match = sourceMapRegex.exec(content)) !== null) {
        pushDiscoveredJsLink(links, seenUrls, baseUrl, match[1], "sourcemap", "sourcemap");
    }

    const jsUrlRegex = /["']([^"'\s]*?(?:\/assets\/|\/static\/|\/js\/|\/dist\/|\/build\/|\/chunks?\/)?[^"'\s]*?\.[a-f0-9]{6,10}\.js(?:\?[^"'\s]*)?)["']/gi;
    while ((match = jsUrlRegex.exec(content)) !== null) {
        pushDiscoveredJsLink(links, seenUrls, baseUrl, match[1], "webpack", "js_string");
    }

    const simpleJsRegex = /["']((?:\/|\.\.?\/)[^"'\s]+\.js(?:\?[^"'\s]*)?)["']/g;
    while ((match = simpleJsRegex.exec(content)) !== null) {
        pushDiscoveredJsLink(links, seenUrls, baseUrl, match[1], "dynamic", "js_path");
    }

    const frameworkChunkRegex = /["']((?:https?:\/\/[^"'\\\s]+|(?:\\\/|\/)(?:_next|_nuxt|assets|static|build|dist|js|chunks?|webpack|runtime)[^"'\\\s]+?\.js(?:\?[^"'\\\s]*)?|(?:[A-Za-z0-9_-]+\/)+(?:chunks?|assets|static|js)\/[^"'\\\s]+?\.js(?:\?[^"'\\\s]*)?))["']/gi;
    while ((match = frameworkChunkRegex.exec(content)) !== null) {
        pushDiscoveredJsLink(links, seenUrls, baseUrl, match[1], "webpack", "framework_chunk");
    }

    const escapedChunkRegex = /((?:\\\/)+(?:_next|_nuxt|assets|static|build|dist|js|chunks?|webpack|runtime)(?:[^"'\\]|\\.)+?\.js(?:\?[^"'\\\s]*)?)/gi;
    while ((match = escapedChunkRegex.exec(content)) !== null) {
        pushDiscoveredJsLink(links, seenUrls, baseUrl, match[1], "webpack", "escaped_chunk");
    }

    return links;
}

function resolveSourceMapSourceUrl(mapUrl: string, sourceRoot: string | undefined, sourcePath: string | undefined): string {
    const normalizedSourcePath = String(sourcePath || "").trim();
    if (!normalizedSourcePath) return "";

    const normalizedSourceRoot = String(sourceRoot || "").trim();
    if (normalizedSourceRoot) {
        const rootedUrl = resolveUrl(mapUrl, normalizedSourceRoot.endsWith("/")
            ? `${normalizedSourceRoot}${normalizedSourcePath}`
            : `${normalizedSourceRoot}/${normalizedSourcePath}`);
        if (rootedUrl) return rootedUrl;
    }

    return resolveUrl(mapUrl, normalizedSourcePath);
}

function parseSourceMapScriptContents(mapText: string, mapUrl: string): ScriptContentSource[] {
    const scriptContents: ScriptContentSource[] = [];
    const seenSources = new Set<string>();

    try {
        const queue: SourceMapLike[] = [JSON.parse(mapText) as SourceMapLike];
        let queueIndex = 0;
        while (queueIndex < queue.length) {
            const mapValue = queue[queueIndex++];
            if (!mapValue || typeof mapValue !== "object") {
                continue;
            }

            const sources = Array.isArray(mapValue.sources) ? mapValue.sources : [];
            const sourcesContent = Array.isArray(mapValue.sourcesContent) ? mapValue.sourcesContent : [];

            for (let index = 0; index < sources.length; index += 1) {
                const sourceContent = sourcesContent[index];
                if (typeof sourceContent !== "string" || sourceContent.trim().length < 10) {
                    continue;
                }

                const sourcePath = sources[index];
                const resolvedSource = resolveSourceMapSourceUrl(mapUrl, mapValue.sourceRoot, sourcePath)
                    || `sourcemap://${mapUrl}#${sourcePath || index}`;
                if (seenSources.has(resolvedSource)) {
                    continue;
                }

                seenSources.add(resolvedSource);
                scriptContents.push({
                    source: resolvedSource,
                    content: sourceContent,
                });
            }

            if (Array.isArray(mapValue.sections)) {
                for (const section of mapValue.sections) {
                    if (section?.map && typeof section.map === "object") {
                        queue.push(section.map);
                    }
                }
            }
        }
    } catch {
        return [];
    }

    return scriptContents;
}

function parseManifest(content: string, manifestUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();

    try {
        const json = JSON.parse(content);
        const queue: unknown[] = [json];
        let queueIndex = 0;
        while (queueIndex < queue.length) {
            const current = queue[queueIndex++];
            if (typeof current === "string" && looksLikeJs(current)) {
                const url = resolveUrl(manifestUrl, current);
                if (url && !seenUrls.has(url)) {
                    seenUrls.add(url);
                    links.push({ url, type: "manifest", source: "manifest" });
                }
                continue;
            }

            if (Array.isArray(current)) {
                queue.push(...current);
                continue;
            }

            if (current && typeof current === "object") {
                queue.push(...Object.values(current as Record<string, unknown>));
            }
        }
    } catch {
        const jsRegex = /["']([^"']+\.js(?:\?[^"']*)?)["']/gi;
        let match;
        while ((match = jsRegex.exec(content)) !== null) {
            const url = resolveUrl(manifestUrl, match[1]);
            if (url && !seenUrls.has(url)) {
                seenUrls.add(url);
                links.push({ url, type: "manifest", source: "manifest" });
            }
        }
    }

    return links;
}

function getManifestUrls(baseUrl: string): string[] {
    return [
        "/asset-manifest.json",
        "/manifest.json",
        "/.vite/manifest.json",
        "/build/asset-manifest.json",
        "/static/asset-manifest.json",
    ]
        .map(path => resolveUrl(baseUrl, path))
        .filter(Boolean);
}

function getSameOriginLinks(html: string, baseUrl: string): string[] {
    const links: string[] = [];
    const seenUrls = new Set<string>();
    const linkRegex = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
    let match;

    while ((match = linkRegex.exec(html)) !== null) {
        const href = match[1] || match[2] || match[3];
        if (!href || href.startsWith("#") || href.startsWith("javascript:")) continue;

        const url = resolveUrl(baseUrl, href);
        if (url && !seenUrls.has(url) && isSameOrigin(baseUrl, url)) {
            const path = new URL(url).pathname;
            if (!/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip)$/i.test(path)) {
                seenUrls.add(url);
                links.push(url);
            }
        }
    }

    return links;
}

function pushJsLink(
    collectedLinks: JsLink[],
    seenUrls: Set<string>,
    link: JsLink,
    maxJsFiles: number,
    includeSameOriginOnly: boolean,
    baseUrl: string,
) {
    if (collectedLinks.length >= maxJsFiles) return;
    if (!link.url || seenUrls.has(link.url)) return;
    if (includeSameOriginOnly && !isSameOrigin(baseUrl, link.url)) return;

    seenUrls.add(link.url);
    collectedLinks.push(link);
}

async function discoverJavascriptAssets(
    baseUrl: string,
    initialHtml: string,
    timeout: number,
    userAgent: string,
    crawlDepth: number,
    maxJsFiles: number,
    includeSameOriginOnly: boolean,
    followSourceMaps: boolean,
    probeSpaManifests: boolean,
): Promise<JsDiscoveryResult> {
    const jsLinks: JsLink[] = [];
    const scriptContents: ScriptContentSource[] = [];
    const crawledPages: string[] = [baseUrl];
    const seenJsUrls = new Set<string>();
    const pagesToCrawl: Array<{ url: string; depth: number; html?: string }> = [
        { url: baseUrl, depth: 0, html: initialHtml },
    ];
    const visitedPages = new Set<string>();

    while (pagesToCrawl.length > 0 && jsLinks.length < maxJsFiles) {
        const current = pagesToCrawl.shift();
        if (!current || visitedPages.has(current.url)) {
            continue;
        }
        visitedPages.add(current.url);

        let html = current.html;
        if (typeof html !== "string") {
            const pageResult = await fetchWithTimeout(current.url, timeout, userAgent);
            if (!pageResult || !pageResult.ok) {
                continue;
            }
            html = pageResult.text;
            crawledPages.push(current.url);
        }

        for (const link of extractScriptTags(html, current.url)) {
            pushJsLink(jsLinks, seenJsUrls, link, maxJsFiles, includeSameOriginOnly, baseUrl);
        }
        for (const link of extractLinkTags(html, current.url)) {
            pushJsLink(jsLinks, seenJsUrls, link, maxJsFiles, includeSameOriginOnly, baseUrl);
        }

        for (const inlineScript of extractInlineScripts(html)) {
            scriptContents.push({
                source: `inline://${current.url}#${inlineScript.hash}`,
                content: inlineScript.content,
            });
            for (const link of extractJsFromContent(inlineScript.content, current.url)) {
                pushJsLink(jsLinks, seenJsUrls, link, maxJsFiles, includeSameOriginOnly, baseUrl);
            }
        }

        if (crawlDepth > 1 && current.depth < crawlDepth - 1) {
            for (const pageUrl of getSameOriginLinks(html, current.url).slice(0, DEFAULT_PAGE_CRAWL_LIMIT)) {
                if (!visitedPages.has(pageUrl)) {
                    pagesToCrawl.push({ url: pageUrl, depth: current.depth + 1 });
                }
            }
        }
    }

    if (probeSpaManifests && jsLinks.length < maxJsFiles) {
        const manifestResults = await runSequentially(getManifestUrls(baseUrl).map(manifestUrl => async () => ({
                manifestUrl,
                result: await fetchWithTimeout(manifestUrl, timeout, userAgent, "application/json,*/*"),
            })));

        for (const { manifestUrl, result } of manifestResults) {
            if (!result || !result.ok || !result.contentType.includes("json")) {
                continue;
            }
            for (const link of parseManifest(result.text, manifestUrl)) {
                pushJsLink(jsLinks, seenJsUrls, link, maxJsFiles, includeSameOriginOnly, baseUrl);
            }
        }
    }

    if (crawlDepth > 0 && jsLinks.length > 0) {
        const jsFetchQueue = jsLinks
            .filter(link => followSourceMaps || link.type !== "sourcemap")
            .slice(0, maxJsFiles);
        const visitedScriptUrls = new Set<string>();

        while (jsFetchQueue.length > 0 && scriptContents.length < maxJsFiles * 2) {
            const batch = jsFetchQueue.splice(0, 1);
            const batchResults = await runSequentially(batch.map(link => async () => ({
                    link,
                    result: await fetchWithTimeout(
                        link.url,
                        timeout,
                        userAgent,
                        link.type === "sourcemap"
                            ? "application/json,text/plain,*/*"
                            : "application/javascript,text/javascript,text/plain,*/*",
                    ),
                })));

            for (const { link, result } of batchResults) {
                if (visitedScriptUrls.has(link.url)) {
                    continue;
                }
                visitedScriptUrls.add(link.url);
                if (!result || !result.ok) {
                    continue;
                }

                link.size = result.size;
                if (link.type === "sourcemap") {
                    for (const sourceContent of parseSourceMapScriptContents(result.text, link.url)) {
                        scriptContents.push(sourceContent);
                    }
                    continue;
                }

                scriptContents.push({
                    source: link.url,
                    content: result.text,
                });

                for (const nestedLink of extractJsFromContent(result.text, link.url)) {
                    if (nestedLink.type === "sourcemap" && !followSourceMaps) {
                        continue;
                    }
                    if (!seenJsUrls.has(nestedLink.url)) {
                        pushJsLink(
                            jsLinks,
                            seenJsUrls,
                            nestedLink,
                            maxJsFiles,
                            includeSameOriginOnly,
                            baseUrl,
                        );
                        if (!visitedScriptUrls.has(nestedLink.url) && nestedLink.type !== "inline") {
                            jsFetchQueue.push(nestedLink);
                        }
                    }
                }
            }
        }
    }

    return {
        jsLinks,
        scriptContents,
        crawledPages,
    };
}

// Calculate risk score
function calculateRiskScore(severity: string, eventType: string, count: number): number {
    let score = 0;
    
    switch (severity) {
        case "critical": score += 40; break;
        case "high": score += 30; break;
        case "medium": score += 20; break;
        case "low": score += 10; break;
    }
    
    switch (eventType) {
        case "api_endpoints_added": score += 20; break;
        case "api_endpoints_removed": score += 15; break;
        case "api_change": score += 15; break;
        case "graphql_discovered": score += 20; break;
        case "openapi_discovered": score += 15; break;
    }
    
    // Bonus for multiple changes
    score += Math.min(count * 2, 20);
    
    return Math.min(score, 100);
}

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        required: ["targets"],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "List of base URLs to monitor for API changes"
            },
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: 3000,
                minimum: 3000,
                maximum: 5000
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            crawlDepth: {
                type: "integer",
                description: "Depth to crawl for JS discovery (0 = current page only, 1 = current page + JS bundles, 2+ = crawl same-origin pages)",
                default: 1,
                minimum: 0,
                maximum: 3
            },
            maxJsFiles: {
                type: "integer",
                description: "Maximum JavaScript files to analyze per target",
                default: 100,
                minimum: 10,
                maximum: 300
            },
            includeSameOriginOnly: {
                type: "boolean",
                description: "Only analyze JavaScript assets from the same origin",
                default: false
            },
            followSourceMaps: {
                type: "boolean",
                description: "Follow sourceMappingURL references during JS discovery",
                default: false
            },
            probeSpaManifests: {
                type: "boolean",
                description: "Probe common SPA manifest endpoints to discover bundled JS",
                default: true
            },
            includeGraphQL: {
                type: "boolean",
                description: "Check for GraphQL endpoints",
                default: false
            },
            includeOpenAPI: {
                type: "boolean",
                description: "Check for OpenAPI/Swagger specs",
                default: false
            },
            previousSnapshots: {
                type: "object",
                description: "Previous API snapshots for comparison"
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
                    results: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                baseUrl: { type: "string" },
                                success: { type: "boolean" },
                                snapshot: {
                                    type: "object",
                                    properties: {
                                        baseUrl: { type: "string" },
                                        graphqlEndpoint: { type: "string" },
                                        openApiSpec: { type: "string" },
                                        lastChecked: { type: "string" },
                                        endpoints: {
                                            type: "array",
                                            items: {
                                                type: "object",
                                                properties: {
                                                    path: { type: "string" },
                                                    method: { type: "string" },
                                                    source: { type: "string" },
                                                    requestUrl: { type: "string" },
                                                    requestMethod: { type: "string" },
                                                    responseStatus: { type: "integer" },
                                                    responseContentType: { type: "string" },
                                                    responsePreview: { type: "string" },
                                                    responseFetchedAt: { type: "string" },
                                                    responseError: { type: "string" },
                                                    responseSize: { type: "integer" },
                                                }
                                            }
                                        }
                                    }
                                },
                                addedEndpoints: { type: "array" },
                                removedEndpoints: { type: "array" }
                            }
                        },
                        description: "API monitoring results"
                    },
                    changeEvents: { type: "array", description: "Change events detected" },
                    snapshots: { type: "object", description: "API snapshots by URL" },
                    summary: {
                        type: "object",
                        properties: {
                            totalTargets: { type: "integer" },
                            totalEndpoints: { type: "integer" },
                            totalJsFiles: { type: "integer" },
                            addedEndpoints: { type: "integer" },
                            removedEndpoints: { type: "integer" }
                        }
                    }
                }
            },
            error: { type: "string", description: "Error message if failed" }
        }
    };
}

pluginGlobals.get_output_schema = get_output_schema;

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!input.targets || !Array.isArray(input.targets)) {
            return {
                success: false,
                error: "Invalid input: targets array is required"
            };
        }
        
        // Filter out empty strings
        const validTargets = input.targets.filter(t => typeof t === 'string' && t.trim().length > 0);
        if (validTargets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets array must contain at least one non-empty string"
            };
        }
        
        const timeout = Math.max(3000, Math.min(input.timeout || 3000, 5000));
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const crawlDepth = input.crawlDepth ?? 1;
        const maxJsFiles = Math.max(10, Math.min(input.maxJsFiles || DEFAULT_MAX_JS_FILES, 300));
        const includeSameOriginOnly = input.includeSameOriginOnly === true;
        const followSourceMaps = input.followSourceMaps === true;
        const probeSpaManifests = input.probeSpaManifests !== false;
        const includeGraphQL = input.includeGraphQL !== false;
        const includeOpenAPI = input.includeOpenAPI !== false;
        const previousSnapshots = input.previousSnapshots || {};
        const monitorExecution = input.__monitorExecution;
        const totalProgressUnits = validTargets.length + 2;

        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: totalProgressUnits,
            phase: "prepare",
            message: "Preparing API discovery",
        });
        
        const results: ApiResult[] = [];
        const changeEvents: ChangeEvent[] = [];
        const newSnapshots: Record<string, ApiSnapshot> = {};
        
        let successfulChecks = 0;
        let failedChecks = 0;
        let totalEndpoints = 0;
        let totalJsFiles = 0;
        let addedEndpointsCount = 0;
        let removedEndpointsCount = 0;
        let apiChanges = 0;
        let completedTargets = 0;
        
        const targetTasks = validTargets.map((target) => async () => {
            let baseUrl = target;
            if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
                baseUrl = `https://${baseUrl}`;
            }
            
            const result: ApiResult = {
                baseUrl,
                success: false,
            };
            
            try {
                const allEndpoints: ApiEndpoint[] = [];
                let graphqlEndpoint: string | undefined;
                let openApiSpec: string | undefined;
                let jsFilesAnalyzed = 0;
                
                const pageResult = await fetchWithTimeout(
                    baseUrl,
                    timeout,
                    userAgent,
                    "text/html,application/xhtml+xml,*/*",
                );

                if (pageResult.status === null) {
                    result.error = describeTargetFetchFailure(pageResult);
                    failedChecks++;
                    results.push(result);
                    return;
                }
                
                successfulChecks++;

                const pageContent = canAnalyzePageResponse(pageResult) ? pageResult.text : "";
                const directJsTarget = Boolean(pageContent) && (looksLikeJs(baseUrl) || pageResult.contentType.includes("javascript"));
                const scriptSources = !pageContent ? [] : directJsTarget ? [{ source: baseUrl, content: pageContent }] : (await discoverJavascriptAssets(baseUrl, pageContent, timeout, userAgent, crawlDepth, maxJsFiles, includeSameOriginOnly, followSourceMaps, probeSpaManifests)).scriptContents;

                jsFilesAnalyzed = directJsTarget
                    ? 1
                    : scriptSources.filter(source => !source.source.startsWith("inline://")).length;
                totalJsFiles += jsFilesAnalyzed;

                for (const source of scriptSources) {
                    try {
                        const endpoints = safeExtractApisFromJs(source.content, source.source);
                        allEndpoints.push(...endpoints);
                    } catch {
                        continue;
                    }
                }
                
                // Check common API paths
                const urlObj = new URL(baseUrl);
                // Check GraphQL
                if (includeGraphQL) {
                    const graphqlMatches = await runSequentially(["/graphql", "/gql", "/api/graphql"].map((gqlPath) => async () => {
                            try {
                                const gqlUrl = `${urlObj.origin}${gqlPath}`;
                                const gqlResponse = await fetchHttpProbe(
                                    gqlUrl,
                                    3000,
                                    userAgent,
                                    "POST",
                                    "application/json,*/*",
                                    JSON.stringify({ query: "{ __typename }" }),
                                );

                                if (!gqlResponse?.ok) return null;
                                const gqlResult = gqlResponse.text;
                                if (gqlResult.includes("__typename") || gqlResult.includes("data")) {
                                    return {
                                        path: gqlPath,
                                        requestUrl: gqlResponse.finalUrl || gqlUrl,
                                        responseStatus: gqlResponse.status,
                                        responseContentType: gqlResponse.contentType,
                                        responsePreview: normalizeResponsePreview(gqlResult),
                                        responseFetchedAt: gqlResponse.fetchedAt,
                                        responseSize: gqlResponse.size,
                                    };
                                }
                            } catch {
                                // GraphQL not available
                            }
                            return null;
                        }));

                    const discoveredGraphql = graphqlMatches.find((value): value is {
                        path: string;
                        requestUrl: string;
                        responseStatus: number;
                        responseContentType: string;
                        responsePreview: string;
                        responseFetchedAt: string;
                        responseSize: number;
                    } => Boolean(value));
                    if (discoveredGraphql) {
                        graphqlEndpoint = discoveredGraphql.requestUrl || discoveredGraphql.path;
                        allEndpoints.push({
                            path: discoveredGraphql.path,
                            method: "POST",
                            source: "graphql-probe",
                            requestUrl: discoveredGraphql.requestUrl,
                            requestMethod: "POST",
                            responseStatus: discoveredGraphql.responseStatus,
                            responseContentType: discoveredGraphql.responseContentType,
                            responsePreview: discoveredGraphql.responsePreview,
                            responseFetchedAt: discoveredGraphql.responseFetchedAt,
                            responseSize: discoveredGraphql.responseSize,
                        });
                    }
                }
                
                // Deduplicate endpoints
                const uniqueEndpoints: ApiEndpoint[] = [];
                const seen = new Set<string>();
                for (const ep of allEndpoints) {
                    const key = `${ep.method || ""}:${ep.path}`;
                    if (!seen.has(key)) {
                        seen.add(key);
                        uniqueEndpoints.push(ep);
                    }
                }
                
                const enrichedEndpoints = await runSequentially(uniqueEndpoints.map((endpoint) => async () =>
                        captureEndpointResponse(endpoint, baseUrl, timeout, userAgent)
                    ));

                totalEndpoints += enrichedEndpoints.length;
                
                // Create snapshot
                const snapshot: ApiSnapshot = {
                    baseUrl,
                    endpoints: enrichedEndpoints,
                    graphqlEndpoint,
                    openApiSpec,
                    lastChecked: new Date().toISOString(),
                };
                
                result.success = true;
                result.snapshot = snapshot;
                newSnapshots[baseUrl] = snapshot;

                await reportMonitorProgress(monitorExecution, {
                    current: completedTargets + 1,
                    total: totalProgressUnits,
                    phase: "scan",
                    currentTarget: baseUrl,
                    message: `Analyzed ${jsFilesAnalyzed} JS files and discovered ${enrichedEndpoints.length} API endpoints`,
                });
                
                // Compare with previous snapshot
                const prevSnapshot = previousSnapshots[baseUrl];
                if (prevSnapshot) {
                    const prevPaths = new Set(prevSnapshot.endpoints.map(e => `${e.method || ""}:${e.path}`));
                    const newPaths = new Set(enrichedEndpoints.map(e => `${e.method || ""}:${e.path}`));
                    
                    // Find added endpoints
                    const addedEndpoints = enrichedEndpoints.filter(e => !prevPaths.has(`${e.method || ""}:${e.path}`));
                    const removedEndpoints = prevSnapshot.endpoints.filter(e => !newPaths.has(`${e.method || ""}:${e.path}`));
                    
                    result.addedEndpoints = addedEndpoints;
                    result.removedEndpoints = removedEndpoints;
                    
                    // Generate change events
                    if (addedEndpoints.length > 0) {
                        apiChanges++;
                        addedEndpointsCount += addedEndpoints.length;
                        
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_added",
                            severity: "high",
                            title: `New API Endpoints Discovered: ${urlObj.hostname}`,
                            description: `${addedEndpoints.length} new API endpoint(s) discovered: ${addedEndpoints.map(e => e.path).join(", ")}`,
                            newValue: JSON.stringify(addedEndpoints.map(e => e.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "new", "discovery"],
                            autoTriggerEnabled: true,
                            riskScore: 0,
                            metadata: {
                                addedEndpoints,
                                count: addedEndpoints.length,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, addedEndpoints.length);
                        changeEvents.push(event);
                    }
                    
                    if (removedEndpoints.length > 0) {
                        apiChanges++;
                        removedEndpointsCount += removedEndpoints.length;
                        
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_removed",
                            severity: "low",
                            title: `API Endpoints Removed: ${urlObj.hostname}`,
                            description: `${removedEndpoints.length} API endpoint(s) removed: ${removedEndpoints.map(e => e.path).join(", ")}`,
                            oldValue: JSON.stringify(removedEndpoints.map(e => e.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "removed"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                removedEndpoints,
                                count: removedEndpoints.length,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, removedEndpoints.length);
                        changeEvents.push(event);
                    }
                    
                    // GraphQL discovered
                    if (graphqlEndpoint && !prevSnapshot.graphqlEndpoint) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "graphql_discovered",
                            severity: "high",
                            title: `GraphQL Endpoint Discovered: ${urlObj.hostname}`,
                            description: `A GraphQL endpoint was discovered at ${graphqlEndpoint}. This is a high-value target for testing.`,
                            newValue: graphqlEndpoint,
                            detectionMethod: "api_monitor",
                            tags: ["api", "graphql", "discovery"],
                            autoTriggerEnabled: true,
                            riskScore: 0,
                            metadata: { graphqlEndpoint },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, 1);
                        changeEvents.push(event);
                    }
                    
                    // OpenAPI spec discovered
                    if (openApiSpec && !prevSnapshot.openApiSpec) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "openapi_discovered",
                            severity: "medium",
                            title: `OpenAPI Spec Discovered: ${urlObj.hostname}`,
                            description: `An OpenAPI/Swagger specification was discovered at ${openApiSpec}.`,
                            newValue: openApiSpec,
                            detectionMethod: "api_monitor",
                            tags: ["api", "openapi", "swagger", "discovery"],
                            autoTriggerEnabled: true,
                            riskScore: 0,
                            metadata: { openApiSpec },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, 1);
                        changeEvents.push(event);
                    }
                } else {
                    // First scan - report all as discovered
                    if (enrichedEndpoints.length > 0) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_discovered",
                            severity: "medium",
                            title: `API Endpoints Discovered: ${urlObj.hostname}`,
                            description: `Initial scan discovered ${enrichedEndpoints.length} API endpoint(s).`,
                            newValue: JSON.stringify(enrichedEndpoints.map(e => e.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "initial-scan"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                endpoints: enrichedEndpoints,
                                graphqlEndpoint,
                                openApiSpec,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, enrichedEndpoints.length);
                        changeEvents.push(event);
                    }
                }
                
            } catch (error: any) {
                result.error = error.message || String(error);
                failedChecks++;
            }
            
            results.push(result);
            completedTargets += 1;
            await reportMonitorProgress(monitorExecution, {
                current: completedTargets,
                total: totalProgressUnits,
                currentTarget: baseUrl,
                phase: "discover",
                message: `Completed API discovery for ${baseUrl}`,
            });
        });

        await runSequentially(targetTasks);

        await reportMonitorProgress(monitorExecution, {
            current: validTargets.length + 1,
            total: totalProgressUnits,
            phase: "compare",
            message: "Comparing API snapshots",
        });

        await reportMonitorProgress(monitorExecution, {
            current: totalProgressUnits,
            total: totalProgressUnits,
            phase: "build",
            message: "Building API results",
        });
        
        return {
            success: true,
            data: {
                results,
                changeEvents,
                snapshots: newSnapshots,
                summary: {
                    totalTargets: validTargets.length,
                    successfulChecks,
                    failedChecks,
                    totalEndpoints,
                    totalJsFiles,
                    addedEndpoints: addedEndpointsCount,
                    removedEndpoints: removedEndpointsCount,
                    apiChanges,
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
