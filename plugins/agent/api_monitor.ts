/**
 * API Endpoint Change Monitor
 * 
 * @plugin api_monitor
 * @name API Monitor
 * @version 1.2.0
 * @author Sentinel Team
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
    concurrency?: number;
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

interface FetchResult {
    text: string;
    size: number;
    contentType: string;
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

async function runWithConcurrency<T>(tasks: Array<() => Promise<T>>, concurrency: number): Promise<T[]> {
    const results: T[] = [];
    let index = 0;
    const workerCount = Math.max(1, Math.min(concurrency, tasks.length || 1));
    const workers = Array.from({ length: workerCount }, async () => {
        while (index < tasks.length) {
            const current = index++;
            results[current] = await tasks[current]();
        }
    });
    await Promise.all(workers);
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

// Common API file paths to check
const COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/rest",
    "/graphql",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
];

const DEFAULT_MAX_JS_FILES = 100;
const DEFAULT_PAGE_CRAWL_LIMIT = 20;

// Extract API endpoints from JavaScript content
function extractApisFromJs(content: string, source: string): ApiEndpoint[] {
    const endpoints: ApiEndpoint[] = [];
    const seen = new Set<string>();
    
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
        // Regex fallback
        const stringPattern = /(['"`])([^'"`\n]{3,200})\1/g;
        let match;
        while ((match = stringPattern.exec(content)) !== null) {
            literals.push({ value: match[2], line: 0 });
        }
    }
    
    for (const literal of literals) {
        const value = literal.value.trim();
        if (seen.has(value)) continue;
        
        // Check API patterns
        for (const pattern of API_PATTERNS) {
            if (pattern.test(value)) {
                seen.add(value);
                endpoints.push({
                    path: value,
                    source,
                });
                break;
            }
        }
        
        // Check for full API URLs
        if (!seen.has(value) && /^https?:\/\/[^\/]+\/(?:api|v[0-9]+|rest|graphql)/i.test(value)) {
            seen.add(value);
            try {
                const url = new URL(value);
                endpoints.push({
                    path: url.pathname,
                    source,
                });
            } catch {
                // Invalid URL
            }
        }
    }
    
    // Extract from fetch/axios calls with method info
    const fetchPattern = /(?:fetch|axios)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
    let fetchMatch;
    while ((fetchMatch = fetchPattern.exec(content)) !== null) {
        const method = fetchMatch[1].toUpperCase();
        const path = fetchMatch[2];
        const key = `${method}:${path}`;
        if (!seen.has(key)) {
            seen.add(key);
            endpoints.push({
                path,
                method,
                source,
            });
        }
    }
    
    return endpoints;
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
        if (!response.ok) {
            return null;
        }

        const text = await response.text();
        return {
            text,
            size: text.length,
            contentType: response.headers.get("content-type") || "",
        };
    } catch {
        clearTimeout(timeoutId);
        return null;
    }
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

function extractJsFromContent(content: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    let match;

    const esImportRegex = /import\s+(?:[\w\s{},*]+\s+from\s+)?["']([^"']+)["']/g;
    while ((match = esImportRegex.exec(content)) !== null) {
        const path = match[1];
        if (looksLikeJs(path) || !path.startsWith(".")) {
            const url = resolveUrl(baseUrl, path);
            if (url && !seenUrls.has(url) && looksLikeJs(url)) {
                seenUrls.add(url);
                links.push({ url, type: "module", source: "es_import" });
            }
        }
    }

    const dynamicImportRegex = /import\s*\(\s*["']([^"']+)["']\s*\)/g;
    while ((match = dynamicImportRegex.exec(content)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url) && looksLikeJs(url)) {
            seenUrls.add(url);
            links.push({ url, type: "dynamic", source: "dynamic_import" });
        }
    }

    const requireRegex = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
    while ((match = requireRegex.exec(content)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url) && looksLikeJs(url)) {
            seenUrls.add(url);
            links.push({ url, type: "dynamic", source: "require" });
        }
    }

    const sourceMapRegex = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
    while ((match = sourceMapRegex.exec(content)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: "sourcemap", source: "sourcemap" });
        }
    }

    const jsUrlRegex = /["']([^"'\s]*?(?:\/assets\/|\/static\/|\/js\/|\/dist\/|\/build\/|\/chunks?\/)?[^"'\s]*?\.[a-f0-9]{6,10}\.js(?:\?[^"'\s]*)?)["']/gi;
    while ((match = jsUrlRegex.exec(content)) !== null) {
        const path = match[1];
        if (path && !path.startsWith("data:") && !path.includes("{{")) {
            const url = resolveUrl(baseUrl, path);
            if (url && !seenUrls.has(url)) {
                seenUrls.add(url);
                links.push({ url, type: "webpack", source: "js_string" });
            }
        }
    }

    const simpleJsRegex = /["']((?:\/|\.\.?\/)[^"'\s]+\.js(?:\?[^"'\s]*)?)["']/g;
    while ((match = simpleJsRegex.exec(content)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url) && !match[1].startsWith("data:")) {
            seenUrls.add(url);
            links.push({ url, type: "dynamic", source: "js_path" });
        }
    }

    return links;
}

function parseManifest(content: string, manifestUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();

    try {
        const json = JSON.parse(content);
        const extractFromObj = (obj: unknown) => {
            if (typeof obj === "string" && looksLikeJs(obj)) {
                const url = resolveUrl(manifestUrl, obj);
                if (url && !seenUrls.has(url)) {
                    seenUrls.add(url);
                    links.push({ url, type: "manifest", source: "manifest" });
                }
            } else if (Array.isArray(obj)) {
                obj.forEach(extractFromObj);
            } else if (obj && typeof obj === "object") {
                Object.values(obj as Record<string, unknown>).forEach(extractFromObj);
            }
        };
        extractFromObj(json);
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
    concurrency: number,
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
            if (!pageResult) {
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
        const manifestResults = await runWithConcurrency(
            getManifestUrls(baseUrl).map(manifestUrl => async () => ({
                manifestUrl,
                result: await fetchWithTimeout(manifestUrl, timeout, userAgent, "application/json,*/*"),
            })),
            Math.min(3, concurrency),
        );

        for (const { manifestUrl, result } of manifestResults) {
            if (!result || !result.contentType.includes("json")) {
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
            const batch = jsFetchQueue.splice(0, concurrency);
            const batchResults = await runWithConcurrency(
                batch.map(link => async () => ({
                    link,
                    result: await fetchWithTimeout(
                        link.url,
                        timeout,
                        userAgent,
                        "application/javascript,text/javascript,text/plain,*/*",
                    ),
                })),
                Math.min(concurrency, batch.length || 1),
            );

            for (const { link, result } of batchResults) {
                if (visitedScriptUrls.has(link.url)) {
                    continue;
                }
                visitedScriptUrls.add(link.url);
                if (!result) {
                    continue;
                }

                link.size = result.size;
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
                default: 15000,
                minimum: 5000,
                maximum: 60000
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            concurrency: {
                type: "integer",
                description: "Number of targets to scan concurrently",
                default: 5,
                minimum: 1,
                maximum: 20
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
                default: true
            },
            includeOpenAPI: {
                type: "boolean",
                description: "Check for OpenAPI/Swagger specs",
                default: true
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
                                snapshot: { type: "object" },
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
        
        const timeout = input.timeout || 15000;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const concurrency = Math.max(1, Math.min(input.concurrency || 5, 20));
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

                if (!pageResult) {
                    result.error = "Failed to fetch target page";
                    failedChecks++;
                    results.push(result);
                    return;
                }
                
                successfulChecks++;

                const directJsTarget = looksLikeJs(baseUrl) || pageResult.contentType.includes("javascript");
                const scriptSources = directJsTarget
                    ? [{ source: baseUrl, content: pageResult.text }]
                    : (await discoverJavascriptAssets(
                        baseUrl,
                        pageResult.text,
                        timeout,
                        userAgent,
                        crawlDepth,
                        maxJsFiles,
                        includeSameOriginOnly,
                        followSourceMaps,
                        probeSpaManifests,
                        concurrency,
                    )).scriptContents;

                jsFilesAnalyzed = directJsTarget
                    ? 1
                    : scriptSources.filter(source => !source.source.startsWith("inline://")).length;
                totalJsFiles += jsFilesAnalyzed;

                for (const source of scriptSources) {
                    const endpoints = extractApisFromJs(source.content, source.source);
                    allEndpoints.push(...endpoints);
                }
                
                // Check common API paths
                const urlObj = new URL(baseUrl);
                await runWithConcurrency(
                    COMMON_API_PATHS.map((path) => async () => {
                        try {
                            const apiUrl = `${urlObj.origin}${path}`;
                            const apiResponse = await fetch(apiUrl, {
                                method: "GET",
                                headers: {
                                    "User-Agent": userAgent,
                                    "Accept": "application/json,*/*",
                                },
                                // @ts-ignore
                                timeout: 5000,
                            });

                            if (apiResponse.ok) {
                                allEndpoints.push({
                                    path,
                                    source: "probe",
                                });

                                if (includeOpenAPI && !openApiSpec && (path.includes("swagger") || path.includes("openapi"))) {
                                    const specContent = await apiResponse.text();
                                    if (specContent.includes("openapi") || specContent.includes("swagger")) {
                                        openApiSpec = apiUrl;
                                    }
                                }
                            }
                        } catch {
                            // Path doesn't exist
                        }
                    }),
                    concurrency,
                );
                
                // Check GraphQL
                if (includeGraphQL) {
                    const graphqlMatches = await runWithConcurrency(
                        ["/graphql", "/gql", "/api/graphql"].map((gqlPath) => async () => {
                            try {
                                const gqlUrl = `${urlObj.origin}${gqlPath}`;
                                const gqlResponse = await fetch(gqlUrl, {
                                    method: "POST",
                                    headers: {
                                        "User-Agent": userAgent,
                                        "Content-Type": "application/json",
                                    },
                                    body: JSON.stringify({ query: "{ __typename }" }),
                                    // @ts-ignore
                                    timeout: 5000,
                                });

                                if (!gqlResponse.ok) return null;
                                const gqlResult = await gqlResponse.text();
                                if (gqlResult.includes("__typename") || gqlResult.includes("data")) {
                                    return gqlPath;
                                }
                            } catch {
                                // GraphQL not available
                            }
                            return null;
                        }),
                        concurrency,
                    );

                    const discoveredGraphql = graphqlMatches.find((value): value is string => Boolean(value));
                    if (discoveredGraphql) {
                        graphqlEndpoint = discoveredGraphql;
                        allEndpoints.push({
                            path: discoveredGraphql,
                            method: "POST",
                            source: "graphql-probe",
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
                
                totalEndpoints += uniqueEndpoints.length;
                
                // Create snapshot
                const snapshot: ApiSnapshot = {
                    baseUrl,
                    endpoints: uniqueEndpoints,
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
                    message: `Analyzed ${jsFilesAnalyzed} JS files and discovered ${uniqueEndpoints.length} API endpoints`,
                });
                
                // Compare with previous snapshot
                const prevSnapshot = previousSnapshots[baseUrl];
                if (prevSnapshot) {
                    const prevPaths = new Set(prevSnapshot.endpoints.map(e => `${e.method || ""}:${e.path}`));
                    const newPaths = new Set(uniqueEndpoints.map(e => `${e.method || ""}:${e.path}`));
                    
                    // Find added endpoints
                    const addedEndpoints = uniqueEndpoints.filter(e => !prevPaths.has(`${e.method || ""}:${e.path}`));
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
                    if (uniqueEndpoints.length > 0) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_discovered",
                            severity: "medium",
                            title: `API Endpoints Discovered: ${urlObj.hostname}`,
                            description: `Initial scan discovered ${uniqueEndpoints.length} API endpoint(s).`,
                            newValue: JSON.stringify(uniqueEndpoints.map(e => e.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "initial-scan"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                endpoints: uniqueEndpoints,
                                graphqlEndpoint,
                                openApiSpec,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, uniqueEndpoints.length);
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

        await runWithConcurrency(targetTasks, concurrency);

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
