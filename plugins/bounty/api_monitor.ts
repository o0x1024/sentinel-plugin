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
 * @tags api, endpoint, monitor, change-detection, rest, javascript, spa
 * @description Monitor API endpoints for changes by discovering JavaScript assets and extracting API-like path literals from JS bundles and pages
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
    maxPages?: number;
    maxJsFiles?: number;
    includeSameOriginOnly?: boolean;
    followSourceMaps?: boolean;
    probeSpaManifests?: boolean;
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

interface JsDiscoveryResult {
    jsLinks: JsLink[];
    scriptContents: ScriptContentSource[];
    crawledPages: string[];
}

interface ApiEndpoint {
    path: string;
    source: string;
}

interface ApiSnapshot {
    baseUrl: string;
    endpoints: ApiEndpoint[];
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

const DEFAULT_MAX_JS_FILES = 100;
const DEFAULT_PAGE_CRAWL_LIMIT = 20;
const DEFAULT_MAX_PAGES = 20;
const MAX_LITERAL_SCAN_MATCHES = 5000;
const MAX_PATH_CANDIDATE_LENGTH = 2048;
const EXCLUDED_STATIC_PREFIXES = [
    "/_next/",
    "/_nuxt/",
    "/assets/",
    "/static/",
    "/images/",
    "/image/",
    "/img/",
    "/fonts/",
    "/css/",
    "/js/",
    "/dist/",
    "/build/",
    "/chunks/",
    "/webpack/",
    "/runtime/",
];
const EXCLUDED_EXACT_PATHS = new Set([
    "/",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
    "/asset-manifest.json",
    "/browserconfig.xml",
]);
const EXCLUDED_STATIC_EXTENSIONS = new Set([
    "js",
    "mjs",
    "cjs",
    "jsx",
    "ts",
    "tsx",
    "css",
    "scss",
    "sass",
    "less",
    "map",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "avif",
    "ico",
    "bmp",
    "tif",
    "tiff",
    "mp4",
    "webm",
    "mp3",
    "wav",
    "ogg",
    "pdf",
    "zip",
    "gz",
    "tar",
    "woff",
    "woff2",
    "ttf",
    "eot",
]);

function extractPathCandidate(value: string): string | null {
    const normalizedValue = String(value || "").trim();
    if (!normalizedValue) return null;

    if (normalizedValue.startsWith("/")) {
        return normalizedValue;
    }

    if (/^https?:\/\//i.test(normalizedValue)) {
        try {
            return new URL(normalizedValue).pathname;
        } catch {
            return null;
        }
    }

    return null;
}

function isStaticAssetPath(path: string): boolean {
    const lastSegment = path.split("/").pop() || "";
    const extensionMatch = lastSegment.match(/\.([a-z0-9]+)$/i);
    if (!extensionMatch) {
        return false;
    }

    return EXCLUDED_STATIC_EXTENSIONS.has(extensionMatch[1].toLowerCase());
}

function normalizeEndpointPath(value: string): string | null {
    const pathCandidate = extractPathCandidate(value);
    if (!pathCandidate) return null;

    const normalizedPath = pathCandidate.split("#")[0].split("?")[0].trim();
    if (!normalizedPath || !normalizedPath.startsWith("/") || normalizedPath.startsWith("//")) {
        return null;
    }
    if (normalizedPath.length > MAX_PATH_CANDIDATE_LENGTH) {
        return null;
    }
    if (/[\s\\]/.test(normalizedPath)) {
        return null;
    }
    if (EXCLUDED_EXACT_PATHS.has(normalizedPath)) {
        return null;
    }
    if (EXCLUDED_STATIC_PREFIXES.some(prefix => normalizedPath.startsWith(prefix))) {
        return null;
    }
    if (isStaticAssetPath(normalizedPath)) {
        return null;
    }

    return normalizedPath;
}

function pushApiEndpoint(
    endpoints: ApiEndpoint[],
    seen: Set<string>,
    pathCandidate: string,
    source: string,
) {
    const normalizedPath = normalizeEndpointPath(pathCandidate);
    if (!normalizedPath) return;

    if (seen.has(normalizedPath)) return;
    seen.add(normalizedPath);
    endpoints.push({
        path: normalizedPath,
        source,
    });
}

// Extract API endpoints from JavaScript content
function extractApisFromJs(content: string, source: string): ApiEndpoint[] {
    const endpoints: ApiEndpoint[] = [];
    const seen = new Set<string>();
    const result = Sentinel.AST.parse(content, source);
    for (const literal of result.literals.slice(0, MAX_LITERAL_SCAN_MATCHES)) {
        pushApiEndpoint(endpoints, seen, literal.value.trim(), source);
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
    maxPages: number,
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
    const queuedPages = new Set<string>([baseUrl]);

    while (pagesToCrawl.length > 0 && jsLinks.length < maxJsFiles && visitedPages.size < maxPages) {
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
                if (visitedPages.size + pagesToCrawl.length >= maxPages) {
                    break;
                }
                if (!visitedPages.has(pageUrl) && !queuedPages.has(pageUrl)) {
                    queuedPages.add(pageUrl);
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
            maxPages: {
                type: "integer",
                description: "Maximum same-origin pages to crawl per target when crawlDepth is greater than 1",
                default: 20,
                minimum: 1,
                maximum: 50
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
                                        lastChecked: { type: "string" },
                                        endpoints: {
                                            type: "array",
                                            items: {
                                                type: "object",
                                                properties: {
                                                    path: { type: "string" },
                                                    source: { type: "string" },
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
        const maxPages = Math.max(1, Math.min(input.maxPages || DEFAULT_MAX_PAGES, 50));
        const maxJsFiles = Math.max(10, Math.min(input.maxJsFiles || DEFAULT_MAX_JS_FILES, 300));
        const includeSameOriginOnly = input.includeSameOriginOnly === true;
        const followSourceMaps = input.followSourceMaps === true;
        const probeSpaManifests = input.probeSpaManifests !== false;
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
                let jsFilesAnalyzed = 0;
                
                const pageResult = await fetchWithTimeout(
                    baseUrl,
                    timeout,
                    userAgent,
                    "text/html,application/xhtml+xml,*/*",
                );

                if (!pageResult || pageResult.status === null) {
                    result.error = describeTargetFetchFailure(pageResult);
                    failedChecks++;
                    results.push(result);
                    return;
                }
                
                successfulChecks++;

                const pageContent = canAnalyzePageResponse(pageResult) ? pageResult.text : "";
                const directJsTarget = Boolean(pageContent) && (looksLikeJs(baseUrl) || pageResult.contentType.includes("javascript"));
                const scriptSources = !pageContent ? [] : directJsTarget ? [{ source: baseUrl, content: pageContent }] : (await discoverJavascriptAssets(baseUrl, pageContent, timeout, userAgent, crawlDepth, maxPages, maxJsFiles, includeSameOriginOnly, followSourceMaps, probeSpaManifests)).scriptContents;

                jsFilesAnalyzed = directJsTarget
                    ? 1
                    : scriptSources.filter(source => !source.source.startsWith("inline://")).length;
                totalJsFiles += jsFilesAnalyzed;

                for (const source of scriptSources) {
                    try {
                        const endpoints = extractApisFromJs(source.content, source.source);
                        allEndpoints.push(...endpoints);
                    } catch {
                        continue;
                    }
                }
                
                const uniqueEndpoints: ApiEndpoint[] = [];
                const seen = new Set<string>();
                for (const ep of allEndpoints) {
                    if (!seen.has(ep.path)) {
                        seen.add(ep.path);
                        uniqueEndpoints.push(ep);
                    }
                }
                totalEndpoints += uniqueEndpoints.length;
                
                const snapshot: ApiSnapshot = {
                    baseUrl,
                    endpoints: uniqueEndpoints,
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
                
                const prevSnapshot = previousSnapshots[baseUrl];
                if (prevSnapshot) {
                    const prevPaths = new Set(prevSnapshot.endpoints.map(e => e.path));
                    const newPaths = new Set(uniqueEndpoints.map(e => e.path));
                    const addedEndpoints = uniqueEndpoints.filter(e => !prevPaths.has(e.path));
                    const removedEndpoints = prevSnapshot.endpoints.filter(e => !newPaths.has(e.path));
                    
                    result.addedEndpoints = addedEndpoints;
                    result.removedEndpoints = removedEndpoints;
                    
                    if (addedEndpoints.length > 0) {
                        apiChanges++;
                        addedEndpointsCount += addedEndpoints.length;
                        
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_added",
                            severity: "high",
                            title: `New API Endpoints Discovered: ${new URL(baseUrl).hostname}`,
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
                            title: `API Endpoints Removed: ${new URL(baseUrl).hostname}`,
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
                } else {
                    if (uniqueEndpoints.length > 0) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_discovered",
                            severity: "medium",
                            title: `API Endpoints Discovered: ${new URL(baseUrl).hostname}`,
                            description: `Initial scan discovered ${uniqueEndpoints.length} API endpoint(s).`,
                            newValue: JSON.stringify(uniqueEndpoints.map(e => e.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "initial-scan"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                endpoints: uniqueEndpoints,
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
