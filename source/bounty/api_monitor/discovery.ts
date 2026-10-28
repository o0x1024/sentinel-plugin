import type { MonitorExecutionContext, ToolInput, JsLink, ScriptContentSource, SourceMapLike, FetchResult, JsDiscoveryResult, ApiEndpoint, HtmlRoute, ApiSnapshot, JsFetchFailure, ChangeEvent, ApiResult, ToolOutput } from './types.ts';

declare const Sentinel: {
    Monitor?: {
        reportProgress?: (payload: Record<string, unknown>) => Promise<boolean>;
    };
};

export async function reportMonitorProgress(
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

export function generateId(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

export async function runWithConcurrency<T>(tasks: Array<() => Promise<T>>, concurrency: number): Promise<T[]> {
    const results: T[] = [];
    let index = 0;
    const workerCount = Math.max(1, Math.min(concurrency, 128, tasks.length || 1));
    const workers = Array.from({ length: workerCount }, async () => {
        while (index < tasks.length) {
            const current = index++;
            results[current] = await tasks[current]();
        }
    });
    await Promise.all(workers);
    return results;
}

export const DEFAULT_MAX_JS_FILES = 50;

export const DEFAULT_PAGE_CRAWL_LIMIT = 50;

export const DEFAULT_MAX_PAGES = 50;

export const PAGE_FETCH_CONCURRENCY_LIMIT = 50;

export const JS_FETCH_CONCURRENCY_LIMIT = 100;

export const MAX_JS_DISCOVERY_DEPTH = 1;

export const MAX_STRING_SCAN_MATCHES = 5000;

export const MAX_PATH_CANDIDATE_LENGTH = 2048;

export const EXCLUDED_STATIC_PREFIXES = [
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
    "/node_modules/",
    "/public/",
    "/media/",
    "/vendor/",
    "/lib/",
    "/bundle/",
];

export const EXCLUDED_EXACT_PATHS = new Set([
    "/",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
    "/asset-manifest.json",
    "/browserconfig.xml",
]);

export const EXCLUDED_STATIC_EXTENSIONS = new Set([
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
    "json",
    "xml",
    "yaml",
    "yml",
    "html",
    "htm",
    "wasm",
    "swf",
    "txt",
    "md",
]);

export const EXCLUDED_HTML_TAG_PATHS = new Set([
    "script", "style", "div", "span", "svg", "path", "link",
    "meta", "title", "body", "head", "html", "form", "input",
    "button", "table", "iframe", "canvas", "video", "audio",
    "img", "source", "object", "embed", "select", "option",
    "textarea", "label", "section", "article", "nav", "header",
    "footer", "main", "aside", "figure", "details", "summary",
]);

export const VENDOR_JS_FILENAME_PATTERNS = [
    /^(?:vue|vue-router|vuex|vue-i18n)(?:[-.][a-z0-9]+)*\.js$/i,
    /^(?:element-plus|echarts|vant|moment|axios|nprogress|vuedraggable|xe-utils)(?:[-.][a-z0-9]+)*\.js$/i,
    /^(?:vendor|vendors|chunk-vendors)(?:[-.][a-z0-9]+)*\.js$/i,
];

export const VENDOR_JS_PATH_SEGMENTS = new Set([
    "node_modules",
    "vendor",
    "vendors",
]);

export function normalizeCommonPathCandidate(value: string, allowRoot: boolean): string | null {
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
    if (!allowRoot && EXCLUDED_EXACT_PATHS.has(normalizedPath)) {
        return null;
    }
    if (EXCLUDED_STATIC_PREFIXES.some(prefix => normalizedPath.startsWith(prefix))) {
        return null;
    }
    if (isStaticAssetPath(normalizedPath)) {
        return null;
    }

    if (normalizedPath.length <= 2) return null;                    // /a, /b
    if (/^\/\d+$/.test(normalizedPath)) return null;                // /1, /123
    if (/^\/[A-Z]$/.test(normalizedPath)) return null;              // /M, /L (SVG commands)
    if (/^\/\./.test(normalizedPath)) return null;                  // /.env, /.git
    if (/[^\x20-\x7E]/.test(normalizedPath)) return null;          // non-ASCII garbled paths
    if (/[(),;={}[\]'"<>!@#$%^&*|~`]/.test(normalizedPath)) return null; // code fragments
    if (/^\/(?:19|20)\d{2}\//.test(normalizedPath)) return null;   // W3C namespace paths (/1999/xlink, /2000/svg)

    const segments = normalizedPath.split("/").filter(Boolean);
    if (segments.length <= 3 && segments.every(s => s.length <= 2)) return null; // all-short segments like /a/b

    if (/^\/([a-z]+)$/i.test(normalizedPath)) {
        const tag = normalizedPath.slice(1).toLowerCase();
        if (EXCLUDED_HTML_TAG_PATHS.has(tag)) return null;
    }

    return normalizedPath;
}

export function extractPathCandidate(value: string): string | null {
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

export function isStaticAssetPath(path: string): boolean {
    const lastSegment = path.split("/").pop() || "";
    const extensionMatch = lastSegment.match(/\.([a-z0-9]+)$/i);
    if (!extensionMatch) {
        return false;
    }

    return EXCLUDED_STATIC_EXTENSIONS.has(extensionMatch[1].toLowerCase());
}

export function normalizeEndpointPath(value: string): string | null {
    return normalizeCommonPathCandidate(value, false);
}

export function normalizeHtmlRoutePath(value: string): string | null {
    return normalizeCommonPathCandidate(value, true);
}

export function pushApiEndpoint(
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

export function pushHtmlRoute(
    routes: HtmlRoute[],
    seen: Set<string>,
    pathCandidate: string,
    source: string,
) {
    const normalizedPath = normalizeHtmlRoutePath(pathCandidate);
    if (!normalizedPath) return;

    if (seen.has(normalizedPath)) return;
    seen.add(normalizedPath);
    routes.push({
        path: normalizedPath,
        source,
    });
}

export function maybePushStringCandidate(candidates: string[], value: string): boolean {
    const candidate = value.trim();
    if (!candidate || (!candidate.includes("/") && !/^https?:/i.test(candidate))) {
        return false;
    }
    candidates.push(candidate);
    return candidates.length >= MAX_STRING_SCAN_MATCHES;
}

export function readEscapedJsChar(content: string, index: number): { value: string; nextIndex: number } {
    const escaped = content[index + 1] || "";
    if (escaped === "x") {
        const hex = content.slice(index + 2, index + 4);
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
            return { value: String.fromCharCode(parseInt(hex, 16)), nextIndex: index + 4 };
        }
    }
    if (escaped === "u") {
        if (content[index + 2] === "{") {
            const end = content.indexOf("}", index + 3);
            const hex = end > index + 3 ? content.slice(index + 3, end) : "";
            if (/^[0-9a-fA-F]{1,6}$/.test(hex)) {
                return { value: String.fromCodePoint(parseInt(hex, 16)), nextIndex: end + 1 };
            }
        }
        const hex = content.slice(index + 2, index + 6);
        if (/^[0-9a-fA-F]{4}$/.test(hex)) {
            return { value: String.fromCharCode(parseInt(hex, 16)), nextIndex: index + 6 };
        }
    }
    return { value: escaped, nextIndex: index + 2 };
}

export function skipJsComment(content: string, index: number): number | null {
    if (content[index] !== "/") return null;
    if (content[index + 1] === "/") {
        const nextLine = content.indexOf("\n", index + 2);
        return nextLine === -1 ? content.length : nextLine + 1;
    }
    if (content[index + 1] === "*") {
        const end = content.indexOf("*/", index + 2);
        return end === -1 ? content.length : end + 2;
    }
    return null;
}

export function skipQuotedJsValue(content: string, index: number): number {
    const quote = content[index];
    let current = index + 1;
    while (current < content.length) {
        if (content[current] === "\\") {
            current += 2;
            continue;
        }
        if (content[current] === quote) {
            return current + 1;
        }
        current += 1;
    }
    return content.length;
}

export function skipTemplateExpression(content: string, index: number): number {
    let current = index;
    let depth = 1;
    while (current < content.length && depth > 0) {
        const commentEnd = skipJsComment(content, current);
        if (commentEnd !== null) {
            current = commentEnd;
            continue;
        }
        const char = content[current];
        if (char === "\"" || char === "'" || char === "`") {
            current = skipQuotedJsValue(content, current);
            continue;
        }
        if (char === "{") depth += 1;
        if (char === "}") depth -= 1;
        current += 1;
    }
    return current;
}

export function extractStringPathCandidates(content: string): string[] {
    const candidates: string[] = [];
    let index = 0;
    while (index < content.length && candidates.length < MAX_STRING_SCAN_MATCHES) {
        const commentEnd = skipJsComment(content, index);
        if (commentEnd !== null) {
            index = commentEnd;
            continue;
        }
        const quote = content[index];
        if (quote !== "\"" && quote !== "'" && quote !== "`") {
            index += 1;
            continue;
        }
        const isTemplate = quote === "`";
        let value = "";
        let tooLong = false;
        index += 1;
        while (index < content.length) {
            const char = content[index];
            if (char === "\\") {
                const escaped = readEscapedJsChar(content, index);
                if (!tooLong) {
                    value += escaped.value;
                    tooLong = value.length > MAX_PATH_CANDIDATE_LENGTH;
                }
                index = escaped.nextIndex;
                continue;
            }
            if (char === quote) {
                index += 1;
                break;
            }
            if (isTemplate && char === "$" && content[index + 1] === "{") {
                if (!tooLong && maybePushStringCandidate(candidates, value)) return candidates;
                value = "";
                tooLong = false;
                index = skipTemplateExpression(content, index + 2);
                continue;
            }
            if (!tooLong) {
                value += char;
                tooLong = value.length > MAX_PATH_CANDIDATE_LENGTH;
            }
            index += 1;
        }
        if (!tooLong && maybePushStringCandidate(candidates, value)) {
            return candidates;
        }
    }
    return candidates;
}

export function extractPathsFromJs(content: string, source: string): {
    htmlRoutes: HtmlRoute[];
    apiEndpoints: ApiEndpoint[];
} {
    const apiEndpoints: ApiEndpoint[] = [];
    const seenApiEndpoints = new Set<string>();
    for (const candidate of extractStringPathCandidates(content)) {
        pushApiEndpoint(apiEndpoints, seenApiEndpoints, candidate, source);
    }
    return {
        htmlRoutes: [],
        apiEndpoints,
    };
}

export function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, "0");
}

export function resolveUrl(base: string, relative: string): string {
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

export function isSameOrigin(baseUrl: string, targetUrl: string): boolean {
    try {
        return new URL(baseUrl).origin === new URL(targetUrl).origin;
    } catch {
        return false;
    }
}

export function looksLikeJs(path: string): boolean {
    if (!path) return false;
    const clean = path.split("?")[0].split("#")[0];
    if (/\.(?:js|mjs|cjs|jsx|ts|tsx)$/i.test(clean)) return true;
    if (/\.[a-f0-9]{6,10}\.js$/i.test(clean)) return true;
    if (/(?:chunk|bundle|vendor|app|main|index)\.[a-f0-9]+/i.test(clean)) return true;
    return false;
}

export function shouldSkipVendorJs(url: string): boolean {
    const pathname = new URL(url).pathname;
    const pathSegments = pathname.split("/").filter(Boolean).map(segment => segment.toLowerCase());
    if (pathSegments.some(segment => VENDOR_JS_PATH_SEGMENTS.has(segment))) {
        return true;
    }

    const filename = pathSegments[pathSegments.length - 1] || "";
    return VENDOR_JS_FILENAME_PATTERNS.some(pattern => pattern.test(filename));
}

export const PAGE_FETCH_TIMEOUT_MS = 12000;

export type DocumentRole = "target" | "page" | "manifest" | "script" | "sourcemap";
export type DocumentCompleted = (url: string, result: FetchResult, role: DocumentRole) => Promise<void>;

export async function fetchDocument(
    url: string,
    userAgent: string,
    accept = "text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,*/*;q=0.8",
    onDocument?: DocumentCompleted,
    role: DocumentRole = "page",
    assertHealthy?: () => void,
): Promise<FetchResult | null> {
    // Fail before scheduling new I/O after a rejected persistence receipt.
    assertHealthy?.();
    let result: FetchResult;
    try {
        const response = await fetch(url, {
            headers: { "User-Agent": userAgent, "Accept": accept, "Accept-Language": "en-US,en;q=0.5" },
            redirect: "follow", timeout: PAGE_FETCH_TIMEOUT_MS, maxBodyBytes: 1048576,
        });
        const text = await response.text();
        result = { ok: response.ok, status: response.status, text, size: text.length,
            contentType: response.headers.get("content-type") || "", finalUrl: response.url || url };
    } catch (error: any) {
        result = { ok: false, status: null, text: "", size: 0, contentType: "", finalUrl: url,
            error: error?.message || String(error) || "Unknown fetch error" };
    }
    // Saving errors are terminal; they must never be converted into network failures.
    if (onDocument) await onDocument(url, result, role);
    return result;
}

export function canAnalyzePageResponse(result: FetchResult): boolean {
    const text = String(result.text || "").trim();
    const contentType = String(result.contentType || "").toLowerCase();
    return Boolean(text) && (!contentType || contentType.includes("text/html") || contentType.includes("application/xhtml+xml") || contentType.includes("javascript") || contentType.includes("ecmascript") || contentType.includes("text/plain"));
}

export function describeTargetFetchFailure(result: FetchResult | null): string {
    if (!result) return "Failed to fetch target page";
    if (result.error) return `Failed to fetch target page: ${result.error}`;
    if (typeof result.status === "number") return `Target page returned HTTP ${result.status}`;
    return "Failed to fetch target page";
}

export function extractScriptTags(html: string, baseUrl: string): JsLink[] {
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

export function extractLinkTags(html: string, baseUrl: string): JsLink[] {
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

export function extractInlineScripts(html: string): Array<{ content: string; hash: string }> {
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

export function extractWebpackRuntimeChunkLinks(content: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    const publicPaths = new Set<string>();
    let match: RegExpExecArray | null;

    const publicPathRegex = /\b[\w$]+\.p\s*=\s*["']([^"']+\/)["']/g;
    while ((match = publicPathRegex.exec(content)) !== null) {
        publicPaths.add(match[1]);
    }

    if (publicPaths.size === 0) {
        return links;
    }

    const chunkMapRegex = /\{((?:(?:"[^"]+"|'[^']+'|\d+)\s*:\s*"[^"]+"\s*,?\s*)+)\}\[e\]\+\s*["']\.js["']/g;
    while ((match = chunkMapRegex.exec(content)) !== null) {
        const mapBody = match[1];
        const pairRegex = /(?:"[^"]+"|'[^']+'|\d+)\s*:\s*"([^"]+)"/g;
        let pairMatch: RegExpExecArray | null;

        while ((pairMatch = pairRegex.exec(mapBody)) !== null) {
            const chunkName = pairMatch[1];
            if (!chunkName) continue;
            for (const publicPath of publicPaths) {
                pushDiscoveredJsLink(
                    links,
                    seenUrls,
                    baseUrl,
                    `${publicPath}${chunkName}.js`,
                    "webpack",
                    "webpack_runtime",
                );
            }
        }
    }

    return links;
}

export function pushDiscoveredJsLink(
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

export function extractJsFromContent(content: string, baseUrl: string): JsLink[] {
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

    for (const runtimeChunkLink of extractWebpackRuntimeChunkLinks(content, baseUrl)) {
        pushDiscoveredJsLink(links, seenUrls, baseUrl, runtimeChunkLink.url, runtimeChunkLink.type, runtimeChunkLink.source);
    }

    return links;
}

export function resolveSourceMapSourceUrl(mapUrl: string, sourceRoot: string | undefined, sourcePath: string | undefined): string {
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

export function parseSourceMapScriptContents(mapText: string, mapUrl: string): ScriptContentSource[] {
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

export function parseManifest(content: string, manifestUrl: string): JsLink[] {
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

export function getManifestUrls(baseUrl: string): string[] {
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

export function extractSameOriginPageLinks(html: string, baseUrl: string): Array<{ url: string; path: string }> {
    const links: Array<{ url: string; path: string }> = [];
    const seenUrls = new Set<string>();
    const linkRegex = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
    let match;

    while ((match = linkRegex.exec(html)) !== null) {
        const href = match[1] || match[2] || match[3];
        if (!href || href.startsWith("#") || href.startsWith("javascript:")) continue;

        const url = resolveUrl(baseUrl, href);
        if (url && !seenUrls.has(url) && isSameOrigin(baseUrl, url)) {
            const path = normalizeHtmlRoutePath(url);
            if (path) {
                seenUrls.add(url);
                links.push({ url, path });
            }
        }
    }

    return links;
}

export function pushJsLink(
    collectedLinks: JsLink[],
    seenUrls: Set<string>,
    link: JsLink,
    maxJsFiles: number,
    includeSameOriginOnly: boolean,
    baseUrl: string,
) {
    if (collectedLinks.length >= maxJsFiles) return false;
    if (!link.url || seenUrls.has(link.url)) return false;
    if (includeSameOriginOnly && !isSameOrigin(baseUrl, link.url)) return false;
    if (link.type !== "sourcemap" && shouldSkipVendorJs(link.url)) return false;

    seenUrls.add(link.url);
    collectedLinks.push(link);
    return true;
}

export async function discoverJavascriptAssets(
    baseUrl: string,
    initialHtml: string,
    userAgent: string,
    crawlDepth: number,
    maxPages: number,
    maxJsFiles: number,
    includeSameOriginOnly: boolean,
    followSourceMaps: boolean,
    probeSpaManifests: boolean,
    onDocument?: DocumentCompleted,
    assertHealthy?: () => void,
    retainScriptContents = true,
): Promise<JsDiscoveryResult> {
    const fetchResource = (url: string, agent: string, accept?: string, role: DocumentRole = "page") =>
        fetchDocument(url, agent, accept, onDocument, role, assertHealthy);
    const jsLinks: JsLink[] = [];
    const scriptContents: ScriptContentSource[] = [];
    const htmlRoutes: HtmlRoute[] = [];
    const jsFetchFailures: JsFetchFailure[] = [];
    const crawledPages: string[] = [baseUrl];
    const discoveryTimings = {
        pageCrawlMs: 0,
        manifestProbeMs: 0,
        jsFetchMs: 0,
        sourceMapFetchMs: 0,
        nestedJsDiscoveryMs: 0,
    };
    const discoveryMetrics = {
        pageFetchCount: 0,
        manifestRequests: 0,
        jsFetchCount: 0,
        jsFetchFailureCount: 0,
        sourceMapFetchCount: 0,
        jsLinksDiscovered: 0,
        inlineScriptCount: 0,
    };
    const seenJsUrls = new Set<string>();
    const seenHtmlRoutes = new Set<string>();
    const pageFetchConcurrency = PAGE_FETCH_CONCURRENCY_LIMIT;
    const pagesToCrawl: Array<{ url: string; depth: number; html?: string }> = [
        { url: baseUrl, depth: 0, html: initialHtml },
    ];
    const visitedPages = new Set<string>();
    const queuedPages = new Set<string>([baseUrl]);

    while (pagesToCrawl.length > 0 && jsLinks.length < maxJsFiles && visitedPages.size < maxPages) {
        const remainingPageBudget = maxPages - visitedPages.size;
        if (remainingPageBudget <= 0) {
            break;
        }

        const batch = pagesToCrawl.splice(0, Math.min(pageFetchConcurrency, remainingPageBudget, pagesToCrawl.length));
        const pageBatch = await runWithConcurrency(
            batch.map((current) => async () => {
                if (visitedPages.has(current.url)) {
                    return null;
                }
                visitedPages.add(current.url);

                if (typeof current.html === "string") {
                    return {
                        current,
                        html: current.html,
                        fetchedRemotely: false,
                        fetchDurationMs: 0,
                    };
                }

                const pageFetchStartedAt = Date.now();
                const pageResult = await fetchResource(current.url, userAgent);
                if (!pageResult || !pageResult.ok) {
                    return null;
                }

                return {
                    current,
                    html: pageResult.text,
                    fetchedRemotely: true,
                    fetchDurationMs: Date.now() - pageFetchStartedAt,
                };
            }),
            Math.min(pageFetchConcurrency, batch.length || 1),
        );

        for (const page of pageBatch) {
            if (!page) {
                continue;
            }

            const { current, html, fetchedRemotely } = page;
            if (fetchedRemotely) {
                crawledPages.push(current.url);
                discoveryMetrics.pageFetchCount += 1;
                discoveryTimings.pageCrawlMs += page.fetchDurationMs;
            }

            pushHtmlRoute(htmlRoutes, seenHtmlRoutes, current.url, `page:${current.url}`);

            for (const link of extractScriptTags(html, current.url)) {
                pushJsLink(jsLinks, seenJsUrls, link, maxJsFiles, includeSameOriginOnly, baseUrl);
            }
            for (const link of extractLinkTags(html, current.url)) {
                pushJsLink(jsLinks, seenJsUrls, link, maxJsFiles, includeSameOriginOnly, baseUrl);
            }

            for (const inlineScript of extractInlineScripts(html)) {
                discoveryMetrics.inlineScriptCount += 1;
                scriptContents.push({
                    source: `inline://${current.url}#${inlineScript.hash}`,
                    content: retainScriptContents ? inlineScript.content : "",
                });
                const nestedDiscoveryStartedAt = Date.now();
                for (const link of extractJsFromContent(inlineScript.content, current.url)) {
                    pushJsLink(jsLinks, seenJsUrls, link, maxJsFiles, includeSameOriginOnly, baseUrl);
                }
                discoveryTimings.nestedJsDiscoveryMs += Date.now() - nestedDiscoveryStartedAt;
            }

            const pageLinks = extractSameOriginPageLinks(html, current.url).slice(0, DEFAULT_PAGE_CRAWL_LIMIT);
            for (const pageLink of pageLinks) {
                pushHtmlRoute(htmlRoutes, seenHtmlRoutes, pageLink.path, `html_link:${current.url}`);
            }

            if (crawlDepth > 1 && current.depth < crawlDepth - 1) {
                for (const pageLink of pageLinks) {
                    if (visitedPages.size + pagesToCrawl.length >= maxPages) {
                        break;
                    }
                    if (!visitedPages.has(pageLink.url) && !queuedPages.has(pageLink.url)) {
                        queuedPages.add(pageLink.url);
                        pagesToCrawl.push({ url: pageLink.url, depth: current.depth + 1 });
                    }
                }
            }
        }
    }

    if (probeSpaManifests && jsLinks.length < maxJsFiles) {
        const manifestUrls = getManifestUrls(baseUrl);
        discoveryMetrics.manifestRequests = manifestUrls.length;
        const manifestProbeStartedAt = Date.now();
        const manifestResults = await runWithConcurrency(manifestUrls.map(manifestUrl => async () => ({
            manifestUrl,
            result: await fetchResource(manifestUrl, userAgent, "application/json,*/*", "manifest"),
        })), manifestUrls.length);
        discoveryTimings.manifestProbeMs += Date.now() - manifestProbeStartedAt;

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
        const jsFetchConcurrency = JS_FETCH_CONCURRENCY_LIMIT;
        const jsFetchQueue: Array<{ link: JsLink; depth: number }> = jsLinks
            .filter(link => followSourceMaps || link.type !== "sourcemap")
            .slice(0, maxJsFiles)
            .map(link => ({ link, depth: 0 }));
        const visitedScriptUrls = new Set<string>();

        while (jsFetchQueue.length > 0 && scriptContents.length < maxJsFiles * 2) {
            const batch = jsFetchQueue.splice(0, jsFetchConcurrency);
            const batchResults = await runWithConcurrency(batch.map(({ link, depth }) => async () => ({
                fetchStartedAt: Date.now(),
                link,
                depth,
                result: await fetchResource(
                    link.url,
                    userAgent,
                    link.type === "sourcemap"
                        ? "application/json,text/plain,*/*"
                        : "application/javascript,text/javascript,text/plain,*/*",
                    link.type === "sourcemap" ? "sourcemap" : "script",
                ),
            })), Math.min(jsFetchConcurrency, batch.length || 1));

            for (const { link, result, fetchStartedAt, depth } of batchResults) {
                const fetchDurationMs = Date.now() - fetchStartedAt;
                discoveryMetrics.jsFetchCount += 1;
                discoveryTimings.jsFetchMs += fetchDurationMs;
                if (visitedScriptUrls.has(link.url)) {
                    continue;
                }
                visitedScriptUrls.add(link.url);
                if (!result || !result.ok) {
                    discoveryMetrics.jsFetchFailureCount += 1;
                    jsFetchFailures.push({
                        url: link.url,
                        finalUrl: result?.finalUrl || link.url,
                        linkType: link.type,
                        discoverySource: link.source,
                        status: result?.status ?? null,
                        contentType: result?.contentType || "",
                        size: result?.size ?? 0,
                        error: result?.error,
                    });
                    continue;
                }

                link.size = result.size;
                if (link.type === "sourcemap") {
                    discoveryMetrics.sourceMapFetchCount += 1;
                    discoveryTimings.sourceMapFetchMs += fetchDurationMs;
                    for (const sourceContent of parseSourceMapScriptContents(result.text, link.url)) {
                        scriptContents.push(retainScriptContents ? sourceContent : { source: sourceContent.source, content: "" });
                    }
                    continue;
                }

                scriptContents.push({
                    source: link.url,
                    content: retainScriptContents ? result.text : "",
                });

                if (depth < MAX_JS_DISCOVERY_DEPTH) {
                    const nestedDiscoveryStartedAt = Date.now();
                    for (const nestedLink of extractJsFromContent(result.text, link.url)) {
                        if (nestedLink.type === "sourcemap" && !followSourceMaps) {
                            continue;
                        }
                        if (!seenJsUrls.has(nestedLink.url)) {
                            const linkAdded = pushJsLink(
                                jsLinks,
                                seenJsUrls,
                                nestedLink,
                                maxJsFiles,
                                includeSameOriginOnly,
                                baseUrl,
                            );
                            if (linkAdded && !visitedScriptUrls.has(nestedLink.url) && nestedLink.type !== "inline") {
                                jsFetchQueue.push({ link: nestedLink, depth: depth + 1 });
                            }
                        }
                    }
                    discoveryTimings.nestedJsDiscoveryMs += Date.now() - nestedDiscoveryStartedAt;
                }
            }
        }
    }

    discoveryMetrics.jsLinksDiscovered = jsLinks.length;
    return {
        jsLinks,
        scriptContents,
        crawledPages,
        htmlRoutes,
        jsFetchFailures,
        timings: discoveryTimings,
        metrics: discoveryMetrics,
    };
}

export function calculateRiskScore(severity: string, eventType: string, count: number): number {
    let score = 0;

    switch (severity) {
        case "critical": score += 40; break;
        case "high": score += 30; break;
        case "medium": score += 20; break;
        case "low": score += 10; break;
    }

    switch (eventType) {
        case "html_routes_added": score += 10; break;
        case "html_routes_removed": score += 8; break;
        case "api_endpoints_added": score += 20; break;
        case "api_endpoints_removed": score += 15; break;
        case "api_change": score += 15; break;
    }

    score += Math.min(count * 2, 20);

    return Math.min(score, 100);
}
