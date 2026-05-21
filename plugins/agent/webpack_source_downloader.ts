/**
 * Webpack Source Downloader
 *
 * @plugin webpack_source_downloader
 * @name Webpack Source Downloader
 * @version 1.0.3
 * @author Sentinel Team
 * @main_category agent
 * @category utility
 * @monitor_type web
 * @default_severity info
 * @tags webpack, sourcemap, source, frontend, download
 * @description Download original frontend source files exposed through webpack:// and webpack-internal:// source maps.
 */

declare const Sentinel: {
    Monitor?: {
        reportProgress?(request: Record<string, unknown>): Promise<boolean> | boolean;
    };
};

interface ToolInput {
    targets: string[];
    userAgent?: string;
    maxJsFiles?: number;
    maxSourceMaps?: number;
    maxSourceFiles?: number;
    maxSourceFileSize?: number;
    includePatterns?: string[];
    excludePatterns?: string[];
    includeNonWebpackSources?: boolean;
    probeSiblingSourceMaps?: boolean;
    __monitorExecution?: MonitorExecutionContext;
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

interface SourceMapLike {
    version?: number;
    file?: string;
    sourceRoot?: string;
    sources?: string[];
    sourcesContent?: Array<string | null>;
    sections?: Array<{ map?: SourceMapLike }>;
}

interface FetchTextResult {
    ok: boolean;
    status: number | null;
    url: string;
    contentType: string;
    text: string;
    size: number;
    error?: string;
}

interface DownloadableSourceFile {
    target: string;
    sourceMapUrl: string;
    sourcePath: string;
    downloadPath: string;
    archivePath: string;
    filename: string;
    mimeType: string;
    encoding: "utf-8";
    content: string;
    contentBase64: string;
    size: number;
    sha256: string;
}

interface SourceMapRecord {
    url: string;
    source: string;
    status: "downloaded" | "parsed" | "failed" | "skipped";
    sourceCount: number;
    extractedFiles: number;
    error?: string;
}

interface TargetResult {
    target: string;
    success: boolean;
    fetchedJsFiles: number;
    fetchedSourceMaps: number;
    extractedFiles: number;
    skippedSourcesWithoutContent: number;
    skippedSourcesByFilter: number;
    skippedSourcesTooLarge: number;
    files: DownloadableSourceFile[];
    sourceMaps: SourceMapRecord[];
    errors: string[];
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: TargetResult[];
        files: DownloadableSourceFile[];
        summary: {
            totalTargets: number;
            successfulTargets: number;
            failedTargets: number;
            fetchedJsFiles: number;
            fetchedSourceMaps: number;
            extractedFiles: number;
            skippedSourcesWithoutContent: number;
            skippedSourcesByFilter: number;
            skippedSourcesTooLarge: number;
        };
        download_manifest: Array<{
            archivePath: string;
            sourcePath: string;
            sourceMapUrl: string;
            size: number;
            sha256: string;
            mimeType: string;
        }>;
        surface_artifacts: {
            frontend_source_files: Array<{
                archivePath: string;
                sourcePath: string;
                sourceMapUrl: string;
                size: number;
                sha256: string;
                mimeType: string;
            }>;
        };
    };
    error?: string;
}

const pluginGlobals = globalThis as typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const DEFAULT_USER_AGENT = "Sentinel-Webpack-Source-Downloader/1.0";
const DEFAULT_MAX_JS_FILES = 50;
const DEFAULT_MAX_SOURCE_MAPS = 50;
const DEFAULT_MAX_SOURCE_FILES = 500;
const DEFAULT_MAX_SOURCE_FILE_SIZE = 750_000;
const MAX_REMOTE_TEXT_BYTES = 20_000_000;
const DEFAULT_EXCLUDE_PATTERNS = ["node_modules/", "(webpack)/"];

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

function clampInteger(value: unknown, fallback: number, min: number, max: number): number {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(Math.floor(parsed), max));
}

function isHttpUrl(value: string): boolean {
    return /^https?:\/\//i.test(value.trim());
}

function resolveUrl(baseUrl: string, value: string): string {
    const candidate = value.trim().replace(/\\\//g, "/");
    if (!candidate || candidate.startsWith("webpack://") || candidate.startsWith("webpack-internal://")) {
        return "";
    }
    try {
        return new URL(candidate, baseUrl).toString();
    } catch {
        return "";
    }
}

async function fetchText(url: string, userAgent: string): Promise<FetchTextResult> {
    try {
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "Accept": "text/html,application/javascript,text/javascript,application/json,*/*",
                "User-Agent": userAgent,
            },
        });
        const contentType = response.headers.get("content-type") || "";
        const contentLength = Number(response.headers.get("content-length") || "0");
        if (Number.isFinite(contentLength) && contentLength > MAX_REMOTE_TEXT_BYTES) {
            return {
                ok: false,
                status: response.status,
                url: response.url || url,
                contentType,
                text: "",
                size: contentLength,
                error: `remote body is too large: ${contentLength} bytes`,
            };
        }
        const text = await response.text();
        return {
            ok: response.ok,
            status: response.status,
            url: response.url || url,
            contentType,
            text: text.length > MAX_REMOTE_TEXT_BYTES ? "" : text,
            size: text.length,
            error: response.ok
                ? (text.length > MAX_REMOTE_TEXT_BYTES ? `remote body is too large: ${text.length} bytes` : undefined)
                : `HTTP ${response.status}`,
        };
    } catch (error: any) {
        return {
            ok: false,
            status: null,
            url,
            contentType: "",
            text: "",
            size: 0,
            error: error?.message || String(error),
        };
    }
}

function isSourceMapUrl(url: string): boolean {
    return /\.map(?:[?#].*)?$/i.test(url);
}

function isJavaScriptUrl(url: string): boolean {
    return /\.(?:js|mjs|cjs)(?:[?#].*)?$/i.test(url);
}

function looksLikeSourceMap(text: string, contentType: string): boolean {
    if (/json|source-map/i.test(contentType)) return /"sources"\s*:/.test(text);
    return /^\s*\{/.test(text) && /"sources"\s*:/.test(text);
}

function looksLikeHtml(text: string, contentType: string): boolean {
    return /html/i.test(contentType) || /<script[\s>]/i.test(text) || /<!doctype html/i.test(text);
}

function extractScriptUrls(html: string, baseUrl: string): string[] {
    const urls: string[] = [];
    const seen = new Set<string>();
    const scriptRegex = /<script\b[^>]*\bsrc\s*=\s*(?:(["'])(.*?)\1|([^"'\s>]+))/gi;
    let match: RegExpExecArray | null;
    while ((match = scriptRegex.exec(html)) !== null) {
        const resolved = resolveUrl(baseUrl, match[2] || match[3] || "");
        if (resolved && !seen.has(resolved)) {
            seen.add(resolved);
            urls.push(resolved);
        }
    }
    return urls;
}

function extractSourceMapUrls(jsText: string, jsUrl: string, probeSiblingSourceMaps: boolean): string[] {
    const urls: string[] = [];
    const seen = new Set<string>();
    const sourceMapRegex = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
    let match: RegExpExecArray | null;
    while ((match = sourceMapRegex.exec(jsText)) !== null) {
        const value = match[1].trim();
        const resolved = value.startsWith("data:")
            ? value
            : resolveUrl(jsUrl, value);
        if (resolved && !seen.has(resolved)) {
            seen.add(resolved);
            urls.push(resolved);
        }
    }
    if (probeSiblingSourceMaps) {
        const sibling = `${jsUrl.split("#")[0].split("?")[0]}.map`;
        if (!seen.has(sibling)) {
            seen.add(sibling);
            urls.push(sibling);
        }
    }
    return urls;
}

function parseDataSourceMapUrl(url: string): string | null {
    const match = url.match(/^data:application\/json(?:;charset=[^;,]+)?(;base64)?,(.*)$/i);
    if (!match) return null;
    const payload = match[2] || "";
    try {
        if (match[1]) {
            return atob(payload);
        }
        return decodeURIComponent(payload);
    } catch {
        return null;
    }
}

function shouldIncludeSource(
    sourcePath: string,
    includeNonWebpackSources: boolean,
    includePatterns: string[],
    excludePatterns: string[],
): boolean {
    const normalized = sourcePath.trim();
    const isWebpackSource = /^webpack(?:-internal)?:\/\//i.test(normalized);
    if (!includeNonWebpackSources && !isWebpackSource) {
        return false;
    }
    if (includePatterns.length > 0 && !includePatterns.some(pattern => normalized.includes(pattern))) {
        return false;
    }
    if (excludePatterns.some(pattern => normalized.includes(pattern))) {
        return false;
    }
    return true;
}

function buildEffectiveSourcePath(sourceRoot: string | undefined, sourcePath: string): string {
    const normalizedSourcePath = String(sourcePath || "").trim();
    const normalizedSourceRoot = String(sourceRoot || "").trim();
    if (!normalizedSourceRoot || /^webpack(?:-internal)?:\/\//i.test(normalizedSourcePath) || /^https?:\/\//i.test(normalizedSourcePath)) {
        return normalizedSourcePath;
    }
    return `${normalizedSourceRoot.replace(/\/+$/g, "")}/${normalizedSourcePath.replace(/^\/+/g, "")}`;
}

function normalizeDownloadPath(sourcePath: string, index: number): string {
    let value = sourcePath
        .replace(/^webpack(?:-internal)?:\/\//i, "")
        .replace(/^\/+/, "")
        .replace(/\\/g, "/")
        .split("#")[0]
        .split("?")[0]
        .trim();

    value = value
        .split("/")
        .filter(segment => segment && segment !== "." && segment !== "..")
        .join("/");

    if (!value) {
        value = `source_${index}.txt`;
    }
    return value.replace(/[<>:"|*]/g, "_");
}

function uniquePath(path: string, seenPaths: Set<string>): string {
    if (!seenPaths.has(path)) {
        seenPaths.add(path);
        return path;
    }

    const slashIndex = path.lastIndexOf("/");
    const dir = slashIndex >= 0 ? `${path.slice(0, slashIndex + 1)}` : "";
    const name = slashIndex >= 0 ? path.slice(slashIndex + 1) : path;
    const dotIndex = name.lastIndexOf(".");
    const stem = dotIndex > 0 ? name.slice(0, dotIndex) : name;
    const ext = dotIndex > 0 ? name.slice(dotIndex) : "";
    let counter = 2;
    while (seenPaths.has(`${dir}${stem}__${counter}${ext}`)) {
        counter += 1;
    }
    const result = `${dir}${stem}__${counter}${ext}`;
    seenPaths.add(result);
    return result;
}

function filenameFromPath(path: string): string {
    return path.split("/").filter(Boolean).pop() || "source.txt";
}

function mimeTypeFromFilename(filename: string): string {
    const lower = filename.toLowerCase();
    if (lower.endsWith(".ts")) return "text/typescript";
    if (lower.endsWith(".tsx")) return "text/tsx";
    if (lower.endsWith(".js") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "application/javascript";
    if (lower.endsWith(".jsx")) return "text/jsx";
    if (lower.endsWith(".vue")) return "text/x-vue";
    if (lower.endsWith(".css") || lower.endsWith(".scss") || lower.endsWith(".sass") || lower.endsWith(".less")) return "text/css";
    if (lower.endsWith(".json")) return "application/json";
    if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html";
    if (lower.endsWith(".svg")) return "image/svg+xml";
    return "text/plain";
}

function textToBase64(text: string): string {
    const bytes = new TextEncoder().encode(text);
    let binary = "";
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        const chunk = bytes.subarray(offset, offset + chunkSize);
        binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
}

async function sha256Hex(text: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

function archiveRootForTarget(target: string): string {
    try {
        const url = new URL(target);
        return `${url.hostname}${url.pathname.replace(/[^a-zA-Z0-9._/-]+/g, "_")}`.replace(/\/+$/g, "") || url.hostname;
    } catch {
        return "target";
    }
}

async function extractFilesFromSourceMap(
    target: string,
    sourceMapUrl: string,
    mapText: string,
    options: {
        includeNonWebpackSources: boolean;
        includePatterns: string[];
        excludePatterns: string[];
        maxSourceFileSize: number;
        maxSourceFiles: number;
        seenDownloadPaths: Set<string>;
        archiveRoot: string;
    },
): Promise<{
    files: DownloadableSourceFile[];
    sourceCount: number;
    skippedSourcesWithoutContent: number;
    skippedSourcesByFilter: number;
    skippedSourcesTooLarge: number;
    error?: string;
}> {
    const files: DownloadableSourceFile[] = [];
    let sourceCount = 0;
    let skippedSourcesWithoutContent = 0;
    let skippedSourcesByFilter = 0;
    let skippedSourcesTooLarge = 0;

    let parsed: SourceMapLike;
    try {
        parsed = JSON.parse(mapText) as SourceMapLike;
    } catch (error: any) {
        return {
            files,
            sourceCount,
            skippedSourcesWithoutContent,
            skippedSourcesByFilter,
            skippedSourcesTooLarge,
            error: error?.message || String(error),
        };
    }

    const queue: SourceMapLike[] = [parsed];
    for (let queueIndex = 0; queueIndex < queue.length; queueIndex += 1) {
        const map = queue[queueIndex];
        const sources = Array.isArray(map.sources) ? map.sources : [];
        const sourcesContent = Array.isArray(map.sourcesContent) ? map.sourcesContent : [];
        sourceCount += sources.length;

        for (let index = 0; index < sources.length; index += 1) {
            const sourcePath = buildEffectiveSourcePath(map.sourceRoot, String(sources[index] || ""));
            const content = sourcesContent[index];

            if (!shouldIncludeSource(sourcePath, options.includeNonWebpackSources, options.includePatterns, options.excludePatterns)) {
                skippedSourcesByFilter += 1;
                continue;
            }
            if (typeof content !== "string") {
                skippedSourcesWithoutContent += 1;
                continue;
            }
            if (content.length > options.maxSourceFileSize) {
                skippedSourcesTooLarge += 1;
                continue;
            }
            if (files.length >= options.maxSourceFiles) {
                skippedSourcesByFilter += 1;
                continue;
            }

            const downloadPath = uniquePath(normalizeDownloadPath(sourcePath, index), options.seenDownloadPaths);
            const filename = filenameFromPath(downloadPath);
            const archivePath = `${options.archiveRoot}/${downloadPath}`;
            const sha256 = await sha256Hex(content);

            files.push({
                target,
                sourceMapUrl,
                sourcePath,
                downloadPath,
                archivePath,
                filename,
                mimeType: mimeTypeFromFilename(filename),
                encoding: "utf-8",
                content,
                contentBase64: textToBase64(content),
                size: content.length,
                sha256,
            });
        }

        if (Array.isArray(map.sections)) {
            for (const section of map.sections) {
                if (section?.map && typeof section.map === "object") {
                    queue.push(section.map);
                }
            }
        }
    }

    return {
        files,
        sourceCount,
        skippedSourcesWithoutContent,
        skippedSourcesByFilter,
        skippedSourcesTooLarge,
    };
}

async function processSourceMapUrl(
    target: string,
    sourceMapUrl: string,
    userAgent: string,
    result: TargetResult,
    options: {
        includeNonWebpackSources: boolean;
        includePatterns: string[];
        excludePatterns: string[];
        maxSourceFileSize: number;
        maxSourceFiles: number;
        seenDownloadPaths: Set<string>;
        archiveRoot: string;
    },
): Promise<void> {
    let mapText = "";
    if (sourceMapUrl.startsWith("data:")) {
        const parsed = parseDataSourceMapUrl(sourceMapUrl);
        if (!parsed) {
            result.sourceMaps.push({
                url: sourceMapUrl.slice(0, 128),
                source: "inline",
                status: "failed",
                sourceCount: 0,
                extractedFiles: 0,
                error: "invalid data source map",
            });
            return;
        }
        mapText = parsed;
    } else {
        const fetched = await fetchText(sourceMapUrl, userAgent);
        result.fetchedSourceMaps += 1;
        if (!fetched.ok || !fetched.text) {
            const error = fetched.error || "empty source map response";
            result.errors.push(`${sourceMapUrl}: ${error}`);
            result.sourceMaps.push({
                url: sourceMapUrl,
                source: target,
                status: "failed",
                sourceCount: 0,
                extractedFiles: 0,
                error,
            });
            return;
        }
        mapText = fetched.text;
    }

    const extracted = await extractFilesFromSourceMap(target, sourceMapUrl, mapText, {
        ...options,
        maxSourceFiles: Math.max(0, options.maxSourceFiles - result.files.length),
    });
    result.skippedSourcesWithoutContent += extracted.skippedSourcesWithoutContent;
    result.skippedSourcesByFilter += extracted.skippedSourcesByFilter;
    result.skippedSourcesTooLarge += extracted.skippedSourcesTooLarge;

    if (extracted.error) {
        result.errors.push(`${sourceMapUrl}: ${extracted.error}`);
        result.sourceMaps.push({
            url: sourceMapUrl,
            source: target,
            status: "failed",
            sourceCount: extracted.sourceCount,
            extractedFiles: 0,
            error: extracted.error,
        });
        return;
    }

    result.files.push(...extracted.files);
    result.extractedFiles += extracted.files.length;
    result.sourceMaps.push({
        url: sourceMapUrl.startsWith("data:") ? sourceMapUrl.slice(0, 128) : sourceMapUrl,
        source: target,
        status: "parsed",
        sourceCount: extracted.sourceCount,
        extractedFiles: extracted.files.length,
    });
}

async function processTarget(
    target: string,
    userAgent: string,
    options: {
        maxJsFiles: number;
        maxSourceMaps: number;
        maxSourceFiles: number;
        maxSourceFileSize: number;
        includePatterns: string[];
        excludePatterns: string[];
        includeNonWebpackSources: boolean;
        probeSiblingSourceMaps: boolean;
    },
): Promise<TargetResult> {
    const result: TargetResult = {
        target,
        success: false,
        fetchedJsFiles: 0,
        fetchedSourceMaps: 0,
        extractedFiles: 0,
        skippedSourcesWithoutContent: 0,
        skippedSourcesByFilter: 0,
        skippedSourcesTooLarge: 0,
        files: [],
        sourceMaps: [],
        errors: [],
    };

    if (!isHttpUrl(target)) {
        result.errors.push("target must be an absolute http:// or https:// URL");
        return result;
    }

    const entry = await fetchText(target, userAgent);
    if (!entry.ok || !entry.text) {
        result.errors.push(entry.error || "empty response");
        return result;
    }

    const jsUrls: string[] = [];
    const sourceMapUrls: string[] = [];
    const seenJsUrls = new Set<string>();
    const seenSourceMapUrls = new Set<string>();

    if (isSourceMapUrl(entry.url) || looksLikeSourceMap(entry.text, entry.contentType)) {
        seenSourceMapUrls.add(entry.url);
        sourceMapUrls.push(entry.url);
    } else if (isJavaScriptUrl(entry.url) || !looksLikeHtml(entry.text, entry.contentType)) {
        seenJsUrls.add(entry.url);
        jsUrls.push(entry.url);
        for (const mapUrl of extractSourceMapUrls(entry.text, entry.url, options.probeSiblingSourceMaps)) {
            if (!seenSourceMapUrls.has(mapUrl)) {
                seenSourceMapUrls.add(mapUrl);
                sourceMapUrls.push(mapUrl);
            }
        }
    } else {
        for (const jsUrl of extractScriptUrls(entry.text, entry.url)) {
            if (!seenJsUrls.has(jsUrl) && jsUrls.length < options.maxJsFiles) {
                seenJsUrls.add(jsUrl);
                jsUrls.push(jsUrl);
            }
        }
    }

    for (const jsUrl of jsUrls.slice(0, options.maxJsFiles)) {
        if (sourceMapUrls.length >= options.maxSourceMaps) {
            break;
        }
        if (jsUrl === entry.url) {
            result.fetchedJsFiles += 1;
            continue;
        }
        const js = await fetchText(jsUrl, userAgent);
        result.fetchedJsFiles += 1;
        if (!js.ok || !js.text) {
            result.errors.push(`${jsUrl}: ${js.error || "empty JS response"}`);
            continue;
        }
        for (const mapUrl of extractSourceMapUrls(js.text, js.url, options.probeSiblingSourceMaps)) {
            if (!seenSourceMapUrls.has(mapUrl) && sourceMapUrls.length < options.maxSourceMaps) {
                seenSourceMapUrls.add(mapUrl);
                sourceMapUrls.push(mapUrl);
            }
        }
    }

    const sourceMapOptions = {
        includeNonWebpackSources: options.includeNonWebpackSources,
        includePatterns: options.includePatterns,
        excludePatterns: options.excludePatterns,
        maxSourceFileSize: options.maxSourceFileSize,
        maxSourceFiles: options.maxSourceFiles,
        seenDownloadPaths: new Set<string>(),
        archiveRoot: archiveRootForTarget(target),
    };

    for (const sourceMapUrl of sourceMapUrls.slice(0, options.maxSourceMaps)) {
        if (result.files.length >= options.maxSourceFiles) {
            break;
        }
        await processSourceMapUrl(target, sourceMapUrl, userAgent, result, sourceMapOptions);
    }

    result.success = result.extractedFiles > 0;
    return result;
}

export function get_input_schema() {
    return {
        type: "object",
        required: ["targets"],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "Absolute page, JavaScript bundle, or source map URLs to inspect",
            },
            userAgent: {
                type: "string",
                description: "User-Agent header for fetching pages, bundles, and source maps",
                default: DEFAULT_USER_AGENT,
            },
            maxJsFiles: {
                type: "integer",
                description: "Maximum JavaScript bundle URLs fetched per target",
                default: DEFAULT_MAX_JS_FILES,
                minimum: 1,
                maximum: 300,
            },
            maxSourceMaps: {
                type: "integer",
                description: "Maximum source map URLs fetched per target",
                default: DEFAULT_MAX_SOURCE_MAPS,
                minimum: 1,
                maximum: 300,
            },
            maxSourceFiles: {
                type: "integer",
                description: "Maximum extracted source files per target",
                default: DEFAULT_MAX_SOURCE_FILES,
                minimum: 1,
                maximum: 5000,
            },
            maxSourceFileSize: {
                type: "integer",
                description: "Maximum individual extracted source file size in bytes",
                default: DEFAULT_MAX_SOURCE_FILE_SIZE,
                minimum: 1024,
                maximum: 5_000_000,
            },
            includePatterns: {
                type: "array",
                items: { type: "string" },
                description: "Optional source path substrings that must match, for example src/ or .vue",
            },
            excludePatterns: {
                type: "array",
                items: { type: "string" },
                description: "Optional source path substrings to exclude, for example node_modules",
                default: DEFAULT_EXCLUDE_PATTERNS,
            },
            includeNonWebpackSources: {
                type: "boolean",
                description: "Also extract non-webpack source map entries",
                default: false,
            },
            probeSiblingSourceMaps: {
                type: "boolean",
                description: "Also request bundle.js.map for each discovered bundle",
                default: false,
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
                    files: {
                        type: "array",
                        description: "Extracted downloadable source files with UTF-8 content and Base64 content",
                    },
                    summary: { type: "object" },
                    download_manifest: {
                        type: "array",
                        description: "Lightweight file manifest for building an archive or download list",
                    },
                    surface_artifacts: { type: "object" },
                },
            },
            error: { type: "string" },
        },
    };
}

pluginGlobals.get_output_schema = get_output_schema;

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!Array.isArray(input.targets) || input.targets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets must contain at least one absolute URL",
            };
        }

        const targets = input.targets
            .map(target => String(target || "").trim())
            .filter(Boolean);
        if (targets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets must contain at least one non-empty URL",
            };
        }

        const userAgent = input.userAgent || DEFAULT_USER_AGENT;
        const options = {
            maxJsFiles: clampInteger(input.maxJsFiles, DEFAULT_MAX_JS_FILES, 1, 300),
            maxSourceMaps: clampInteger(input.maxSourceMaps, DEFAULT_MAX_SOURCE_MAPS, 1, 300),
            maxSourceFiles: clampInteger(input.maxSourceFiles, DEFAULT_MAX_SOURCE_FILES, 1, 5000),
            maxSourceFileSize: clampInteger(input.maxSourceFileSize, DEFAULT_MAX_SOURCE_FILE_SIZE, 1024, 5_000_000),
            includePatterns: Array.isArray(input.includePatterns) ? input.includePatterns.map(String).filter(Boolean) : [],
            excludePatterns: Array.isArray(input.excludePatterns)
                ? input.excludePatterns.map(String).filter(Boolean)
                : DEFAULT_EXCLUDE_PATTERNS,
            includeNonWebpackSources: input.includeNonWebpackSources === true,
            probeSiblingSourceMaps: input.probeSiblingSourceMaps === true,
        };

        await reportMonitorProgress(input.__monitorExecution, {
            current: 0,
            total: targets.length,
            phase: "prepare",
            message: "Preparing webpack source download",
        });

        const results: TargetResult[] = [];
        for (let index = 0; index < targets.length; index += 1) {
            const target = targets[index];
            await reportMonitorProgress(input.__monitorExecution, {
                current: index,
                total: targets.length,
                phase: "download",
                currentTarget: target,
                message: `Extracting webpack sources from ${target}`,
            });
            results.push(await processTarget(target, userAgent, options));
        }

        const files = results.flatMap(result => result.files);
        const successfulTargets = results.filter(result => result.success).length;
        const summary = {
            totalTargets: targets.length,
            successfulTargets,
            failedTargets: targets.length - successfulTargets,
            fetchedJsFiles: results.reduce((sum, result) => sum + result.fetchedJsFiles, 0),
            fetchedSourceMaps: results.reduce((sum, result) => sum + result.fetchedSourceMaps, 0),
            extractedFiles: files.length,
            skippedSourcesWithoutContent: results.reduce((sum, result) => sum + result.skippedSourcesWithoutContent, 0),
            skippedSourcesByFilter: results.reduce((sum, result) => sum + result.skippedSourcesByFilter, 0),
            skippedSourcesTooLarge: results.reduce((sum, result) => sum + result.skippedSourcesTooLarge, 0),
        };

        const downloadManifest = files.map(file => ({
            archivePath: file.archivePath,
            sourcePath: file.sourcePath,
            sourceMapUrl: file.sourceMapUrl,
            size: file.size,
            sha256: file.sha256,
            mimeType: file.mimeType,
        }));

        await reportMonitorProgress(input.__monitorExecution, {
            current: targets.length,
            total: targets.length,
            phase: "complete",
            message: `Extracted ${files.length} webpack source file(s)`,
        });

        return {
            success: files.length > 0,
            data: {
                results,
                files,
                summary,
                download_manifest: downloadManifest,
                surface_artifacts: {
                    frontend_source_files: downloadManifest,
                },
            },
            error: files.length > 0 ? undefined : "No webpack source files with sourcesContent were extracted",
        };
    } catch (error: any) {
        return {
            success: false,
            error: error?.message || String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
