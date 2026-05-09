/**
 * Favicon Fingerprinter Tool
 *
 * @plugin favicon_fingerprinter
 * @name Favicon Fingerprinter
 * @version 1.2.1
 * @author Sentinel Team
 * @main_category bounty
 * @category recon
 * @default_severity info
 * @tags favicon, fingerprint, web, asm, surface
 * @description Fetch favicons from existing web targets and emit fingerprint/evidence enrichment artifacts without creating new web assets
 */

declare const Sentinel: {
    Dictionary?: {
        getEntries?(idOrName: string, limit?: number): Promise<any[]>;
        getDefaultId?(dictType: string): Promise<string | null>;
    };
    Monitor?: {
        reportProgress?(request: Record<string, unknown>): Promise<boolean> | boolean;
    };
};

interface ToolInput {
    targets: string[];
    dictionaryId?: string;
    dictionaryEntries?: RuleEntry[];
    timeout?: number;
    concurrency?: number;
    followRedirects?: boolean;
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

interface RuleEntry {
    id?: string;
    word: string;
    category?: string | null;
    metadata?: any;
}

interface FingerprintResult {
    target: string;
    success: boolean;
    iconUrl?: string;
    faviconHash?: string;
    contentType?: string;
    bytes?: number;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        targets: string[];
        results: FingerprintResult[];
        summary: {
            totalTargets: number;
            successfulFingerprints: number;
            failedFingerprints: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;
const DEFAULT_TIMEOUT_MS = 5000;
const MIN_TIMEOUT_MS = 1000;
const MAX_TIMEOUT_MS = 30000;
const DEFAULT_CONCURRENCY = 32;
const MIN_CONCURRENCY = 1;
const MAX_CONCURRENCY = 64;

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
        return input.dictionaryEntries.map(entry => ({
            ...entry,
            metadata: parseMetadata(entry.metadata),
        }));
    }

    const candidates = [input.dictionaryId, "builtin_favicon_fingerprint_rules", "Favicon Fingerprint Rules"]
        .filter((value): value is string => typeof value === "string" && value.trim().length > 0);

    for (const candidate of candidates) {
        const rules = await loadDictionaryEntries(candidate);
        if (rules.length > 0) {
            return rules;
        }
    }

    return [];
}

function normalizeWebAssetKey(value: string): string {
    const trimmed = String(value || "").trim();
    if (!trimmed) return "";
    try {
        const url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
        if (url.pathname === "/") {
            url.pathname = "";
        }
        if (!url.search && !url.hash) {
            return url.toString().replace(/\/$/, "");
        }
        return url.toString();
    } catch {
        return "";
    }
}

function normalizeTarget(value: string): string {
    return normalizeWebAssetKey(value);
}

function toWrappedBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    const base64 = btoa(binary);
    return `${base64.match(/.{1,76}/g)?.join("\n") || ""}\n`;
}

function murmurHash3X86_32(value: string, seed = 0): number {
    let remainder = value.length & 3;
    const bytes = value.length - remainder;
    let hash = seed;
    let cursor = 0;
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;

    while (cursor < bytes) {
        let k1 =
            (value.charCodeAt(cursor) & 0xff)
            | ((value.charCodeAt(cursor + 1) & 0xff) << 8)
            | ((value.charCodeAt(cursor + 2) & 0xff) << 16)
            | ((value.charCodeAt(cursor + 3) & 0xff) << 24);
        cursor += 4;

        k1 = Math.imul(k1, c1);
        k1 = (k1 << 15) | (k1 >>> 17);
        k1 = Math.imul(k1, c2);

        hash ^= k1;
        hash = (hash << 13) | (hash >>> 19);
        hash = (Math.imul(hash, 5) + 0xe6546b64) | 0;
    }

    let k1 = 0;
    switch (remainder) {
        case 3:
            k1 ^= (value.charCodeAt(cursor + 2) & 0xff) << 16;
        case 2:
            k1 ^= (value.charCodeAt(cursor + 1) & 0xff) << 8;
        case 1:
            k1 ^= value.charCodeAt(cursor) & 0xff;
            k1 = Math.imul(k1, c1);
            k1 = (k1 << 15) | (k1 >>> 17);
            k1 = Math.imul(k1, c2);
            hash ^= k1;
    }

    hash ^= value.length;
    hash ^= hash >>> 16;
    hash = Math.imul(hash, 0x85ebca6b);
    hash ^= hash >>> 13;
    hash = Math.imul(hash, 0xc2b2ae35);
    hash ^= hash >>> 16;

    return hash | 0;
}

function computeFofaIconHash(buffer: ArrayBuffer): string {
    return String(murmurHash3X86_32(toWrappedBase64(buffer), 0));
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

function extractIconCandidates(baseUrl: URL, html: string): string[] {
    const candidates: string[] = [];
    const pattern = /<link\b[^>]*rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["'][^>]*>/gi;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(html)) !== null) {
        const rawHref = match[1]?.trim();
        if (!rawHref) continue;
        try {
            candidates.push(new URL(rawHref, baseUrl).toString());
        } catch {
            continue;
        }
    }

    candidates.push(new URL("/favicon.ico", baseUrl).toString());
    return Array.from(new Set(candidates));
}

function matchFaviconRule(faviconHash: string, iconUrl: string, rules: RuleEntry[]): RuleEntry | undefined {
    for (const rule of rules) {
        const metadata = parseMetadata(rule.metadata);
        const matchers = Array.isArray(metadata.matchers) ? metadata.matchers : [];
        if (matchers.length > 0) {
            const operator = String(metadata.operator || "or").toLowerCase();
            const matched = operator === "and"
                ? matchers.every((matcher: any) => {
                    const part = String(matcher?.part || "").toLowerCase();
                    const type = String(matcher?.type || "contains").toLowerCase();
                    const source = part.includes("url") ? iconUrl : faviconHash;
                    const value = String(matcher?.value || "");
                    if (type === "equals") return source.toLowerCase() === value.toLowerCase();
                    if (type === "regex") {
                        try {
                            return new RegExp(value, "i").test(source);
                        } catch {
                            return false;
                        }
                    }
                    return source.toLowerCase().includes(value.toLowerCase());
                })
                : matchers.some((matcher: any) => {
                    const part = String(matcher?.part || "").toLowerCase();
                    const type = String(matcher?.type || "contains").toLowerCase();
                    const source = part.includes("url") ? iconUrl : faviconHash;
                    const value = String(matcher?.value || "");
                    if (type === "equals") return source.toLowerCase() === value.toLowerCase();
                    if (type === "regex") {
                        try {
                            return new RegExp(value, "i").test(source);
                        } catch {
                            return false;
                        }
                    }
                    return source.toLowerCase().includes(value.toLowerCase());
                });
            if (matched) {
                return rule;
            }
            continue;
        }

        if (faviconHash.toLowerCase().includes(rule.word.toLowerCase())) {
            return rule;
        }
    }

    return undefined;
}

async function fingerprintTarget(
    target: string,
    timeout: number,
    followRedirects: boolean,
    rules: RuleEntry[],
): Promise<FingerprintResult & { fingerprint?: any; evidence?: any }> {
    const canonicalUrl = new URL(target);
    const assetKey = normalizeWebAssetKey(canonicalUrl.toString());
    try {
        const pageResponse = await fetchWithTimeout(
            canonicalUrl.toString(),
            {
                method: "GET",
                redirect: followRedirects ? "follow" : "manual",
            },
            timeout,
        );
        const html = await pageResponse.text();
        const candidates = extractIconCandidates(canonicalUrl, html);

        for (const iconUrl of candidates) {
            try {
                const iconResponse = await fetchWithTimeout(
                    iconUrl,
                    {
                        method: "GET",
                        redirect: followRedirects ? "follow" : "manual",
                    },
                    timeout,
                );
                if (!iconResponse.ok) continue;
                const buffer = await iconResponse.arrayBuffer();
                if (!buffer || buffer.byteLength === 0) continue;

                const faviconHash = computeFofaIconHash(buffer);
                const matchedRule = matchFaviconRule(faviconHash, iconUrl, rules);
                const metadata = parseMetadata(matchedRule?.metadata);
                return {
                    target: assetKey,
                    success: true,
                    iconUrl,
                    faviconHash,
                    contentType: iconResponse.headers.get("content-type") || undefined,
                    bytes: buffer.byteLength,
                    fingerprint: matchedRule && metadata.product && metadata.asset_category
                        ? {
                            asset_type: "web",
                            asset_key: assetKey,
                            fingerprint_type: "favicon",
                            fingerprint_key: iconUrl,
                            fingerprint_value: faviconHash,
                            rule_id: metadata.rule_id || matchedRule.id || `favicon_rule:${matchedRule.word}`,
                            rule_word: matchedRule.word,
                            rule_name: metadata.name || matchedRule.word,
                            normalized_product: metadata.product,
                            normalized_vendor: metadata.vendor,
                            normalized_category: metadata.asset_category,
                            normalized_family: metadata.asset_family,
                            confidence: 0.95,
                            evidence: `Fetched favicon from ${iconUrl}`,
                        }
                        : undefined,
                    evidence: {
                        asset_type: "web",
                        asset_key: assetKey,
                        evidence_type: "favicon_metadata",
                        title: `Favicon fingerprint for ${canonicalUrl.hostname}`,
                        content_json: {
                            icon_url: iconUrl,
                            icon_hash: faviconHash,
                            content_type: iconResponse.headers.get("content-type"),
                            size_bytes: buffer.byteLength,
                        },
                    },
                };
            } catch {
                continue;
            }
        }

        return {
            target: assetKey,
            success: false,
            error: "No favicon could be fetched",
        };
    } catch (error) {
        return {
            target: assetKey,
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

async function runConcurrently<T>(
    tasks: Array<() => Promise<T>>,
    concurrency: number,
): Promise<T[]> {
    const results = new Array<T>(tasks.length);
    let nextIndex = 0;
    const workerCount = Math.min(concurrency, tasks.length);

    async function worker() {
        while (nextIndex < tasks.length) {
            const index = nextIndex;
            nextIndex += 1;
            results[index] = await tasks[index]();
        }
    }

    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    return results;
}

export function get_input_schema() {
    return {
        type: "object",
        required: ["targets"],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "HTTP or HTTPS URLs to fingerprint via favicon",
            },
            dictionaryId: {
                type: "string",
                description: "Structured fingerprint dictionary ID or name",
            },
            dictionaryEntries: {
                type: "array",
                description: "Structured rule entries injected by workflow",
                items: {
                    type: "object",
                    properties: {
                        id: { type: "string" },
                        word: { type: "string" },
                        category: { type: "string" },
                        metadata: { type: "object" },
                    },
                    required: ["word"],
                },
            },
            timeout: {
                type: "integer",
                description: "Network timeout in milliseconds",
                default: DEFAULT_TIMEOUT_MS,
                minimum: MIN_TIMEOUT_MS,
                maximum: MAX_TIMEOUT_MS,
            },
            concurrency: {
                type: "integer",
                description: "Maximum concurrent favicon fetches",
                default: DEFAULT_CONCURRENCY,
                minimum: MIN_CONCURRENCY,
                maximum: MAX_CONCURRENCY,
            },
            followRedirects: {
                type: "boolean",
                description: "Follow HTTP redirects",
                default: true,
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
                    targets: { type: "array", items: { type: "string" } },
                    results: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                target: { type: "string" },
                                success: { type: "boolean" },
                                iconUrl: { type: "string" },
                                faviconHash: { type: "string" },
                                contentType: { type: "string" },
                                bytes: { type: "number" },
                                error: { type: "string" },
                            },
                            required: ["target", "success"],
                        },
                    },
                    summary: {
                        type: "object",
                        properties: {
                            totalTargets: { type: "number" },
                            successfulFingerprints: { type: "number" },
                            failedFingerprints: { type: "number" },
                        },
                        required: ["totalTargets", "successfulFingerprints", "failedFingerprints"],
                    },
                    surface_artifacts: {
                        type: "object",
                        description: "Favicon fingerprint and evidence artifacts that enrich matching existing web assets without creating web assets",
                        properties: {
                            fingerprints: {
                                type: "array",
                                description: "Strict favicon fingerprint artifacts with explicit rule_* and normalized_* fields",
                                items: { type: "object" },
                            },
                            evidences: {
                                type: "array",
                                description: "Structured favicon evidence artifacts",
                                items: { type: "object" },
                            },
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
        if (!Array.isArray(input.targets) || input.targets.length === 0) {
            return { success: false, error: "Invalid input: targets array is required" };
        }

        const targets = Array.from(new Set(input.targets.map(normalizeTarget).filter(Boolean)));
        if (targets.length === 0) {
            return { success: false, error: "No valid web targets provided" };
        }

        const timeout = clampInteger(input.timeout, DEFAULT_TIMEOUT_MS, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
        const concurrency = clampInteger(
            input.concurrency,
            DEFAULT_CONCURRENCY,
            MIN_CONCURRENCY,
            MAX_CONCURRENCY,
        );
        const rules = await loadRules(input);
        const monitorExecution = input.__monitorExecution;

        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: targets.length,
            phase: "prepare",
            message: `Preparing favicon fingerprints (${targets.length} targets, concurrency ${concurrency})`,
        });

        let completedTargets = 0;
        const tasks = targets.map((target) => async () => {
            try {
                return await fingerprintTarget(target, timeout, input.followRedirects !== false, rules);
            } finally {
                completedTargets += 1;
                await reportMonitorProgress(monitorExecution, {
                    current: completedTargets,
                    total: targets.length,
                    currentTarget: target,
                    phase: "fingerprint",
                    message: `Fetched favicon fingerprint for ${target}`,
                });
            }
        });
        const fingerprints = await runConcurrently(tasks, concurrency);

        return {
            success: true,
            data: {
                targets,
                results: fingerprints.map(({ fingerprint, evidence, ...result }) => result),
                summary: {
                    totalTargets: targets.length,
                    successfulFingerprints: fingerprints.filter((item) => item.success).length,
                    failedFingerprints: fingerprints.filter((item) => !item.success).length,
                },
                surface_artifacts: {
                    fingerprints: fingerprints
                        .map((item) => item.fingerprint)
                        .filter(Boolean),
                    evidences: fingerprints
                        .map((item) => item.evidence)
                        .filter(Boolean),
                },
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
