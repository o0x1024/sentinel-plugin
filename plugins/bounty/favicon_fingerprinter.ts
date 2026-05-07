/**
 * Favicon Fingerprinter Tool
 *
 * @plugin favicon_fingerprinter
 * @name Favicon Fingerprinter
 * @version 1.1.1
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
    faviconSha256?: string;
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

function normalizeTarget(value: string): string {
    const trimmed = String(value || "").trim();
    if (!trimmed) return "";
    try {
        return new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`).toString();
    } catch {
        return "";
    }
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    return bytesToHex(new Uint8Array(digest));
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

function matchFaviconRule(faviconSha256: string, iconUrl: string, rules: RuleEntry[]): RuleEntry | undefined {
    for (const rule of rules) {
        const metadata = parseMetadata(rule.metadata);
        const matchers = Array.isArray(metadata.matchers) ? metadata.matchers : [];
        if (matchers.length > 0) {
            const operator = String(metadata.operator || "or").toLowerCase();
            const matched = operator === "and"
                ? matchers.every((matcher: any) => {
                    const part = String(matcher?.part || "").toLowerCase();
                    const type = String(matcher?.type || "contains").toLowerCase();
                    const source = part.includes("url") ? iconUrl : faviconSha256;
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
                    const source = part.includes("url") ? iconUrl : faviconSha256;
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

        if (faviconSha256.toLowerCase().includes(rule.word.toLowerCase())) {
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

                const faviconSha256 = await sha256Hex(buffer);
                const matchedRule = matchFaviconRule(faviconSha256, iconUrl, rules);
                const metadata = parseMetadata(matchedRule?.metadata);
                return {
                    target: canonicalUrl.toString(),
                    success: true,
                    iconUrl,
                    faviconSha256,
                    contentType: iconResponse.headers.get("content-type") || undefined,
                    bytes: buffer.byteLength,
                    fingerprint: matchedRule && metadata.product && metadata.asset_category
                        ? {
                            asset_type: "web",
                            asset_key: canonicalUrl.toString(),
                            fingerprint_type: "favicon",
                            fingerprint_key: iconUrl,
                            fingerprint_value: faviconSha256,
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
                        asset_key: canonicalUrl.toString(),
                        evidence_type: "favicon_metadata",
                        title: `Favicon fingerprint for ${canonicalUrl.hostname}`,
                        content_json: {
                            icon_url: iconUrl,
                            sha256: faviconSha256,
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
            target: canonicalUrl.toString(),
            success: false,
            error: "No favicon could be fetched",
        };
    } catch (error) {
        return {
            target: canonicalUrl.toString(),
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
                    results: { type: "array" },
                    summary: { type: "object" },
                    surface_artifacts: {
                        type: "object",
                        description: "Favicon fingerprint and evidence artifacts that enrich matching existing web assets without creating web assets",
                        properties: {
                            fingerprints: {
                                type: "array",
                                description: "Strict favicon fingerprint artifacts with explicit rule_* and normalized_* fields",
                            },
                            evidences: {
                                type: "array",
                                description: "Structured favicon evidence artifacts",
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
