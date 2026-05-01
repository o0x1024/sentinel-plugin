/**
 * Favicon Fingerprinter Tool
 *
 * @plugin favicon_fingerprinter
 * @name Favicon Fingerprinter
 * @version 1.0.0
 * @author Sentinel Team
 * @main_category bounty
 * @category recon
 * @default_severity info
 * @tags favicon, fingerprint, web, asm, surface
 * @description Fetch favicons from web targets and emit favicon fingerprint and evidence artifacts for ASM and network asset mapping workflows
 */

declare const Sentinel: {
    Dictionary?: {
        getEntries?(idOrName: string, limit?: number): Promise<any[]>;
        getDefaultId?(dictType: string): Promise<string | null>;
    };
};

interface ToolInput {
    targets: string[];
    dictionaryId?: string;
    dictionaryEntries?: RuleEntry[];
    timeout?: number;
    followRedirects?: boolean;
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

async function runSequentially<T>(tasks: Array<() => Promise<T>>): Promise<T[]> {
    // Rust controls request pacing; plugins only submit work to the runtime queue.
    const results: T[] = [];
    for (const task of tasks) {
        results.push(await task());
    }
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
                default: 10000,
                minimum: 1000,
                maximum: 60000,
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
                        description: "Favicon fingerprint and evidence artifacts for surface graph ingestion",
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

        const timeout = Math.max(1000, Math.min(input.timeout || 10000, 60000));
                const rules = await loadRules(input);

        const tasks = targets.map((target) => () => fingerprintTarget(target, timeout, input.followRedirects !== false, rules));
        const fingerprints = await runSequentially(tasks);

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
