/**
 * Technology Fingerprinter Tool
 *
 * @plugin tech_fingerprinter
 * @name Technology Fingerprinter
 * @version 2.1.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags fingerprint, technology, dictionary, web
 * @description Identify web technologies using dictionary-driven fingerprint rules with structured matchers.
 */

declare const Sentinel: {
    Dictionary?: {
        get?(idOrName: string): Promise<any>;
        getDefaultId?(dictType: string): Promise<string | null>;
        getEntries?(idOrName: string, limit?: number): Promise<any[]>;
    };
};

interface ToolInput {
    url?: string;
    base_url?: string;
    targets?: string[];
    dictionaryId?: string;
    dictionaryEntries?: RuleEntry[];
    timeout?: number;
    userAgent?: string;
    concurrency?: number;
    maxTargets?: number;
}

interface RuleEntry {
    word: string;
    category?: string | null;
    metadata?: any;
}

interface TechnologyResult {
    name: string;
    category: string;
    version?: string;
    confidence: number;
    evidence: string[];
}

interface PerTargetResult {
    url: string;
    technologies: TechnologyResult[];
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: PerTargetResult[];
        technologies: TechnologyResult[];
        summary: {
            totalTargets: number;
            matchedTargets: number;
            identifiedTechnologies: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

const FALLBACK_RULES: RuleEntry[] = [
    {
        word: "nginx",
        category: "web_server",
        metadata: {
            name: "Nginx",
            confidence: 0.95,
            matchers: [{ part: "header", key: "server", type: "regex", value: "nginx(?:/([0-9.]+))?" }],
            version_patterns: [{ part: "header", key: "server", pattern: "nginx/([0-9.]+)" }],
        },
    },
    {
        word: "apache",
        category: "web_server",
        metadata: {
            name: "Apache HTTP Server",
            confidence: 0.95,
            matchers: [{ part: "header", key: "server", type: "regex", value: "apache(?:/([0-9.]+))?" }],
            version_patterns: [{ part: "header", key: "server", pattern: "apache/([0-9.]+)" }],
        },
    },
    {
        word: "cloudflare",
        category: "cdn",
        metadata: {
            name: "Cloudflare",
            confidence: 0.9,
            operator: "or",
            matchers: [
                { part: "header", key: "server", type: "contains", value: "cloudflare" },
                { part: "header", key: "cf-ray", type: "exists" },
            ],
        },
    },
    {
        word: "nextjs",
        category: "framework",
        metadata: {
            name: "Next.js",
            confidence: 0.85,
            operator: "or",
            matchers: [
                { part: "body", type: "contains", value: "__NEXT_DATA__" },
                { part: "body", type: "contains", value: "_next/static" },
                { part: "header", key: "x-powered-by", type: "contains", value: "Next.js" },
            ],
        },
    },
    {
        word: "vuejs",
        category: "framework",
        metadata: {
            name: "Vue.js",
            confidence: 0.8,
            operator: "or",
            matchers: [
                { part: "body", type: "regex", value: "data-v-[a-f0-9]+" },
                { part: "body", type: "contains", value: "__VUE__" },
            ],
        },
    },
    {
        word: "swagger_ui",
        category: "api_doc",
        metadata: {
            name: "Swagger UI",
            confidence: 0.95,
            operator: "or",
            matchers: [
                { part: "title", type: "contains", value: "Swagger UI" },
                { part: "body", type: "contains", value: "swagger-ui" },
            ],
        },
    },
];

export function get_input_schema() {
    return {
        type: "object",
        properties: {
            url: { type: "string", description: "Target URL" },
            base_url: { type: "string", description: "Base URL alias" },
            targets: { type: "array", items: { type: "string" }, description: "Multiple target URLs" },
            dictionaryId: { type: "string", description: "Structured fingerprint dictionary ID or name" },
            dictionaryEntries: { type: "array", description: "Structured rule entries injected by workflow" },
            timeout: { type: "integer", default: 10000, minimum: 1000, maximum: 60000 },
            userAgent: { type: "string", default: "Sentinel-Tech-Fingerprinter/2.0" },
            concurrency: { type: "integer", default: 5, minimum: 1, maximum: 20 },
            maxTargets: { type: "integer", default: 20, minimum: 1, maximum: 200 },
        },
    };
}

export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean" },
            data: {
                type: "object",
                properties: {
                    results: { type: "array" },
                    technologies: { type: "array" },
                    summary: { type: "object" },
                    surface_artifacts: { type: "object" },
                },
            },
            error: { type: "string" },
        },
    };
}

globalThis.get_input_schema = get_input_schema;
globalThis.get_output_schema = get_output_schema;

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

function normalizeTarget(raw?: string): string | null {
    if (!raw || typeof raw !== "string") return null;
    const trimmed = raw.trim();
    if (!trimmed) return null;
    return trimmed.startsWith("http://") || trimmed.startsWith("https://") ? trimmed : `https://${trimmed}`;
}

function parseTitle(html: string): string {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match?.[1]?.trim() || "";
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

    const defaultDictionaryId = Sentinel?.Dictionary?.getDefaultId
        ? await Sentinel.Dictionary.getDefaultId("fingerprint_rule")
        : null;

    const candidates = [input.dictionaryId, defaultDictionaryId, "builtin_web_fingerprint_rules", "Web Fingerprint Rules"]
        .filter((value): value is string => typeof value === "string" && value.trim().length > 0);

    for (const candidate of candidates) {
        const rules = await loadDictionaryEntries(candidate);
        if (rules.length > 0) return rules;
    }

    return FALLBACK_RULES;
}

async function fetchWithTimeout(url: string, timeout: number, userAgent: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
        return await fetch(url, {
            method: "GET",
            redirect: "follow",
            signal: controller.signal,
            headers: {
                "User-Agent": userAgent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        });
    } finally {
        clearTimeout(timer);
    }
}

function matcherHit(ctx: Record<string, any>, matcher: any): boolean {
    const part = String(matcher?.part || "body").toLowerCase();
    const type = String(matcher?.type || "contains").toLowerCase();
    const value = matcher?.value;

    if (part === "status") {
        if (type === "in" && Array.isArray(value)) return value.includes(ctx.status);
        return ctx.status === value;
    }

    const source = part === "header"
        ? String(ctx.headers[String(matcher?.key || "").toLowerCase()] || "")
        : part === "title"
            ? ctx.title
            : ctx.body;

    if (type === "exists") return source.length > 0;
    if (type === "equals") return source === String(value || "");
    if (type === "regex") {
        try {
            return new RegExp(String(value || ""), "i").test(source);
        } catch {
            return false;
        }
    }
    if (type === "in" && Array.isArray(value)) return value.includes(source);
    return source.toLowerCase().includes(String(value || "").toLowerCase());
}

function ruleMatched(ctx: Record<string, any>, metadata: Record<string, any>): boolean {
    const matchers = Array.isArray(metadata.matchers) ? metadata.matchers : [];
    if (matchers.length === 0) return false;
    const operator = String(metadata.operator || "or").toLowerCase();
    return operator === "and"
        ? matchers.every((matcher: any) => matcherHit(ctx, matcher))
        : matchers.some((matcher: any) => matcherHit(ctx, matcher));
}

function extractVersion(ctx: Record<string, any>, metadata: Record<string, any>): string | undefined {
    const patterns = Array.isArray(metadata.version_patterns) ? metadata.version_patterns : [];
    for (const item of patterns) {
        const part = String(item?.part || "").toLowerCase();
        const source = part === "header"
            ? String(ctx.headers[String(item?.key || "").toLowerCase()] || "")
            : part === "title"
                ? ctx.title
                : ctx.body;
        try {
            const match = source.match(new RegExp(String(item?.pattern || ""), "i"));
            if (match?.[1]) return match[1];
        } catch {
            continue;
        }
    }
    return undefined;
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const timeout = Number(input.timeout || 10000);
        const userAgent = input.userAgent || "Sentinel-Tech-Fingerprinter/2.0";
        const concurrency = Math.max(1, Math.min(Number(input.concurrency || 5), 20));
        const targets = Array.from(new Set([
            normalizeTarget(input.url),
            normalizeTarget(input.base_url),
            ...(Array.isArray(input.targets) ? input.targets.map(normalizeTarget) : []),
        ].filter((value): value is string => Boolean(value)))).slice(0, Number(input.maxTargets || 20));

        if (targets.length === 0) {
            return { success: false, error: "At least one target URL is required" };
        }

        const rules = await loadRules(input);
        const results: PerTargetResult[] = [];
        const fingerprints: any[] = [];

        await runWithConcurrency(
            targets.map((target) => async () => {
                try {
                    const response = await fetchWithTimeout(target, timeout, userAgent);
                    const body = await response.text();
                    const headers: Record<string, string> = {};
                    response.headers.forEach((value, key) => { headers[String(key).toLowerCase()] = value; });
                    const ctx = {
                        status: response.status,
                        headers,
                        body,
                        title: parseTitle(body),
                    };

                    const technologies = rules
                        .filter(rule => ruleMatched(ctx, parseMetadata(rule.metadata)))
                        .map(rule => {
                            const metadata = parseMetadata(rule.metadata);
                            const tech = {
                                name: metadata.name || rule.word,
                                category: rule.category || "technology",
                                version: extractVersion(ctx, metadata),
                                confidence: Math.round(Number(metadata.confidence || 0.8) * 100),
                                evidence: [`matched:${rule.word}`],
                            };

                            fingerprints.push({
                                asset_type: "web",
                                asset_key: target,
                                fingerprint_type: "technology",
                                fingerprint_key: rule.word,
                                fingerprint_value: tech.name,
                                version: tech.version,
                                confidence: tech.confidence,
                                source: "tech_fingerprinter",
                                web_key: target,
                            });

                            return tech;
                        });

                    results.push({ url: target, technologies });
                } catch {
                    results.push({ url: target, technologies: [] });
                }
            }),
            concurrency,
        );

        return {
            success: true,
            data: {
                results,
                technologies: results[0]?.technologies || [],
                summary: {
                    totalTargets: targets.length,
                    matchedTargets: results.filter(item => item.technologies.length > 0).length,
                    identifiedTechnologies: results.reduce((sum, item) => sum + item.technologies.length, 0),
                },
                surface_artifacts: {
                    fingerprints,
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

globalThis.analyze = analyze;
