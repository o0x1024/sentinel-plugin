/**
 * Sensitive File Scanner Tool
 *
 * @plugin sensitive_file_scanner
 * @name Sensitive File Scanner
 * @version 1.1.0
 * @author Sentinel Team
 * @category risk
 * @default_severity medium
 * @tags risk, exposure, file, dictionary, web
 * @description Scan web targets for exposed sensitive files using structured dictionary rules.
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

interface Finding {
    title: string;
    severity: string;
    url: string;
    description: string;
    evidence?: string;
    cwe?: string;
    remediation?: string;
    tags?: string[];
}

interface ToolOutput {
    success: boolean;
    data?: {
        findings: Finding[];
        summary: {
            totalTargets: number;
            scannedRules: number;
            findings: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

const FALLBACK_RULES: RuleEntry[] = [
    { word: "swagger-ui.html", category: "api_doc", metadata: { path: "swagger-ui.html", severity: "medium", description: "Swagger UI is publicly accessible", tags: ["swagger", "openapi"] } },
    { word: "v3/api-docs", category: "api_doc", metadata: { path: "v3/api-docs", severity: "medium", description: "OpenAPI document is publicly accessible", tags: ["openapi"] } },
    { word: "config", category: "config", metadata: { path: "config", severity: "high", description: "Potential configuration file exposed", tags: ["config"] } },
    { word: "nohup.out", category: "log", metadata: { path: "nohup.out", severity: "medium", description: "nohup.out log file exposed", tags: ["log"] } },
    { word: "actuator/env", category: "exposure", metadata: { path: "actuator/env", severity: "high", description: "Spring Actuator environment endpoint exposed", tags: ["spring", "actuator"] } },
];

export function get_input_schema() {
    return {
        type: "object",
        properties: {
            url: { type: "string" },
            base_url: { type: "string" },
            targets: { type: "array", items: { type: "string" } },
            dictionaryId: { type: "string" },
            dictionaryEntries: { type: "array" },
            timeout: { type: "integer", default: 8000, minimum: 1000, maximum: 60000 },
            userAgent: { type: "string", default: "Sentinel-Sensitive-File-Scanner/1.0" },
            concurrency: { type: "integer", default: 8, minimum: 1, maximum: 50 },
            maxTargets: { type: "integer", default: 10, minimum: 1, maximum: 100 },
        },
    };
}

export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean" },
            data: { type: "object" },
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
    const trimmed = raw.trim().replace(/\/+$/, "");
    if (!trimmed) return null;
    return trimmed.startsWith("http://") || trimmed.startsWith("https://") ? trimmed : `https://${trimmed}`;
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

async function loadStructuredDictionary(idOrName: string): Promise<RuleEntry[]> {
    if (!Sentinel?.Dictionary?.getEntries) return [];
    try {
        const entries = await Sentinel.Dictionary.getEntries(idOrName, 10000);
        return entries
            .filter((item: any) => item && typeof item.word === "string")
            .map((item: any) => ({ word: item.word, category: item.category || null, metadata: parseMetadata(item.metadata) }));
    } catch {
        return [];
    }
}

async function loadRules(input: ToolInput): Promise<RuleEntry[]> {
    if (Array.isArray(input.dictionaryEntries) && input.dictionaryEntries.length > 0) {
        return input.dictionaryEntries.map(entry => ({ ...entry, metadata: parseMetadata(entry.metadata) }));
    }
    const defaultDictionaryId = Sentinel?.Dictionary?.getDefaultId
        ? await Sentinel.Dictionary.getDefaultId("sensitive_file")
        : null;
    const candidates = [input.dictionaryId, defaultDictionaryId, "builtin_sensitive_files_web", "Sensitive Files Web"]
        .filter((value): value is string => typeof value === "string" && value.trim().length > 0);
    for (const candidate of candidates) {
        const rules = await loadStructuredDictionary(candidate);
        if (rules.length > 0) return rules;
    }
    return FALLBACK_RULES;
}

async function fetchWithTimeout(url: string, timeout: number, userAgent: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
        return await fetch(url, { method: "GET", signal: controller.signal, headers: { "User-Agent": userAgent } });
    } finally {
        clearTimeout(timer);
    }
}

function joinUrl(baseUrl: string, path: string): string {
    return `${baseUrl}/${String(path || "").replace(/^\/+/, "")}`;
}

function matcherHit(body: string, matcher: any): boolean {
    const type = String(matcher?.type || "contains").toLowerCase();
    const value = String(matcher?.value || "");
    if (!value) return true;
    if (type === "regex") {
        try {
            return new RegExp(value, "i").test(body);
        } catch {
            return false;
        }
    }
    return body.toLowerCase().includes(value.toLowerCase());
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const timeout = Number(input.timeout || 8000);
        const userAgent = input.userAgent || "Sentinel-Sensitive-File-Scanner/1.0";
        const concurrency = Math.max(1, Math.min(Number(input.concurrency || 8), 50));
        const targets = Array.from(new Set([
            normalizeTarget(input.url),
            normalizeTarget(input.base_url),
            ...(Array.isArray(input.targets) ? input.targets.map(normalizeTarget) : []),
        ].filter((value): value is string => Boolean(value)))).slice(0, Number(input.maxTargets || 10));

        if (targets.length === 0) {
            return { success: false, error: "At least one web target is required" };
        }

        const rules = await loadRules(input);
        const findings: Finding[] = [];
        const vulnerabilityFindings: any[] = [];

        const scanTasks: Array<{ target: string; rule: RuleEntry }> = [];
        for (const target of targets) {
            for (const rule of rules) {
                scanTasks.push({ target, rule });
            }
        }

        await runWithConcurrency(
            scanTasks.map(({ target, rule }) => async () => {
                const metadata = parseMetadata(rule.metadata);
                if (metadata.enabled === false) return;
                const path = metadata.path || rule.word;
                const url = joinUrl(target, path);
                try {
                    const response = await fetchWithTimeout(url, timeout, userAgent);
                    if (response.status !== 200) return;
                    const body = await response.text();
                    const matchers = Array.isArray(metadata.matchers) ? metadata.matchers : [];
                    if (matchers.length > 0 && !matchers.every((matcher: any) => matcherHit(body, matcher))) return;

                    const finding = {
                        title: metadata.name || `Sensitive file exposed: ${path}`,
                        severity: metadata.severity || "medium",
                        url,
                        description: metadata.description || `Sensitive file exposed at ${url}`,
                        evidence: body.slice(0, 500),
                        cwe: metadata.cwe || "CWE-200",
                        remediation: metadata.remediation || "Restrict public access to this resource.",
                        tags: Array.isArray(metadata.tags) ? metadata.tags : [],
                    };
                    findings.push(finding);
                    vulnerabilityFindings.push({
                        title: finding.title,
                        severity: finding.severity,
                        target: url,
                        vulnerability_type: rule.category || "sensitive_file_exposure",
                        description: finding.description,
                        evidence: finding.evidence,
                        source: "sensitive_file_scanner",
                    });
                } catch {
                    return;
                }
            }),
            concurrency,
        );

        return {
            success: true,
            data: {
                findings,
                summary: {
                    totalTargets: targets.length,
                    scannedRules: rules.length,
                    findings: findings.length,
                },
                surface_artifacts: {
                    findings: vulnerabilityFindings,
                },
            },
        };
    } catch (error: any) {
        return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
}

globalThis.analyze = analyze;
