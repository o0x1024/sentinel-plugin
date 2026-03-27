/**
 * Sensitive File Scanner Tool
 *
 * @plugin sensitive_file_scanner
 * @name Sensitive File Scanner
 * @version 1.3.1
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
            attemptedRequests: number;
            connectivityFailures: number;
            timeoutErrors: number;
            networkErrors: number;
            skippedTargets: number;
            skippedDeadTargetProbes: number;
            heuristicFiltered: number;
            statusBuckets: Record<string, number>;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

interface ScanStats {
    attemptedRequests: number;
    connectivityFailures: number;
    timeoutErrors: number;
    networkErrors: number;
    skippedTargets: number;
    skippedDeadTargetProbes: number;
    heuristicFiltered: number;
    statusBuckets: Record<string, number>;
}

interface PreparedRule {
    rule: RuleEntry;
    metadata: Record<string, any>;
    path: string;
    matchers: any[];
    negativeMatchers: any[];
}

interface ResponseContext {
    url: string;
    status: number;
    headers: Record<string, string>;
    contentType: string;
    title: string;
    body: string;
}

const pluginGlobals = globalThis as typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

export function get_input_schema() {
    return {
        type: "object",
        required: [],
        properties: {
            url: {
                type: "string",
                description: "Single target URL to scan for exposed sensitive files"
            },
            base_url: {
                type: "string",
                description: "Base URL alias for a single target"
            },
            targets: {
                type: "array",
                items: { type: "string" },
                description: "List of target URLs to scan"
            },
            dictionaryId: {
                type: "string",
                description: "Structured dictionary ID or name used to resolve sensitive file rules"
            },
            dictionaryEntries: {
                type: "array",
                description: "Inline sensitive file rules that override dictionary loading",
                items: {
                    type: "object",
                    required: ["word"],
                    properties: {
                        word: {
                            type: "string",
                            description: "Rule key or relative path to probe"
                        },
                        category: {
                            type: "string",
                            description: "Rule category used for normalized finding type"
                        },
                        metadata: {
                            description: "Rule metadata object or JSON string with path, matchers, severity and tags"
                        }
                    }
                }
            },
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: 3000,
                minimum: 1000,
                maximum: 60000
            },
            userAgent: {
                type: "string",
                description: "User-Agent header used when requesting candidate files",
                default: "Sentinel-Sensitive-File-Scanner/1.0"
            },
            concurrency: {
                type: "integer",
                description: "Number of concurrent file probes",
                default: 50,
                minimum: 1,
                maximum: 50
            },
            maxTargets: {
                type: "integer",
                description: "Optional maximum number of normalized targets to scan",
                minimum: 1,
                maximum: 100
            },
        },
    };
}

export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: {
                type: "boolean",
                description: "Whether the scan completed successfully"
            },
            data: {
                type: "object",
                properties: {
                    findings: {
                        type: "array",
                        description: "Sensitive file exposure findings discovered during scanning",
                        items: {
                            type: "object",
                            properties: {
                                title: { type: "string" },
                                severity: { type: "string" },
                                url: { type: "string" },
                                description: { type: "string" },
                                evidence: { type: "string" },
                                cwe: { type: "string" },
                                remediation: { type: "string" },
                                tags: {
                                    type: "array",
                                    items: { type: "string" }
                                }
                            }
                        }
                    },
                    summary: {
                        type: "object",
                        properties: {
                            totalTargets: { type: "integer" },
                            scannedRules: { type: "integer" },
                            findings: { type: "integer" },
                            attemptedRequests: { type: "integer" },
                            connectivityFailures: { type: "integer" },
                            timeoutErrors: { type: "integer" },
                            networkErrors: { type: "integer" },
                            skippedTargets: { type: "integer" },
                            skippedDeadTargetProbes: { type: "integer" },
                            heuristicFiltered: { type: "integer" },
                            statusBuckets: { type: "object" }
                        },
                        description: "High-level scan summary"
                    },
                    surface_artifacts: {
                        type: "object",
                        description: "Normalized findings prepared for surface graph and upper-layer ingestion",
                        properties: {
                            findings: {
                                type: "array",
                                description: "Normalized vulnerability findings"
                            }
                        }
                    }
                }
            },
            error: {
                type: "string",
                description: "Error message if the scan fails"
            },
        },
    };
}

pluginGlobals.get_input_schema = get_input_schema;
pluginGlobals.get_output_schema = get_output_schema;

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
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) return null;
    return trimmed;
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
    return [];
}

async function fetchWithTimeout(url: string, timeout: number, userAgent: string, method: "GET" | "HEAD" = "GET"): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
        return await fetch(url, { method, signal: controller.signal, headers: { "User-Agent": userAgent } });
    } finally {
        clearTimeout(timer);
    }
}

async function probeStatus(url: string, timeout: number, userAgent: string): Promise<Response> {
    const headResponse = await fetchWithTimeout(url, timeout, userAgent, "HEAD");
    if (headResponse.status === 405 || headResponse.status === 501) {
        try {
            await headResponse.body?.cancel();
        } catch {
            // Ignore body cleanup failures on fallback probes.
        }
        return fetchWithTimeout(url, timeout, userAgent, "GET");
    }
    return headResponse;
}

async function discardResponse(response: Response | null | undefined): Promise<void> {
    if (!response) return;
    try {
        await response.body?.cancel();
    } catch {
        // Ignore cleanup failures when the body has already been consumed.
    }
}

function joinUrl(baseUrl: string, path: string): string {
    return `${baseUrl}/${String(path || "").replace(/^\/+/, "")}`;
}

function extractTitle(html: string): string {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match?.[1]?.trim() || "";
}

function buildHeadersObject(response: Response): Record<string, string> {
    const headers: Record<string, string> = {};
    response.headers.forEach((value: string, key: string) => {
        headers[key.toLowerCase()] = value;
    });
    return headers;
}

function buildResponseContext(url: string, response: Response, body: string | null): ResponseContext {
    return {
        url,
        status: response.status,
        headers: buildHeadersObject(response),
        contentType: response.headers.get("content-type") || "",
        title: body ? extractTitle(body) : "",
        body: body || "",
    };
}

function matcherSource(context: ResponseContext, matcher: any): any {
    const part = String(matcher?.part || "body").toLowerCase();
    if (part === "status") return context.status;
    if (part === "header") return context.headers[String(matcher?.key || "").toLowerCase()] || "";
    if (part === "title") return context.title;
    if (part === "content_type") return context.contentType;
    if (part === "url") return context.url;
    return context.body;
}

function matcherHit(context: ResponseContext, matcher: any): boolean {
    const type = String(matcher?.type || "contains").toLowerCase();
    const expected = matcher?.value;
    const source = matcherSource(context, matcher);
    const flags = typeof matcher?.flags === "string" && matcher.flags.trim().length > 0 ? matcher.flags : "i";

    if (type === "exists") return source !== undefined && source !== null && String(source).length > 0;
    if (type === "equals") return String(source || "") === String(expected || "");
    if (type === "in" && Array.isArray(expected)) return expected.map(String).includes(String(source || ""));
    if (type === "regex") {
        try {
            return new RegExp(String(expected || ""), flags).test(String(source || ""));
        } catch {
            return false;
        }
    }

    return String(source || "").toLowerCase().includes(String(expected || "").toLowerCase());
}

function matchAll(context: ResponseContext, matchers: any[], operator?: string): boolean {
    if (!Array.isArray(matchers) || matchers.length === 0) return false;
    return String(operator || "and").toLowerCase() === "or"
        ? matchers.some(matcher => matcherHit(context, matcher))
        : matchers.every(matcher => matcherHit(context, matcher));
}

function buildNegativeMatchers(metadata: Record<string, any>): any[] {
    return Array.isArray(metadata.negative_matchers) ? metadata.negative_matchers : [];
}

function bucketStatus(status: number): string {
    if (status >= 200 && status < 300) return "2xx";
    if (status >= 300 && status < 400) return "3xx";
    if (status >= 400 && status < 500) return "4xx";
    if (status >= 500 && status < 600) return "5xx";
    return "other";
}

function ensureStatusBucket(stats: ScanStats, bucket: string): void {
    stats.statusBuckets[bucket] = (stats.statusBuckets[bucket] || 0) + 1;
}

function classifyError(error: any): "timeout" | "network" {
    const message = String(error?.message || error || "").toLowerCase();
    if (message.includes("abort") || message.includes("timeout")) return "timeout";
    return "network";
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!input || typeof input !== "object") {
            return { success: false, error: "Invalid input: expected an object payload" };
        }

        const timeout = Number(input.timeout || 3000);
        const userAgent = input.userAgent || "Sentinel-Sensitive-File-Scanner/1.0";
        const concurrency = Math.max(1, Math.min(Number(input.concurrency || 50), 50));
        const normalizedTargets = Array.from(new Set([
            normalizeTarget(input.url),
            normalizeTarget(input.base_url),
            ...(Array.isArray(input.targets) ? input.targets.map(normalizeTarget) : []),
        ].filter((value): value is string => Boolean(value))));
        const maxTargets = Number.isFinite(Number(input.maxTargets))
            ? Math.max(1, Number(input.maxTargets))
            : normalizedTargets.length;
        const targets = normalizedTargets.slice(0, maxTargets);

        if (targets.length === 0) {
            return { success: false, error: "At least one web target is required" };
        }

        const rules = await loadRules(input);
        if (rules.length === 0) {
            return {
                success: false,
                error: "No sensitive file rules loaded. Configure dictionaryEntries or a sensitive_file dictionary with explicit matchers.",
            };
        }
        const preparedRules: PreparedRule[] = rules
            .map((rule) => {
                const metadata = parseMetadata(rule.metadata);
                return {
                    rule,
                    metadata,
                    path: metadata.path || rule.word,
                    matchers: Array.isArray(metadata.matchers) ? metadata.matchers : [],
                    negativeMatchers: buildNegativeMatchers(metadata),
                };
            })
            .filter((preparedRule) => preparedRule.metadata.enabled !== false);
        const findings: Finding[] = [];
        const vulnerabilityFindings: any[] = [];
        const stats: ScanStats = {
            attemptedRequests: 0,
            connectivityFailures: 0,
            timeoutErrors: 0,
            networkErrors: 0,
            skippedTargets: 0,
            skippedDeadTargetProbes: 0,
            heuristicFiltered: 0,
            statusBuckets: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 },
        };
        await runWithConcurrency(
            targets.map((target) => async () => {
                for (const preparedRule of preparedRules) {
                    const { rule, metadata, path, matchers, negativeMatchers } = preparedRule;
                    const url = joinUrl(target, path);
                    const effectiveMatchers = matchers;
                    const shouldReadBody = effectiveMatchers.length > 0 || negativeMatchers.length > 0;
                    let response: Response | null = null;
                    try {
                        stats.attemptedRequests += 1;
                        response = shouldReadBody
                            ? await fetchWithTimeout(url, timeout, userAgent)
                            : await probeStatus(url, timeout, userAgent);
                        let body: string | null = null;
                        if (shouldReadBody) {
                            body = await response.text();
                        }
                        ensureStatusBucket(stats, bucketStatus(response.status));
                        if (response.status !== 200) {
                            await discardResponse(response);
                            continue;
                        }
                        if (effectiveMatchers.length === 0 && negativeMatchers.length === 0) {
                            stats.heuristicFiltered += 1;
                            await discardResponse(response);
                            continue;
                        }
                        const context = buildResponseContext(url, response, body);
                        if (negativeMatchers.length > 0 && matchAll(context, negativeMatchers, metadata.negative_operator || "or")) {
                            stats.heuristicFiltered += 1;
                            await discardResponse(response);
                            continue;
                        }
                        if (effectiveMatchers.length > 0) {
                            if (!matchAll(context, effectiveMatchers, metadata.match_operator || "and")) {
                                await discardResponse(response);
                                continue;
                            }
                        } else {
                            stats.heuristicFiltered += 1;
                            await discardResponse(response);
                            continue;
                        }

                        const finding = {
                            title: metadata.name || `Sensitive file exposed: ${path}`,
                            severity: metadata.severity || "medium",
                            url,
                            description: metadata.description || `Sensitive file exposed at ${url}`,
                            evidence: body ? body.slice(0, 500) : undefined,
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
                    } catch (error) {
                        const kind = classifyError(error);
                        stats.connectivityFailures += 1;
                        if (kind === "timeout") {
                            stats.timeoutErrors += 1;
                        } else {
                            stats.networkErrors += 1;
                        }
                        stats.skippedTargets += 1;
                        await discardResponse(response);
                        break;
                    }
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
                    attemptedRequests: stats.attemptedRequests,
                    connectivityFailures: stats.connectivityFailures,
                    timeoutErrors: stats.timeoutErrors,
                    networkErrors: stats.networkErrors,
                    skippedTargets: stats.skippedTargets,
                    skippedDeadTargetProbes: stats.skippedDeadTargetProbes,
                    heuristicFiltered: stats.heuristicFiltered,
                    statusBuckets: stats.statusBuckets,
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

pluginGlobals.analyze = analyze;
