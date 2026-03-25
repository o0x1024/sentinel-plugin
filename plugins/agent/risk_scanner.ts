/**
 * Risk Scanner Tool
 *
 * @plugin risk_scanner
 * @name Risk Scanner
 * @version 2.2.0
 * @author Sentinel Team
 * @category risk
 * @default_severity medium
 * @tags risk, poc, verification, dictionary, workflow
 * @description Execute safe dictionary-driven verification rules with variables, preconditions, chained requests, and structured evidence.
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
    technologies?: Array<string | { name?: string }>;
    fingerprints?: string[];
    dictionaryId?: string;
    dictionaryEntries?: RuleEntry[];
    safe_mode?: boolean;
    maxRules?: number;
    timeout?: number;
    userAgent?: string;
    concurrency?: number;
    stopOnFirstHit?: boolean;
    variables?: Record<string, any>;
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
    impact?: string;
    remediation?: string;
    cwe?: string;
}

interface ExecutionStep {
    id: string;
    method: string;
    url: string;
    status?: number;
    matched: boolean;
    extracted: Record<string, any>;
}

interface ToolOutput {
    success: boolean;
    data?: {
        findings: Finding[];
        evidence: any[];
        summary: {
            totalTargets: number;
            executedRules: number;
            matchedRules: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST"]);

const FALLBACK_RULES: RuleEntry[] = [
    {
        word: "swagger_ui_exposed",
        category: "api_exposure",
        metadata: {
            name: "Swagger UI Exposed",
            severity: "medium",
            finding_type: "api_exposure",
            match_scope: { fingerprints: ["swagger ui"] },
            requests: [
                {
                    id: "swagger",
                    method: "GET",
                    path: "swagger-ui.html",
                    matchers: [{ part: "body", type: "contains", value: "swagger-ui" }],
                },
            ],
            description: "Swagger UI is publicly accessible.",
            remediation: "Restrict Swagger UI in production environments.",
            safe_mode: true,
        },
    },
    {
        word: "spring_actuator_env_exposed",
        category: "config_exposure",
        metadata: {
            name: "Spring Actuator Env Exposed",
            severity: "high",
            finding_type: "config_exposure",
            match_scope: { fingerprints: ["spring", "spring boot"] },
            requests: [
                {
                    id: "env",
                    method: "GET",
                    path: "actuator/env",
                    matchers: [{ part: "body", type: "contains", value: "\"propertySources\"" }],
                },
            ],
            description: "Spring Actuator environment endpoint is publicly accessible.",
            remediation: "Disable or protect actuator endpoints.",
            cwe: "CWE-200",
            safe_mode: true,
        },
    },
];

const DEFAULT_CONCURRENCY = 4;
const MAX_CONCURRENCY = 20;

export function get_input_schema() {
    return {
        type: "object",
        required: [],
        properties: {
            url: {
                type: "string",
                description: "Single target URL to verify with dictionary-driven risk rules"
            },
            base_url: {
                type: "string",
                description: "Base URL alias for a single target"
            },
            targets: {
                type: "array",
                items: { type: "string" },
                description: "List of target URLs or hostnames to verify"
            },
            technologies: {
                type: "array",
                description: "Observed technologies used to scope matching rules",
                items: {
                    anyOf: [
                        { type: "string" },
                        {
                            type: "object",
                            properties: {
                                name: {
                                    type: "string",
                                    description: "Technology name"
                                }
                            }
                        }
                    ]
                }
            },
            fingerprints: {
                type: "array",
                items: { type: "string" },
                description: "Observed fingerprint names used for rule filtering"
            },
            dictionaryId: {
                type: "string",
                description: "Structured dictionary ID or name used to load verification rules"
            },
            dictionaryEntries: {
                type: "array",
                description: "Inline rule entries that override dictionary loading",
                items: {
                    type: "object",
                    required: ["word"],
                    properties: {
                        word: {
                            type: "string",
                            description: "Rule identifier"
                        },
                        category: {
                            type: "string",
                            description: "Rule category used for normalized finding type"
                        },
                        metadata: {
                            description: "Rule metadata object or JSON string with requests, matchers and finding fields"
                        }
                    }
                }
            },
            variables: {
                type: "object",
                description: "Variables injected into rule templates and request paths"
            },
            safe_mode: {
                type: "boolean",
                description: "Skip rules explicitly marked as unsafe",
                default: true
            },
            maxRules: {
                type: "integer",
                description: "Maximum number of applicable rules to execute",
                default: 20,
                minimum: 1,
                maximum: 200
            },
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: 8000,
                minimum: 1000,
                maximum: 60000
            },
            userAgent: {
                type: "string",
                description: "User-Agent header used for outbound requests",
                default: "Sentinel-Risk-Scanner/2.0"
            },
            concurrency: {
                type: "integer",
                description: "Number of concurrent rule executions",
                default: DEFAULT_CONCURRENCY,
                minimum: 1,
                maximum: MAX_CONCURRENCY
            },
            stopOnFirstHit: {
                type: "boolean",
                description: "Stop executing more rules after the first positive finding",
                default: false
            }
        },
    };
}

export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: {
                type: "boolean",
                description: "Whether the risk verification run completed successfully"
            },
            data: {
                type: "object",
                properties: {
                    findings: {
                        type: "array",
                        description: "Matched risk findings produced by the executed rules",
                        items: {
                            type: "object",
                            properties: {
                                title: { type: "string" },
                                severity: { type: "string" },
                                url: { type: "string" },
                                description: { type: "string" },
                                impact: { type: "string" },
                                remediation: { type: "string" },
                                cwe: { type: "string" }
                            }
                        }
                    },
                    evidence: {
                        type: "array",
                        description: "Structured execution evidence captured during rule evaluation"
                    },
                    summary: {
                        type: "object",
                        description: "High-level execution summary",
                        properties: {
                            totalTargets: { type: "integer" },
                            executedRules: { type: "integer" },
                            matchedRules: { type: "integer" }
                        }
                    },
                    surface_artifacts: {
                        type: "object",
                        description: "Normalized findings and evidences prepared for upper-layer ingestion",
                        properties: {
                            findings: {
                                type: "array",
                                description: "Normalized vulnerability findings"
                            },
                            evidences: {
                                type: "array",
                                description: "Normalized evidence records"
                            }
                        }
                    }
                }
            },
            error: {
                type: "string",
                description: "Error message if the risk verification run fails"
            },
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

function getInputNumber(input: ToolInput, camelKey: keyof ToolInput, snakeKey: string, fallback: number): number {
    const snakeValue = (input as any)?.[snakeKey];
    const camelValue = input?.[camelKey];
    const value = snakeValue ?? camelValue;
    const parsed = Number(value ?? fallback);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function getInputBoolean(input: ToolInput, camelKey: keyof ToolInput, snakeKey: string, fallback: boolean): boolean {
    const snakeValue = (input as any)?.[snakeKey];
    const camelValue = input?.[camelKey];
    return typeof snakeValue === "boolean"
        ? snakeValue
        : typeof camelValue === "boolean"
            ? camelValue
            : fallback;
}

function getInputString(input: ToolInput, camelKey: keyof ToolInput, snakeKey: string, fallback = ""): string {
    const snakeValue = (input as any)?.[snakeKey];
    const camelValue = input?.[camelKey];
    const value = snakeValue ?? camelValue;
    return typeof value === "string" && value.trim().length > 0 ? value : fallback;
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

function asArray<T>(value: T[] | T | undefined | null): T[] {
    return Array.isArray(value) ? value : value == null ? [] : [value];
}

function parseTitle(html: string): string {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match?.[1]?.trim() || "";
}

function joinUrl(baseUrl: string, path: string): string {
    return `${baseUrl}/${String(path || "").replace(/^\/+/, "")}`;
}

function deepGet(source: any, path: string): any {
    if (!path) return source;
    return path.split(".").reduce((acc, key) => {
        if (acc == null) return undefined;
        if (key.endsWith("]")) {
            const match = key.match(/^([^[\]]+)\[(\d+)\]$/);
            if (!match) return acc?.[key];
            const [, arrayKey, indexText] = match;
            return acc?.[arrayKey]?.[Number(indexText)];
        }
        return acc?.[key];
    }, source);
}

function renderTemplate(value: any, context: Record<string, any>): any {
    if (typeof value !== "string") return value;
    return value.replace(/\{\{\s*([^}]+?)\s*\}\}/g, (_, expr) => {
        const resolved = deepGet(context, String(expr).trim());
        if (resolved == null) return "";
        return typeof resolved === "string" ? resolved : JSON.stringify(resolved);
    });
}

function tryParseJson(body: string): any {
    try {
        return JSON.parse(body);
    } catch {
        return undefined;
    }
}

function matcherHit(ctx: Record<string, any>, matcher: any): boolean {
    const part = String(matcher?.part || "body").toLowerCase();
    const type = String(matcher?.type || "contains").toLowerCase();
    const expected = matcher?.value;

    if (part === "status") {
        if (type === "in" && Array.isArray(expected)) return expected.includes(ctx.status);
        return ctx.status === expected;
    }

    const source = part === "header"
        ? String(ctx.headers[String(matcher?.key || "").toLowerCase()] || "")
        : part === "title"
            ? ctx.title
            : part === "json"
                ? deepGet(ctx.json || {}, String(matcher?.path || matcher?.key || ""))
                : ctx.body;

    if (type === "exists") return source !== undefined && source !== null && String(source).length > 0;
    if (type === "equals") return String(source) === String(expected ?? "");
    if (type === "in" && Array.isArray(expected)) return expected.map(String).includes(String(source));
    if (type === "regex") {
        try {
            return new RegExp(String(expected || ""), "i").test(String(source || ""));
        } catch {
            return false;
        }
    }
    return String(source || "").toLowerCase().includes(String(expected || "").toLowerCase());
}

function matchAll(ctx: Record<string, any>, matchers: any[], operator?: string): boolean {
    if (!Array.isArray(matchers) || matchers.length === 0) return false;
    return String(operator || "and").toLowerCase() === "or"
        ? matchers.some(matcher => matcherHit(ctx, matcher))
        : matchers.every(matcher => matcherHit(ctx, matcher));
}

function evaluateCondition(condition: any, context: Record<string, any>): boolean {
    if (condition?.matchers) {
        return matchAll(context, asArray(condition.matchers), condition.operator || "and");
    }

    const field = String(condition?.field || "");
    const op = String(condition?.op || "equals").toLowerCase();
    const actual = deepGet(context, field);
    const expected = condition?.value;

    if (op === "exists") return actual !== undefined && actual !== null && String(actual).length > 0;
    if (op === "contains") return String(actual || "").toLowerCase().includes(String(expected || "").toLowerCase());
    if (op === "in" && Array.isArray(expected)) return expected.map(String).includes(String(actual));
    if (op === "regex") {
        try {
            return new RegExp(String(expected || ""), "i").test(String(actual || ""));
        } catch {
            return false;
        }
    }
    return String(actual) === String(expected);
}

function evaluatePreconditions(preconditions: any[], context: Record<string, any>): boolean {
    if (!Array.isArray(preconditions) || preconditions.length === 0) return true;
    return preconditions.every(condition => evaluateCondition(condition, context));
}

function getObservedFingerprints(input: ToolInput): string[] {
    return [
        ...asArray(input.fingerprints),
        ...asArray(input.technologies).map(item => typeof item === "string" ? item : item?.name || ""),
    ]
        .filter(Boolean)
        .map(item => String(item).toLowerCase());
}

function ruleMatchesFingerprintScope(rule: RuleEntry, observedFingerprints: string[]): boolean {
    const metadata = parseMetadata(rule.metadata);
    if (metadata.enabled === false) return false;

    const scope = metadata.match_scope || {};
    const expectedFingerprints = asArray(scope.fingerprints).map(item => String(item).toLowerCase());

    if (expectedFingerprints.length > 0 && !expectedFingerprints.some(item => observedFingerprints.includes(item))) {
        return false;
    }

    return true;
}

function ruleApplies(rule: RuleEntry, input: ToolInput, targetContext: Record<string, any>): boolean {
    if (!ruleMatchesFingerprintScope(rule, getObservedFingerprints(input))) {
        return false;
    }

    return evaluatePreconditions(asArray(parseMetadata(rule.metadata).preconditions), targetContext);
}

function dedupeRules(rules: RuleEntry[]): RuleEntry[] {
    const seen = new Set<string>();
    const deduped: RuleEntry[] = [];

    for (const rule of rules) {
        const metadata = parseMetadata(rule.metadata);
        const ruleId = String(rule.word || metadata.name || "").trim().toLowerCase();
        if (!ruleId || seen.has(ruleId)) continue;
        seen.add(ruleId);
        deduped.push({ ...rule, metadata });
    }

    return deduped;
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
        ? await Sentinel.Dictionary.getDefaultId("poc_rule")
        : null;

    const candidates = [input.dictionaryId, (input as any)?.dictionary_id, defaultDictionaryId, "builtin_safe_poc_rules", "Safe POC Rules"]
        .filter((value): value is string => typeof value === "string" && value.trim().length > 0);

    for (const candidate of candidates) {
        const rules = await loadStructuredDictionary(candidate);
        if (rules.length > 0) return rules;
    }

    return FALLBACK_RULES;
}

async function fetchWithTimeout(url: string, init: RequestInit, timeout: number): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
        return await fetch(url, { ...init, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }
}

function normalizeRequests(metadata: Record<string, any>): any[] {
    const requests = Array.isArray(metadata.requests) ? metadata.requests : metadata.request ? [metadata.request] : [];
    return requests.map((request, index) => ({
        id: request?.id || `step_${index + 1}`,
        method: String(request?.method || "GET").toUpperCase(),
        path: request?.path || "/",
        headers: request?.headers || {},
        body: request?.body,
        timeout_ms: Number(request?.timeout_ms || 8000),
        matchers: Array.isArray(request?.matchers) ? request.matchers : undefined,
        extractors: Array.isArray(request?.extractors) ? request.extractors : [],
    }));
}

function buildRequestContext(baseContext: Record<string, any>, executionContext: Record<string, any>): Record<string, any> {
    return {
        ...baseContext,
        ...executionContext,
        steps: executionContext.steps || {},
        extracted: executionContext.extracted || {},
    };
}

function applyExtractors(extractors: any[], responseContext: Record<string, any>): Record<string, any> {
    const extracted: Record<string, any> = {};
    for (const extractor of extractors) {
        const name = String(extractor?.name || "").trim();
        if (!name) continue;
        const sourcePart = String(extractor?.part || "body").toLowerCase();
        const source = sourcePart === "header"
            ? String(responseContext.headers[String(extractor?.key || "").toLowerCase()] || "")
            : sourcePart === "title"
                ? responseContext.title
                : sourcePart === "json"
                    ? deepGet(responseContext.json || {}, String(extractor?.path || extractor?.key || ""))
                    : responseContext.body;

        if (extractor?.type === "regex") {
            try {
                const match = String(source || "").match(new RegExp(String(extractor?.pattern || extractor?.value || ""), "i"));
                if (match?.[1]) extracted[name] = match[1];
            } catch {
                continue;
            }
            continue;
        }

        if (extractor?.type === "json_path") {
            extracted[name] = deepGet(responseContext.json || {}, String(extractor?.path || ""));
            continue;
        }

        extracted[name] = source;
    }
    return extracted;
}

async function executeRule(target: string, rule: RuleEntry, input: ToolInput): Promise<{ finding?: Finding; evidence?: any; matched: boolean }> {
    const metadata = parseMetadata(rule.metadata);
    const baseContext: Record<string, any> = {
        target,
        base_url: target,
        url: target,
        rule_id: rule.word,
        category: rule.category || "",
        variables: input.variables || {},
        fingerprints: asArray(input.fingerprints),
        technologies: asArray(input.technologies).map(item => typeof item === "string" ? item : item?.name || ""),
    };

    if (!ruleApplies(rule, input, baseContext)) {
        return { matched: false };
    }

    const requests = normalizeRequests(metadata);
    if (requests.length === 0) return { matched: false };

    const executionContext: Record<string, any> = { steps: {}, extracted: {} };
    const evidenceSteps: ExecutionStep[] = [];
    let lastResponseContext: Record<string, any> | null = null;

    for (const request of requests) {
        const context = buildRequestContext(baseContext, executionContext);
        const method = String(request.method || "GET").toUpperCase();

        if (input.safe_mode !== false && !SAFE_METHODS.has(method)) {
            return { matched: false };
        }

        const renderedPath = renderTemplate(request.path, context);
        const url = joinUrl(target, renderedPath);
        const headers = Object.fromEntries(
            Object.entries(request.headers || {}).map(([key, value]) => [key, renderTemplate(value, context)])
        );
        const body = request.body == null ? undefined : renderTemplate(request.body, context);

        try {
            const response = await fetchWithTimeout(
                url,
                {
                    method,
                    headers: {
                        "User-Agent": input.userAgent || "Sentinel-Risk-Scanner/2.0",
                        ...headers,
                    },
                    body: body == null ? undefined : String(body),
                },
                Number(request.timeout_ms || input.timeout || 8000)
            );

            const responseBody = await response.text();
            const responseHeaders: Record<string, string> = {};
            response.headers.forEach((value, key) => { responseHeaders[String(key).toLowerCase()] = value; });
            const responseContext = {
                status: response.status,
                body: responseBody,
                headers: responseHeaders,
                title: parseTitle(responseBody),
                json: tryParseJson(responseBody),
                url,
            };

            const extracted = applyExtractors(asArray(request.extractors), responseContext);
            executionContext.steps[request.id] = responseContext;
            executionContext.extracted = { ...executionContext.extracted, ...extracted };
            lastResponseContext = responseContext;

            const stepMatchers = Array.isArray(request.matchers) ? request.matchers : [];
            const stepMatched = stepMatchers.length === 0 ? true : matchAll(responseContext, stepMatchers, request.operator || "and");

            evidenceSteps.push({
                id: request.id,
                method,
                url,
                status: response.status,
                matched: stepMatched,
                extracted,
            });

            if (!stepMatched) {
                return {
                    matched: false,
                    evidence: { rule_id: rule.word, target, steps: evidenceSteps },
                };
            }
        } catch (error: any) {
            evidenceSteps.push({
                id: request.id,
                method,
                url,
                matched: false,
                extracted: {},
            });
            return {
                matched: false,
                evidence: {
                    rule_id: rule.word,
                    target,
                    steps: evidenceSteps,
                    error: error instanceof Error ? error.message : String(error),
                },
            };
        }
    }

    const finalMatchers = Array.isArray(metadata.matchers) ? metadata.matchers : [];
    const finalMatched = finalMatchers.length === 0
        ? true
        : lastResponseContext != null && matchAll(lastResponseContext, finalMatchers, metadata.operator || "and");

    const evidence = {
        rule_id: rule.word,
        target,
        steps: evidenceSteps,
        final_matchers: finalMatchers,
        extracted: executionContext.extracted,
    };

    if (!finalMatched || !lastResponseContext) {
        return { matched: false, evidence };
    }

    const finding: Finding = {
        title: metadata.name || rule.word,
        severity: metadata.severity || "medium",
        url: lastResponseContext.url,
        description: metadata.description || `Risk verification rule ${rule.word} matched.`,
        impact: metadata.impact || "",
        remediation: metadata.remediation || "Restrict access and harden the affected component.",
        cwe: metadata.cwe || "",
    };

    return { matched: true, finding, evidence };
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!input || typeof input !== "object") {
            return { success: false, error: "Invalid input: expected an object payload" };
        }

        const safeMode = getInputBoolean(input, "safe_mode", "safe_mode", true);
        const maxRules = getInputNumber(input, "maxRules", "max_rules", 20);
        const timeout = getInputNumber(input, "timeout", "timeout_ms", 8000);
        const userAgent = getInputString(input, "userAgent", "user_agent", "Sentinel-Risk-Scanner/2.0");
        const concurrency = Math.max(1, Math.min(getInputNumber(input, "concurrency", "concurrency", DEFAULT_CONCURRENCY), MAX_CONCURRENCY));
        const stopOnFirstHit = getInputBoolean(input, "stopOnFirstHit", "stop_on_first_hit", false);
        const normalizedInput: ToolInput = {
            ...input,
            safe_mode: safeMode,
            maxRules,
            timeout,
            userAgent,
            concurrency,
            stopOnFirstHit,
            dictionaryId: getInputString(input, "dictionaryId", "dictionary_id") || input.dictionaryId,
        };
        const targets = Array.from(new Set([
            normalizeTarget(input.url),
            normalizeTarget(input.base_url),
            ...asArray(input.targets).map(normalizeTarget),
        ].filter((value): value is string => Boolean(value))));

        if (targets.length === 0) {
            return { success: false, error: "At least one target URL is required" };
        }

        const observedFingerprints = getObservedFingerprints(normalizedInput);
        const allRules = dedupeRules(await loadRules(normalizedInput));
        const rules = allRules
            .filter(rule => {
                const metadata = parseMetadata(rule.metadata);
                if (metadata.enabled === false) return false;
                if (safeMode && metadata.safe_mode === false) return false;
                return ruleMatchesFingerprintScope(rule, observedFingerprints);
            })
            .slice(0, maxRules);

        const findings: Finding[] = [];
        const evidence: any[] = [];
        const vulnerabilityFindings: any[] = [];

        const scanTasks: Array<{ target: string; rule: RuleEntry }> = [];
        for (const target of targets) {
            for (const rule of rules) {
                scanTasks.push({ target, rule });
            }
        }

        let stopRequested = false;
        let executedRuleCount = 0;
        await runWithConcurrency(
            scanTasks.map(({ target, rule }) => async () => {
                if (stopRequested) return;
                executedRuleCount += 1;

                const result = await executeRule(target, rule, normalizedInput);
                if (result.evidence) evidence.push(result.evidence);
                if (!result.matched || !result.finding) return;

                const metadata = parseMetadata(rule.metadata);
                findings.push(result.finding);
                vulnerabilityFindings.push({
                    title: result.finding.title,
                    severity: result.finding.severity,
                    target: result.finding.url,
                    vulnerability_type: metadata.finding_type || rule.category || "risk_verification",
                    description: result.finding.description,
                    source: "risk_scanner",
                });

                if (stopOnFirstHit) {
                    stopRequested = true;
                }
            }),
            concurrency,
        );

        return {
            success: true,
            data: {
                findings,
                evidence,
                summary: {
                    totalTargets: targets.length,
                    executedRules: executedRuleCount,
                    matchedRules: findings.length,
                },
                surface_artifacts: {
                    findings: vulnerabilityFindings,
                    evidences: evidence,
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
