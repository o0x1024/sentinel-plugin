/**
 * Technology Fingerprinter Tool
 *
 * @plugin tech_fingerprinter
 * @name Technology Fingerprinter
 * @version 2.2.4
 * @author Sentinel Team
 * @main_category bounty
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
    Monitor?: {
        reportProgress?(request: Record<string, unknown>): Promise<boolean> | boolean;
    };
};

interface ToolInput {
    url?: string;
    base_url?: string;
    targets?: string[];
    dictionaryId?: string;
    dictionaryEntries?: RuleEntry[];
    concurrency?: number;
    userAgent?: string;
    previousSnapshots?: Record<string, TechnologySnapshot>;
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

interface TechnologySnapshot {
    url: string;
    technologies: Array<{
        name: string;
        category: string;
        version?: string;
    }>;
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

interface ToolOutput {
    success: boolean;
    data?: {
        results: PerTargetResult[];
        technologies: TechnologyResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, TechnologySnapshot>;
        summary: {
            totalTargets: number;
            matchedTargets: number;
            identifiedTechnologies: number;
            technologyChanges: number;
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
const DEFAULT_TIMEOUT_MS = 3000;
const MIN_TIMEOUT_MS = 3000;
const MAX_TIMEOUT_MS = 3000;
const DEFAULT_CONCURRENCY = 32;
const MIN_CONCURRENCY = 1;
const MAX_CONCURRENCY = 32;

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

export function get_input_schema() {
    return {
        type: "object",
        properties: {
            url: { type: "string", description: "Target URL" },
            base_url: { type: "string", description: "Base URL alias" },
            targets: { type: "array", items: { type: "string" }, description: "Multiple target URLs" },
            dictionaryId: { type: "string", "x-control": "dictionary-picker", "x-dictionary-type": "fingerprint_rule", description: "Structured fingerprint dictionary ID or name" },
            dictionaryEntries: { type: "array", description: "Structured rule entries injected by workflow" },
            concurrency: {
                type: "integer",
                default: DEFAULT_CONCURRENCY,
                minimum: MIN_CONCURRENCY,
                maximum: MAX_CONCURRENCY,
            },
            userAgent: { type: "string", default: "Sentinel-Tech-Fingerprinter/2.0" },
            previousSnapshots: { type: "object", description: "Previous technology snapshots keyed by target URL" },
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
                    changeEvents: { type: "array" },
                    snapshots: { type: "object" },
                    summary: { type: "object" },
                    surface_artifacts: {
                        type: "object",
                        properties: {
                            fingerprints: {
                                type: "array",
                                description: "Strict normalized fingerprint artifacts with rule_id, rule_word, rule_name, normalized_product, and normalized_category",
                            },
                            evidences: {
                                type: "array",
                                description: "Structured evidence artifacts describing captured technology snapshots",
                            },
                        },
                    },
                },
            },
            error: { type: "string" },
        },
    };
}

pluginGlobals.get_input_schema = get_input_schema;
pluginGlobals.get_output_schema = get_output_schema;

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

    const defaultDictionaryId = Sentinel?.Dictionary?.getDefaultId
        ? await Sentinel.Dictionary.getDefaultId("fingerprint_rule")
        : null;

    const candidates = [input.dictionaryId, defaultDictionaryId, "builtin_web_fingerprint_rules", "Web Fingerprint Rules"]
        .filter((value): value is string => typeof value === "string" && value.trim().length > 0);

    for (const candidate of candidates) {
        const rules = await loadDictionaryEntries(candidate);
        if (rules.length > 0) return rules;
    }

    return [];
}

async function fetchPage(url: string, userAgent: string): Promise<Response> {
    return await fetch(url, {
        method: "GET",
        redirect: "follow",
        headers: {
            "User-Agent": userAgent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    });
}

function normalizeTechnologySnapshot(technologies: Array<{ name: string; category: string; version?: string }>): Array<{ name: string; category: string; version?: string }> {
    const unique = new Map<string, { name: string; category: string; version?: string }>();
    for (const technology of technologies) {
        const normalized = {
            name: String(technology.name || "").trim(),
            category: String(technology.category || "technology").trim() || "technology",
            version: technology.version ? String(technology.version).trim() : undefined,
        };
        if (!normalized.name) continue;
        const key = `${normalized.name.toLowerCase()}::${normalized.category.toLowerCase()}`;
        unique.set(key, normalized);
    }
    return Array.from(unique.values()).sort((left, right) => {
        const categoryCompare = left.category.localeCompare(right.category);
        return categoryCompare !== 0 ? categoryCompare : left.name.localeCompare(right.name);
    });
}

function buildTechnologyEventId(url: string, timestamp: string): string {
    return `technology-${url}-${timestamp}`.replace(/[^a-zA-Z0-9_-]+/g, "-").slice(0, 120);
}

function createTechnologyChangeEvent(
    url: string,
    added: Array<{ name: string; category: string; version?: string }>,
    removed: Array<{ name: string; category: string; version?: string }>,
    updated: Array<{ name: string; category: string; oldVersion?: string; newVersion?: string }>,
    timestamp: string,
): ChangeEvent {
    const severity: ChangeEvent["severity"] = removed.length > 0 || updated.length > 0 ? "medium" : "low";
    const parts: string[] = [];
    if (added.length > 0) {
        parts.push(`added ${added.map(item => `${item.name}${item.version ? ` ${item.version}` : ""}`).join(", ")}`);
    }
    if (removed.length > 0) {
        parts.push(`removed ${removed.map(item => `${item.name}${item.version ? ` ${item.version}` : ""}`).join(", ")}`);
    }
    if (updated.length > 0) {
        parts.push(`updated ${updated.map(item => `${item.name} ${item.oldVersion || "unknown"} -> ${item.newVersion || "unknown"}`).join(", ")}`);
    }
    return {
        id: buildTechnologyEventId(url, timestamp),
        assetId: url,
        eventType: "technology_change",
        severity,
        title: `Technology stack changed for ${url}`,
        description: parts.join("; "),
        oldValue: JSON.stringify({ removed, updated: updated.map(item => ({ name: item.name, category: item.category, version: item.oldVersion })) }),
        newValue: JSON.stringify({ added, updated: updated.map(item => ({ name: item.name, category: item.category, version: item.newVersion })) }),
        detectionMethod: "tech_fingerprinter",
        tags: ["technology", "change", "fingerprint"],
        autoTriggerEnabled: true,
        riskScore: removed.length > 0 || updated.length > 0 ? 58 : 40,
        metadata: {
            url,
            added,
            removed,
            updated,
        },
    };
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

function normalizeConfidence(value: unknown): number {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
        return 0.8;
    }
    if (numeric > 1) {
        return Math.max(0, Math.min(numeric / 100, 1));
    }
    return Math.max(0, Math.min(numeric, 1));
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const concurrency = clampInteger(
            input.concurrency,
            DEFAULT_CONCURRENCY,
            MIN_CONCURRENCY,
            MAX_CONCURRENCY,
        );
        const userAgent = input.userAgent || "Sentinel-Tech-Fingerprinter/2.0";
        const targets = Array.from(new Set([
            normalizeTarget(input.url),
            normalizeTarget(input.base_url),
            ...(Array.isArray(input.targets) ? input.targets.map(normalizeTarget) : []),
        ].filter((value): value is string => Boolean(value))));

        if (targets.length === 0) {
            return { success: false, error: "At least one target URL is required" };
        }

        const rules = await loadRules(input);
        if (rules.length === 0) {
            return {
                success: false,
                error: "No technology fingerprint rules loaded. Configure dictionaryEntries or a fingerprint_rule dictionary with explicit matchers.",
            };
        }
        const results: PerTargetResult[] = [];
        const fingerprints: any[] = [];
        const previousSnapshots = input.previousSnapshots || {};
        const changeEvents: ChangeEvent[] = [];
        const snapshots: Record<string, TechnologySnapshot> = {};
        const timestamp = new Date().toISOString();
        const monitorExecution = input.__monitorExecution;

        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: targets.length,
            phase: "prepare",
            message: `Preparing technology fingerprints (${targets.length} targets, concurrency ${concurrency})`,
        });

        let completedTargets = 0;
        await runConcurrently(targets.map((target) => async () => {
                try {
                    const response = await fetchPage(target, userAgent);
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
                            const version = extractVersion(ctx, metadata);
                            const ruleName = metadata.name || rule.word;
                            const normalizedProduct = metadata.product || ruleName;
                            const normalizedCategory = metadata.asset_category || rule.category || "technology";
                            const normalizedFamily = metadata.asset_family || null;
                            const normalizedVendor = metadata.vendor || null;
                            const confidence = normalizeConfidence(metadata.confidence);
                            const tech = {
                                name: ruleName,
                                category: normalizedCategory,
                                version,
                                confidence: Math.round(confidence * 100),
                                evidence: [`matched:${rule.word}`],
                            };

                            fingerprints.push({
                                asset_type: "web",
                                asset_key: target,
                                fingerprint_type: "technology",
                                fingerprint_key: rule.word,
                                fingerprint_value: tech.name,
                                rule_id: metadata.rule_id || rule.id || `fingerprint_rule:${rule.word}`,
                                rule_word: rule.word,
                                rule_name: ruleName,
                                normalized_product: normalizedProduct,
                                normalized_vendor: normalizedVendor || undefined,
                                normalized_category: normalizedCategory,
                                normalized_family: normalizedFamily || undefined,
                                version: tech.version,
                                confidence,
                                is_primary: Boolean(metadata.is_primary),
                                match_source_part: Array.isArray(metadata.matchers) && metadata.matchers.length > 0
                                    ? String(metadata.matchers[0]?.part || "body").toLowerCase()
                                    : "body",
                                source: "tech_fingerprinter",
                                evidence: `matched:${rule.word}`,
                            });

                            return tech;
                        });

                    const normalizedTechnologies = normalizeTechnologySnapshot(
                        technologies.map(item => ({
                            name: item.name,
                            category: item.category,
                            version: item.version,
                        })),
                    );

                    snapshots[target] = {
                        url: target,
                        technologies: normalizedTechnologies,
                        lastChecked: timestamp,
                    };

                    const previous = previousSnapshots[target];
                    if (previous) {
                        const previousMap = new Map(normalizeTechnologySnapshot(previous.technologies || []).map(item => [`${item.name.toLowerCase()}::${item.category.toLowerCase()}`, item]));
                        const currentMap = new Map(normalizedTechnologies.map(item => [`${item.name.toLowerCase()}::${item.category.toLowerCase()}`, item]));
                        const added = normalizedTechnologies.filter(item => !previousMap.has(`${item.name.toLowerCase()}::${item.category.toLowerCase()}`));
                        const removed = Array.from(previousMap.entries())
                            .filter(([key]) => !currentMap.has(key))
                            .map(([, value]) => value);
                        const updated = normalizedTechnologies.flatMap((item) => {
                            const key = `${item.name.toLowerCase()}::${item.category.toLowerCase()}`;
                            const previousItem = previousMap.get(key);
                            if (!previousItem || previousItem.version === item.version) {
                                return [];
                            }
                            return [{
                                name: item.name,
                                category: item.category,
                                oldVersion: previousItem.version,
                                newVersion: item.version,
                            }];
                        });
                        if (added.length > 0 || removed.length > 0 || updated.length > 0) {
                            changeEvents.push(createTechnologyChangeEvent(target, added, removed, updated, timestamp));
                        }
                    }

                    results.push({ url: target, technologies });
                } catch {
                    snapshots[target] = {
                        url: target,
                        technologies: [],
                        lastChecked: timestamp,
                    };
                    results.push({ url: target, technologies: [] });
                } finally {
                    completedTargets += 1;
                    await reportMonitorProgress(monitorExecution, {
                        current: completedTargets,
                        total: targets.length,
                        currentTarget: target,
                        phase: "fingerprint",
                        message: `Checked technology fingerprint for ${target}`,
                    });
                }
            }), concurrency);

        const uniqueTechnologies = Array.from(
            new Map(
                results
                    .flatMap(item => item.technologies)
                    .map(item => [`${item.name.toLowerCase()}::${item.category.toLowerCase()}::${item.version || ""}`, item]),
            ).values(),
        );

        return {
            success: true,
            data: {
                results,
                technologies: uniqueTechnologies,
                changeEvents,
                snapshots,
                summary: {
                    totalTargets: targets.length,
                    matchedTargets: results.filter(item => item.technologies.length > 0).length,
                    identifiedTechnologies: results.reduce((sum, item) => sum + item.technologies.length, 0),
                    technologyChanges: changeEvents.length,
                },
                surface_artifacts: {
                    fingerprints,
                    changes: changeEvents.map(event => ({
                        asset_key: event.assetId,
                        asset_type: "web",
                        change_type: event.eventType,
                        severity: event.severity,
                        title: event.title,
                        description: event.description,
                        old_value: event.oldValue,
                        new_value: event.newValue,
                        risk_score: event.riskScore,
                        source: "tech_fingerprinter",
                        metadata: event.metadata,
                    })),
                    evidences: Object.values(snapshots).map(snapshot => ({
                        asset_type: "web",
                        asset_key: snapshot.url,
                        evidence_type: "technology_snapshot",
                        title: `Technology Snapshot: ${snapshot.url}`,
                        content_json: snapshot,
                        source: "tech_fingerprinter",
                    })),
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
