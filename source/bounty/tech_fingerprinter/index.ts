/**
 * Technology Fingerprinter Tool
 *
 * @plugin tech_fingerprinter
 * @name Technology Fingerprinter
 * @version 2.6.1
 * @author Sentinel Team
 * @main_category bounty
 * @category recon
 * @monitor_type web
 * @input_mode asset
 * @target_asset_types ["web"]
 * @seed_bindings []
 * @default_severity info
 * @tags fingerprint, technology, dictionary, web, normalized, surface, capability:fetch, capability:dictionary, capability:monitor-events, monitor:results-stream-v1
 * @description Identify web technologies using dictionary-driven fingerprint rules with structured matchers.
 */
import { createMonitorResultStream } from '../../shared/monitor_results.ts';


declare const Sentinel: {
    Dictionary?: {
        get?(idOrName: string): Promise<any>;
        getDefaultId?(dictType: string): Promise<string | null>;
        getEntries?(idOrName: string, limit?: number): Promise<any[]>;
    };
    Monitor?: {
        reportProgress?(request: Record<string, unknown>): Promise<boolean> | boolean;
        commitResults?(request: Record<string, unknown>): Promise<{ ok: boolean; sequence: number }> | { ok: boolean; sequence: number };
    };
};

interface ToolInput {
    url?: string;
    base_url?: string;
    targets?: string[];
    target_objects?: Array<{ type: string; value: string; source: string; asset_id?: string }>;
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
    result_stream?: { protocol: "monitor-results-v1"; targets: string[]; max_work_items: number; max_pending_commits: number; max_bytes: number };
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
    confidence?: number;
    evidence: string[];
}

interface PerTargetResult {
    url: string;
    technologies: TechnologyResult[];
    status: "identified" | "unidentified" | "failed";
    error?: string;
    http_status?: number;
    final_url?: string;
    checked_at: string;
    failure_category?: string;
    timings?: Record<string, number | string | null>;
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
        stream_complete?: boolean;
        results: PerTargetResult[];
        technologies: TechnologyResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, TechnologySnapshot>;
        summary: {
            totalTargets: number;
            matchedTargets: number;
            identifiedTechnologies: number;
            technologyChanges: number;
            failedTargets: number;
            skippedTargets: number;
            diagnostics?: Record<string, number>;
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
            target_objects: { type: "array", items: { type: "object" }, description: "Runtime Web asset references supplied by the monitor host" },
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
    let stopped = false;
    const workerCount = Math.min(concurrency, tasks.length);

    async function worker() {
        while (!stopped && nextIndex < tasks.length) {
            const index = nextIndex;
            nextIndex += 1;
            try { results[index] = await tasks[index](); }
            catch (error) { stopped = true; throw error; }
        }
    }

    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    return results;
}

function normalizeTarget(raw: unknown): string {
    if (typeof raw !== "string" || !raw || raw.trim() !== raw || /[\s\x00-\x1f\x7f\\]/.test(raw)) {
        throw new Error("Target must be a non-empty URL without whitespace");
    }
    if (!/^https?:\/\/[^/\\]/i.test(raw)) throw new Error("Target must start with http:// or https:// and a host");
    const url = new URL(raw);
    if (!/^https?:$/i.test(url.protocol) || !url.hostname || url.username || url.password || raw.includes("#") || url.port === "0") {
        throw new Error("Target must be an absolute HTTP(S) URL without credentials or a fragment");
    }
    if (!url.hostname.startsWith("[")) {
        const host = url.hostname.replace(/\.$/, "");
        if (host.length > 253 || host.split(".").some(label => label.length > 63
            || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) {
            throw new Error("Target must contain a valid DNS hostname or IP address");
        }
    }
    // Preserve the exact asset identity; validation must not rewrite a stored key.
    return raw;
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
    if (!Sentinel?.Dictionary?.getEntries) throw new Error("Dictionary API unavailable; capability:dictionary is required");
    const entries = await Sentinel.Dictionary.getEntries(idOrName, 10000);
    return entries
        .filter((item: any) => item && typeof item.word === "string")
        .map((item: any) => ({
            id: typeof item.id === "string" ? item.id : undefined,
            word: item.word,
            category: typeof item.category === "string" ? item.category : null,
            metadata: parseMetadata(item.metadata),
        }));
}

async function loadRules(input: ToolInput): Promise<RuleEntry[]> {
    if (Array.isArray(input.dictionaryEntries) && input.dictionaryEntries.length > 0) {
        return input.dictionaryEntries.map(entry => ({
            ...entry,
            metadata: parseMetadata(entry.metadata),
        }));
    }

    const dictionaryId = input.dictionaryId || (Sentinel?.Dictionary?.getDefaultId
        ? await Sentinel.Dictionary.getDefaultId("fingerprint_rule") : null);
    if (!dictionaryId) throw new Error("Configure a fingerprint_rule dictionary before probing");
    return await loadDictionaryEntries(dictionaryId);
}

async function fetchPage(url: string, userAgent: string): Promise<Response> {
    const options: RequestInit & { timeout: number } = {
        method: "GET",
        redirect: "follow",
        headers: {
            "User-Agent": userAgent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        timeout: DEFAULT_TIMEOUT_MS,
    };
    return await fetch(url, options);
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

function matchedEvidence(ctx: Record<string, any>, metadata: Record<string, any>): Array<{part: string; key?: string; value: string}> {
    const matchers = Array.isArray(metadata.matchers) ? metadata.matchers : [];
    if (matchers.length === 0) throw new Error("Fingerprint rule requires explicit matchers");
    const hits = matchers.filter((matcher: any) => matcherHit(ctx, matcher));
    if (String(metadata.operator || "or").toLowerCase() === "and" && hits.length !== matchers.length) return [];
    return hits.map((matcher: any) => {
        const part = String(matcher.part || "body").toLowerCase();
        const key = part === "header" ? String(matcher.key).toLowerCase() : undefined;
        const source = part === "header" ? String(ctx.headers[key!] || "") : part === "title" ? ctx.title : part === "status" ? String(ctx.status) : ctx.body;
        let value = String(matcher.value || "");
        if (matcher.type === "regex") value = source.match(new RegExp(value, "i"))?.[0] || "";
        if (matcher.type === "exists") value = "[present]";
        if (key === "set-cookie") {
            // Only cookie names are evidence; discard every value and attribute.
            value = value.split("=")[0].replace(/^[\s;,]+/, "") + "=[REDACTED]";
        } else if (key && /authorization|cookie|token|secret|api[-_]?key/i.test(key)) {
            value = "[REDACTED]";
        }
        value = value.replace(/((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s;<>"']+/gi, "$1[REDACTED]");
        return { part, key, value: value.slice(0, 180) };
    });
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

function normalizeConfidence(value: unknown): number | undefined {
    const numeric = value == null ? NaN : Number(value);
    if (!Number.isFinite(numeric)) {
        return undefined;
    }
    if (numeric > 1) {
        return Math.max(0, Math.min(numeric / 100, 1));
    }
    return Math.max(0, Math.min(numeric, 1));
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const scanStartedAt = Date.now();
        const concurrency = clampInteger(
            input.concurrency,
            DEFAULT_CONCURRENCY,
            MIN_CONCURRENCY,
            MAX_CONCURRENCY,
        );
        const userAgent = input.userAgent || "Sentinel-Tech-Fingerprinter/2.0";
        if (input.targets !== undefined && !Array.isArray(input.targets)) {
            return { success: false, error: "targets must be an array" };
        }
        const rawTargets: unknown[] = [
            ...(input.url !== undefined ? [input.url] : []),
            ...(input.base_url !== undefined ? [input.base_url] : []),
            ...(input.targets || []),
        ];
        if (rawTargets.length === 0) return { success: false, error: "At least one target URL is required" };
        const targets: string[] = [];
        let skippedTargets = 0;
        let eligibleMonitorTargets: Set<string> | undefined;
        if (input.__monitorExecution || input.target_objects !== undefined) {
            if (!Array.isArray(input.target_objects)) throw new Error("Monitor target_objects must contain existing Web asset references");
            eligibleMonitorTargets = new Set(input.target_objects
                .filter(item => item && item.type === "web" && item.source === "surface_asset"
                    && typeof item.asset_id === "string" && item.asset_id.trim().length > 0
                    && typeof item.value === "string")
                .map(item => item.value));
        }
        const seen = new Set<unknown>();
        for (let index = 0; index < rawTargets.length; index++) {
            if (seen.has(rawTargets[index])) continue;
            seen.add(rawTargets[index]);
            try {
                const target = normalizeTarget(rawTargets[index]);
                if (eligibleMonitorTargets && !eligibleMonitorTargets.has(target)) { skippedTargets++; continue; }
                targets.push(target);
            } catch {
                // Do not persist a rejected raw value: it may contain credentials.
                skippedTargets++;
            }
        }

        const dictionaryStartedAt = Date.now();
        const rules = targets.length > 0 ? await loadRules(input) : [];
        const dictionaryLoadMs = Date.now() - dictionaryStartedAt;
        if (targets.length > 0 && rules.length === 0) {
            return {
                success: false,
                error: "No technology fingerprint rules loaded. Configure dictionaryEntries or a fingerprint_rule dictionary with explicit matchers.",
            };
        }
        for (const rule of rules) {
            const metadata = parseMetadata(rule.metadata);
            if (!Array.isArray(metadata.matchers) || metadata.matchers.length === 0) {
                throw new Error(`Fingerprint rule ${rule.word} requires explicit matchers`);
            }
            if (metadata.operator && !["and", "or"].includes(metadata.operator)) throw new Error(`Invalid operator in fingerprint rule ${rule.word}`);
            for (const matcher of metadata.matchers) {
                if (!["header", "body", "title", "status"].includes(matcher.part)) throw new Error(`Invalid source part in fingerprint rule ${rule.word}`);
                if (matcher.part === "header" && !matcher.key) throw new Error(`Missing header key in fingerprint rule ${rule.word}`);
                if (!["contains", "equals", "regex", "exists", "in"].includes(matcher.type)) throw new Error(`Invalid matcher type in fingerprint rule ${rule.word}`);
                if (["contains", "regex"].includes(matcher.type) && (typeof matcher.value !== "string" || !matcher.value)) throw new Error(`Missing matcher value in fingerprint rule ${rule.word}`);
                if (matcher.type === "regex") new RegExp(matcher.value, "i");
            }
            for (const pattern of metadata.version_patterns || []) new RegExp(pattern.pattern, "i");
        }
        const stream = createMonitorResultStream(input);
        const results: PerTargetResult[] = [];
        const timestamp = new Date().toISOString();
        const totalTargets = targets.length;
        const fingerprints: any[] = [];
        const evidences: any[] = [];
        const previousSnapshots = input.previousSnapshots || {};
        const changeEvents: ChangeEvent[] = [];
        const snapshots: Record<string, TechnologySnapshot> = stream.enabled ? {} : { ...previousSnapshots };
        const monitorExecution = input.__monitorExecution;

        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: totalTargets,
            phase: "prepare",
            message: `Preparing technology fingerprints (${targets.length} targets, concurrency ${concurrency})`,
        });

        let completedTargets = 0;
        let matchedTargets = 0;
        let identifiedTechnologies = 0;
        let failedTargets = 0;
        let technologyChanges = 0;
        let matchingMs = 0;
        const diagnostics = () => ({ dictionary_load_ms: dictionaryLoadMs, matching_ms_sum: matchingMs,
            scan_wall_ms: Date.now() - scanStartedAt });
        const changeArtifacts = (events: ChangeEvent[]) => events.map(event => ({
            asset_key: event.assetId, asset_type: "web", change_type: event.eventType,
            severity: event.severity, title: event.title, description: event.description,
            old_value: event.oldValue, new_value: event.newValue, risk_score: event.riskScore,
            source: "tech_fingerprinter", metadata: event.metadata,
        }));
        async function commitPending(): Promise<void> {
            if (!stream.enabled) return;
            while (results.length > 0) {
                const result = results.shift()!;
                const take = (items: any[], key: (item: any) => string): any[] => {
                    const selected = items.filter(item => key(item) === result.url);
                    const remaining = items.filter(item => key(item) !== result.url);
                    items.splice(0, items.length, ...remaining);
                    return selected;
                };
                const chunkSnapshots: Record<string, TechnologySnapshot> = {};
                if (snapshots[result.url]) {
                    chunkSnapshots[result.url] = snapshots[result.url];
                    delete snapshots[result.url];
                }
                const changes = take(changeEvents, event => event.assetId);
                await stream.record(result.url, result.url, { success: true, data: {
                    results: [result], snapshots: chunkSnapshots,
                    summary: { totalTargets: 1, failedTargets: result.status === 'failed' ? 1 : 0 },
                    surface_artifacts: {
                        fingerprints: take(fingerprints, item => item.asset_key),
                        evidences: take(evidences, item => item.asset_key), changes: changeArtifacts(changes),
                    },
                } }, { status: result.status === 'failed' ? 'failed' : 'ok',
                    ...(result.failure_category ? { failure_category: result.failure_category } : {}) });
            }
        }
        await runConcurrently(targets.map((target) => async () => {
                stream.assertHealthy();
                let matchingStartedAt: number | undefined;
                try {
                    const response = await fetchPage(target, userAgent);
                    const body = await response.text();
                    matchingStartedAt = Date.now();
                    const headers: Record<string, string> = {};
                    response.headers.forEach((value, key) => { headers[String(key).toLowerCase()] = value; });
                    const ctx = {
                        status: response.status,
                        headers,
                        body,
                        title: parseTitle(body),
                    };

                    const technologies = rules
                        .map(rule => ({ rule, matches: matchedEvidence(ctx, parseMetadata(rule.metadata)) }))
                        .filter(item => item.matches.length > 0)
                        .map(({ rule, matches }) => {
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
                                confidence: confidence === undefined ? undefined : Math.round(confidence * 100),
                                evidence: matches.map(hit => `${hit.part}${hit.key ? ":" + hit.key : ""}: ${hit.value}`),
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
                                match_source_part: matches[0].part,
                                source: "tech_fingerprinter",
                                request_url: target,
                                final_url: response.url || target,
                                http_status: response.status,
                                checked_at: timestamp,
                                match_details: matches,
                                evidence: tech.evidence.join("\n"),
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
                            technologyChanges++;
                        }
                    }

                    const result: PerTargetResult = {
                        url: target, technologies, status: technologies.length ? "identified" : "unidentified",
                        http_status: response.status, final_url: response.url || target, checked_at: timestamp,
                        timings: (response as Response & { timings?: Record<string, number | string | null> }).timings,
                    };
                    results.push(result);
                    if (technologies.length > 0) matchedTargets++;
                    identifiedTechnologies += technologies.length;
                    evidences.push({ asset_type: "web", asset_key: target, evidence_type: "technology_probe",
                        title: `Technology Probe: ${target}`, content_json: result,
                        content_text: `HTTP ${response.status}; ${result.status}; ${technologies.map(item => item.name).join(", ") || "UNKNOWN"}` });
                } catch (error) {
                    const typed = error as { category?: string; timings?: Record<string, number | string | null>; message?: string };
                    const allowed = new Set(["timeout", "dns", "tls", "connect", "redirect", "response_body", "request_config", "permission", "queue", "network_other"]);
                    const category = matchingStartedAt !== undefined ? "processing"
                        : typed?.category && allowed.has(typed.category) ? typed.category
                        : /timeout|timed out|abort/i.test(typed?.message || "") ? "timeout" : "network_other";
                    const labels: Record<string, string> = { timeout: "Request timed out", dns: "DNS resolution failed", tls: "TLS negotiation failed",
                        connect: "Connection failed", redirect: "Redirect failed", response_body: "Response body read failed", request_config: "Invalid HTTP request configuration",
                        permission: "Request permission denied", queue: "Request queue failed", processing: "Fingerprint processing failed", network_other: "HTTP request failed" };
                    const message = labels[category];
                    const result: PerTargetResult = { url: target, technologies: [], status: "failed", error: message, checked_at: timestamp,
                        failure_category: category, timings: typed?.timings };
                    results.push(result);
                    failedTargets++;
                    evidences.push({ asset_type: "web", asset_key: target, evidence_type: "technology_probe_failure",
                        title: `Technology Probe Failed: ${target}`, content_text: message, content_json: result });
                } finally {
                    if (matchingStartedAt !== undefined) matchingMs += Date.now() - matchingStartedAt;
                    completedTargets += 1;
                    await commitPending();
                    if (!stream.enabled) await reportMonitorProgress(monitorExecution, {
                        current: completedTargets,
                        total: totalTargets,
                        currentTarget: target,
                        phase: "fingerprint",
                        message: `Checked technology fingerprint for ${target}`,
                    });
                }
            }), concurrency);
        await commitPending();

        const uniqueTechnologies = Array.from(
            new Map(
                results
                    .flatMap(item => item.technologies)
                    .map(item => [`${item.name.toLowerCase()}::${item.category.toLowerCase()}::${item.version || ""}`, item]),
            ).values(),
        );

        return await stream.finish({
            success: true,
            data: {

                results,
                technologies: uniqueTechnologies,
                changeEvents,
                snapshots,
                summary: {
                    totalTargets,
                    matchedTargets,
                    identifiedTechnologies,
                    technologyChanges,
                    failedTargets,
                    skippedTargets,
                    diagnostics: diagnostics(),
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
                    evidences,
                },
            },
        });
    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
