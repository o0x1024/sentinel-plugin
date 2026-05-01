/**
 * DNS Resolver Tool
 *
 * @plugin dns_resolver
 * @name DNS Resolver
 * @version 1.0.1
 * @author Sentinel Team
 * @main_category bounty
 * @category recon
 * @default_severity info
 * @tags dns, resolver, mapping, domain, asm
 * @description Resolve DNS records for domains and produce typed surface graph artifacts for ASM and network asset mapping
 */

type RecordType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT";

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

interface ToolInput {
    targets: string[];
    recordTypes?: RecordType[];
    timeout?: number;
    concurrency?: number;
    previousSnapshots?: Record<string, DnsSnapshot>;
    __monitorExecution?: MonitorExecutionContext;
}

interface DnsAnswer {
    name: string;
    type: number;
    TTL?: number;
    data: string;
}

interface DnsQueryResult {
    target: string;
    success: boolean;
    records: Array<{
        recordType: RecordType;
        value: string;
        ttl?: number;
    }>;
    error?: string;
}

interface DnsSnapshot {
    target: string;
    records: DnsQueryResult["records"];
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
        targets: string[];
        results: DnsQueryResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, DnsSnapshot>;
        summary: {
            totalTargets: number;
            successfulTargets: number;
            failedTargets: number;
            totalRecords: number;
            dnsChanges: number;
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

const DEFAULT_RECORD_TYPES: RecordType[] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"];
const DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
];

const DNS_TYPE_CODES: Record<RecordType, number> = {
    A: 1,
    NS: 2,
    CNAME: 5,
    MX: 15,
    TXT: 16,
    AAAA: 28,
};

function normalizeTarget(value: string): string {
    const trimmed = value.trim();
    if (!trimmed) return "";
    try {
        const normalized = trimmed.includes("://") ? trimmed : `https://${trimmed}`;
        return new URL(normalized).hostname.toLowerCase();
    } catch {
        return trimmed
            .replace(/^https?:\/\//i, "")
            .split("/")[0]
            .split(":")[0]
            .trim()
            .toLowerCase();
    }
}

function guessRootDomain(hostname: string): string {
    const parts = hostname.split(".").filter(Boolean);
    if (parts.length <= 2) return hostname;
    return parts.slice(-2).join(".");
}

function isIpLiteral(value: string): boolean {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
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

async function queryDoh(name: string, recordType: RecordType, timeout: number): Promise<DnsAnswer[]> {
    for (const endpoint of DOH_ENDPOINTS) {
        const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${recordType}`;
        try {
            const response = await fetchWithTimeout(
                url,
                {
                    method: "GET",
                    headers: {
                        "accept": "application/dns-json",
                    },
                },
                timeout,
            );
            if (!response.ok) {
                continue;
            }

            const data = await response.json();
            if (!Array.isArray(data?.Answer)) {
                return [];
            }
            return data.Answer as DnsAnswer[];
        } catch {
            continue;
        }
    }
    return [];
}

async function runWithConcurrency<T>(tasks: Array<() => Promise<T>>, concurrency: number): Promise<T[]> {
    const results: T[] = [];
    const workers = Array.from({ length: Math.max(1, concurrency) }, async () => {
        while (tasks.length > 0) {
            const task = tasks.shift();
            if (!task) break;
            results.push(await task());
        }
    });
    await Promise.all(workers);
    return results;
}

function recordIdentity(record: { recordType: RecordType; value: string }): string {
    return `${record.recordType}:${record.value.trim().toLowerCase()}`;
}

function normalizeRecords(records: DnsQueryResult["records"]): DnsQueryResult["records"] {
    const unique = new Map<string, DnsQueryResult["records"][number]>();
    for (const record of records) {
        const normalized = {
            recordType: record.recordType,
            value: String(record.value || "").trim(),
            ttl: record.ttl,
        };
        if (!normalized.value) continue;
        const key = recordIdentity(normalized);
        if (!unique.has(key)) {
            unique.set(key, normalized);
        }
    }
    return Array.from(unique.values()).sort((left, right) => {
        const typeCompare = left.recordType.localeCompare(right.recordType);
        return typeCompare !== 0 ? typeCompare : left.value.localeCompare(right.value);
    });
}

function formatRecord(record: { recordType: RecordType; value: string }): string {
    return `${record.recordType} ${record.value}`;
}

function buildEventId(prefix: string, target: string, timestamp: string): string {
    return `${prefix}-${target}-${timestamp}`.replace(/[^a-zA-Z0-9_-]+/g, "-").slice(0, 120);
}

function createDnsChangeEvent(
    target: string,
    added: DnsQueryResult["records"],
    removed: DnsQueryResult["records"],
    timestamp: string,
): ChangeEvent {
    const sensitiveTypes = new Set<RecordType>(["A", "AAAA", "CNAME", "MX", "NS"]);
    const totalChanges = added.length + removed.length;
    const hasSensitiveRemoval = removed.some(record => sensitiveTypes.has(record.recordType));
    const hasRoutingChange = [...added, ...removed].some(record => sensitiveTypes.has(record.recordType));
    const severity: ChangeEvent["severity"] = hasSensitiveRemoval
        ? "high"
        : hasRoutingChange || totalChanges >= 4
            ? "medium"
            : "low";
    const baseScore = severity === "high" ? 72 : severity === "medium" ? 54 : 32;
    const riskScore = Math.min(95, baseScore + Math.min(totalChanges, 5) * 5);
    const parts: string[] = [];
    if (added.length > 0) {
        parts.push(`added ${added.length} record(s): ${added.map(formatRecord).join(", ")}`);
    }
    if (removed.length > 0) {
        parts.push(`removed ${removed.length} record(s): ${removed.map(formatRecord).join(", ")}`);
    }

    return {
        id: buildEventId("dns", target, timestamp),
        assetId: target,
        eventType: "dns_change",
        severity,
        title: `DNS records changed for ${target}`,
        description: parts.join("; "),
        oldValue: removed.map(formatRecord).join("\n") || undefined,
        newValue: added.map(formatRecord).join("\n") || undefined,
        detectionMethod: "dns_resolver",
        tags: ["dns", "change", ...(removed.length > 0 ? ["removed"] : []), ...(added.length > 0 ? ["added"] : [])],
        autoTriggerEnabled: true,
        riskScore,
        metadata: {
            target,
            added,
            removed,
        },
    };
}

export function get_input_schema() {
    return {
        type: "object",
        required: ["targets"],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "Domains or URLs to resolve",
            },
            recordTypes: {
                type: "array",
                items: { type: "string", enum: DEFAULT_RECORD_TYPES },
                description: "DNS record types to resolve",
                default: DEFAULT_RECORD_TYPES,
            },
            timeout: {
                type: "integer",
                description: "DNS query timeout in milliseconds",
                default: 10000,
                minimum: 1000,
                maximum: 60000,
            },
            concurrency: {
                type: "integer",
                description: "Concurrent DNS queries",
                default: 10,
                minimum: 1,
                maximum: 50,
            },
            previousSnapshots: {
                type: "object",
                description: "Previous DNS snapshots keyed by target for change detection",
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
                    results: { type: "array", description: "DNS resolution results" },
                    changeEvents: { type: "array", description: "Detected DNS change events" },
                    snapshots: { type: "object", description: "DNS snapshots keyed by target" },
                    summary: { type: "object" },
                    surface_artifacts: {
                        type: "object",
                        description: "Typed network surface artifacts for surface graph ingestion",
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
            return {
                success: false,
                error: "Invalid input: targets array is required",
            };
        }

        const targets = Array.from(
            new Set(
                input.targets
                    .map(normalizeTarget)
                    .filter((target) => target.length > 0 && !isIpLiteral(target)),
            ),
        );

        if (targets.length === 0) {
            return {
                success: false,
                error: "No valid domain targets to resolve",
            };
        }

        const timeout = Math.max(1000, Math.min(input.timeout || 10000, 60000));
        const concurrency = Math.max(1, Math.min(input.concurrency || 10, 50));
        const recordTypes = (input.recordTypes?.length ? input.recordTypes : DEFAULT_RECORD_TYPES)
            .filter((type): type is RecordType => type in DNS_TYPE_CODES);
        const previousSnapshots = input.previousSnapshots || {};
        const monitorExecution = input.__monitorExecution;
        const totalProgressUnits = targets.length + 2;
        const timestamp = new Date().toISOString();

        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: totalProgressUnits,
            phase: "prepare",
            message: "Preparing DNS resolution",
        });

        let completedTargets = 0;

        const tasks = targets.map((target) => async (): Promise<DnsQueryResult> => {
            try {
                const records: DnsQueryResult["records"] = [];
                for (const recordType of recordTypes) {
                    const answers = await queryDoh(target, recordType, timeout);
                    for (const answer of answers) {
                        records.push({
                            recordType,
                            value: String(answer.data || "").trim(),
                            ttl: answer.TTL,
                        });
                    }
                }

                return {
                    target,
                    success: true,
                    records,
                };
            } catch (error: any) {
                return {
                    target,
                    success: false,
                    records: [],
                    error: error instanceof Error ? error.message : String(error),
                };
            } finally {
                completedTargets += 1;
                await reportMonitorProgress(monitorExecution, {
                    current: completedTargets,
                    total: totalProgressUnits,
                    currentTarget: target,
                    phase: "resolve",
                    message: `Resolving DNS records for ${target}`,
                });
            }
        });

        const results = await runWithConcurrency(tasks, concurrency);
        await reportMonitorProgress(monitorExecution, {
            current: targets.length + 1,
            total: totalProgressUnits,
            phase: "compare",
            message: "Comparing DNS snapshots",
        });
        const changeEvents: ChangeEvent[] = [];
        const snapshots: Record<string, DnsSnapshot> = {};
        const domains = new Map<string, any>();
        const ips = new Map<string, any>();
        const evidences: any[] = [];
        const relations = new Map<string, any>();

        for (const target of targets) {
            domains.set(target, {
                fqdn: target,
                root_domain: guessRootDomain(target),
                main_domain: guessRootDomain(target),
                source: "dns_resolver",
                confidence: 0.98,
            });
        }

        for (const result of results) {
            result.records = normalizeRecords(result.records);

            if (result.success) {
                snapshots[result.target] = {
                    target: result.target,
                    records: result.records,
                    lastChecked: timestamp,
                };

                const previous = previousSnapshots[result.target];
                if (previous) {
                    const previousRecords = normalizeRecords(previous.records || []);
                    const previousKeys = new Set(previousRecords.map(recordIdentity));
                    const currentKeys = new Set(result.records.map(recordIdentity));
                    const added = result.records.filter(record => !previousKeys.has(recordIdentity(record)));
                    const removed = previousRecords.filter(record => !currentKeys.has(recordIdentity(record)));
                    if (added.length > 0 || removed.length > 0) {
                        changeEvents.push(createDnsChangeEvent(result.target, added, removed, timestamp));
                    }
                }
            }

            evidences.push({
                asset_type: "domain",
                asset_key: result.target,
                evidence_type: "dns_records",
                title: `DNS Records: ${result.target}`,
                content_json: result.records,
                source: "dns_resolver",
            });

            for (const record of result.records) {
                const value = record.value.replace(/\.$/, "");
                if (!value) continue;

                if (record.recordType === "A" || record.recordType === "AAAA") {
                    ips.set(value, {
                        ip_address: value,
                        ip_version: record.recordType === "AAAA" ? "IPv6" : "IPv4",
                        source: "dns_resolver",
                        confidence: 0.98,
                    });
                    relations.set(`${result.target}->${value}->resolves_to`, {
                        from_type: "domain",
                        from_key: result.target,
                        to_type: "ip",
                        to_key: value,
                        relation_type: "resolves_to",
                        source: "dns_resolver",
                        confidence: 0.98,
                    });
                    continue;
                }

                if (["CNAME", "MX", "NS"].includes(record.recordType)) {
                    domains.set(value, {
                        fqdn: value,
                        root_domain: guessRootDomain(value),
                        main_domain: guessRootDomain(value),
                        source: "dns_resolver",
                        confidence: 0.85,
                    });

                    const relationType =
                        record.recordType === "CNAME"
                            ? "aliases_to"
                            : record.recordType === "MX"
                              ? "has_mx"
                              : "has_ns";

                    relations.set(`${result.target}->${value}->${relationType}`, {
                        from_type: "domain",
                        from_key: result.target,
                        to_type: "domain",
                        to_key: value,
                        relation_type: relationType,
                        source: "dns_resolver",
                        confidence: 0.9,
                    });
                }
            }
        }

        const successfulTargets = results.filter((result) => result.success).length;
        const totalRecords = results.reduce((sum, result) => sum + result.records.length, 0);

        await reportMonitorProgress(monitorExecution, {
            current: totalProgressUnits,
            total: totalProgressUnits,
            phase: "build",
            message: "Building DNS artifacts",
        });

        return {
            success: true,
            data: {
                targets,
                results,
                changeEvents,
                snapshots,
                summary: {
                    totalTargets: targets.length,
                    successfulTargets,
                    failedTargets: targets.length - successfulTargets,
                    totalRecords,
                    dnsChanges: changeEvents.length,
                },
                surface_artifacts: {
                    domains: Array.from(domains.values()),
                    ips: Array.from(ips.values()),
                    changes: changeEvents.map(event => ({
                        asset_key: event.assetId,
                        asset_type: "domain",
                        change_type: event.eventType,
                        severity: event.severity,
                        title: event.title,
                        description: event.description,
                        old_value: event.oldValue,
                        new_value: event.newValue,
                        risk_score: event.riskScore,
                        source: "dns_resolver",
                        metadata: event.metadata,
                    })),
                    evidences,
                    relations: Array.from(relations.values()),
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
