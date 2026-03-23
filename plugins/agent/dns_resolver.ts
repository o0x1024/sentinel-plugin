/**
 * DNS Resolver Tool
 *
 * @plugin dns_resolver
 * @name DNS Resolver
 * @version 1.0.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags dns, resolver, mapping, domain, asm
 * @description Resolve DNS records for domains and produce typed surface graph artifacts for ASM and network asset mapping
 */

type RecordType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT";

interface ToolInput {
    targets: string[];
    recordTypes?: RecordType[];
    timeout?: number;
    concurrency?: number;
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

interface ToolOutput {
    success: boolean;
    data?: {
        targets: string[];
        results: DnsQueryResult[];
        summary: {
            totalTargets: number;
            successfulTargets: number;
            failedTargets: number;
            totalRecords: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

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
        },
    };
}

globalThis.get_input_schema = get_input_schema;

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

globalThis.get_output_schema = get_output_schema;

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
            }
        });

        const results = await runWithConcurrency(tasks, concurrency);

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

        return {
            success: true,
            data: {
                targets,
                results,
                summary: {
                    totalTargets: targets.length,
                    successfulTargets,
                    failedTargets: targets.length - successfulTargets,
                    totalRecords,
                },
                surface_artifacts: {
                    domains: Array.from(domains.values()),
                    ips: Array.from(ips.values()),
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

globalThis.analyze = analyze;
