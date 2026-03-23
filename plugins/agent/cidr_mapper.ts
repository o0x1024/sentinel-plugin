/**
 * CIDR Mapper Tool
 *
 * @plugin cidr_mapper
 * @name CIDR Mapper
 * @version 1.0.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags cidr, ip, network, asm, surface
 * @description Expand IPv4 CIDR blocks and individual IP targets into typed IP and host surface artifacts for ASM and network asset mapping workflows
 */

interface ToolInput {
    targets: string[];
    maxHosts?: number;
    includeNetworkBroadcast?: boolean;
}

interface MappingResult {
    target: string;
    kind: "cidr" | "ip";
    generatedHosts: number;
    truncated: boolean;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        targets: string[];
        results: MappingResult[];
        summary: {
            totalTargets: number;
            generatedIps: number;
            generatedHosts: number;
            truncatedTargets: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

function isIpv4(value: string): boolean {
    const parts = value.split(".");
    if (parts.length !== 4) return false;
    return parts.every((part) => {
        if (!/^\d+$/.test(part)) return false;
        const num = Number(part);
        return num >= 0 && num <= 255;
    });
}

function ipv4ToInt(ip: string): number {
    return ip.split(".").reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

function intToIpv4(value: number): string {
    return [
        (value >>> 24) & 255,
        (value >>> 16) & 255,
        (value >>> 8) & 255,
        value & 255,
    ].join(".");
}

function normalizeTarget(value: string): string {
    return String(value || "").trim();
}

function expandIpv4Cidr(
    cidr: string,
    maxHosts: number,
    includeNetworkBroadcast: boolean,
): { addresses: string[]; truncated: boolean } {
    const [rawIp, rawPrefix] = cidr.split("/");
    const prefix = Number(rawPrefix);
    if (!isIpv4(rawIp) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
        throw new Error(`Unsupported CIDR target: ${cidr}`);
    }

    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = ipv4ToInt(rawIp) & mask;
    const hostCount = prefix === 32 ? 1 : Math.pow(2, 32 - prefix);
    const startOffset = includeNetworkBroadcast || prefix >= 31 ? 0 : 1;
    const endExclusive = includeNetworkBroadcast || prefix >= 31 ? hostCount : hostCount - 1;
    const totalUsable = Math.max(0, endExclusive - startOffset);
    const capped = Math.min(totalUsable, Math.max(1, maxHosts));
    const addresses: string[] = [];

    for (let offset = 0; offset < capped; offset += 1) {
        addresses.push(intToIpv4(network + startOffset + offset));
    }

    return {
        addresses,
        truncated: totalUsable > capped,
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
                description: "IPv4 addresses or IPv4 CIDR ranges to expand",
            },
            maxHosts: {
                type: "integer",
                description: "Maximum number of hosts to emit per CIDR range",
                default: 1024,
                minimum: 1,
                maximum: 65536,
            },
            includeNetworkBroadcast: {
                type: "boolean",
                description: "Include network and broadcast addresses when expanding CIDR ranges",
                default: false,
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
                    results: { type: "array" },
                    summary: { type: "object" },
                    surface_artifacts: {
                        type: "object",
                        description: "Typed IP and host assets for surface graph ingestion",
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
            return { success: false, error: "Invalid input: targets array is required" };
        }

        const targets = Array.from(new Set(input.targets.map(normalizeTarget).filter(Boolean)));
        const maxHosts = Math.max(1, Math.min(input.maxHosts || 1024, 65536));
        const includeNetworkBroadcast = Boolean(input.includeNetworkBroadcast);

        const ips: any[] = [];
        const hosts: any[] = [];
        const relations: any[] = [];
        const evidences: any[] = [];
        const results: MappingResult[] = [];
        const seenIps = new Set<string>();
        const seenHosts = new Set<string>();

        for (const target of targets) {
            try {
                let addresses: string[] = [];
                let truncated = false;
                let kind: MappingResult["kind"] = "ip";

                if (target.includes("/")) {
                    kind = "cidr";
                    const expanded = expandIpv4Cidr(target, maxHosts, includeNetworkBroadcast);
                    addresses = expanded.addresses;
                    truncated = expanded.truncated;
                } else if (isIpv4(target)) {
                    addresses = [target];
                } else {
                    throw new Error(`Unsupported target: ${target}`);
                }

                for (const ip of addresses) {
                    if (!seenIps.has(ip)) {
                        seenIps.add(ip);
                        ips.push({
                            ip_address: ip,
                            ip_version: "ipv4",
                            cidr: kind === "cidr" ? target : `${ip}/32`,
                            network_boundary_type: "internet",
                            source_seed: target,
                        });
                    }

                    if (!seenHosts.has(ip)) {
                        seenHosts.add(ip);
                        hosts.push({
                            hostname: ip,
                            ip_addresses: [ip],
                            device_type: "network_node",
                            lifecycle_status: "active",
                            labels: kind === "cidr" ? ["cidr_seed"] : ["ip_seed"],
                            last_online_at: new Date().toISOString(),
                        });
                    }

                    relations.push({
                        from_type: "ip",
                        from_key: ip,
                        to_type: "host",
                        to_key: ip,
                        relation_type: "identifies_host",
                        confidence: 1,
                    });

                    evidences.push({
                        asset_type: "ip",
                        asset_key: ip,
                        evidence_type: "cidr_mapping",
                        title: `CIDR mapping evidence for ${ip}`,
                        content_json: {
                            seed: target,
                            emitted_ip: ip,
                            mapping_kind: kind,
                        },
                    });
                }

                results.push({
                    target,
                    kind,
                    generatedHosts: addresses.length,
                    truncated,
                });
            } catch (error) {
                results.push({
                    target,
                    kind: target.includes("/") ? "cidr" : "ip",
                    generatedHosts: 0,
                    truncated: false,
                    error: error instanceof Error ? error.message : String(error),
                });
            }
        }

        return {
            success: true,
            data: {
                targets,
                results,
                summary: {
                    totalTargets: targets.length,
                    generatedIps: ips.length,
                    generatedHosts: hosts.length,
                    truncatedTargets: results.filter((item) => item.truncated).length,
                },
                surface_artifacts: {
                    ips,
                    hosts,
                    relations,
                    evidences,
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

globalThis.analyze = analyze;
