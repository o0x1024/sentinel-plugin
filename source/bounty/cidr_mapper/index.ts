/**
 * CIDR Mapper Tool
 *
 * @plugin cidr_mapper
 * @name CIDR Mapper
 * @version 1.0.5
 * @author Sentinel Team
 * @main_category bounty
 * @monitor_type ip
 * @input_mode asset
 * @target_asset_types ["ip","ip_range"]
 * @category recon
 * @target_sources ["surface_asset","bounty_asset","scope"]
 * @seed_bindings []
 * @default_severity info
 * @tags cidr, ip, network, asm, surface, capability:monitor-events, monitor:results-stream-v2
 * @description Expand IPv4 CIDR blocks and individual IP targets into typed IP surface artifacts for ASM and network asset mapping workflows
 */
import { createMonitorResultStream } from "../../shared/monitor_results.ts";
import { createMonitorTargetWriter } from "../../shared/monitor_target_writer.ts";

interface ToolInput {
    targets: string[];
    maxHosts?: number;
    includeNetworkBroadcast?: boolean;
}

interface MappingResult {
    target: string;
    kind: "cidr" | "ip";
    generatedIps: number;
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
            truncatedTargets: number;
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
                        description: "Typed IP assets for surface graph ingestion",
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
        const stream = createMonitorResultStream(input);
        const writeTarget = createMonitorTargetWriter(input, stream, normalizeTarget);
        if (!Array.isArray(input.targets) || input.targets.length === 0) throw new Error("Invalid input: targets array is required");
        const targets = Array.from(new Set(input.targets.map(normalizeTarget).filter(Boolean)));
        const maxHosts = Math.max(1, Math.min(input.maxHosts || 1024, 65536));
        const seenIps = new Set<string>();
        const ips: any[] = [], evidences: any[] = [], results: MappingResult[] = [];
        let generatedIps = 0;
        for (const target of targets) {
            stream.assertHealthy();
            const kind = target.includes("/") ? "cidr" : "ip";
            let addresses: string[] = [], truncated = false, error: string | undefined;
            try {
                if (kind === "cidr") ({ addresses, truncated } = expandIpv4Cidr(target, maxHosts, Boolean(input.includeNetworkBroadcast)));
                else if (isIpv4(target)) addresses = [target];
                else throw new Error(`Unsupported target: ${target}`);
            } catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
            for (let offset = 0; offset < addresses.length; offset += 256) {
                stream.assertHealthy();
                const pageIps: any[] = [], pageEvidences: any[] = [];
                for (const ip of addresses.slice(offset, offset + 256)) {
                    if (!seenIps.has(ip)) {
                        seenIps.add(ip); generatedIps++;
                        pageIps.push({ ip_address: ip, ip_version: "ipv4", cidr: kind === "cidr" ? target : `${ip}/32`, network_boundary_type: "internet", source_seed: target });
                    }
                    pageEvidences.push({ asset_type: "ip", asset_key: ip, evidence_type: "cidr_mapping", title: `CIDR mapping evidence for ${ip}`,
                        content_json: { seed: target, emitted_ip: ip, mapping_kind: kind } });
                }
                if (!stream.enabled) { ips.push(...pageIps); evidences.push(...pageEvidences); }
                await writeTarget(target, `mapping-page:${offset / 256}`, { success: true, data: {
                    surface_artifacts: { ips: pageIps, evidences: pageEvidences },
                } }, { complete: false });
            }
            const result: MappingResult = { target, kind, generatedIps: addresses.length, truncated, ...(error ? { error } : {}) };
            results.push(result);
            await writeTarget(target, "mapping-complete", { success: true, data: { results: [result] } }, { status: error ? "failed" : "ok", error });
        }
        if (stream.enabled) return await stream.finish<ToolOutput>({ success: true });
        return await stream.finish({ success: true, data: { targets, results, summary: {
            totalTargets: targets.length, generatedIps, truncatedTargets: results.filter(item => item.truncated).length,
        }, surface_artifacts: { ips, evidences } } });
    } catch (error) { return { success: false, error: error instanceof Error ? error.message : String(error) }; }
}

pluginGlobals.analyze = analyze;
