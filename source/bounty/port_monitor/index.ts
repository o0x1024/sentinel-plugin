/**
 * Port Change Monitor
 *
 * @plugin port_monitor
 * @name Port Monitor
 * @version 1.3.10
 * @author Sentinel Team
 * @main_category bounty
 * @monitor_type port
 * @input_mode asset
 * @target_asset_types ["ip","service"]
 * @category monitor
 * @target_sources ["surface_asset","bounty_asset","scope"]
 * @seed_bindings []
 * @default_severity medium
 * @tags port, monitor, network, asm, surface, ip, host, change-detection, native, capability:network-scan, capability:monitor-events, monitor:results-stream-v2
 * @description Monitor typed host and IP targets for port exposure changes using native Rust-backed port discovery, prioritizing structured monitor targets and preserving strict IP-only execution semantics for ASM workflows
 */
import { createMonitorResultStream } from "../../shared/monitor_results.ts";
import { createMonitorTargetWriter } from "../../shared/monitor_target_writer.ts";

interface ToolInput {
    targets?: Array<string | ServiceTarget>;  // Legacy host list or service endpoints
    target_objects?: Array<string | ServiceTarget>;
    service_targets?: Array<string | ServiceTarget>;
    ports?: number[];   // Specific ports to scan (default: common ports)
    detectService?: boolean;
    previousSnapshots?: Record<string, PortSnapshot>;
    __monitorExecution?: MonitorExecutionContext;
}

interface PortInfo {
    port: number;
    state: "open" | "closed" | "filtered";
    service?: string;
    banner?: string;
    protocol: "tcp";
}

interface PortSnapshot {
    host: string;
    openPorts: PortInfo[];
    lastChecked: string;
}

interface ServiceTarget {
    type?: string;
    value?: string;
    host?: string;
    host_key?: string;
    ip_or_host?: string;
    port?: number;
    port_number?: number;
    protocol?: string;
    transport_protocol?: string;
    service_name?: string;
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

interface PortResult {
    host: string;
    success: boolean;
    snapshot?: PortSnapshot;
    newPorts?: PortInfo[];
    closedPorts?: PortInfo[];
    serviceChanges?: Array<{ port: number; oldService?: string; newService?: string }>;
    error?: string;
    knownOpenPorts?: PortInfo[];
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: PortResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, PortSnapshot>;
        summary: {
            totalTargets: number;
            successfulScans: number;
            failedScans: number;
            totalOpenPorts: number;
            newPortsOpened: number;
            portsClosed: number;
            serviceChanges: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

interface NativePortScanTarget {
    host: string;
    ports?: number[];
}

interface NativePortScanResult {
    host: string;
    resolved_ips: string[];
    open_ports: number[];
    error?: string;
}

interface NativePortScanResponse {
    success: boolean;
    results: NativePortScanResult[];
    summary?: {
        total_targets: number;
        successful_scans: number;
        failed_scans: number;
        total_open_ports: number;
    };
    error?: string;
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

type NormalizedTargetType = "generic" | "service" | "host" | "ip";

interface NormalizedHostTarget {
    host: string;
    ports?: number[];
    sourceType: NormalizedTargetType;
}

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;

// Common ports to scan
const COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017
];

// High-risk ports
const HIGH_RISK_PORTS = new Set([
    21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017
]);

const DEFAULT_CONCURRENCY = 32;
const MAX_CONCURRENCY = 32;

// Generate UUID
function generateId(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function isIpLiteral(value: string): boolean {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
}

function normalizeHostTarget(target: string | ServiceTarget): NormalizedHostTarget | null {
    if (typeof target === "string") {
        const trimmed = target.trim();
        if (!trimmed) return null;

        try {
            if (trimmed.includes("://")) {
                const parsed = new URL(trimmed);
                const host = parsed.hostname;
                const port = parsed.port ? Number(parsed.port) : 0;
                return host ? { host, ports: port > 0 ? [port] : undefined, sourceType: "generic" } : null;
            }
        } catch {
            // Fall through to host:port parsing.
        }

        const base = trimmed.split("/")[0];
        if (!base) return null;

        const colonParts = base.split(":");
        if (colonParts.length === 2 && /^\d+$/.test(colonParts[1])) {
            return { host: colonParts[0], ports: [Number(colonParts[1])], sourceType: "generic" };
        }

        return { host: base, sourceType: "generic" };
    }

    if (!target || typeof target !== "object") {
        return null;
    }

    const sourceType = String(target.type || "").trim().toLowerCase() as NormalizedTargetType | "";

    if (typeof target.value === "string" && target.value.trim()) {
        const normalized = normalizeHostTarget(target.value);
        if (!normalized) return null;
        if (sourceType === "ip" && !isIpLiteral(normalized.host)) {
            return null;
        }
        return {
            ...normalized,
            sourceType: sourceType || normalized.sourceType,
        };
    }

    const host = String(target.host || target.ip_or_host || target.host_key || "").trim();
    const port = Number(target.port ?? target.port_number ?? 0);
    if (!host) return null;
    if (sourceType === "ip" && !isIpLiteral(host)) {
        return null;
    }
    return {
        host,
        ports: port > 0 ? [port] : undefined,
        sourceType: sourceType || "generic",
    };
}

function collectRawTargets(input: ToolInput): Array<string | ServiceTarget> {
    const serviceTargets = Array.isArray(input.service_targets) ? input.service_targets : [];
    const typedTargets = Array.isArray(input.target_objects) ? input.target_objects : [];
    const legacyTargets = Array.isArray(input.targets) ? input.targets : [];

    const selectedTargets = serviceTargets.length > 0
        ? [...serviceTargets, ...typedTargets]
        : typedTargets.length > 0
            ? typedTargets
            : legacyTargets;

    return selectedTargets.filter((target) => {
        if (typeof target === "string") {
            return target.trim().length > 0;
        }
        if (!target || typeof target !== "object") {
            return false;
        }
        return !target.type || target.type === "service" || target.type === "host" || target.type === "ip";
    });
}

// Calculate risk score
function calculateRiskScore(severity: string, eventType: string, ports: number[]): number {
    let score = 0;

    switch (severity) {
        case "critical": score += 40; break;
        case "high": score += 30; break;
        case "medium": score += 20; break;
        case "low": score += 10; break;
    }

    switch (eventType) {
        case "ports_opened": score += 20; break;
        case "ports_closed": score += 5; break;
        case "high_risk_port_opened": score += 30; break;
    }

    // Bonus for high-risk ports
    for (const port of ports) {
        if (HIGH_RISK_PORTS.has(port)) {
            score += 5;
        }
    }

    return Math.min(score, 100);
}

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        properties: {
            targets: {
                type: "array",
                description: "Legacy host targets or service endpoint strings"
            },
            target_objects: {
                type: "array",
                description: "Structured monitor targets including service endpoints"
            },
            service_targets: {
                type: "array",
                description: "Structured service endpoints with host, port, and protocol fields"
            },
            ports: {
                type: "array",
                items: { type: "integer" },
                description: "Specific ports to scan (default: common ports)"
            },
            detectService: {
                type: "boolean",
                description: "Reserved for compatibility; service fingerprinting is handled by dedicated service plugins",
                default: false
            },
            previousSnapshots: {
                type: "object",
                description: "Previous port snapshots for comparison"
            }
        }
    };
}

pluginGlobals.get_input_schema = get_input_schema;

/**
 * Export output schema
 */
export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean", description: "Whether the operation succeeded" },
            data: {
                type: "object",
                properties: {
                    results: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                host: { type: "string" },
                                success: { type: "boolean" },
                                snapshot: { type: "object" },
                                newPorts: { type: "array" },
                                closedPorts: { type: "array" }
                            }
                        },
                        description: "Port scan results"
                    },
                    changeEvents: { type: "array", description: "Change events detected" },
                    snapshots: { type: "object", description: "Port snapshots by host" },
                    summary: {
                        type: "object",
                        properties: {
                            totalTargets: { type: "integer" },
                            totalOpenPorts: { type: "integer" },
                            newPortsOpened: { type: "integer" },
                            portsClosed: { type: "integer" }
                        }
                    },
                    surface_artifacts: {
                        type: "object",
                        description: "Typed network surface artifacts for surface graph ingestion"
                    }
                }
            },
            error: { type: "string", description: "Error message if failed" }
        }
    };
}

pluginGlobals.get_output_schema = get_output_schema;

function mapOpenPorts(openPorts: number[]): PortInfo[] {
    return [...new Set(openPorts)]
        .filter(port => Number.isInteger(port) && port > 0)
        .sort((left, right) => left - right)
        .map(port => ({
            port,
            state: "open",
            protocol: "tcp",
        }));
}

async function scanPortsWithNativeEngine(
    targets: NativePortScanTarget[],
    defaultPorts: number[],
    monitorExecution?: MonitorExecutionContext
): Promise<NativePortScanResponse> {
    if (typeof Sentinel === "undefined" || !Sentinel.Network || typeof Sentinel.Network.scanPorts !== "function") {
        throw new Error("Native port scanning engine is not available");
    }

    return await Sentinel.Network.scanPorts({
        targets,
        ports: defaultPorts,
        tries: 1,
        monitor_progress: monitorExecution ? {
            taskId: monitorExecution.task_id,
            taskName: monitorExecution.task_name,
            programId: monitorExecution.program_id,
            executionMode: monitorExecution.execution_mode,
            startedAt: monitorExecution.started_at,
            currentPlugin: monitorExecution.current_plugin,
            currentPluginIndex: monitorExecution.current_plugin_index,
            completedSteps: monitorExecution.completed_steps,
            totalSteps: monitorExecution.total_steps,
            importedAssets: monitorExecution.imported_assets || 0,
        } : undefined,
    });
}

/**
 * Main analysis function
 */
function projectPortOutput(nativeResults: NativePortScanResult[], previousSnapshots: Record<string, PortSnapshot>): ToolOutput {
        const results: PortResult[] = [], changeEvents: ChangeEvent[] = [];
        const newSnapshots: Record<string, PortSnapshot> = {};
        let successfulScans = 0, failedScans = 0, totalOpenPorts = 0, newPortsOpened = 0, portsClosed = 0;
        for (const nativeResult of nativeResults) {
            const host = nativeResult.host;
            const result: PortResult = {
                host, success: false, knownOpenPorts: mapOpenPorts(nativeResult.open_ports || []),
            };
            totalOpenPorts += result.knownOpenPorts!.length;

            try {
                if (nativeResult.error) {
                    throw new Error(nativeResult.error);
                }

                const openPorts = mapOpenPorts(nativeResult.open_ports || []);
                result.success = true;
                successfulScans++;

                // Create snapshot
                const snapshot: PortSnapshot = {
                    host,
                    openPorts,
                    lastChecked: new Date().toISOString(),
                };

                result.snapshot = snapshot;
                newSnapshots[host] = snapshot;

                // Compare with previous snapshot
                const prevSnapshot = previousSnapshots[host];
                if (prevSnapshot) {
                    const prevPortSet = new Set(prevSnapshot.openPorts.map(p => p.port));
                    const newPortSet = new Set(openPorts.map(p => p.port));

                    // Find newly opened ports
                    const newPorts = openPorts.filter(p => !prevPortSet.has(p.port));
                    const closedPorts = prevSnapshot.openPorts.filter(p => !newPortSet.has(p.port));

                    result.newPorts = newPorts;
                    result.closedPorts = closedPorts;

                    // Generate change events for new ports
                    if (newPorts.length > 0) {
                        newPortsOpened += newPorts.length;

                        const highRiskNew = newPorts.filter(p => HIGH_RISK_PORTS.has(p.port));
                        const severity = highRiskNew.length > 0 ? "high" : "medium";
                        const eventType = highRiskNew.length > 0 ? "high_risk_port_opened" : "ports_opened";

                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: host,
                            eventType,
                            severity,
                            title: `New Ports Opened: ${host}`,
                            description: `${newPorts.length} new port(s) detected: ${newPorts.map(p => `${p.port}/tcp`).join(", ")}`,
                            newValue: JSON.stringify(newPorts.map(p => p.port)),
                            detectionMethod: "port_monitor",
                            tags: ["port", "open", "change", ...(highRiskNew.length > 0 ? ["high-risk"] : [])],
                            autoTriggerEnabled: severity === "high",
                            riskScore: 0,
                            metadata: {
                                newPorts,
                                highRiskPorts: highRiskNew.map(p => p.port),
                                resolvedIps: nativeResult.resolved_ips || [],
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, newPorts.map(p => p.port));
                        changeEvents.push(event);
                    }

                    // Generate change events for closed ports
                    if (closedPorts.length > 0) {
                        portsClosed += closedPorts.length;

                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: host,
                            eventType: "ports_closed",
                            severity: "low",
                            title: `Ports Closed: ${host}`,
                            description: `${closedPorts.length} port(s) no longer accessible: ${closedPorts.map(p => `${p.port}/tcp`).join(", ")}`,
                            oldValue: JSON.stringify(closedPorts.map(p => p.port)),
                            detectionMethod: "port_monitor",
                            tags: ["port", "closed", "change"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                closedPorts,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, closedPorts.map(p => p.port));
                        changeEvents.push(event);
                    }
                } else {
                    // First scan - report discovery
                    if (openPorts.length > 0) {
                        const highRiskPorts = openPorts.filter(p => HIGH_RISK_PORTS.has(p.port));

                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: host,
                            eventType: "ports_discovered",
                            severity: highRiskPorts.length > 0 ? "medium" : "low",
                            title: `Open Ports Discovered: ${host}`,
                            description: `Initial scan found ${openPorts.length} open port(s): ${openPorts.map(p => `${p.port}/tcp`).join(", ")}`,
                            newValue: JSON.stringify(openPorts.map(p => p.port)),
                            detectionMethod: "port_monitor",
                            tags: ["port", "discovery", "initial-scan"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                openPorts,
                                highRiskPorts: highRiskPorts.map(p => p.port),
                                resolvedIps: nativeResult.resolved_ips || [],
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, openPorts.map(p => p.port));
                        changeEvents.push(event);
                    }
                }

            } catch (error: any) {
                result.error = error.message || String(error);
                failedScans++;
            }

            results.push(result);
        }


        return {
            success: true,
            data: {
                results,
                changeEvents,
                snapshots: newSnapshots,
                summary: {
                    totalTargets: nativeResults.length,
                    successfulScans,
                    failedScans,
                    totalOpenPorts,
                    newPortsOpened,
                    portsClosed,
                    serviceChanges: 0,
                },
                surface_artifacts: {
                    domains: [...new Set(results
                        .map(result => result.host)
                        .filter(host => !isIpLiteral(host))
                    )].map(domainName => ({
                        domain_name: domainName,
                        fqdn: domainName,
                        source: "port_monitor",
                        confidence: 0.95,
                    })),
                    ips: [...new Set(results
                        .map(result => result.host)
                        .filter(host => isIpLiteral(host))
                    )].map(ipAddress => ({
                        ip_address: ipAddress,
                        ip_version: ipAddress.includes(":") ? "IPv6" : "IPv4",
                        source: "port_monitor",
                        confidence: 0.95,
                    })),
                    ports: results.flatMap(result =>
                        (result.snapshot?.openPorts || result.knownOpenPorts || []).map(portInfo => ({
                            host_key: result.host,
                            ip_or_host: result.host,
                            port: portInfo.port,
                            transport_protocol: portInfo.protocol,
                            state: portInfo.state,
                            source: "port_monitor",
                            confidence: 0.95,
                        }))
                    ),
                    changes: changeEvents.map(event => ({
                        asset_key: event.assetId,
                        asset_type: isIpLiteral(event.assetId) ? "ip" : "domain",
                        change_type: event.eventType,
                        severity: event.severity,
                        title: event.title,
                        description: event.description,
                        old_value: event.oldValue,
                        new_value: event.newValue,
                        risk_score: event.riskScore,
                        source: "port_monitor",
                        metadata: event.metadata,
                    })),
                    evidences: results
                        .filter(result => result.snapshot)
                        .map(result => ({
                            asset_type: isIpLiteral(result.host) ? "ip" : "domain",
                            asset_key: result.host,
                            evidence_type: "port_snapshot",
                            title: `Port Snapshot: ${result.host}`,
                            content_text: `${result.snapshot?.openPorts.length || 0} open ports`,
                            content_json: result.snapshot,
                            source: "port_monitor",
                        })),
                    relations: results.flatMap(result =>
                        (result.snapshot?.openPorts || result.knownOpenPorts || []).map(portInfo => ({
                            from_type: isIpLiteral(result.host) ? "ip" : "domain",
                            from_key: result.host,
                            to_type: "port",
                            to_key: `${result.host}:${portInfo.port}/${portInfo.protocol}`,
                            relation_type: "exposes_port",
                            source: "port_monitor",
                            confidence: 0.95,
                        }))
                    ),
                },
            },
        };

}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const stream = createMonitorResultStream(input);
        const writeTarget = createMonitorTargetWriter(input, stream, value => normalizeHostTarget(value)?.host || "");
        const rawTargets = collectRawTargets(input);
        if (rawTargets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets array is required"
            };
        }

        const normalizedTargetSpecs = rawTargets
            .map(normalizeHostTarget)
            .filter((target): target is NonNullable<typeof target> => Boolean(target));

        if (normalizedTargetSpecs.length === 0) {
            return {
                success: false,
                error: "Invalid input: no valid host or service targets provided"
            };
        }

        const targetPortMap = new Map<string, Set<number>>();
        for (const target of normalizedTargetSpecs) {
            const entry = targetPortMap.get(target.host) || new Set<number>();
            for (const port of target.ports || []) {
                if (port > 0) {
                    entry.add(port);
                }
            }
            targetPortMap.set(target.host, entry);
        }

        const validTargets = [...targetPortMap.keys()];
        const defaultPorts = [...new Set(input.ports || COMMON_PORTS)].sort((left, right) => left - right);
        const previousSnapshots = input.previousSnapshots || {};
        const monitorExecution = input.__monitorExecution;

        const completedResults: NativePortScanResult[] = [];
        let nextHost = 0;
        await Promise.all(Array.from({ length: Math.min(2, validTargets.length) }, async () => {
            while (nextHost < validTargets.length) {
                const host = validTargets[nextHost++];
                const selected = [...(targetPortMap.get(host) || new Set<number>())].sort((a, b) => a - b);
                const ports = selected.length ? selected : defaultPorts;
                const openPorts = new Set<number>(), resolvedIps = new Set<string>();
                let error: string | undefined;
                for (let offset = 0; offset < ports.length; offset += 256) {
                    stream.assertHealthy();
                    const batch = ports.slice(offset, offset + 256);
                    const response = await scanPortsWithNativeEngine([{ host, ports: batch }], batch, monitorExecution);
                    if (!Array.isArray(response.results) || response.results.length !== 1 || response.results[0].host !== host) {
                        throw new Error(response.error || "Native port scan returned no authoritative host result");
                    }
                    const result = response.results[0];
                    error = result.error;
                    for (const ip of result.resolved_ips || []) resolvedIps.add(ip);
                    for (const port of result.open_ports || []) {
                        if (!batch.includes(port)) throw new Error("Native port scan returned a port outside its batch");
                        openPorts.add(port);
                    }
                    const partial: any = projectPortOutput([result], {});
                    // A bounded port set is discovery evidence, never a complete host baseline.
                    delete partial.data!.snapshots;
                    partial.data!.changeEvents = [];
                    // Batch counters are deltas; host totals are reported only by host-complete.
                    partial.data!.summary = { portBatches: 1, requestedPorts: batch.length, confirmedOpenPorts: result.open_ports?.length || 0 };
                    partial.data!.surface_artifacts!.changes = [];
                    partial.data!.surface_artifacts!.evidences = [{ asset_type: isIpLiteral(host) ? "ip" : "domain", asset_key: host,
                        evidence_type: "port_probe_batch", title: `Port probe batch: ${host}`, source: "port_monitor",
                        content_json: { host, ports: batch, open_ports: result.open_ports || [], error } }];
                    await writeTarget(host, `ports:${offset / 256}`, partial as any, { complete: false, status: error ? "failed" : "ok", error });
                    if (error) break;
                }
                const complete: NativePortScanResult = { host, open_ports: [...openPorts].sort((a, b) => a - b), resolved_ips: [...resolvedIps], ...(error ? { error } : {}) };
                if (!stream.enabled) completedResults.push(complete);
                const projected = projectPortOutput([complete], previousSnapshots).data!;
                await writeTarget(host, "host-complete", { success: true, data: {
                    results: [{ host, success: !error, ...(error ? { error } : {}), knownOpenPortCount: complete.open_ports.length }],
                    snapshots: projected.snapshots,
                    changeEvents: projected.changeEvents,
                    summary: projected.summary,
                    surface_artifacts: { changes: projected.surface_artifacts!.changes, evidences: projected.surface_artifacts!.evidences },
                } }, { snapshot_complete: !error, status: error ? "failed" : "ok", error });
            }
        }));
        return await stream.finish(stream.enabled ? { success: true } : projectPortOutput(completedResults, previousSnapshots));

    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
