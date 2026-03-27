/**
 * Port Change Monitor
 * 
 * @plugin port_monitor
 * @name Port Monitor
 * @version 1.2.0
 * @author Sentinel Team
 * @category monitor
 * @default_severity medium
 * @tags port, service, monitor, change-detection, scan
 * @description Monitor hosts for port/service changes, generating ChangeEvents for workflow automation
 */

interface ToolInput {
    targets?: Array<string | ServiceTarget>;  // Legacy host list or service endpoints
    target_objects?: Array<string | ServiceTarget>;
    service_targets?: Array<string | ServiceTarget>;
    ports?: number[];   // Specific ports to scan (default: common ports)
    timeout?: number;
    concurrency?: number;
    detectService?: boolean;
    previousSnapshots?: Record<string, PortSnapshot>;
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

// Well-known port services
const PORT_SERVICES: Record<number, string> = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
};

// High-risk ports
const HIGH_RISK_PORTS = new Set([
    21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017
]);

const DEFAULT_CONCURRENCY = 10;
const MAX_CONCURRENCY = 30;
const MAX_TARGET_CONCURRENCY = 4;

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

function normalizeHostTarget(target: string | ServiceTarget): { host: string; ports?: number[] } | null {
    if (typeof target === "string") {
        const trimmed = target.trim();
        if (!trimmed) return null;

        try {
            if (trimmed.includes("://")) {
                const parsed = new URL(trimmed);
                const host = parsed.hostname;
                const port = parsed.port ? Number(parsed.port) : 0;
                return host ? { host, ports: port > 0 ? [port] : undefined } : null;
            }
        } catch {
            // Fall through to host:port parsing.
        }

        const base = trimmed.split("/")[0];
        if (!base) return null;

        const colonParts = base.split(":");
        if (colonParts.length === 2 && /^\d+$/.test(colonParts[1])) {
            return { host: colonParts[0], ports: [Number(colonParts[1])] };
        }

        return { host: base };
    }

    if (!target || typeof target !== "object") {
        return null;
    }

    if (typeof target.value === "string" && target.value.trim()) {
        return normalizeHostTarget(target.value);
    }

    const host = String(target.host || target.ip_or_host || target.host_key || "").trim();
    const port = Number(target.port ?? target.port_number ?? 0);
    if (!host) return null;
    return { host, ports: port > 0 ? [port] : undefined };
}

function collectRawTargets(input: ToolInput): Array<string | ServiceTarget> {
    return [
        ...(Array.isArray(input.service_targets) ? input.service_targets : []),
        ...(Array.isArray(input.target_objects) ? input.target_objects : []),
        ...(Array.isArray(input.targets) ? input.targets : []),
    ].filter((target) => {
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
        case "service_change": score += 15; break;
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

// Run tasks with concurrency limit
async function runWithConcurrency<T>(
    tasks: (() => Promise<T>)[],
    concurrency: number
): Promise<T[]> {
    const results: T[] = new Array(tasks.length);
    const workerCount = Math.max(1, Math.min(concurrency, tasks.length || 1));
    let index = 0;

    const workers = Array.from({ length: workerCount }, async () => {
        while (index < tasks.length) {
            const currentIndex = index;
            index++;
            results[currentIndex] = await tasks[currentIndex]();
        }
    });

    await Promise.all(workers);
    return results;
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
            timeout: {
                type: "integer",
                description: "Connection timeout in milliseconds per port",
                default: 3000,
                minimum: 1000,
                maximum: 30000
            },
            concurrency: {
                type: "integer",
                description: "Number of concurrent port checks",
                default: DEFAULT_CONCURRENCY,
                minimum: 1,
                maximum: MAX_CONCURRENCY
            },
            detectService: {
                type: "boolean",
                description: "Try to detect service on open ports",
                default: true
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

/**
 * Check if a single port is open via HTTP probe
 */
async function checkPort(host: string, port: number, timeout: number, detectService: boolean): Promise<PortInfo> {
    const portInfo: PortInfo = {
        port,
        state: "closed",
        protocol: "tcp",
    };
    
    try {
        // Try HTTP/HTTPS probe for web ports
        if ([80, 443, 8080, 8443, 8888, 3000, 5000, 9000].includes(port)) {
            const protocol = [443, 8443].includes(port) ? "https" : "http";
            const url = `${protocol}://${host}:${port}/`;
            
            const response = await fetch(url, {
                method: "HEAD",
                // @ts-ignore
                timeout,
            });
            
            portInfo.state = "open";
            portInfo.service = protocol.toUpperCase();
            
            // Try to get server header
            const server = response.headers.get("server");
            if (server) {
                portInfo.banner = server;
            }
            
            return portInfo;
        }
        
        // For other ports, try TCP connect via Deno.connect
        // @ts-ignore - Deno API
        const conn = await Deno.connect({
            hostname: host,
            port: port,
            transport: "tcp",
        });
        
        portInfo.state = "open";
        portInfo.service = PORT_SERVICES[port] || "unknown";
        
        // Try to read banner if detectService is enabled
        if (detectService) {
            try {
                // Set a short read timeout
                const buffer = new Uint8Array(256);
                // @ts-ignore
                conn.setReadDeadline(Date.now() + 2000);
                const bytesRead = await conn.read(buffer);
                
                if (bytesRead && bytesRead > 0) {
                    const banner = new TextDecoder().decode(buffer.subarray(0, bytesRead)).trim();
                    if (banner && banner.length > 0 && banner.length < 200) {
                        portInfo.banner = banner.replace(/[\x00-\x1f]/g, '').substring(0, 100);
                    }
                }
            } catch {
                // Banner grab failed, that's ok
            }
        }
        
        conn.close();
        return portInfo;
        
    } catch (error: any) {
        // Connection failed - port is likely closed or filtered
        if (error.message?.includes("timed out") || error.message?.includes("timeout")) {
            portInfo.state = "filtered";
        }
        return portInfo;
    }
}

/**
 * Scan all ports for a host
 */
async function scanHost(
    host: string,
    ports: number[],
    timeout: number,
    concurrency: number,
    detectService: boolean
): Promise<PortInfo[]> {
    const openPorts: PortInfo[] = [];
    
    // Create tasks for each port
    const tasks = ports.map(port => async () => {
        const result = await checkPort(host, port, timeout, detectService);
        if (result.state === "open") {
            openPorts.push(result);
        }
        return result;
    });
    
    // Run with concurrency
    await runWithConcurrency(tasks, concurrency);
    
    // Sort by port number
    openPorts.sort((a, b) => a.port - b.port);
    
    return openPorts;
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
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
        const timeout = input.timeout || 3000;
        const concurrency = Math.max(1, Math.min(input.concurrency || DEFAULT_CONCURRENCY, MAX_CONCURRENCY));
        const targetConcurrency = Math.max(1, Math.min(MAX_TARGET_CONCURRENCY, validTargets.length, concurrency));
        const detectService = input.detectService !== false;
        const previousSnapshots = input.previousSnapshots || {};
        
        const results: PortResult[] = [];
        const changeEvents: ChangeEvent[] = [];
        const newSnapshots: Record<string, PortSnapshot> = {};
        
        let successfulScans = 0;
        let failedScans = 0;
        let totalOpenPorts = 0;
        let newPortsOpened = 0;
        let portsClosed = 0;
        let serviceChangesCount = 0;
        
        await runWithConcurrency(validTargets.map((target) => async () => {
            // Parse host from target (could be IP, hostname, or URL)
            let host = target;
            try {
                if (target.includes("://")) {
                    const url = new URL(target);
                    host = url.hostname;
                } else {
                    host = target.split("/")[0].split(":")[0];
                }
            } catch {
                // Use as-is
            }
            
            const result: PortResult = {
                host,
                success: false,
            };
            
            try {
                const selectedPorts = [...(targetPortMap.get(host) || new Set<number>())];
                const scanPorts = (selectedPorts.length > 0 ? selectedPorts : defaultPorts)
                    .sort((left, right) => left - right);
                const openPorts = await scanHost(host, scanPorts, timeout, concurrency, detectService);
                
                result.success = true;
                successfulScans++;
                totalOpenPorts += openPorts.length;
                
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
                    
                    // Check for service changes on existing ports
                    const serviceChanges: Array<{ port: number; oldService?: string; newService?: string }> = [];
                    for (const newPort of openPorts) {
                        const prevPort = prevSnapshot.openPorts.find(p => p.port === newPort.port);
                        if (prevPort && prevPort.service !== newPort.service) {
                            serviceChanges.push({
                                port: newPort.port,
                                oldService: prevPort.service,
                                newService: newPort.service,
                            });
                        }
                    }
                    result.serviceChanges = serviceChanges;
                    
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
                            description: `${newPorts.length} new port(s) detected: ${newPorts.map(p => `${p.port}/${p.service || 'unknown'}`).join(", ")}`,
                            newValue: JSON.stringify(newPorts.map(p => p.port)),
                            detectionMethod: "port_monitor",
                            tags: ["port", "open", "change", ...(highRiskNew.length > 0 ? ["high-risk"] : [])],
                            autoTriggerEnabled: severity === "high",
                            riskScore: 0,
                            metadata: {
                                newPorts,
                                highRiskPorts: highRiskNew.map(p => p.port),
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
                            description: `${closedPorts.length} port(s) no longer accessible: ${closedPorts.map(p => `${p.port}/${p.service || 'unknown'}`).join(", ")}`,
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
                    
                    // Generate change events for service changes
                    if (serviceChanges.length > 0) {
                        serviceChangesCount += serviceChanges.length;
                        
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: host,
                            eventType: "service_change",
                            severity: "medium",
                            title: `Service Changes Detected: ${host}`,
                            description: `${serviceChanges.length} service(s) changed: ${serviceChanges.map(s => `${s.port}: ${s.oldService || 'unknown'} → ${s.newService || 'unknown'}`).join(", ")}`,
                            detectionMethod: "port_monitor",
                            tags: ["port", "service", "change"],
                            autoTriggerEnabled: true,
                            riskScore: 0,
                            metadata: {
                                serviceChanges,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, serviceChanges.map(s => s.port));
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
                            description: `Initial scan found ${openPorts.length} open port(s): ${openPorts.map(p => `${p.port}/${p.service || 'unknown'}`).join(", ")}`,
                            newValue: JSON.stringify(openPorts.map(p => p.port)),
                            detectionMethod: "port_monitor",
                            tags: ["port", "discovery", "initial-scan"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                openPorts,
                                highRiskPorts: highRiskPorts.map(p => p.port),
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
            return null;
        }), targetConcurrency);
        
        return {
            success: true,
            data: {
                results,
                changeEvents,
                snapshots: newSnapshots,
                summary: {
                    totalTargets: validTargets.length,
                    successfulScans,
                    failedScans,
                    totalOpenPorts,
                    newPortsOpened,
                    portsClosed,
                    serviceChanges: serviceChangesCount,
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
                        (result.snapshot?.openPorts || []).map(portInfo => ({
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
                        (result.snapshot?.openPorts || []).map(portInfo => ({
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
        
    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
