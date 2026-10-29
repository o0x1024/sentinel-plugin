/**
 * SSL/TLS Certificate Monitor
 *
 * @plugin cert_monitor
 * @name Certificate Monitor
 * @version 1.2.8
 * @author Sentinel Team
 * @main_category bounty
 * @monitor_type cert
 * @input_mode asset
 * @target_asset_types ["domain","web"]
 * @category monitor
 * @target_sources ["surface_asset","bounty_asset","scope"]
 * @seed_bindings []
 * @default_severity medium
 * @tags certificate, ssl, tls, monitor, change-detection, expiry, capability:tls-inspect, capability:monitor-events, monitor:results-stream-v2
 * @description Monitor SSL/TLS certificates for changes and expiry, generating ChangeEvents for workflow automation
 */
import { createMonitorResultStream } from "../../shared/monitor_results.ts";
import { createMonitorTargetWriter } from "../../shared/monitor_target_writer.ts";

interface ToolInput {
    targets: string[];  // List of domains/URLs to monitor
    target_objects?: Array<{type?: string;value?: string;port?: number;protocol?: string;service_name?: string;transport_protocol?: string;encrypted_transport?: boolean}>;
    checkExpiry?: boolean;
    expiryWarningDays?: number;  // Warn if expiring within N days
    concurrency?: number;
    previousSnapshots?: Record<string, CertSnapshot>;  // Previous state for comparison
    __monitorExecution?: MonitorExecutionContext;
}

interface CertInfo {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    fingerprint: string;
    serialNumber: string;
    altNames: string[];
    protocol?: string;
    cipher?: string;
}

interface NativeTlsCertificate {
    subject: string; issuer: string; serialNumber: string; validFrom: string; validTo: string;
    fingerprintSha256: string; subjectAltNames: string[]; tlsVersion?: string; cipherSuite?: string;
}
interface TlsProbeResponse { success: boolean; cert?: NativeTlsCertificate; error?: string; }

const CERT_MONITOR_TLS_TIMEOUT_MS = 3000;
const DEFAULT_CONCURRENCY = 32;
const MAX_CONCURRENCY = 32;

interface CertSnapshot {
    domain: string;
    fingerprint: string;
    validTo: string;
    issuer: string;
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

interface CertResult {
    domain: string;
    success: boolean;
    certInfo?: CertInfo;
    snapshot?: CertSnapshot;
    daysUntilExpiry?: number;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: CertResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, CertSnapshot>;
        summary: {
            totalTargets: number;
            successfulChecks: number;
            failedChecks: number;
            certificateChanges: number;
            expiringCertificates: number;
            expiredCertificates: number;
        };
        surface_artifacts?: Record<string, any[]>;
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

interface MonitorProgressUpdate {
    current?: number;
    total?: number;
    message?: string;
    currentTarget?: string;
    phase?: string;
    phaseLabel?: string;
    indeterminate?: boolean;
}

async function reportMonitorProgress(
    monitorExecution: MonitorExecutionContext | undefined,
    update: MonitorProgressUpdate,
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

function formatTargetLabel(domain: string, index: number, total: number): string {
    if (total <= 0) return domain;
    return `${domain} (${index}/${total})`;
}

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;

// Generate UUID
function generateId(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Calculate risk score
function calculateRiskScore(severity: string, eventType: string): number {
    let score = 0;

    // Base score from severity
    switch (severity) {
        case "critical": score += 40; break;
        case "high": score += 30; break;
        case "medium": score += 20; break;
        case "low": score += 10; break;
    }

    // Event type importance
    switch (eventType) {
        case "certificate_expired": score += 30; break;
        case "certificate_expiring": score += 20; break;
        case "certificate_change": score += 15; break;
        case "issuer_change": score += 25; break;
    }

    return Math.min(score, 100);
}

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        required: ["targets"],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "List of domains or URLs to monitor certificates"
            },
            target_objects: { type: "array", description: "Host-owned typed target descriptors", items: { type: "object" } },
            checkExpiry: {
                type: "boolean",
                description: "Check certificate expiry dates",
                default: true
            },
            expiryWarningDays: {
                type: "integer",
                description: "Days before expiry to generate warning",
                default: 30,
                minimum: 1,
                maximum: 365
            },
            concurrency: {
                type: "integer",
                description: "Number of concurrent TLS certificate checks",
                default: DEFAULT_CONCURRENCY,
                minimum: 1,
                maximum: MAX_CONCURRENCY
            },
            previousSnapshots: {
                type: "object",
                description: "Previous certificate snapshots for comparison",
                additionalProperties: {
                    type: "object",
                    properties: {
                        domain: { type: "string" },
                        fingerprint: { type: "string" },
                        validTo: { type: "string" },
                        issuer: { type: "string" },
                        lastChecked: { type: "string" }
                    }
                }
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
                                domain: { type: "string" },
                                success: { type: "boolean" },
                                certInfo: { type: "object" },
                                daysUntilExpiry: { type: "integer" }
                            }
                        },
                        description: "Certificate check results"
                    },
                    changeEvents: { type: "array", description: "Change events detected" },
                    snapshots: { type: "object", description: "Certificate snapshots by domain" },
                    summary: {
                        type: "object",
                        properties: {
                            totalTargets: { type: "integer" },
                            certificateChanges: { type: "integer" },
                            expiringCertificates: { type: "integer" },
                            expiredCertificates: { type: "integer" }
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
 * Parse domain from URL
 */
function tlsTarget(target: string): { hostname: string; port: number; key: string } {
    const value = target.includes("://") ? target : `https://${target}`;
    const parsed = new URL(value);
    if (!parsed.hostname || !["https:", "http:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) throw new Error("Invalid TLS inspection target");
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const port = parsed.port ? Number(parsed.port) : 443;
    if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error("Invalid TLS inspection port");
    const hostKey = hostname.includes(":") ? `[${hostname}]` : hostname;
    return { hostname, port, key: port === 443 ? hostname : `${hostKey}:${port}` };
}
function certificateKey(fingerprint: string): string {
    const sha256 = fingerprint.replaceAll(":", "").toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error("Native TLS certificate SHA-256 fingerprint is invalid");
    return sha256;
}
function certificateDomain(value: string): boolean {
    return value.length <= 253 && !/^\d+(?:\.\d+){3}$/.test(value) && value.split(".").every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

async function getCertificateInfo(target: string): Promise<CertInfo> {
    const { hostname, port } = tlsTarget(target);
    const tlsApi = (globalThis as any)?.Sentinel?.TLS;
    if (typeof tlsApi?.getCertificate !== "function") throw new Error("Native TLS inspection API is unavailable");
    const response: TlsProbeResponse = await tlsApi.getCertificate(hostname, { port, timeoutMs: CERT_MONITOR_TLS_TIMEOUT_MS });
    if (!response?.success || !response.cert) throw new Error("Native TLS certificate inspection failed");
    const cert = response.cert;
    for (const field of ["subject", "issuer", "validFrom", "validTo", "fingerprintSha256", "serialNumber"] as const) {
        if (typeof cert[field] !== "string" || !cert[field].trim()) throw new Error(`Native TLS certificate is missing ${field}`);
    }
    if (!Number.isFinite(Date.parse(cert.validFrom)) || !Number.isFinite(Date.parse(cert.validTo))) throw new Error("Native TLS certificate validity dates are invalid");
    if (!Array.isArray(cert.subjectAltNames) || cert.subjectAltNames.some(name => typeof name !== "string" || !name)) throw new Error("Native TLS certificate SAN list is invalid");
    return { subject: cert.subject, issuer: cert.issuer, serialNumber: cert.serialNumber, validFrom: cert.validFrom, validTo: cert.validTo,
        fingerprint: cert.fingerprintSha256, altNames: cert.subjectAltNames,
        ...(cert.tlsVersion ? { protocol: cert.tlsVersion } : {}), ...(cert.cipherSuite ? { cipher: cert.cipherSuite } : {}) };
}

async function runWithConcurrency<T>(
    tasks: (() => Promise<T>)[],
    concurrency: number,
): Promise<T[]> {
    if (tasks.length === 0) {
        return [];
    }

    const workerCount = Math.max(1, Math.min(concurrency, tasks.length));
    const results = new Array<T>(tasks.length);
    let nextIndex = 0;

    await Promise.all(Array.from({ length: workerCount }, async () => {
        while (true) {
            const currentIndex = nextIndex++;
            if (currentIndex >= tasks.length) {
                return;
            }
            results[currentIndex] = await tasks[currentIndex]();
        }
    }));

    return results;
}

/**
 * Main analysis function
 */
function projectCertificateOutput(results: CertResult[], changeEvents: ChangeEvent[], newSnapshots: Record<string, CertSnapshot>, summary: Record<string, number>): ToolOutput {
        const certificates = results
            .filter((result) => result.success && result.certInfo)
            .map((result) => {
                const certInfo = result.certInfo!;
                return {
                    domain: result.domain,
                    hostname: result.domain,
                    subject: certInfo.subject,
                    issuer: certInfo.issuer,
                    fingerprint: certInfo.fingerprint,
                    valid_from: certInfo.validFrom,
                    valid_to: certInfo.validTo,
                    san: certInfo.altNames,
                    tls_version: certInfo.protocol,
                    is_valid: new Date(certInfo.validTo).getTime() > Date.now(),
                };
            });

        const discoveredSubdomains = new Set<string>(
            certificates.flatMap((cert) => [cert.domain, ...cert.san]).filter(certificateDomain),
        );


        return {
            success: true,
            data: {
                results,
                changeEvents,
                snapshots: newSnapshots,
                summary,
                surface_artifacts: {
                    certificates: certificates.map(cert => ({
                        sha256: certificateKey(cert.fingerprint),
                        issuer: cert.issuer,
                        subject: cert.subject,
                        san_list: cert.san,
                        valid_from: cert.valid_from,
                        valid_to: cert.valid_to,
                        protocol: cert.tls_version,
                        hostname: cert.hostname,
                        self_signed_flag: cert.issuer === cert.subject,
                        related_domains: Array.from(new Set([cert.domain, ...cert.san])).filter(certificateDomain),
                        risk_status: !cert.is_valid ? "expired" : "valid",
                        source: "cert_monitor",
                        confidence: 0.98,
                    })),
                    domains: [...discoveredSubdomains].sort().map(domain => ({
                        fqdn: domain,
                        root_domain: domain.split(".").slice(-2).join("."),
                        source: "cert_monitor",
                        confidence: 0.7,
                    })),
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
                        source: "cert_monitor",
                        metadata: event.metadata,
                    })),
                    evidences: certificates.map(cert => ({
                        asset_type: "certificate",
                        asset_key: certificateKey(cert.fingerprint),
                        evidence_type: "certificate_snapshot",
                        title: `Certificate Snapshot: ${cert.hostname}`,
                        content_text: `${cert.subject} | ${cert.issuer} | ${cert.valid_to}`,
                        content_json: {
                            hostname: cert.hostname,
                            domain: cert.domain,
                            subject: cert.subject,
                            issuer: cert.issuer,
                            fingerprint: cert.fingerprint,
                            valid_from: cert.valid_from,
                            valid_to: cert.valid_to,
                            san: cert.san,
                            tls_version: cert.tls_version,
                        },
                        source: "cert_monitor",
                    })),
                    relations: certificates.flatMap(cert =>
                        Array.from(new Set([cert.domain, ...cert.san])).filter(certificateDomain).map(domain => ({
                            from_type: "domain",
                            from_key: domain,
                            to_type: "certificate",
                            to_key: certificateKey(cert.fingerprint),
                            relation_type: "covered_by_certificate",
                            source: "cert_monitor",
                            confidence: 0.9,
                        })),
                    ),
                },
            },
        };

}

function certificateTargetSupported(target: string, input: ToolInput): boolean {
    const typed = input.target_objects?.find(item => item.value === target && item.type === "service");
    if (!typed) return true;
    if ((typed.transport_protocol || typed.protocol || '').toLowerCase() === 'udp') return false;
    return typed.encrypted_transport === true
        || /(?:https|ssl|tls|wss)/i.test(`${typed.protocol || ""} ${typed.service_name || ""}`)
        || [443,8443,9443].includes(Number(typed.port));
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const stream = createMonitorResultStream(input);
        const writeTarget = createMonitorTargetWriter(input, stream, target => certificateTargetSupported(target, input) ? tlsTarget(target).key : null);
        if (!input.targets || !Array.isArray(input.targets)) {
            return {
                success: false,
                error: "Invalid input: targets array is required"
            };
        }

        // Filter out empty strings
        const validTargets = input.targets.filter(t => typeof t === 'string' && t.trim().length > 0);
        if (validTargets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets array must contain at least one non-empty string"
            };
        }

        const checkExpiry = input.checkExpiry !== false;
        const expiryWarningDays = input.expiryWarningDays || 30;
        const previousSnapshots = input.previousSnapshots || {};
        const monitorExecution = input.__monitorExecution;

        const candidates: string[] = [];
        for (const target of validTargets) {
            const tlsApplicable = certificateTargetSupported(target, input);
            if (tlsApplicable) candidates.push(target);
            else await stream.record(target,"not-tls-service",{success:true,data:{results:[]}},{status:"skipped",complete:true});
        }
        const normalizedDomains = Array.from(
            new Set(
                candidates
                    .map((target) => tlsTarget(target).key)
                    .filter((domain) => domain.length > 0),
            ),
        );
        const totalProgressUnits = normalizedDomains.length;
        let completedProgressUnits = 0;

        const advanceProgress = async (update: MonitorProgressUpdate, current = completedProgressUnits) => {
            completedProgressUnits = Math.min(
                totalProgressUnits,
                Math.max(0, current),
            );
            await reportMonitorProgress(monitorExecution, {
                total: totalProgressUnits,
                current: completedProgressUnits,
                ...update,
            });
        };

        await advanceProgress({
            phase: "prepare",
            message: "Preparing certificate checks",
            phaseLabel: "Preparing certificate checks",
            indeterminate: true,
        });

        const results: CertResult[] = [];
        const changeEvents: ChangeEvent[] = [];
        const newSnapshots: Record<string, CertSnapshot> = {};

        let successfulChecks = 0;
        let failedChecks = 0;
        let certificateChanges = 0;
        let expiringCertificates = 0;
        let expiredCertificates = 0;
        let completedDomains = 0;

        async function processDomain(endpoint: string, domainIndex: number): Promise<void> {
            const domain = tlsTarget(endpoint).hostname;
            stream.assertHealthy();
            const targetChangeEvents: ChangeEvent[] = [];
            const result: CertResult = {
                domain,
                success: false,
            };
            const targetLabel = formatTargetLabel(
                domain,
                domainIndex + 1,
                normalizedDomains.length,
            );

            try {
                await advanceProgress({
                    currentTarget: targetLabel,
                    phase: "probe",
                    phaseLabel: "Connecting",
                    message: `Connecting to ${domain}`,
                });

                const certInfo = await getCertificateInfo(endpoint);

                await advanceProgress({
                    currentTarget: targetLabel,
                    phase: "probe",
                    phaseLabel: "Reading certificate",
                    message: certInfo
                        ? `Retrieved certificate for ${domain}`
                        : `Unable to retrieve certificate for ${domain}`,
                });

                if (certInfo) {
                    result.success = true;
                    result.certInfo = certInfo;
                    successfulChecks++;

                    // Create snapshot
                    const snapshot: CertSnapshot = {
                        domain,
                        fingerprint: certInfo.fingerprint,
                        validTo: certInfo.validTo,
                        issuer: certInfo.issuer,
                        lastChecked: new Date().toISOString(),
                    };
                    result.snapshot = snapshot;
                    if (!stream.enabled) newSnapshots[endpoint] = snapshot;

                    // Check for changes against previous snapshot
                    const prevSnapshot = previousSnapshots[endpoint];
                    if (prevSnapshot) {
                        // Certificate fingerprint changed
                        if (prevSnapshot.fingerprint !== certInfo.fingerprint) {
                            certificateChanges++;

                            const event: ChangeEvent = {
                                id: generateId(),
                                assetId: domain,
                                eventType: "certificate_change",
                                severity: "medium",
                                title: `SSL Certificate Changed: ${domain}`,
                                description: `The SSL/TLS certificate for ${domain} has been replaced with a new certificate.`,
                                oldValue: prevSnapshot.fingerprint,
                                newValue: certInfo.fingerprint,
                                detectionMethod: "cert_monitor",
                                tags: ["certificate", "ssl", "tls", "change"],
                                autoTriggerEnabled: true,
                                riskScore: 0,
                                metadata: {
                                    previousIssuer: prevSnapshot.issuer,
                                    newIssuer: certInfo.issuer,
                                    previousValidTo: prevSnapshot.validTo,
                                    newValidTo: certInfo.validTo,
                                },
                            };
                            event.riskScore = calculateRiskScore(event.severity, event.eventType);
                            targetChangeEvents.push(event);
                        }

                        // Issuer changed (potentially suspicious)
                        if (prevSnapshot.issuer !== certInfo.issuer && prevSnapshot.issuer !== "Unknown") {
                            const event: ChangeEvent = {
                                id: generateId(),
                                assetId: domain,
                                eventType: "issuer_change",
                                severity: "high",
                                title: `Certificate Issuer Changed: ${domain}`,
                                description: `The certificate issuer for ${domain} has changed, which could indicate a certificate replacement or potential security issue.`,
                                oldValue: prevSnapshot.issuer,
                                newValue: certInfo.issuer,
                                detectionMethod: "cert_monitor",
                                tags: ["certificate", "issuer", "change", "security"],
                                autoTriggerEnabled: true,
                                riskScore: 0,
                                metadata: {
                                    domain,
                                    fingerprint: certInfo.fingerprint,
                                },
                            };
                            event.riskScore = calculateRiskScore(event.severity, event.eventType);
                            targetChangeEvents.push(event);
                        }
                    }

                    // Check certificate expiry
                    if (checkExpiry) {
                        const validTo = new Date(certInfo.validTo);
                        const now = new Date();
                        const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
                        result.daysUntilExpiry = daysUntilExpiry;

                        if (daysUntilExpiry <= 0) {
                            expiredCertificates++;

                            const event: ChangeEvent = {
                                id: generateId(),
                                assetId: domain,
                                eventType: "certificate_expired",
                                severity: "critical",
                                title: `Certificate Expired: ${domain}`,
                                description: `The SSL/TLS certificate for ${domain} has expired ${Math.abs(daysUntilExpiry)} days ago.`,
                                newValue: certInfo.validTo,
                                detectionMethod: "cert_monitor",
                                tags: ["certificate", "expired", "critical", "security"],
                                autoTriggerEnabled: true,
                                riskScore: 0,
                                metadata: {
                                    daysExpired: Math.abs(daysUntilExpiry),
                                    fingerprint: certInfo.fingerprint,
                                    issuer: certInfo.issuer,
                                },
                            };
                            event.riskScore = calculateRiskScore(event.severity, event.eventType);
                            targetChangeEvents.push(event);
                        } else if (daysUntilExpiry <= expiryWarningDays) {
                            expiringCertificates++;

                            const severity = daysUntilExpiry <= 7 ? "high" : "medium";
                            const event: ChangeEvent = {
                                id: generateId(),
                                assetId: domain,
                                eventType: "certificate_expiring",
                                severity: severity,
                                title: `Certificate Expiring Soon: ${domain}`,
                                description: `The SSL/TLS certificate for ${domain} will expire in ${daysUntilExpiry} days.`,
                                newValue: certInfo.validTo,
                                detectionMethod: "cert_monitor",
                                tags: ["certificate", "expiring", "warning"],
                                autoTriggerEnabled: daysUntilExpiry <= 7,
                                riskScore: 0,
                                metadata: {
                                    daysUntilExpiry,
                                    fingerprint: certInfo.fingerprint,
                                    issuer: certInfo.issuer,
                                },
                            };
                            event.riskScore = calculateRiskScore(event.severity, event.eventType);
                            targetChangeEvents.push(event);
                        }
                    }
                } else {
                    result.error = "Failed to retrieve certificate";
                    failedChecks++;
                }
            } catch (error: any) {
                result.error = error.message || String(error);
                failedChecks++;
            }

            if (!stream.enabled) { results.push(result); changeEvents.push(...targetChangeEvents); }
            await writeTarget(endpoint, "tls-certificate", projectCertificateOutput([result], targetChangeEvents,
                result.snapshot ? { [endpoint]: result.snapshot } : {}, {}) as any, { snapshot_complete: result.success, status: result.success ? "ok" : "failed", error: result.error });
            completedDomains += 1
            await advanceProgress({
                currentTarget: targetLabel,
                phase: "probe",
                phaseLabel: result.success ? "Completed" : "Failed",
                message: result.success
                    ? `Finished certificate check for ${domain}`
                    : `Certificate check failed for ${domain}`,
            }, completedDomains);
        }

        const concurrency = Math.max(
            1,
            Math.min(input.concurrency || DEFAULT_CONCURRENCY, MAX_CONCURRENCY, normalizedDomains.length),
        );
        await runWithConcurrency(
            normalizedDomains.map((domain, targetIndex) => () => processDomain(domain, targetIndex)),
            concurrency,
        );

        await advanceProgress({
            phase: "compare",
            message: "Comparing certificate snapshots",
            phaseLabel: "Comparing snapshots",
        });

        if (stream.enabled) return await stream.finish<ToolOutput>({ success: true });
        return await stream.finish(projectCertificateOutput(results, changeEvents, newSnapshots, {
            totalTargets: normalizedDomains.length, successfulChecks, failedChecks, certificateChanges, expiringCertificates, expiredCertificates,
        }));

    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
