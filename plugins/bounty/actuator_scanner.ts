/**
 * Actuator Path Scanner
 *
 * @plugin actuator_scanner
 * @name Actuator Path Scanner
 * @version 1.0.0
 * @author Sentinel Team
 * @main_category bounty
 * @category risk
 * @monitor_type risk
 * @target_asset_types web, api
 * @default_severity high
 * @tags actuator, spring, exposure, misconfiguration, java, web
 * @description Scan for exposed Spring Boot Actuator endpoints by backtracking through API path segments. Detects sensitive actuator endpoints like /env, /heapdump, /mappings that may leak configuration, secrets, or enable remote code execution.
 */

declare const Sentinel: {
    Monitor?: {
        reportProgress?(update: Record<string, unknown>): Promise<boolean>;
    };
};

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
    targets?: string[];
    api_paths?: string[];
    actuator_endpoints?: string[];
    include_actuator_prefix?: boolean;
    userAgent?: string;
    concurrency?: number;
    timeout?: number;
    __monitorExecution?: MonitorExecutionContext;
}

interface Finding {
    title: string;
    severity: string;
    url: string;
    endpoint: string;
    description: string;
    evidence?: string;
    cwe?: string;
    remediation?: string;
    tags?: string[];
}

interface ToolOutput {
    success: boolean;
    data?: {
        findings: Finding[];
        summary: {
            totalApiPaths: number;
            generatedProbeUrls: number;
            deduplicatedProbeUrls: number;
            confirmedExposures: number;
            requestsMade: number;
            errors: number;
        };
        surface_artifacts?: { findings: any[] };
    };
    error?: string;
}

interface ActuatorEndpointDef {
    name: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    keys: string[];
    description: string;
}

interface Soft404Baseline {
    status: number;
    bodyText: string;
    contentLength: number;
    title: string;
}

const ACTUATOR_ENDPOINTS: ActuatorEndpointDef[] = [
    { name: "env", severity: "critical", keys: ["propertySources", "activeProfiles", "systemProperties", "systemEnvironment"], description: "Environment properties exposure - may contain secrets, database credentials, API keys" },
    { name: "info", severity: "low", keys: ["app", "build", "git"], description: "Application info - may reveal version and build details" },
    // { name: "heapdump", severity: "critical", keys: [], description: "JVM heap dump - contains in-memory secrets, session tokens, and sensitive data" },
    // { name: "shutdown", severity: "critical", keys: ["message"], description: "Remote shutdown endpoint - allows denial of service" },
    // { name: "restart", severity: "critical", keys: ["message"], description: "Remote restart endpoint - allows denial of service" },
    // { name: "jolokia", severity: "critical", keys: ["request", "value", "agent", "config"], description: "JMX over HTTP - may allow remote code execution" },
    // { name: "mappings", severity: "high", keys: ["contexts", "dispatcherServlets", "servletFilters", "handler"], description: "URL mapping exposure - reveals all API endpoints and internal routes" },
    // { name: "beans", severity: "high", keys: ["contexts", "beans", "scope", "dependencies"], description: "Spring beans exposure - reveals application architecture and dependencies" },
    // { name: "configprops", severity: "high", keys: ["contexts", "beans", "prefix", "properties"], description: "Configuration properties - may expose sensitive configuration values" },
    // { name: "conditions", severity: "high", keys: ["contexts", "positiveMatches", "negativeMatches", "unconditionalClasses"], description: "Auto-configuration conditions report" },
    // { name: "loggers", severity: "high", keys: ["levels", "loggers", "effectiveLevel", "configuredLevel"], description: "Logger configuration - can be modified to enable debug logging" },
    // { name: "threaddump", severity: "high", keys: ["threads", "threadName", "threadState", "stackTrace"], description: "Thread dump - reveals internal execution state and stack traces" },
    // { name: "metrics", severity: "medium", keys: ["names", "measurements", "availableTags"], description: "Application metrics exposure" },
    // { name: "httptrace", severity: "high", keys: ["traces", "timestamp", "principal", "request", "response"], description: "HTTP trace - may contain authentication tokens and session data" },
    // { name: "trace", severity: "high", keys: ["traces", "timestamp", "info"], description: "Legacy trace endpoint (Spring Boot 1.x)" },
    // { name: "auditevents", severity: "medium", keys: ["events", "timestamp", "principal", "type"], description: "Audit events - reveals authentication attempts and user activity" },
    // { name: "scheduledtasks", severity: "medium", keys: ["cron", "fixedDelay", "fixedRate"], description: "Scheduled tasks exposure - reveals internal job scheduling" },
    // { name: "flyway", severity: "medium", keys: ["contexts", "flywayBeans", "migrations"], description: "Flyway migration info - reveals database schema history" },
    // { name: "liquibase", severity: "medium", keys: ["contexts", "liquibaseBeans", "changeSets"], description: "Liquibase migration info - reveals database schema history" },
    // { name: "health", severity: "medium", keys: ["status", "components", "details", "diskSpace"], description: "Health check with component details" },
    // { name: "gateway/routes", severity: "high", keys: ["route_id", "predicates", "filters", "uri"], description: "Spring Cloud Gateway routes - reveals internal routing and backend services" },
    // { name: "caches", severity: "medium", keys: ["cacheManagers", "caches"], description: "Cache manager exposure" },
    // { name: "sessions", severity: "high", keys: ["sessions", "sessionId", "principalName"], description: "Active sessions - may allow session hijacking" },
];

const pluginGlobals = globalThis as typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

export function get_input_schema() {
    return {
        type: "object",
        required: [],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "Base URLs to scan (e.g. [\"http://example.com\"]). Used for root-level actuator probing.",
            },
            api_paths: {
                type: "array",
                items: { type: "string" },
                description: "Full API paths to backtrack from (e.g. [\"http://example.com/api/v1/users\"]). The scanner will probe actuator endpoints at each path level.",
            },
            actuator_endpoints: {
                type: "array",
                items: { type: "string" },
                description: "Custom actuator endpoint names to probe (overrides built-in list). Example: [\"env\", \"health\", \"heapdump\"]",
            },
            include_actuator_prefix: {
                type: "boolean",
                description: "Also probe /actuator/* prefix variants (Spring Boot 2.x+). Default: true",
                default: true,
            },
            userAgent: {
                type: "string",
                description: "User-Agent header for requests",
                default: "Sentinel-Actuator-Scanner/1.0",
            },
            concurrency: {
                type: "integer",
                description: "Maximum concurrent requests",
                default: 16,
                minimum: 1,
                maximum: 64,
            },
            timeout: {
                type: "integer",
                description: "Per-request timeout in milliseconds",
                default: 5000,
                minimum: 1000,
                maximum: 30000,
            },
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
                    findings: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                title: { type: "string" },
                                severity: { type: "string" },
                                url: { type: "string" },
                                endpoint: { type: "string" },
                                description: { type: "string" },
                                evidence: { type: "string" },
                                cwe: { type: "string" },
                                remediation: { type: "string" },
                                tags: { type: "array", items: { type: "string" } },
                            },
                        },
                    },
                    summary: {
                        type: "object",
                        properties: {
                            totalApiPaths: { type: "integer" },
                            generatedProbeUrls: { type: "integer" },
                            deduplicatedProbeUrls: { type: "integer" },
                            confirmedExposures: { type: "integer" },
                            requestsMade: { type: "integer" },
                            errors: { type: "integer" },
                        },
                    },
                    surface_artifacts: { type: "object" },
                },
            },
            error: { type: "string" },
        },
    };
}

pluginGlobals.get_input_schema = get_input_schema;
pluginGlobals.get_output_schema = get_output_schema;

async function runWithConcurrency<T>(tasks: Array<() => Promise<T>>, concurrency: number): Promise<T[]> {
    const results = new Array<T>(tasks.length);
    let nextIndex = 0;
    const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, async () => {
        while (nextIndex < tasks.length) {
            const currentIndex = nextIndex++;
            results[currentIndex] = await tasks[currentIndex]();
        }
    });
    await Promise.all(workers);
    return results;
}

function normalizeUrl(raw?: string): string | null {
    if (!raw || typeof raw !== "string") return null;
    let trimmed = raw.trim().replace(/\/+$/, "");
    if (!trimmed) return null;
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
        trimmed = "https://" + trimmed;
    }
    return trimmed;
}

function extractOrigin(url: string): string {
    try {
        const parsed = new URL(url);
        return `${parsed.protocol}//${parsed.host}`;
    } catch {
        const match = url.match(/^(https?:\/\/[^/]+)/);
        return match ? match[1] : url;
    }
}

function getPathSegments(url: string): string[] {
    try {
        const parsed = new URL(url);
        return parsed.pathname.split("/").filter(Boolean);
    } catch {
        const withoutOrigin = url.replace(/^https?:\/\/[^/]+/, "");
        return withoutOrigin.split("/").filter(Boolean);
    }
}

function generateBacktrackPaths(apiPath: string, endpointNames: string[], includeActuatorPrefix: boolean): string[] {
    const origin = extractOrigin(apiPath);
    const segments = getPathSegments(apiPath);
    const probeUrls: string[] = [];

    for (let depth = segments.length; depth >= 0; depth--) {
        const basePath = depth === 0 ? "" : "/" + segments.slice(0, depth).join("/");
        for (const endpoint of endpointNames) {
            probeUrls.push(`${origin}${basePath}/${endpoint}`);
            if (includeActuatorPrefix && endpoint !== "actuator") {
                probeUrls.push(`${origin}${basePath}/actuator/${endpoint}`);
            }
        }
    }

    return probeUrls;
}

function getEndpointDef(url: string): ActuatorEndpointDef | null {
    const path = url.replace(/^https?:\/\/[^/]+/, "");
    const lastSegment = path.split("/").filter(Boolean).pop() || "";
    const secondLast = path.split("/").filter(Boolean).slice(-2).join("/");

    for (const def of ACTUATOR_ENDPOINTS) {
        if (lastSegment === def.name || secondLast === def.name) {
            return def;
        }
    }
    return null;
}

function randomProbePath(): string {
    const seed = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
    return `sentinel-actuator-baseline-${seed}`;
}

async function buildSoft404Baseline(origin: string, userAgent: string): Promise<Soft404Baseline | null> {
    const baselineUrl = `${origin}/${randomProbePath()}`;
    try {
        const response = await fetch(baselineUrl, {
            method: "GET",
            headers: { "User-Agent": userAgent, "Accept": "application/json, text/html, */*" },
            redirect: "follow",
        });
        const body = await response.text();
        return {
            status: response.status,
            bodyText: body.slice(0, 4000).toLowerCase().replace(/\s+/g, " ").trim(),
            contentLength: body.length,
            title: extractTitle(body),
        };
    } catch {
        return null;
    }
}

function extractTitle(html: string): string {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match?.[1]?.trim() || "";
}

function tokenize(text: string): string[] {
    return text.toLowerCase().replace(/\s+/g, " ").trim().match(/[a-z0-9_/-]{3,}/g) || [];
}

function jaccardSimilarity(a: string[], b: string[]): number {
    if (a.length === 0 || b.length === 0) return 0;
    const setA = new Set(a);
    const setB = new Set(b);
    let intersection = 0;
    for (const token of setA) {
        if (setB.has(token)) intersection++;
    }
    const union = new Set([...setA, ...setB]).size;
    return union === 0 ? 0 : intersection / union;
}

function isSoft404(body: string, status: number, baseline: Soft404Baseline | null): boolean {
    if (status === 404 || status === 403 || status === 401) return false;

    if (baseline && baseline.status === 200 && status === 200) {
        const normalizedBody = body.slice(0, 4000).toLowerCase().replace(/\s+/g, " ").trim();
        if (normalizedBody === baseline.bodyText) return true;
        const similarity = jaccardSimilarity(tokenize(normalizedBody), tokenize(baseline.bodyText));
        if (similarity >= 0.85) return true;
    }

    const lowerBody = body.toLowerCase();
    const soft404Markers = ["404", "not found", "page not found", "does not exist", "cannot be found", "no such", "找不到", "不存在"];
    if (status === 200 && soft404Markers.some(m => lowerBody.includes(m))) {
        return true;
    }

    return false;
}

function isHeapdumpResponse(body: string, contentType: string): boolean {
    if (contentType.includes("application/octet-stream") || contentType.includes("application/x-heap-dump")) {
        return body.length > 1000;
    }
    return false;
}

function validateActuatorResponse(
    body: string,
    status: number,
    contentType: string,
    endpointDef: ActuatorEndpointDef,
): boolean {
    if (status !== 200) return false;

    if (endpointDef.name === "heapdump") {
        return isHeapdumpResponse(body, contentType);
    }

    if (!contentType.includes("json") && !contentType.includes("vnd.spring-boot.actuator")) {
        return false;
    }

    if (endpointDef.keys.length === 0) return true;

    let parsed: any;
    try {
        parsed = JSON.parse(body);
    } catch {
        return false;
    }

    if (typeof parsed !== "object" || parsed === null) return false;

    if (endpointDef.name === "health" && typeof parsed.status === "string") {
        const validStatuses = ["UP", "DOWN", "OUT_OF_SERVICE", "UNKNOWN"];
        if (validStatuses.includes(parsed.status.toUpperCase())) return true;
    }

    if (endpointDef.name === "env") {
        if (parsed.propertySources || parsed.activeProfiles || parsed.systemProperties || parsed.systemEnvironment) {
            return true;
        }
    }

    if (endpointDef.name === "actuator" || parsed._links) {
        return true;
    }

    const bodyStr = JSON.stringify(parsed);
    const matchedKeys = endpointDef.keys.filter(key => bodyStr.includes(`"${key}"`));
    return matchedKeys.length >= Math.min(2, endpointDef.keys.length);
}

interface ProbeResult {
    url: string;
    endpoint: string;
    confirmed: boolean;
    status?: number;
    evidence?: string;
    error?: string;
}

async function probeActuatorUrl(
    url: string,
    endpointDef: ActuatorEndpointDef,
    userAgent: string,
    baseline: Soft404Baseline | null,
): Promise<ProbeResult> {
    try {
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "User-Agent": userAgent,
                "Accept": "application/json, application/vnd.spring-boot.actuator.v3+json, */*",
            },
            redirect: "follow",
        });

        const status = response.status;

        if (status === 404 || status === 403 || status === 401 || status === 405 || status >= 500) {
            return { url, endpoint: endpointDef.name, confirmed: false, status };
        }

        const body = await response.text();
        const contentType = (response.headers?.get?.("content-type") || "").toLowerCase();

        if (isSoft404(body, status, baseline)) {
            return { url, endpoint: endpointDef.name, confirmed: false, status };
        }

        const confirmed = validateActuatorResponse(body, status, contentType, endpointDef);
        return {
            url,
            endpoint: endpointDef.name,
            confirmed,
            status,
            evidence: confirmed ? body.slice(0, 500) : undefined,
        };
    } catch (error: any) {
        return {
            url,
            endpoint: endpointDef.name,
            confirmed: false,
            error: error?.message || String(error),
        };
    }
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!input || typeof input !== "object") {
            return { success: false, error: "Invalid input: expected an object payload" };
        }

        const userAgent = input.userAgent || "Sentinel-Actuator-Scanner/1.0";
        const concurrency = Math.max(1, Math.min(64, Number(input.concurrency) || 16));
        const includeActuatorPrefix = input.include_actuator_prefix !== false;
        const monitorExecution = input.__monitorExecution;

        const rawTargets = Array.isArray(input.targets) ? input.targets : [];
        const rawApiPaths = Array.isArray(input.api_paths) ? input.api_paths : [];

        if (rawTargets.length === 0 && rawApiPaths.length === 0) {
            return { success: false, error: "At least one target or api_path is required" };
        }

        const endpointNames: string[] = Array.isArray(input.actuator_endpoints) && input.actuator_endpoints.length > 0
            ? input.actuator_endpoints
            : ACTUATOR_ENDPOINTS.map(e => e.name);

        const endpointNameSet = new Set(endpointNames);
        if (!endpointNameSet.has("actuator") && includeActuatorPrefix) {
            endpointNames.unshift("actuator");
        }

        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: 100,
            phase: "prepare",
            message: "Generating probe URLs from API paths",
        });

        const allProbeUrls: string[] = [];
        let totalGenerated = 0;

        for (const apiPath of rawApiPaths) {
            const normalized = normalizeUrl(apiPath);
            if (!normalized) continue;
            const urls = generateBacktrackPaths(normalized, endpointNames, includeActuatorPrefix);
            totalGenerated += urls.length;
            allProbeUrls.push(...urls);
        }

        for (const target of rawTargets) {
            const normalized = normalizeUrl(target);
            if (!normalized) continue;
            const origin = extractOrigin(normalized);
            for (const endpoint of endpointNames) {
                allProbeUrls.push(`${origin}/${endpoint}`);
                totalGenerated++;
                if (includeActuatorPrefix && endpoint !== "actuator") {
                    allProbeUrls.push(`${origin}/actuator/${endpoint}`);
                    totalGenerated++;
                }
            }
        }

        const deduplicatedUrls = [...new Set(allProbeUrls)];

        await reportMonitorProgress(monitorExecution, {
            current: 5,
            total: 100,
            phase: "baseline",
            message: `Generated ${deduplicatedUrls.length} unique probe URLs (from ${totalGenerated} total). Building soft-404 baselines...`,
        });

        const origins = [...new Set(deduplicatedUrls.map(extractOrigin))];
        const baselineMap = new Map<string, Soft404Baseline | null>();
        await runWithConcurrency(
            origins.map(origin => async () => {
                const baseline = await buildSoft404Baseline(origin, userAgent);
                baselineMap.set(origin, baseline);
            }),
            Math.min(concurrency, origins.length),
        );

        await reportMonitorProgress(monitorExecution, {
            current: 10,
            total: 100,
            phase: "probe",
            message: `Probing ${deduplicatedUrls.length} actuator URLs across ${origins.length} origins...`,
        });

        const findings: Finding[] = [];
        const vulnerabilityFindings: any[] = [];
        let requestsMade = 0;
        let errors = 0;
        let completed = 0;

        const confirmedPrefixes = new Set<string>();

        const probeTasks = deduplicatedUrls.map(url => async () => {
            const endpointDef = getEndpointDef(url);
            if (!endpointDef) {
                completed++;
                return;
            }

            const origin = extractOrigin(url);
            const baseline = baselineMap.get(origin) || null;

            const result = await probeActuatorUrl(url, endpointDef, userAgent, baseline);
            requestsMade++;

            if (result.error) {
                errors++;
            }

            if (result.confirmed) {
                const pathPrefix = url.replace(/\/[^/]+$/, "");
                if (confirmedPrefixes.has(`${pathPrefix}/${endpointDef.name}`)) {
                    completed++;
                    return;
                }
                confirmedPrefixes.add(`${pathPrefix}/${endpointDef.name}`);

                const finding: Finding = {
                    title: `Spring Boot Actuator Exposed: /${endpointDef.name}`,
                    severity: endpointDef.severity,
                    url: result.url,
                    endpoint: endpointDef.name,
                    description: endpointDef.description,
                    evidence: result.evidence,
                    cwe: "CWE-200",
                    remediation: "Restrict access to actuator endpoints via Spring Security or network-level controls. In production, disable sensitive endpoints or require authentication.",
                    tags: ["actuator", "spring-boot", "misconfiguration", endpointDef.name],
                };
                findings.push(finding);
                vulnerabilityFindings.push({
                    title: finding.title,
                    severity: finding.severity,
                    target: finding.url,
                    vulnerability_type: "actuator_exposure",
                    description: finding.description,
                    evidence: finding.evidence,
                    source: "actuator_scanner",
                });
            }

            completed++;
            if (completed % 50 === 0 || completed === deduplicatedUrls.length) {
                const progress = 10 + Math.floor((completed / deduplicatedUrls.length) * 85);
                await reportMonitorProgress(monitorExecution, {
                    current: progress,
                    total: 100,
                    phase: "probe",
                    message: `Probed ${completed}/${deduplicatedUrls.length} URLs, found ${findings.length} exposures`,
                });
            }
        });

        await runWithConcurrency(probeTasks, concurrency);

        await reportMonitorProgress(monitorExecution, {
            current: 100,
            total: 100,
            phase: "complete",
            message: `Scan complete: ${findings.length} actuator exposures found`,
        });

        return {
            success: true,
            data: {
                findings,
                summary: {
                    totalApiPaths: rawApiPaths.length + rawTargets.length,
                    generatedProbeUrls: totalGenerated,
                    deduplicatedProbeUrls: deduplicatedUrls.length,
                    confirmedExposures: findings.length,
                    requestsMade,
                    errors,
                },
                surface_artifacts: {
                    findings: vulnerabilityFindings,
                },
            },
        };
    } catch (error: any) {
        return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
}

pluginGlobals.analyze = analyze;
