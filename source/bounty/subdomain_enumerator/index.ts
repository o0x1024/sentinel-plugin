/**
 * Subdomain Enumerator Tool
 *
 * @plugin subdomain_enumerator
 * @name Subdomain Enumerator
 * @version 2.2.6
 * @author Sentinel Team
 * @main_category bounty
 * @category recon
 * @monitor_type dns
 * @input_mode seed
 * @target_asset_types []
 * @seed_bindings [{"seed_type":"root_domain","input_key":"domains"},{"seed_type":"domain","input_key":"domains"}]
 * @default_severity info
 * @tags subdomain, reconnaissance, domain, enumeration, dns, osint, certificate-transparency, threat-intelligence, passive-dns, api, capability:fetch
 * @description Enumerate subdomains using multiple data sources (crt.sh, HackerTarget, RapidDNS, AlienVault, VirusTotal, URLScan, etc.)
 */
import { extractSubdomains, queryCrtsh, queryHackerTarget, queryRapidDNS, queryAlienVault, queryVirusTotal, queryURLScan, queryAnubis, queryDNSDumpster, querySublist3r, queryCertSpotter, queryThreatMiner, queryNetcraft, queryRiddler, queryRobtex, querySiteDossier, queryDNSGrep, queryBeVigil, queryCensys, queryVirusTotalAPI, querySecurityTrails, queryShodan, queryGitHub, queryBinaryEdge, queryFullHunt, queryGoogleCT, queryMySSL, queryIP138, queryRiskIQ, queryThreatBook, queryFOFA, queryHunter, queryQuake, queryZoomEye, querySpyse, queryChinaz, queryCeBaidu, queryQianxun, queryWindvane, queryRacent, queryCDX, queryArchive, queryChinazAPI, queryCIRCL, queryCloudflare, queryDNSDB, queryIPv4Info, queryPassiveDNS, queryBingAPI, queryGoogleAPI, queryGitee } from './sources.ts';

interface ToolInput {
    domain?: string;
    domains?: string[] | string;
    targets?: string[] | string;
    target_objects?: Array<{ type?: string; value?: string }>;
    sources?: string[];
    removeDuplicates?: boolean;
    apiConfig?: ApiConfig;
    previousSnapshots?: Record<string, SubdomainSnapshot>;
}

interface SubdomainResult {
    subdomain: string;
    source: string;
}

interface SourceResult {
    source: string;
    subdomains: string[];
    count: number;
    error?: string;
    responseTime: number;
}

interface SubdomainSnapshot {
    domain: string;
    subdomains: string[];
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
        domain: string;
        subdomains: string[];
        sourceResults: SourceResult[];
        slowSources?: SourceResult[];
        skippedSources?: string[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, SubdomainSnapshot>;
        summary: {
            totalUnique: number;
            totalFound: number;
            sourcesQueried: number;
            sourcesSucceeded: number;
            sourcesFailed: number;
            sourcesSkipped: number;
            subdomainChanges: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

// Available data sources
const AVAILABLE_SOURCES = [
    // Certificate sources
    "crtsh",
    "certspotter",
    "censys",
    "google_ct",
    "myssl",
    "racent",

    // Dataset sources
    "hackertarget",
    "rapiddns",
    "anubis",
    "dnsdumpster",
    "sublist3r",
    "bevigil",
    "binaryedge",
    "cebaidu",
    "chinaz",
    "chinaz_api",
    "circl",
    "cloudflare",
    "dnsdb",
    "dnsgrep",
    "fullhunt",
    "ip138",
    "ipv4info",
    "netcraft",
    "passivedns",
    "qianxun",
    "riddler",
    "robtex",
    "securitytrails",
    "sitedossier",
    "spyse",
    "windvane",

    // Intelligence sources
    "alienvault",
    "virustotal",
    "virustotal_api",
    "riskiq",
    "threatbook",
    "threatminer",

    // Search engines
    "urlscan",
    "bing_api",
    "fofa",
    "gitee",
    "github",
    "google_api",
    "hunter",
    "quake",
    "shodan",
    "zoomeye",

    // Check/Crawl methods
    "cdx",
    "archive"
] as const;

type DataSource = typeof AVAILABLE_SOURCES[number];

const SOURCE_PRIORITY: Partial<Record<DataSource, number>> = {
    certspotter: 1,
    crtsh: 2,
    rapiddns: 3,
    anubis: 4,
    alienvault: 5,
    threatminer: 6,
    urlscan: 7,
    cdx: 8,
    archive: 9,
    netcraft: 10,
    dnsgrep: 11,
    sitedossier: 12,
    robtex: 13,
    virustotal: 14,
};

// API configuration interface
interface ApiConfig {
    // Certificate sources
    censys_id?: string;
    censys_secret?: string;
    racent_token?: string;

    // Dataset sources
    bevigil_token?: string;
    binaryedge_token?: string;
    chinaz_token?: string;
    circl_user?: string;
    circl_pass?: string;
    cloudflare_token?: string;
    dnsdb_token?: string;
    fullhunt_token?: string;
    ipv4info_token?: string;
    passivedns_token?: string;
    passivedns_addr?: string;
    securitytrails_token?: string;
    spyse_token?: string;
    windvane_token?: string;

    // Intelligence sources
    riskiq_user?: string;
    riskiq_key?: string;
    threatbook_token?: string;
    virustotal_token?: string;

    // Search engines
    bing_token?: string;
    fofa_email?: string;
    fofa_key?: string;
    github_token?: string;
    google_key?: string;
    google_cx?: string;
    hunter_token?: string;
    quake_token?: string;
    shodan_token?: string;
    zoomeye_token?: string;
}

const SOURCE_REQUIRED_CONFIG: Partial<Record<DataSource, Array<keyof ApiConfig>>> = {
    censys: ["censys_id", "censys_secret"],
    racent: ["racent_token"],
    bevigil: ["bevigil_token"],
    binaryedge: ["binaryedge_token"],
    chinaz_api: ["chinaz_token"],
    circl: ["circl_user", "circl_pass"],
    cloudflare: ["cloudflare_token"],
    dnsdb: ["dnsdb_token"],
    fullhunt: ["fullhunt_token"],
    ipv4info: ["ipv4info_token"],
    passivedns: ["passivedns_token", "passivedns_addr"],
    securitytrails: ["securitytrails_token"],
    spyse: ["spyse_token"],
    windvane: ["windvane_token"],
    virustotal_api: ["virustotal_token"],
    riskiq: ["riskiq_user", "riskiq_key"],
    threatbook: ["threatbook_token"],
    bing_api: ["bing_token"],
    fofa: ["fofa_email", "fofa_key"],
    github: ["github_token"],
    google_api: ["google_key", "google_cx"],
    hunter: ["hunter_token"],
    quake: ["quake_token"],
    shodan: ["shodan_token"],
    zoomeye: ["zoomeye_token"],
};

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        required: [],
        properties: {
            domain: {
                type: "string",
                description: "Target domain to enumerate subdomains for (e.g., 'example.com')"
            },
            domains: {
                type: "array",
                items: { type: "string" },
                description: "Root domains to enumerate. Monitor scheduler can inject this automatically."
            },
            sources: {
                type: "array",
                items: { type: "string" },
                description: `Data sources to query. Available: ${AVAILABLE_SOURCES.join(", ")}. Default: all sources`,
                default: [...AVAILABLE_SOURCES]
            },
            removeDuplicates: {
                type: "boolean",
                description: "Remove duplicate subdomains from results",
                default: true
            },
            apiConfig: {
                type: "object",
                description: "API keys and credentials for various data sources",
                properties: {
                    // Certificate sources
                    censys_id: { type: "string", description: "Censys API ID" },
                    censys_secret: { type: "string", description: "Censys API Secret" },
                    racent_token: { type: "string", description: "Racent API token" },

                    // Dataset sources
                    bevigil_token: { type: "string", description: "BeVigil API token" },
                    binaryedge_token: { type: "string", description: "BinaryEdge API token" },
                    chinaz_token: { type: "string", description: "Chinaz API key" },
                    circl_user: { type: "string", description: "CIRCL username" },
                    circl_pass: { type: "string", description: "CIRCL password" },
                    cloudflare_token: { type: "string", description: "Cloudflare API token" },
                    dnsdb_token: { type: "string", description: "DNSDB API key" },
                    fullhunt_token: { type: "string", description: "FullHunt API token" },
                    ipv4info_token: { type: "string", description: "IPv4Info API key" },
                    passivedns_token: { type: "string", description: "PassiveDNS API token" },
                    passivedns_addr: { type: "string", description: "PassiveDNS API address" },
                    securitytrails_token: { type: "string", description: "SecurityTrails API token" },
                    spyse_token: { type: "string", description: "Spyse API token" },
                    windvane_token: { type: "string", description: "Windvane API token" },

                    // Intelligence sources
                    riskiq_user: { type: "string", description: "RiskIQ username" },
                    riskiq_key: { type: "string", description: "RiskIQ API key" },
                    threatbook_token: { type: "string", description: "ThreatBook API token" },
                    virustotal_token: { type: "string", description: "VirusTotal API token" },

                    // Search engines
                    bing_token: { type: "string", description: "Bing API key" },
                    fofa_email: { type: "string", description: "FOFA email" },
                    fofa_key: { type: "string", description: "FOFA API key" },
                    github_token: { type: "string", description: "GitHub API token" },
                    google_key: { type: "string", description: "Google API key" },
                    google_cx: { type: "string", description: "Google Custom Search Engine ID" },
                    hunter_token: { type: "string", description: "Hunter API token" },
                    quake_token: { type: "string", description: "Quake API token" },
                    shodan_token: { type: "string", description: "Shodan API token" },
                    zoomeye_token: { type: "string", description: "ZoomEye API token" }
                }
            },
            previousSnapshots: {
                type: "object",
                description: "Previous subdomain snapshots keyed by root domain for change detection"
            }
        }
    };
}

function normalizeStringList(value: unknown): string[] {
    if (Array.isArray(value)) {
        return value
            .map(item => String(item || "").trim())
            .filter(Boolean);
    }
    if (typeof value === "string") {
        return value
            .split(",")
            .map(item => item.trim())
            .filter(Boolean);
    }
    return [];
}

function resolveInputDomain(input: ToolInput): string {
    const candidates = [
        typeof input.domain === "string" ? input.domain : "",
        ...normalizeStringList(input.domains),
        ...normalizeStringList(input.targets),
        ...((Array.isArray(input.target_objects) ? input.target_objects : [])
            .filter(item => item?.type === "domain" || item?.type === "root_domain")
            .map(item => String(item?.value || "").trim())),
    ];

    for (const candidate of candidates) {
        const normalized = candidate.toLowerCase().trim();
        if (normalized) {
            return normalized;
        }
    }

    return "";
}

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
                    domain: { type: "string", description: "Target domain" },
                    subdomains: {
                        type: "array",
                        items: { type: "string" },
                        description: "List of discovered subdomains"
                    },
                    sourceResults: {
                        type: "array",
                        description: "Results from each data source"
                    },
                    slowSources: {
                        type: "array",
                        description: "Slowest data source results ordered by response time"
                    },
                    changeEvents: {
                        type: "array",
                        description: "Detected subdomain change events"
                    },
                    snapshots: {
                        type: "object",
                        description: "Subdomain snapshots keyed by root domain"
                    },
                    summary: {
                        type: "object",
                        properties: {
                            totalUnique: { type: "integer" },
                            totalFound: { type: "integer" },
                            sourcesQueried: { type: "integer" },
                            sourcesSucceeded: { type: "integer" },
                            sourcesFailed: { type: "integer" },
                            sourcesSkipped: { type: "integer" }
                        }
                    },
                    skippedSources: {
                        type: "array",
                        items: { type: "string" },
                        description: "Sources skipped by default because required API credentials were not configured"
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

function hasRequiredApiConfig(source: DataSource, apiConfig?: ApiConfig): boolean {
    const keys = SOURCE_REQUIRED_CONFIG[source];
    if (!keys || keys.length === 0) {
        return true;
    }

    return keys.every((key) => {
        const value = apiConfig?.[key];
        return typeof value === "string" && value.trim().length > 0;
    });
}

function prioritizeSources(sources: DataSource[]): DataSource[] {
    return [...sources].sort((left, right) => {
        const leftScore = SOURCE_PRIORITY[left] ?? 100;
        const rightScore = SOURCE_PRIORITY[right] ?? 100;
        if (leftScore !== rightScore) {
            return leftScore - rightScore;
        }
        return left.localeCompare(right);
    });
}

function logSourceResult(result: SourceResult): void {
    const status = result.error ? "failed" : "completed";
    const suffix = result.error ? ` error=${String(result.error).slice(0, 160)}` : "";
    try {
        Sentinel?.log?.(
            "info",
            `[subdomain_enumerator] source=${result.source} ${status} count=${result.count} duration_ms=${result.responseTime}${suffix}`
        );
    } catch {
        // Logging must never affect enumeration results.
    }
}

function buildSubdomainEventId(domain: string, eventType: string, timestamp: string): string {
    return `${eventType}-${domain}-${timestamp}`.replace(/[^a-zA-Z0-9_-]+/g, "-").slice(0, 120);
}

function createSubdomainChangeEvent(domain: string, eventType: "asset_discovered" | "asset_removed", subdomains: string[], timestamp: string): ChangeEvent {
    const discovered = eventType === "asset_discovered";
    const severity: ChangeEvent["severity"] = subdomains.length >= 10 ? "medium" : "low";
    return {
        id: buildSubdomainEventId(domain, eventType, timestamp),
        assetId: domain,
        eventType,
        severity,
        title: discovered
            ? `New subdomains discovered for ${domain}`
            : `Subdomains no longer observed for ${domain}`,
        description: discovered
            ? `Discovered ${subdomains.length} subdomain(s): ${subdomains.join(", ")}`
            : `No longer observed ${subdomains.length} subdomain(s): ${subdomains.join(", ")}`,
        oldValue: discovered ? undefined : subdomains.join("\n"),
        newValue: discovered ? subdomains.join("\n") : undefined,
        detectionMethod: "subdomain_enumerator",
        tags: ["subdomain", discovered ? "discovered" : "removed", "dns"],
        autoTriggerEnabled: true,
        riskScore: discovered ? 44 + Math.min(subdomains.length, 10) : 56 + Math.min(subdomains.length, 10),
        metadata: {
            domain,
            subdomains,
        },
    };
}

/**
 * Query a single data source
 */
async function querySource(
    source: DataSource,
    domain: string ,
    apiConfig?: ApiConfig
): Promise<SourceResult> {
    const startTime = performance.now();

    try {
        let subdomains: string[];

        switch (source) {
            // Certificate sources
            case "crtsh":
                subdomains = await queryCrtsh(domain );
                break;
            case "certspotter":
                subdomains = await queryCertSpotter(domain );
                break;
            case "censys":
                subdomains = await queryCensys(domain , apiConfig?.censys_id, apiConfig?.censys_secret);
                break;
            case "google_ct":
                subdomains = await queryGoogleCT(domain );
                break;
            case "myssl":
                subdomains = await queryMySSL(domain );
                break;
            case "racent":
                subdomains = await queryRacent(domain , apiConfig?.racent_token);
                break;

            // Dataset sources
            case "hackertarget":
                subdomains = await queryHackerTarget(domain );
                break;
            case "rapiddns":
                subdomains = await queryRapidDNS(domain );
                break;
            case "anubis":
                subdomains = await queryAnubis(domain );
                break;
            case "dnsdumpster":
                subdomains = await queryDNSDumpster(domain );
                break;
            case "sublist3r":
                subdomains = await querySublist3r(domain );
                break;
            case "bevigil":
                subdomains = await queryBeVigil(domain , apiConfig?.bevigil_token);
                break;
            case "binaryedge":
                subdomains = await queryBinaryEdge(domain , apiConfig?.binaryedge_token);
                break;
            case "dnsgrep":
                subdomains = await queryDNSGrep(domain );
                break;
            case "fullhunt":
                subdomains = await queryFullHunt(domain , apiConfig?.fullhunt_token);
                break;
            case "netcraft":
                subdomains = await queryNetcraft(domain );
                break;
            case "riddler":
                subdomains = await queryRiddler(domain );
                break;
            case "robtex":
                subdomains = await queryRobtex(domain );
                break;
            case "securitytrails":
                subdomains = await querySecurityTrails(domain , apiConfig?.securitytrails_token);
                break;
            case "sitedossier":
                subdomains = await querySiteDossier(domain );
                break;
            case "spyse":
                subdomains = await querySpyse(domain , apiConfig?.spyse_token);
                break;
            case "ip138":
                subdomains = await queryIP138(domain );
                break;
            case "chinaz":
                subdomains = await queryChinaz(domain );
                break;
            case "chinaz_api":
                subdomains = await queryChinazAPI(domain , apiConfig?.chinaz_token);
                break;
            case "cebaidu":
                subdomains = await queryCeBaidu(domain );
                break;
            case "circl":
                subdomains = await queryCIRCL(domain , apiConfig?.circl_user, apiConfig?.circl_pass);
                break;
            case "cloudflare":
                subdomains = await queryCloudflare(domain , apiConfig?.cloudflare_token);
                break;
            case "dnsdb":
                subdomains = await queryDNSDB(domain , apiConfig?.dnsdb_token);
                break;
            case "ipv4info":
                subdomains = await queryIPv4Info(domain , apiConfig?.ipv4info_token);
                break;
            case "passivedns":
                subdomains = await queryPassiveDNS(domain , apiConfig?.passivedns_token, apiConfig?.passivedns_addr);
                break;
            case "qianxun":
                subdomains = await queryQianxun(domain );
                break;
            case "windvane":
                subdomains = await queryWindvane(domain , apiConfig?.windvane_token);
                break;

            // Intelligence sources
            case "alienvault":
                subdomains = await queryAlienVault(domain );
                break;
            case "virustotal":
                subdomains = await queryVirusTotal(domain );
                break;
            case "virustotal_api":
                subdomains = await queryVirusTotalAPI(domain , apiConfig?.virustotal_token);
                break;
            case "threatminer":
                subdomains = await queryThreatMiner(domain );
                break;
            case "riskiq":
                subdomains = await queryRiskIQ(domain , apiConfig?.riskiq_user, apiConfig?.riskiq_key);
                break;
            case "threatbook":
                subdomains = await queryThreatBook(domain , apiConfig?.threatbook_token);
                break;

            // Search engines
            case "urlscan":
                subdomains = await queryURLScan(domain );
                break;
            case "bing_api":
                subdomains = await queryBingAPI(domain , apiConfig?.bing_token);
                break;
            case "gitee":
                subdomains = await queryGitee(domain );
                break;
            case "github":
                subdomains = await queryGitHub(domain , apiConfig?.github_token);
                break;
            case "google_api":
                subdomains = await queryGoogleAPI(domain , apiConfig?.google_key, apiConfig?.google_cx);
                break;
            case "shodan":
                subdomains = await queryShodan(domain , apiConfig?.shodan_token);
                break;
            case "fofa":
                subdomains = await queryFOFA(domain , apiConfig?.fofa_email, apiConfig?.fofa_key);
                break;
            case "hunter":
                subdomains = await queryHunter(domain , apiConfig?.hunter_token);
                break;
            case "quake":
                subdomains = await queryQuake(domain , apiConfig?.quake_token);
                break;
            case "zoomeye":
                subdomains = await queryZoomEye(domain , apiConfig?.zoomeye_token);
                break;

            // Check methods
            case "cdx":
                subdomains = await queryCDX(domain );
                break;

            // Crawl methods
            case "archive":
                subdomains = await queryArchive(domain );
                break;

            default:
                throw new Error(`Source not implemented: ${source}`);
        }

        const responseTime = performance.now() - startTime;

        return {
            source,
            subdomains,
            count: subdomains.length,
            responseTime: Math.round(responseTime)
        };
    } catch (error: any) {
        const responseTime = performance.now() - startTime;
        return {
            source,
            subdomains: [],
            count: 0,
            error: error.message || String(error),
            responseTime: Math.round(responseTime)
        };
    }
}

/**
 * Run source tasks with bounded plugin concurrency. Host enforces global direct-fetch limit.
 */
async function runSourceTasksWithConcurrency(tasks: Array<() => Promise<SourceResult>>): Promise<SourceResult[]> {
    const results: SourceResult[] = [];
    const workerCount = Math.min(16, tasks.length);
    let nextIndex = 0;

    const workers: Promise<void>[] = [];
    for (let w = 0; w < workerCount; w++) {
        workers.push((async () => {
            while (nextIndex < tasks.length) {
                const currentIndex = nextIndex++;
                try {
                    const result = await tasks[currentIndex]();
                    logSourceResult(result);
                    results[currentIndex] = result;
                } catch (err: any) {
                    results[currentIndex] = {
                        source: "unknown",
                        subdomains: [],
                        count: 0,
                        error: err?.message || String(err),
                        responseTime: 0,
                    };
                }
            }
        })());
    }
    await Promise.all(workers);
    return results;
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const domain = resolveInputDomain(input);

        if (!domain) {
            return {
                success: false,
                error: "Invalid input: domain parameter is required"
            };
        }

        if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) {
            return {
                success: false,
                error: `Invalid domain format: ${domain}`
            };
        }

        const removeDuplicates = input.removeDuplicates !== false;
        const requestedSourceList = Array.isArray(input.sources) ? input.sources : [];
        const requestedSources = requestedSourceList.length > 0;
        const skippedSources: DataSource[] = [];
        const previousSnapshots = input.previousSnapshots || {};
        const timestamp = new Date().toISOString();

        let sources: DataSource[] = [...AVAILABLE_SOURCES];
        if (requestedSources) {
            sources = requestedSourceList.filter(s =>
                AVAILABLE_SOURCES.includes(s as DataSource)
            ) as DataSource[];

            if (sources.length === 0) {
                return {
                    success: false,
                    error: `No valid sources specified. Available: ${AVAILABLE_SOURCES.join(", ")}`
                };
            }
        }

        if (!requestedSources) {
            sources = sources.filter((source) => {
                if (hasRequiredApiConfig(source, input.apiConfig)) {
                    return true;
                }
                skippedSources.push(source);
                return false;
            });
        }

        sources = prioritizeSources(sources);
        try {
            Sentinel?.log?.(
                "info",
                `[subdomain_enumerator] start domain=${domain} sources=${sources.length}`
            );
        } catch {
            // Ignore logging failures.
        }
        const tasks = sources.map(source => () => querySource(source, domain, input.apiConfig));
        const sourceResults = await runSourceTasksWithConcurrency(tasks);

        const allSubdomains: string[] = [];
        let sourcesSucceeded = 0;
        let sourcesFailed = 0;

        for (const result of sourceResults) {
            if (result.error) {
                sourcesFailed++;
            } else {
                sourcesSucceeded++;
            }
            allSubdomains.push(...result.subdomains);
        }

        const slowSources = [...sourceResults]
            .sort((a, b) => b.responseTime - a.responseTime)
            .slice(0, 10);

        const finalSubdomains = removeDuplicates
            ? [...new Set(allSubdomains)].sort()
            : allSubdomains.sort();

        const snapshots: Record<string, SubdomainSnapshot> = {
            [domain]: {
                domain,
                subdomains: finalSubdomains,
                lastChecked: timestamp,
            },
        };
        const changeEvents: ChangeEvent[] = [];
        const previousSnapshot = previousSnapshots[domain];

        if (!previousSnapshot) {
            if (finalSubdomains.length > 0) {
                changeEvents.push(createSubdomainChangeEvent(domain, "asset_discovered", finalSubdomains, timestamp));
            }
        } else {
            const previousSet = new Set((previousSnapshot.subdomains || []).map(item => item.toLowerCase()));
            const currentSet = new Set(finalSubdomains.map(item => item.toLowerCase()));
            const added = finalSubdomains.filter(item => !previousSet.has(item.toLowerCase()));
            const removed = (previousSnapshot.subdomains || []).filter(item => !currentSet.has(item.toLowerCase()));
            if (added.length > 0) {
                changeEvents.push(createSubdomainChangeEvent(domain, "asset_discovered", added, timestamp));
            }
            if (removed.length > 0) {
                changeEvents.push(createSubdomainChangeEvent(domain, "asset_removed", removed, timestamp));
            }
        }

        return {
            success: true,
            data: {
                domain,
                subdomains: finalSubdomains,
                sourceResults: sourceResults.sort((a, b) => b.count - a.count),
                slowSources,
                skippedSources,
                changeEvents,
                snapshots,
                summary: {
                    totalUnique: new Set(allSubdomains).size,
                    totalFound: allSubdomains.length,
                    sourcesQueried: sources.length,
                    sourcesSucceeded,
                    sourcesFailed,
                    sourcesSkipped: skippedSources.length,
                    subdomainChanges: changeEvents.length,
                },
                surface_artifacts: {
                    domains: finalSubdomains.map(subdomain => ({
                        fqdn: subdomain,
                        root_domain: domain,
                        main_domain: domain,
                        source: "subdomain_enumerator",
                        confidence: 0.8,
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
                        source: "subdomain_enumerator",
                        metadata: event.metadata,
                    })),
                    evidences: [{
                        asset_type: "domain",
                        asset_key: domain,
                        evidence_type: "subdomain_snapshot",
                        title: `Subdomain Snapshot: ${domain}`,
                        content_json: snapshots[domain],
                        source: "subdomain_enumerator",
                    }],
                    relations: finalSubdomains.map(subdomain => ({
                        from_type: "domain",
                        from_key: domain,
                        to_type: "domain",
                        to_key: subdomain,
                        relation_type: "contains_subdomain",
                        source: "subdomain_enumerator",
                        confidence: 0.8,
                    })),
                }
            }
        };

    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
