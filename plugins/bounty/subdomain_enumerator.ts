/**
 * Subdomain Enumerator Tool
 * 
 * @plugin subdomain_enumerator
 * @name Subdomain Enumerator
 * @version 2.2.5
 * @author Sentinel Team
 * @main_category bounty
 * @category recon
 * @default_severity info
 * @tags subdomain, reconnaissance, domain, enumeration, dns
 * @description Enumerate subdomains using multiple data sources (crt.sh, HackerTarget, RapidDNS, AlienVault, VirusTotal, URLScan, etc.)
 */

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

// @ts-ignore — One Engine exposes globals via bare assignment, not globalThis
const _nativeFetch: typeof fetch = fetch;

type FetchWithTimeoutInit = RequestInit & {
    timeout?: number;
};

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

const DEFAULT_FETCH_TIMEOUT_MS = 15000;
const RETRYABLE_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

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


function sleep(_ms: number): Promise<void> {
    // QuickJS has no timers; retries proceed immediately without backoff.
    return Promise.resolve();
}

function parseRetryAfter(value: string | null): number | null {
    if (!value) return null;

    const seconds = Number(value);
    if (Number.isFinite(seconds) && seconds >= 0) {
        return seconds * 1000;
    }

    const retryAt = Date.parse(value);
    if (Number.isNaN(retryAt)) {
        return null;
    }

    return Math.max(0, retryAt - Date.now());
}

function isRetryableMethod(method: string): boolean {
    return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

function isRetryableError(error: any): boolean {
    const message = String(error?.message || error || "").toLowerCase();
    return message.includes("timeout")
        || message.includes("network")
        || message.includes("fetch")
        || message.includes("socket")
        || message.includes("connection");
}

async function fetchWithRetry(input: RequestInfo | URL, init: FetchWithTimeoutInit = {}): Promise<Response> {
    const method = String(init.method || "GET").toUpperCase();
    const maxAttempts = isRetryableMethod(method) ? 2 : 1;
    const fetchInit: FetchWithTimeoutInit = {
        ...init,
        timeout: init.timeout ?? DEFAULT_FETCH_TIMEOUT_MS,
    };
    let lastError: any;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const response = await _nativeFetch(input, fetchInit);
            if (attempt < maxAttempts && RETRYABLE_STATUSES.has(response.status)) {
                const retryDelay = parseRetryAfter(response.headers.get("retry-after")) ?? (300 * attempt);
                try {
                    await response.arrayBuffer();
                } catch {
                    // Ignore body drain failures before retry.
                }
                await sleep(Math.min(retryDelay, 2000));
                continue;
            }

            return response;
        } catch (error: any) {
            lastError = error;
            if (attempt >= maxAttempts || !isRetryableError(error)) {
                throw error;
            }
            await sleep(300 * attempt);
        }
    }

    throw lastError ?? new Error("Request failed");
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
 * Extract subdomains from text using regex
 */
function extractSubdomains(text: string, domain: string): string[] {
    const escapedDomain = domain.replace(/\./g, "\\.");
    const regex = new RegExp(`[a-zA-Z0-9][-a-zA-Z0-9]*(?:\\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\\.${escapedDomain}`, "gi");
    const matches = text.match(regex) || [];
    return [...new Set(matches.map(m => m.toLowerCase()))];
}

/**
 * Query crt.sh Certificate Transparency logs
 */
async function queryCrtsh(domain: string ): Promise<string[]> {
    const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
    const response = await fetchWithRetry(url, { 
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    const subdomains = new Set<string>();
    
    try {
        const data = JSON.parse(text.replace(/\n/g, " "));
        for (const entry of data) {
            const nameValue = entry.name_value || "";
            const names = nameValue.split(/\n/);
            for (const name of names) {
                const cleaned = name.trim().toLowerCase();
                if (cleaned && cleaned.endsWith(domain) && !cleaned.startsWith("*")) {
                    subdomains.add(cleaned);
                }
            }
        }
    } catch {
        // Fallback to regex extraction
        return extractSubdomains(text, domain);
    }
    
    return [...subdomains];
}

/**
 * Query HackerTarget API
 */
async function queryHackerTarget(domain: string ): Promise<string[]> {
    const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    if (text.includes("error") || text.includes("API count exceeded")) {
        throw new Error("API rate limit exceeded");
    }
    
    return extractSubdomains(text, domain);
}

/**
 * Query RapidDNS
 */
async function queryRapidDNS(domain: string ): Promise<string[]> {
    const url = `https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query AlienVault OTX
 */
async function queryAlienVault(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    
    // Query passive DNS
    const dnsUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
    try {
        const dnsResponse = await fetchWithRetry(dnsUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        if (dnsResponse.ok) {
            const text = await dnsResponse.text();
            extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        }
    } catch { /* ignore */ }
    
    // Query URL list
    const urlListUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list`;
    try {
        const urlResponse = await fetchWithRetry(urlListUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        if (urlResponse.ok) {
            const text = await urlResponse.text();
            extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        }
    } catch { /* ignore */ }
    
    return [...subdomains];
}

/**
 * Query VirusTotal (public API, no key required)
 */
async function queryVirusTotal(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    let cursor = "";
    let iterations = 0;
    const maxIterations = 3; // Limit iterations to avoid too many requests
    
    while (iterations < maxIterations) {
        const url = `https://www.virustotal.com/ui/domains/${encodeURIComponent(domain)}/subdomains?limit=40&cursor=${cursor}`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://www.virustotal.com/"
            },
            // @ts-ignore
        });
        
        if (!response.ok) {
            break;
        }
        
        const text = await response.text();
        const found = extractSubdomains(text, domain);
        
        if (found.length === 0) {
            break;
        }
        
        found.forEach(s => subdomains.add(s));
        
        try {
            const data = JSON.parse(text);
            cursor = data?.meta?.cursor || "";
            if (!cursor) break;
        } catch {
            break;
        }
        
        iterations++;
    }
    
    return [...subdomains];
}

/**
 * Query URLScan.io
 */
async function queryURLScan(domain: string ): Promise<string[]> {
    const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Anubis DB
 */
async function queryAnubis(domain: string ): Promise<string[]> {
    const url = `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    try {
        const data = JSON.parse(text);
        if (Array.isArray(data)) {
            return data.filter(s => typeof s === "string" && s.endsWith(domain)).map(s => s.toLowerCase());
        }
    } catch { /* fallback to regex */ }
    
    return extractSubdomains(text, domain);
}

/**
 * Query DNSDumpster
 */
async function queryDNSDumpster(domain: string ): Promise<string[]> {
    const baseUrl = "https://dnsdumpster.com/";
    
    // Get CSRF token
    const getResponse = await fetchWithRetry(baseUrl, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://dnsdumpster.com"
        },
        // @ts-ignore
    });
    
    if (!getResponse.ok) {
        throw new Error(`HTTP ${getResponse.status}`);
    }
    
    // Extract CSRF token from cookies
    const cookies = getResponse.headers.get("set-cookie") || "";
    const csrfMatch = cookies.match(/csrftoken=([^;]+)/);
    if (!csrfMatch) {
        throw new Error("Failed to get CSRF token");
    }
    const csrfToken = csrfMatch[1];
    
    // POST request
    const formData = new URLSearchParams();
    formData.append("csrfmiddlewaretoken", csrfToken);
    formData.append("targetip", domain);
    formData.append("user", "free");
    
    const postResponse = await fetchWithRetry(baseUrl, {
        method: "POST",
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://dnsdumpster.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": `csrftoken=${csrfToken}`
        },
        body: formData.toString(),
        // @ts-ignore
    });
    
    if (!postResponse.ok) {
        throw new Error(`HTTP ${postResponse.status}`);
    }
    
    const text = await postResponse.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Sublist3r API
 */
async function querySublist3r(domain: string ): Promise<string[]> {
    const url = `https://api.sublist3r.com/search.php?domain=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    try {
        const data = JSON.parse(text);
        if (Array.isArray(data)) {
            return data.filter(s => typeof s === "string" && s.endsWith(domain)).map(s => s.toLowerCase());
        }
    } catch { /* fallback to regex */ }
    
    return extractSubdomains(text, domain);
}

/**
 * Query CertSpotter
 */
async function queryCertSpotter(domain: string ): Promise<string[]> {
    const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    const subdomains = new Set<string>();
    
    try {
        const data = JSON.parse(text);
        if (Array.isArray(data)) {
            for (const entry of data) {
                const dnsNames = entry.dns_names || [];
                for (const name of dnsNames) {
                    const cleaned = name.trim().toLowerCase();
                    if (cleaned && cleaned.endsWith(domain) && !cleaned.startsWith("*")) {
                        subdomains.add(cleaned);
                    }
                }
            }
        }
    } catch {
        return extractSubdomains(text, domain);
    }
    
    return [...subdomains];
}

/**
 * Query ThreatMiner
 */
async function queryThreatMiner(domain: string ): Promise<string[]> {
    const url = `https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=5`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Netcraft
 */
async function queryNetcraft(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    const baseUrl = "https://searchdns.netcraft.com/";
    let pageNum = 1;
    let last = "";
    let previousLast = "";
    
    for (let i = 0; i < 25; i++) { // Limit to 25 pages (500 results)
        const url = `${baseUrl}?restriction=site+contains&position=limited&host=*.${encodeURIComponent(domain)}&from=${pageNum}${last}`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        const found = extractSubdomains(text, domain);
        
        if (found.length === 0) break;
        found.forEach(s => subdomains.add(s));
        
        if (!text.includes("Next Page")) break;
        
        const lastMatch = text.match(new RegExp(`&last=.*${domain.replace(/\./g, "\\.")}`));
        if (lastMatch) {
            last = lastMatch[0];
        }
        
        // Detect stuck pagination: if cursor didn't advance, stop
        if (last === previousLast) break;
        previousLast = last;
        
        pageNum += 20;
    }
    
    return [...subdomains];
}

/**
 * Query Riddler
 */
async function queryRiddler(domain: string ): Promise<string[]> {
    const url = `https://riddler.io/search?q=pld:${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Robtex
 */
async function queryRobtex(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    const baseUrl = "https://freeapi.robtex.com/pdns";
    
    // Get forward DNS records
    const forwardUrl = `${baseUrl}/forward/${encodeURIComponent(domain)}`;
    const forwardResponse = await fetchWithRetry(forwardUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!forwardResponse.ok) {
        throw new Error(`HTTP ${forwardResponse.status}`);
    }
    
    const forwardText = await forwardResponse.text();
    const lines = forwardText.split("\n");
    const ips = new Set<string>();
    
    for (const line of lines) {
        if (!line.trim()) continue;
        try {
            const record = JSON.parse(line);
            if (record.rrtype === "A" || record.rrtype === "AAAA") {
                ips.add(record.rrdata);
            }
        } catch { /* ignore */ }
    }
    
    // Query reverse DNS for each IP (limit to first 10 IPs)
    const ipArray = [...ips].slice(0, 10);
    for (const ip of ipArray) {
        try {
            const reverseUrl = `${baseUrl}/reverse/${encodeURIComponent(ip)}`;
            const reverseResponse = await fetchWithRetry(reverseUrl, {
                headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
                // @ts-ignore
            });
            
            if (reverseResponse.ok) {
                const reverseText = await reverseResponse.text();
                extractSubdomains(reverseText, domain).forEach(s => subdomains.add(s));
            }
        } catch { /* ignore */ }
    }
    
    return [...subdomains];
}

/**
 * Query SiteDossier
 */
async function querySiteDossier(domain: string ): Promise<string[]> {
    const url = `http://www.sitedossier.com/parentdomain/${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query DNSGrep
 */
async function queryDNSGrep(domain: string ): Promise<string[]> {
    const url = `https://dns.bufferover.run/dns?q=.${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    const subdomains = new Set<string>();
    
    try {
        const data = JSON.parse(text);
        const fdns = data.FDNS_A || [];
        const rdns = data.RDNS || [];
        
        for (const entry of fdns) {
            const parts = entry.split(",");
            if (parts.length > 1) {
                const subdomain = parts[1].toLowerCase();
                if (subdomain.endsWith(domain)) {
                    subdomains.add(subdomain);
                }
            }
        }
        
        for (const entry of rdns) {
            const parts = entry.split(",");
            if (parts.length > 1) {
                const subdomain = parts[1].toLowerCase();
                if (subdomain.endsWith(domain)) {
                    subdomains.add(subdomain);
                }
            }
        }
    } catch {
        return extractSubdomains(text, domain);
    }
    
    return [...subdomains];
}

/**
 * Query BeVigil API
 */
async function queryBeVigil(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("BeVigil API token required");
    }
    
    const url = `https://osint.bevigil.com/api/${encodeURIComponent(domain)}/subdomains/`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-Access-Token": apiToken
        },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    try {
        const data = JSON.parse(text);
        if (data.subdomains && Array.isArray(data.subdomains)) {
            return data.subdomains
                .filter((s: any) => typeof s === "string" && s.endsWith(domain))
                .map((s: string) => s.toLowerCase());
        }
    } catch { /* fallback */ }
    
    return extractSubdomains(text, domain);
}

/**
 * Query Censys API
 */
async function queryCensys(domain: string , apiId?: string, apiSecret?: string): Promise<string[]> {
    if (!apiId || !apiSecret) {
        throw new Error("Censys API credentials required");
    }
    
    const subdomains = new Set<string>();
    const url = "https://search.censys.io/api/v2/certificates/search";
    let cursor: string | undefined;
    
    for (let i = 0; i < 5; i++) { // Limit to 5 pages
        const params = new URLSearchParams({
            q: `names: ${domain}`,
            per_page: "100"
        });
        
        if (cursor) {
            params.append("cursor", cursor);
        }
        
        const auth = btoa(`${apiId}:${apiSecret}`);
        const response = await fetchWithRetry(`${url}?${params}`, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Authorization": `Basic ${auth}`
            },
            // @ts-ignore
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        
        try {
            const data = JSON.parse(text);
            cursor = data?.result?.links?.next;
            if (!cursor) break;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query VirusTotal API
 */
async function queryVirusTotalAPI(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("VirusTotal API token required");
    }
    
    const subdomains = new Set<string>();
    let cursor = "";
    
    for (let i = 0; i < 5; i++) {
        const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/subdomains?limit=40${cursor ? `&cursor=${cursor}` : ""}`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "x-apikey": apiToken
            },
            // @ts-ignore
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const text = await response.text();
        
        try {
            const data = JSON.parse(text);
            const dataArray = data?.data || [];
            
            for (const entry of dataArray) {
                const id = entry?.id;
                if (id && typeof id === "string" && id.endsWith(domain)) {
                    subdomains.add(id.toLowerCase());
                }
            }
            
            cursor = data?.meta?.cursor || "";
            if (!cursor) break;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query SecurityTrails API
 */
async function querySecurityTrails(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("SecurityTrails API token required");
    }
    
    const url = `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "APIKEY": apiToken
        },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    const subdomains: string[] = [];
    
    try {
        const data = JSON.parse(text);
        const subs = data?.subdomains || [];
        
        for (const sub of subs) {
            if (typeof sub === "string") {
                subdomains.push(`${sub}.${domain}`.toLowerCase());
            }
        }
    } catch {
        return extractSubdomains(text, domain);
    }
    
    return subdomains;
}

/**
 * Query Shodan API
 */
async function queryShodan(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Shodan API token required");
    }
    
    const url = `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(apiToken)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    try {
        const data = JSON.parse(text);
        const subs = data?.subdomains || [];
        return subs
            .filter((s: any) => typeof s === "string")
            .map((s: string) => `${s}.${domain}`.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query GitHub API
 */
async function queryGitHub(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("GitHub API token required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 3; page++) {
        const url = `https://api.github.com/search/code?q=${encodeURIComponent(domain)}&per_page=100&page=${page}&sort=indexed`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/vnd.github.v3.text-match+json",
                "Authorization": `token ${apiToken}`
            },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        
        try {
            const data = JSON.parse(text);
            if (!data.items || data.items.length === 0) break;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query BinaryEdge API
 */
async function queryBinaryEdge(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("BinaryEdge API token required");
    }
    
    const subdomains = new Set<string>();
    let page = 1;
    
    for (let i = 0; i < 5; i++) {
        const url = `https://api.binaryedge.io/v2/query/domains/subdomain/${encodeURIComponent(domain)}?page=${page}`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "X-Key": apiToken
            },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        
        try {
            const data = JSON.parse(text);
            const events = data?.events || [];
            
            if (events.length === 0) break;
            
            for (const event of events) {
                if (typeof event === "string" && event.endsWith(domain)) {
                    subdomains.add(event.toLowerCase());
                }
            }
            
            page++;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query FullHunt API
 */
async function queryFullHunt(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("FullHunt API token required");
    }
    
    const url = `https://fullhunt.io/api/v1/domain/${encodeURIComponent(domain)}/subdomains`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-API-KEY": apiToken
        },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    try {
        const data = JSON.parse(text);
        const hosts = data?.hosts || [];
        return hosts
            .filter((h: any) => typeof h === "string" && h.endsWith(domain))
            .map((h: string) => h.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query Google Certificate Transparency
 */
async function queryGoogleCT(domain: string ): Promise<string[]> {
    const url = `https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query MySSL
 */
async function queryMySSL(domain: string ): Promise<string[]> {
    const url = `https://myssl.com/api/v1/discover_sub_domain?domain=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query IP138
 */
async function queryIP138(domain: string ): Promise<string[]> {
    const url = `https://site.ip138.com/${encodeURIComponent(domain)}/domain.htm`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query RiskIQ API
 */
async function queryRiskIQ(domain: string , username?: string, apiKey?: string): Promise<string[]> {
    if (!username || !apiKey) {
        throw new Error("RiskIQ API credentials required");
    }
    
    const url = `https://api.riskiq.net/pt/v2/enrichment/subdomains?query=${encodeURIComponent(domain)}`;
    const auth = btoa(`${username}:${apiKey}`);
    
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
            "Authorization": `Basic ${auth}`
        },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    try {
        const data = JSON.parse(text);
        const subs = data?.subdomains || [];
        return subs
            .filter((s: any) => typeof s === "string")
            .map((s: string) => `${s}.${domain}`.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query ThreatBook API
 */
async function queryThreatBook(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("ThreatBook API key required");
    }
    
    const url = `https://api.threatbook.cn/v3/domain/sub_domains?apikey=${encodeURIComponent(apiKey)}&resource=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    try {
        const data = JSON.parse(text);
        const subs = data?.data?.sub_domains || [];
        return subs
            .filter((s: any) => typeof s === "string" && s.endsWith(domain))
            .map((s: string) => s.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query FOFA API
 */
async function queryFOFA(domain: string , email?: string, apiKey?: string): Promise<string[]> {
    if (!email || !apiKey) {
        throw new Error("FOFA API credentials required");
    }
    
    const subdomains = new Set<string>();
    const query = `domain="${domain}"`;
    const qbase64 = btoa(query);
    
    for (let page = 1; page <= 5; page++) {
        const url = `https://fofa.info/api/v1/search/all?email=${encodeURIComponent(email)}&key=${encodeURIComponent(apiKey)}&qbase64=${qbase64}&page=${page}&size=100&full=true`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        
        try {
            const data = JSON.parse(text);
            if (!data.results || data.results.length === 0) break;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query Hunter API
 */
async function queryHunter(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Hunter API key required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 5; page++) {
        const url = `https://hunter.qianxin.com/openApi/search?api-key=${encodeURIComponent(apiKey)}&search=${encodeURIComponent(domain)}&page=${page}&page_size=100&is_web=1`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        
        try {
            const data = JSON.parse(text);
            if (!data.data?.arr || data.data.arr.length === 0) break;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query Quake API
 */
async function queryQuake(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Quake API key required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 0; page < 5; page++) {
        const url = "https://quake.360.cn/api/v3/search/quake_service";
        const body = JSON.stringify({
            query: `domain:"${domain}"`,
            start: page * 100,
            size: 100
        });
        
        const response = await fetchWithRetry(url, {
            method: "POST",
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json",
                "X-QuakeToken": apiKey
            },
            body,
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        
        try {
            const data = JSON.parse(text);
            if (!data.data || data.data.length === 0) break;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query ZoomEye API
 */
async function queryZoomEye(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("ZoomEye API key required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 5; page++) {
        const url = `https://api.zoomeye.org/domain/search?q=${encodeURIComponent(domain)}&page=${page}&type=1`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "API-KEY": apiKey
            },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        
        try {
            const data = JSON.parse(text);
            if (!data.list || data.list.length === 0) break;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query Spyse API
 */
async function querySpyse(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Spyse API token required");
    }
    
    const url = `https://api.spyse.com/v4/data/domain/subdomain?domain=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Authorization": `Bearer ${apiToken}`
        },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    
    try {
        const data = JSON.parse(text);
        const items = data?.data?.items || [];
        return items
            .map((item: any) => item?.name)
            .filter((s: any) => typeof s === "string" && s.endsWith(domain))
            .map((s: string) => s.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query Chinaz
 */
async function queryChinaz(domain: string ): Promise<string[]> {
    const url = `https://alexa.chinaz.com/${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query CeBaidu
 */
async function queryCeBaidu(domain: string ): Promise<string[]> {
    const url = `https://ce.baidu.com/index/getRelatedSites?site_address=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Qianxun
 */
async function queryQianxun(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 10; page++) {
        const url = `https://www.dnsscan.cn/dns.html?keywords=${encodeURIComponent(domain)}&page=${page}`;
        const response = await fetchWithRetry(url, {
            method: "POST",
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
                ecmsfrom: "",
                show: "",
                num: "",
                classid: "0",
                keywords: domain
            }).toString(),
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        const found = extractSubdomains(text, domain);
        
        if (found.length === 0) break;
        found.forEach(s => subdomains.add(s));
        
        if (!text.includes('<div id="page" class="pagelist">')) break;
        if (text.includes('<li class="disabled"><span>&raquo;</span></li>')) break;
    }
    
    return [...subdomains];
}

/**
 * Query Windvane
 */
async function queryWindvane(domain: string , apiKey?: string): Promise<string[]> {
    const subdomains = new Set<string>();
    const url = "https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService/ListSubDomain";
    
    let page = 1;
    let totalPages = 1;
    
    while (page <= totalPages && page <= 10) {
        const headers: Record<string, string> = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Referer": "https://windvane.lichoin.com"
        };
        
        if (apiKey) {
            headers["X-Api-Key"] = apiKey;
        }
        
        const body = JSON.stringify({
            domain: domain,
            page_request: {
                page: page,
                count: 1000
            }
        });
        
        const response = await fetchWithRetry(url, {
            method: "POST",
            headers,
            body,
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        
        try {
            const data = JSON.parse(text);
            
            if (data.code !== 0) break;
            
            extractSubdomains(text, domain).forEach(s => subdomains.add(s));
            
            const pageInfo = data?.data?.page_response || {};
            totalPages = parseInt(pageInfo.total_page || "1");
            
            page++;
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query Racent
 */
async function queryRacent(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Racent API token required");
    }
    
    const url = `https://face.racent.com/tool/query_ctlog?token=${encodeURIComponent(apiToken)}&keyword=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Common Crawl Index
 */
async function queryCDX(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    const url = `https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.${encodeURIComponent(domain)}&output=json`;
    
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    const lines = text.split("\n");
    
    for (const line of lines) {
        if (!line.trim()) continue;
        try {
            const data = JSON.parse(line);
            const url = data?.url || "";
            extractSubdomains(url, domain).forEach(s => subdomains.add(s));
        } catch { /* ignore */ }
    }
    
    return [...subdomains];
}

/**
 * Query Archive.org Wayback Machine
 */
async function queryArchive(domain: string ): Promise<string[]> {
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Chinaz API
 */
async function queryChinazAPI(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Chinaz API key required");
    }
    
    const url = `https://apidata.chinaz.com/CallAPI/Alexa?key=${encodeURIComponent(apiKey)}&domainName=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query CIRCL PassiveDNS API
 */
async function queryCIRCL(domain: string , username?: string, password?: string): Promise<string[]> {
    if (!username || !password) {
        throw new Error("CIRCL API credentials required");
    }
    
    const url = `https://www.circl.lu/pdns/query/${encodeURIComponent(domain)}`;
    const auth = btoa(`${username}:${password}`);
    
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Authorization": `Basic ${auth}`
        },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Cloudflare API
 */
async function queryCloudflare(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Cloudflare API token required");
    }
    
    const subdomains = new Set<string>();
    const headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": `Bearer ${apiToken}`,
        "Content-Type": "application/json"
    };
    
    // Get account ID
    const accountResponse = await fetchWithRetry("https://api.cloudflare.com/client/v4/accounts", {
        headers,
        // @ts-ignore
    });
    
    if (!accountResponse.ok) {
        throw new Error(`HTTP ${accountResponse.status}`);
    }
    
    const accountData = await accountResponse.json();
    const accountId = accountData?.result?.[0]?.id;
    
    if (!accountId) {
        throw new Error("No Cloudflare account found");
    }
    
    // Get zones for domain
    const zonesResponse = await fetchWithRetry(`https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(domain)}`, {
        headers,
        // @ts-ignore
    });
    
    if (!zonesResponse.ok) {
        throw new Error(`HTTP ${zonesResponse.status}`);
    }
    
    const zonesData = await zonesResponse.json();
    const zoneId = zonesData?.result?.[0]?.id;
    
    if (!zoneId) {
        return []; // Domain not in Cloudflare
    }
    
    // Get DNS records
    let page = 1;
    while (page <= 10) {
        const dnsResponse = await fetchWithRetry(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?page=${page}&per_page=100`, {
            headers,
            // @ts-ignore
        });
        
        if (!dnsResponse.ok) break;
        
        const text = await dnsResponse.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        
        try {
            const dnsData = JSON.parse(text);
            const totalPages = dnsData?.result_info?.total_pages || 0;
            if (page >= totalPages) break;
        } catch {
            break;
        }
        
        page++;
    }
    
    return [...subdomains];
}

/**
 * Query DNSDB API
 */
async function queryDNSDB(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("DNSDB API key required");
    }
    
    const url = `https://api.dnsdb.info/lookup/rrset/name/*.${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-API-Key": apiKey
        },
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query IPv4Info API
 */
async function queryIPv4Info(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("IPv4Info API key required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 0; page < 50; page++) {
        const url = `http://ipv4info.com/api_v1/?type=SUBDOMAINS&key=${encodeURIComponent(apiKey)}&value=${encodeURIComponent(domain)}&page=${page}`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        
        try {
            const data = JSON.parse(text);
            const subs = data?.Subdomains || [];
            
            if (subs.length === 0) break;
            
            extractSubdomains(JSON.stringify(data), domain).forEach(s => subdomains.add(s));
            
            if (subs.length < 300) break; // Less than 300 means last page
        } catch {
            break;
        }
    }
    
    return [...subdomains];
}

/**
 * Query PassiveDNS API
 */
async function queryPassiveDNS(domain: string , apiToken?: string, apiAddr?: string): Promise<string[]> {
    const baseUrl = apiAddr || "http://api.passivedns.cn";
    
    const headers: Record<string, string> = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    };
    
    if (apiToken) {
        headers["X-AuthToken"] = apiToken;
    }
    
    const url = `${baseUrl}/flint/rrset/*.${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers,
        // @ts-ignore
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Bing API
 */
async function queryBingAPI(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Bing API key required");
    }
    
    const subdomains = new Set<string>();
    let offset = 0;
    const perPage = 50;
    
    for (let i = 0; i < 20; i++) { // Limit to 1000 results (20 * 50)
        const query = `site:.${domain}`;
        const url = `https://api.bing.microsoft.com/v7.0/search?q=${encodeURIComponent(query)}&count=${perPage}&offset=${offset}&safesearch=Off`;
        
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Ocp-Apim-Subscription-Key": apiKey
            },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        const found = extractSubdomains(text, domain);
        
        if (found.length === 0) break;
        found.forEach(s => subdomains.add(s));
        
        offset += perPage;
    }
    
    return [...subdomains];
}

/**
 * Query Google Custom Search API
 */
async function queryGoogleAPI(domain: string , apiKey?: string, searchEngineId?: string): Promise<string[]> {
    if (!apiKey || !searchEngineId) {
        throw new Error("Google API key and search engine ID required");
    }
    
    const subdomains = new Set<string>();
    
    for (let start = 1; start <= 91; start += 10) { // Max 100 results (10 pages)
        const query = `site:.${domain}`;
        const url = `https://www.googleapis.com/customsearch/v1?key=${encodeURIComponent(apiKey)}&cx=${encodeURIComponent(searchEngineId)}&q=${encodeURIComponent(query)}&fields=items/link&start=${start}&num=10`;
        
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        const found = extractSubdomains(text, domain);
        
        if (found.length === 0) break;
        found.forEach(s => subdomains.add(s));
    }
    
    return [...subdomains];
}

/**
 * Query Gitee code search
 */
async function queryGitee(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 100; page++) {
        const url = `https://search.gitee.com/?pageno=${page}&q=${encodeURIComponent(domain)}&type=code`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        
        if (!response.ok) break;
        
        const text = await response.text();
        
        if (text.includes('class="empty-box"')) break;
        if (text.includes('<li class="disabled"><a href="###">')) break;
        
        const found = extractSubdomains(text, domain);
        if (found.length === 0) break;
        
        found.forEach(s => subdomains.add(s));
    }
    
    return [...subdomains];
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

