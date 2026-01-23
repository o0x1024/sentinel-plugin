/**
 * Subdomain Enumerator Tool
 * 
 * @plugin subdomain_enumerator
 * @name Subdomain Enumerator
 * @version 1.0.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags subdomain, reconnaissance, domain, enumeration, dns
 * @description Enumerate subdomains using multiple data sources (crt.sh, HackerTarget, RapidDNS, AlienVault, VirusTotal, URLScan, etc.)
 */

interface ToolInput {
    domain: string;
    sources?: string[];
    concurrency?: number;
    timeout?: number;
    removeDuplicates?: boolean;
    apiConfig?: ApiConfig;
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

interface ToolOutput {
    success: boolean;
    data?: {
        domain: string;
        subdomains: string[];
        sourceResults: SourceResult[];
        summary: {
            totalUnique: number;
            totalFound: number;
            sourcesQueried: number;
            sourcesSucceeded: number;
            sourcesFailed: number;
        };
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

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        required: ["domain"],
        properties: {
            domain: {
                type: "string",
                description: "Target domain to enumerate subdomains for (e.g., 'example.com')"
            },
            sources: {
                type: "array",
                items: { type: "string" },
                description: `Data sources to query. Available: ${AVAILABLE_SOURCES.join(", ")}. Default: all sources`,
                default: [...AVAILABLE_SOURCES]
            },
            concurrency: {
                type: "integer",
                description: "Number of concurrent requests",
                default: 5,
                minimum: 1,
                maximum: 10
            },
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: 30000,
                minimum: 5000,
                maximum: 120000
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
            }
        }
    };
}

globalThis.get_input_schema = get_input_schema;

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
                    summary: {
                        type: "object",
                        properties: {
                            totalUnique: { type: "integer" },
                            totalFound: { type: "integer" },
                            sourcesQueried: { type: "integer" },
                            sourcesSucceeded: { type: "integer" },
                            sourcesFailed: { type: "integer" }
                        }
                    }
                }
            },
            error: { type: "string", description: "Error message if failed" }
        }
    };
}

globalThis.get_output_schema = get_output_schema;

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
async function queryCrtsh(domain: string, timeout: number): Promise<string[]> {
    const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
    const response = await fetch(url, { 
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout 
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
async function queryHackerTarget(domain: string, timeout: number): Promise<string[]> {
    const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryRapidDNS(domain: string, timeout: number): Promise<string[]> {
    const url = `https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryAlienVault(domain: string, timeout: number): Promise<string[]> {
    const subdomains = new Set<string>();
    
    // Query passive DNS
    const dnsUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
    try {
        const dnsResponse = await fetch(dnsUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
            timeout
        });
        if (dnsResponse.ok) {
            const text = await dnsResponse.text();
            extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        }
    } catch { /* ignore */ }
    
    // Query URL list
    const urlListUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list`;
    try {
        const urlResponse = await fetch(urlListUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
            timeout
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
async function queryVirusTotal(domain: string, timeout: number): Promise<string[]> {
    const subdomains = new Set<string>();
    let cursor = "";
    let iterations = 0;
    const maxIterations = 3; // Limit iterations to avoid too many requests
    
    while (iterations < maxIterations) {
        const url = `https://www.virustotal.com/ui/domains/${encodeURIComponent(domain)}/subdomains?limit=40&cursor=${cursor}`;
        const response = await fetch(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://www.virustotal.com/"
            },
            // @ts-ignore
            timeout
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
async function queryURLScan(domain: string, timeout: number): Promise<string[]> {
    const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryAnubis(domain: string, timeout: number): Promise<string[]> {
    const url = `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryDNSDumpster(domain: string, timeout: number): Promise<string[]> {
    const baseUrl = "https://dnsdumpster.com/";
    
    // Get CSRF token
    const getResponse = await fetch(baseUrl, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://dnsdumpster.com"
        },
        // @ts-ignore
        timeout
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
    
    const postResponse = await fetch(baseUrl, {
        method: "POST",
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://dnsdumpster.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": `csrftoken=${csrfToken}`
        },
        body: formData.toString(),
        // @ts-ignore
        timeout
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
async function querySublist3r(domain: string, timeout: number): Promise<string[]> {
    const url = `https://api.sublist3r.com/search.php?domain=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryCertSpotter(domain: string, timeout: number): Promise<string[]> {
    const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryThreatMiner(domain: string, timeout: number): Promise<string[]> {
    const url = `https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=5`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryNetcraft(domain: string, timeout: number): Promise<string[]> {
    const subdomains = new Set<string>();
    const baseUrl = "https://searchdns.netcraft.com/";
    let pageNum = 1;
    let last = "";
    
    for (let i = 0; i < 25; i++) { // Limit to 25 pages (500 results)
        const url = `${baseUrl}?restriction=site+contains&position=limited&host=*.${encodeURIComponent(domain)}&from=${pageNum}${last}`;
        const response = await fetch(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
            timeout
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
        
        pageNum += 20;
    }
    
    return [...subdomains];
}

/**
 * Query Riddler
 */
async function queryRiddler(domain: string, timeout: number): Promise<string[]> {
    const url = `https://riddler.io/search?q=pld:${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryRobtex(domain: string, timeout: number): Promise<string[]> {
    const subdomains = new Set<string>();
    const baseUrl = "https://freeapi.robtex.com/pdns";
    
    // Get forward DNS records
    const forwardUrl = `${baseUrl}/forward/${encodeURIComponent(domain)}`;
    const forwardResponse = await fetch(forwardUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
            const reverseResponse = await fetch(reverseUrl, {
                headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
                // @ts-ignore
                timeout
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
async function querySiteDossier(domain: string, timeout: number): Promise<string[]> {
    const url = `http://www.sitedossier.com/parentdomain/${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryDNSGrep(domain: string, timeout: number): Promise<string[]> {
    const url = `https://dns.bufferover.run/dns?q=.${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryBeVigil(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("BeVigil API token required");
    }
    
    const url = `https://osint.bevigil.com/api/${encodeURIComponent(domain)}/subdomains/`;
    const response = await fetch(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-Access-Token": apiToken
        },
        // @ts-ignore
        timeout
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
async function queryCensys(domain: string, timeout: number, apiId?: string, apiSecret?: string): Promise<string[]> {
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
        const response = await fetch(`${url}?${params}`, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Authorization": `Basic ${auth}`
            },
            // @ts-ignore
            timeout
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
async function queryVirusTotalAPI(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("VirusTotal API token required");
    }
    
    const subdomains = new Set<string>();
    let cursor = "";
    
    for (let i = 0; i < 5; i++) {
        const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/subdomains?limit=40${cursor ? `&cursor=${cursor}` : ""}`;
        const response = await fetch(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "x-apikey": apiToken
            },
            // @ts-ignore
            timeout
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
async function querySecurityTrails(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("SecurityTrails API token required");
    }
    
    const url = `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains`;
    const response = await fetch(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "APIKEY": apiToken
        },
        // @ts-ignore
        timeout
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
async function queryShodan(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Shodan API token required");
    }
    
    const url = `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(apiToken)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryGitHub(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("GitHub API token required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 3; page++) {
        const url = `https://api.github.com/search/code?q=${encodeURIComponent(domain)}&per_page=100&page=${page}&sort=indexed`;
        const response = await fetch(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/vnd.github.v3.text-match+json",
                "Authorization": `token ${apiToken}`
            },
            // @ts-ignore
            timeout
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
async function queryBinaryEdge(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("BinaryEdge API token required");
    }
    
    const subdomains = new Set<string>();
    let page = 1;
    
    for (let i = 0; i < 5; i++) {
        const url = `https://api.binaryedge.io/v2/query/domains/subdomain/${encodeURIComponent(domain)}?page=${page}`;
        const response = await fetch(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "X-Key": apiToken
            },
            // @ts-ignore
            timeout
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
async function queryFullHunt(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("FullHunt API token required");
    }
    
    const url = `https://fullhunt.io/api/v1/domain/${encodeURIComponent(domain)}/subdomains`;
    const response = await fetch(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-API-KEY": apiToken
        },
        // @ts-ignore
        timeout
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
async function queryGoogleCT(domain: string, timeout: number): Promise<string[]> {
    const url = `https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryMySSL(domain: string, timeout: number): Promise<string[]> {
    const url = `https://myssl.com/api/v1/discover_sub_domain?domain=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryIP138(domain: string, timeout: number): Promise<string[]> {
    const url = `https://site.ip138.com/${encodeURIComponent(domain)}/domain.htm`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryRiskIQ(domain: string, timeout: number, username?: string, apiKey?: string): Promise<string[]> {
    if (!username || !apiKey) {
        throw new Error("RiskIQ API credentials required");
    }
    
    const url = `https://api.riskiq.net/pt/v2/enrichment/subdomains?query=${encodeURIComponent(domain)}`;
    const auth = btoa(`${username}:${apiKey}`);
    
    const response = await fetch(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
            "Authorization": `Basic ${auth}`
        },
        // @ts-ignore
        timeout
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
async function queryThreatBook(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("ThreatBook API key required");
    }
    
    const url = `https://api.threatbook.cn/v3/domain/sub_domains?apikey=${encodeURIComponent(apiKey)}&resource=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryFOFA(domain: string, timeout: number, email?: string, apiKey?: string): Promise<string[]> {
    if (!email || !apiKey) {
        throw new Error("FOFA API credentials required");
    }
    
    const subdomains = new Set<string>();
    const query = `domain="${domain}"`;
    const qbase64 = btoa(query);
    
    for (let page = 1; page <= 5; page++) {
        const url = `https://fofa.info/api/v1/search/all?email=${encodeURIComponent(email)}&key=${encodeURIComponent(apiKey)}&qbase64=${qbase64}&page=${page}&size=100&full=true`;
        const response = await fetch(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
            timeout
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
async function queryHunter(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Hunter API key required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 5; page++) {
        const url = `https://hunter.qianxin.com/openApi/search?api-key=${encodeURIComponent(apiKey)}&search=${encodeURIComponent(domain)}&page=${page}&page_size=100&is_web=1`;
        const response = await fetch(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
            timeout
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
async function queryQuake(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
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
        
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json",
                "X-QuakeToken": apiKey
            },
            body,
            // @ts-ignore
            timeout
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
async function queryZoomEye(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("ZoomEye API key required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 5; page++) {
        const url = `https://api.zoomeye.org/domain/search?q=${encodeURIComponent(domain)}&page=${page}&type=1`;
        const response = await fetch(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "API-KEY": apiKey
            },
            // @ts-ignore
            timeout
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
async function querySpyse(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Spyse API token required");
    }
    
    const url = `https://api.spyse.com/v4/data/domain/subdomain?domain=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Authorization": `Bearer ${apiToken}`
        },
        // @ts-ignore
        timeout
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
async function queryChinaz(domain: string, timeout: number): Promise<string[]> {
    const url = `https://alexa.chinaz.com/${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryCeBaidu(domain: string, timeout: number): Promise<string[]> {
    const url = `https://ce.baidu.com/index/getRelatedSites?site_address=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryQianxun(domain: string, timeout: number): Promise<string[]> {
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 10; page++) {
        const url = `https://www.dnsscan.cn/dns.html?keywords=${encodeURIComponent(domain)}&page=${page}`;
        const response = await fetch(url, {
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
            timeout
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
async function queryWindvane(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
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
        
        const response = await fetch(url, {
            method: "POST",
            headers,
            body,
            // @ts-ignore
            timeout
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
async function queryRacent(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Racent API token required");
    }
    
    const url = `https://face.racent.com/tool/query_ctlog?token=${encodeURIComponent(apiToken)}&keyword=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryCDX(domain: string, timeout: number): Promise<string[]> {
    const subdomains = new Set<string>();
    const url = `https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.${encodeURIComponent(domain)}&output=json`;
    
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryArchive(domain: string, timeout: number): Promise<string[]> {
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryChinazAPI(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Chinaz API key required");
    }
    
    const url = `https://apidata.chinaz.com/CallAPI/Alexa?key=${encodeURIComponent(apiKey)}&domainName=${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
        timeout
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
async function queryCIRCL(domain: string, timeout: number, username?: string, password?: string): Promise<string[]> {
    if (!username || !password) {
        throw new Error("CIRCL API credentials required");
    }
    
    const url = `https://www.circl.lu/pdns/query/${encodeURIComponent(domain)}`;
    const auth = btoa(`${username}:${password}`);
    
    const response = await fetch(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Authorization": `Basic ${auth}`
        },
        // @ts-ignore
        timeout
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
async function queryCloudflare(domain: string, timeout: number, apiToken?: string): Promise<string[]> {
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
    const accountResponse = await fetch("https://api.cloudflare.com/client/v4/accounts", {
        headers,
        // @ts-ignore
        timeout
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
    const zonesResponse = await fetch(`https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(domain)}`, {
        headers,
        // @ts-ignore
        timeout
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
        const dnsResponse = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?page=${page}&per_page=100`, {
            headers,
            // @ts-ignore
            timeout
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
async function queryDNSDB(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("DNSDB API key required");
    }
    
    const url = `https://api.dnsdb.info/lookup/rrset/name/*.${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-API-Key": apiKey
        },
        // @ts-ignore
        timeout
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
async function queryIPv4Info(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("IPv4Info API key required");
    }
    
    const subdomains = new Set<string>();
    
    for (let page = 0; page < 50; page++) {
        const url = `http://ipv4info.com/api_v1/?type=SUBDOMAINS&key=${encodeURIComponent(apiKey)}&value=${encodeURIComponent(domain)}&page=${page}`;
        const response = await fetch(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
            timeout
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
async function queryPassiveDNS(domain: string, timeout: number, apiToken?: string, apiAddr?: string): Promise<string[]> {
    const baseUrl = apiAddr || "http://api.passivedns.cn";
    
    const headers: Record<string, string> = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    };
    
    if (apiToken) {
        headers["X-AuthToken"] = apiToken;
    }
    
    const url = `${baseUrl}/flint/rrset/*.${encodeURIComponent(domain)}`;
    const response = await fetch(url, {
        headers,
        // @ts-ignore
        timeout
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
async function queryBingAPI(domain: string, timeout: number, apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Bing API key required");
    }
    
    const subdomains = new Set<string>();
    let offset = 0;
    const perPage = 50;
    
    for (let i = 0; i < 20; i++) { // Limit to 1000 results (20 * 50)
        const query = `site:.${domain}`;
        const url = `https://api.bing.microsoft.com/v7.0/search?q=${encodeURIComponent(query)}&count=${perPage}&offset=${offset}&safesearch=Off`;
        
        const response = await fetch(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Ocp-Apim-Subscription-Key": apiKey
            },
            // @ts-ignore
            timeout
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
async function queryGoogleAPI(domain: string, timeout: number, apiKey?: string, searchEngineId?: string): Promise<string[]> {
    if (!apiKey || !searchEngineId) {
        throw new Error("Google API key and search engine ID required");
    }
    
    const subdomains = new Set<string>();
    
    for (let start = 1; start <= 91; start += 10) { // Max 100 results (10 pages)
        const query = `site:.${domain}`;
        const url = `https://www.googleapis.com/customsearch/v1?key=${encodeURIComponent(apiKey)}&cx=${encodeURIComponent(searchEngineId)}&q=${encodeURIComponent(query)}&fields=items/link&start=${start}&num=10`;
        
        const response = await fetch(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
            timeout
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
async function queryGitee(domain: string, timeout: number): Promise<string[]> {
    const subdomains = new Set<string>();
    
    for (let page = 1; page <= 100; page++) {
        const url = `https://search.gitee.com/?pageno=${page}&q=${encodeURIComponent(domain)}&type=code`;
        const response = await fetch(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
            timeout
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
    domain: string,
    timeout: number,
    apiConfig?: ApiConfig
): Promise<SourceResult> {
    const startTime = performance.now();
    
    try {
        let subdomains: string[];
        
        switch (source) {
            // Certificate sources
            case "crtsh":
                subdomains = await queryCrtsh(domain, timeout);
                break;
            case "certspotter":
                subdomains = await queryCertSpotter(domain, timeout);
                break;
            case "censys":
                subdomains = await queryCensys(domain, timeout, apiConfig?.censys_id, apiConfig?.censys_secret);
                break;
            case "google_ct":
                subdomains = await queryGoogleCT(domain, timeout);
                break;
            case "myssl":
                subdomains = await queryMySSL(domain, timeout);
                break;
            case "racent":
                subdomains = await queryRacent(domain, timeout, apiConfig?.racent_token);
                break;
            
            // Dataset sources
            case "hackertarget":
                subdomains = await queryHackerTarget(domain, timeout);
                break;
            case "rapiddns":
                subdomains = await queryRapidDNS(domain, timeout);
                break;
            case "anubis":
                subdomains = await queryAnubis(domain, timeout);
                break;
            case "dnsdumpster":
                subdomains = await queryDNSDumpster(domain, timeout);
                break;
            case "sublist3r":
                subdomains = await querySublist3r(domain, timeout);
                break;
            case "bevigil":
                subdomains = await queryBeVigil(domain, timeout, apiConfig?.bevigil_token);
                break;
            case "binaryedge":
                subdomains = await queryBinaryEdge(domain, timeout, apiConfig?.binaryedge_token);
                break;
            case "dnsgrep":
                subdomains = await queryDNSGrep(domain, timeout);
                break;
            case "fullhunt":
                subdomains = await queryFullHunt(domain, timeout, apiConfig?.fullhunt_token);
                break;
            case "netcraft":
                subdomains = await queryNetcraft(domain, timeout);
                break;
            case "riddler":
                subdomains = await queryRiddler(domain, timeout);
                break;
            case "robtex":
                subdomains = await queryRobtex(domain, timeout);
                break;
            case "securitytrails":
                subdomains = await querySecurityTrails(domain, timeout, apiConfig?.securitytrails_token);
                break;
            case "sitedossier":
                subdomains = await querySiteDossier(domain, timeout);
                break;
            case "spyse":
                subdomains = await querySpyse(domain, timeout, apiConfig?.spyse_token);
                break;
            case "ip138":
                subdomains = await queryIP138(domain, timeout);
                break;
            case "chinaz":
                subdomains = await queryChinaz(domain, timeout);
                break;
            case "chinaz_api":
                subdomains = await queryChinazAPI(domain, timeout, apiConfig?.chinaz_token);
                break;
            case "cebaidu":
                subdomains = await queryCeBaidu(domain, timeout);
                break;
            case "circl":
                subdomains = await queryCIRCL(domain, timeout, apiConfig?.circl_user, apiConfig?.circl_pass);
                break;
            case "cloudflare":
                subdomains = await queryCloudflare(domain, timeout, apiConfig?.cloudflare_token);
                break;
            case "dnsdb":
                subdomains = await queryDNSDB(domain, timeout, apiConfig?.dnsdb_token);
                break;
            case "ipv4info":
                subdomains = await queryIPv4Info(domain, timeout, apiConfig?.ipv4info_token);
                break;
            case "passivedns":
                subdomains = await queryPassiveDNS(domain, timeout, apiConfig?.passivedns_token, apiConfig?.passivedns_addr);
                break;
            case "qianxun":
                subdomains = await queryQianxun(domain, timeout);
                break;
            case "windvane":
                subdomains = await queryWindvane(domain, timeout, apiConfig?.windvane_token);
                break;
            
            // Intelligence sources
            case "alienvault":
                subdomains = await queryAlienVault(domain, timeout);
                break;
            case "virustotal":
                subdomains = await queryVirusTotal(domain, timeout);
                break;
            case "virustotal_api":
                subdomains = await queryVirusTotalAPI(domain, timeout, apiConfig?.virustotal_token);
                break;
            case "threatminer":
                subdomains = await queryThreatMiner(domain, timeout);
                break;
            case "riskiq":
                subdomains = await queryRiskIQ(domain, timeout, apiConfig?.riskiq_user, apiConfig?.riskiq_key);
                break;
            case "threatbook":
                subdomains = await queryThreatBook(domain, timeout, apiConfig?.threatbook_token);
                break;
            
            // Search engines
            case "urlscan":
                subdomains = await queryURLScan(domain, timeout);
                break;
            case "bing_api":
                subdomains = await queryBingAPI(domain, timeout, apiConfig?.bing_token);
                break;
            case "gitee":
                subdomains = await queryGitee(domain, timeout);
                break;
            case "github":
                subdomains = await queryGitHub(domain, timeout, apiConfig?.github_token);
                break;
            case "google_api":
                subdomains = await queryGoogleAPI(domain, timeout, apiConfig?.google_key, apiConfig?.google_cx);
                break;
            case "shodan":
                subdomains = await queryShodan(domain, timeout, apiConfig?.shodan_token);
                break;
            case "fofa":
                subdomains = await queryFOFA(domain, timeout, apiConfig?.fofa_email, apiConfig?.fofa_key);
                break;
            case "hunter":
                subdomains = await queryHunter(domain, timeout, apiConfig?.hunter_token);
                break;
            case "quake":
                subdomains = await queryQuake(domain, timeout, apiConfig?.quake_token);
                break;
            case "zoomeye":
                subdomains = await queryZoomEye(domain, timeout, apiConfig?.zoomeye_token);
                break;
            
            // Check methods
            case "cdx":
                subdomains = await queryCDX(domain, timeout);
                break;
            
            // Crawl methods
            case "archive":
                subdomains = await queryArchive(domain, timeout);
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
 * Run tasks with concurrency limit
 */
async function runWithConcurrency<T>(
    tasks: (() => Promise<T>)[],
    concurrency: number
): Promise<T[]> {
    const results: T[] = [];
    const executing: Promise<void>[] = [];
    
    for (const task of tasks) {
        const p = task().then(result => {
            results.push(result);
        });
        executing.push(p);
        
        if (executing.length >= concurrency) {
            await Promise.race(executing);
            // Remove completed promises
            for (let i = executing.length - 1; i >= 0; i--) {
                // Check if promise is settled by racing with resolved promise
                const settled = await Promise.race([
                    executing[i].then(() => true).catch(() => true),
                    Promise.resolve(false)
                ]);
                if (settled) {
                    executing.splice(i, 1);
                }
            }
        }
    }
    
    await Promise.all(executing);
    return results;
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        // Validate domain
        if (!input.domain || typeof input.domain !== "string") {
            return {
                success: false,
                error: "Invalid input: domain parameter is required"
            };
        }
        
        const domain = input.domain.toLowerCase().trim();
        
        // Validate domain format
        if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) {
            return {
                success: false,
                error: `Invalid domain format: ${domain}`
            };
        }
        
        const timeout = input.timeout || 30000;
        const concurrency = input.concurrency || 20;
        const removeDuplicates = input.removeDuplicates !== false;
        
        // Determine sources to query
        let sources: DataSource[] = [...AVAILABLE_SOURCES];
        if (input.sources && Array.isArray(input.sources) && input.sources.length > 0) {
            sources = input.sources.filter(s => 
                AVAILABLE_SOURCES.includes(s as DataSource)
            ) as DataSource[];
            
            if (sources.length === 0) {
                return {
                    success: false,
                    error: `No valid sources specified. Available: ${AVAILABLE_SOURCES.join(", ")}`
                };
            }
        }
        
        // Create tasks
        const tasks = sources.map(source => () => querySource(source, domain, timeout, input.apiConfig));
        
        // Execute with concurrency
        const sourceResults = await runWithConcurrency(tasks, concurrency);
        
        // Aggregate results
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
        
        // Deduplicate if requested
        const finalSubdomains = removeDuplicates 
            ? [...new Set(allSubdomains)].sort()
            : allSubdomains.sort();
        
        return {
            success: true,
            data: {
                domain,
                subdomains: finalSubdomains,
                sourceResults: sourceResults.sort((a, b) => b.count - a.count),
                summary: {
                    totalUnique: new Set(allSubdomains).size,
                    totalFound: allSubdomains.length,
                    sourcesQueried: sources.length,
                    sourcesSucceeded,
                    sourcesFailed
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

globalThis.analyze = analyze;
