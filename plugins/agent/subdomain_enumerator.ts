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
    "crtsh",
    "hackertarget", 
    "rapiddns",
    "alienvault",
    "virustotal",
    "urlscan",
    "anubis",
    "dnsdumpster",
    "sublist3r",
    "certspotter"
] as const;

type DataSource = typeof AVAILABLE_SOURCES[number];

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
 * Query a single data source
 */
async function querySource(
    source: DataSource,
    domain: string,
    timeout: number
): Promise<SourceResult> {
    const startTime = performance.now();
    
    try {
        let subdomains: string[];
        
        switch (source) {
            case "crtsh":
                subdomains = await queryCrtsh(domain, timeout);
                break;
            case "hackertarget":
                subdomains = await queryHackerTarget(domain, timeout);
                break;
            case "rapiddns":
                subdomains = await queryRapidDNS(domain, timeout);
                break;
            case "alienvault":
                subdomains = await queryAlienVault(domain, timeout);
                break;
            case "virustotal":
                subdomains = await queryVirusTotal(domain, timeout);
                break;
            case "urlscan":
                subdomains = await queryURLScan(domain, timeout);
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
            case "certspotter":
                subdomains = await queryCertSpotter(domain, timeout);
                break;
            default:
                throw new Error(`Unknown source: ${source}`);
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
        const concurrency = input.concurrency || 5;
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
        const tasks = sources.map(source => () => querySource(source, domain, timeout));
        
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
