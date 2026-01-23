/**
 * HTTP Prober Tool
 * 
 * @plugin http_prober
 * @name HTTP Prober
 * @version 1.0.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags http, probe, alive, discovery, web
 * @description Probe HTTP/HTTPS endpoints to check if they are alive, collect response info including status code, title, content length, headers, and technologies
 */

interface ToolInput {
    targets: string[];
    ports?: number[];
    timeout?: number;
    concurrency?: number;
    followRedirects?: boolean;
    maxRedirects?: number;
    userAgent?: string;
    extractTitle?: boolean;
    extractHeaders?: boolean;
    checkHttps?: boolean;
    checkHttp?: boolean;
}

interface ProbeResult {
    url: string;
    alive: boolean;
    statusCode?: number;
    statusText?: string;
    title?: string;
    contentLength?: number;
    contentType?: string;
    server?: string;
    headers?: Record<string, string>;
    redirectUrl?: string;
    responseTime?: number;
    error?: string;
    technologies?: string[];
}

interface ToolOutput {
    success: boolean;
    data?: {
        targets: string[];
        results: ProbeResult[];
        summary: {
            total: number;
            alive: number;
            dead: number;
            byStatusCode: Record<string, number>;
        };
    };
    error?: string;
}

const DEFAULT_PORTS = [80, 443, 8080, 8443];

const TECH_SIGNATURES: Record<string, { header?: string; pattern: RegExp }[]> = {
    "nginx": [
        { header: "server", pattern: /nginx/i },
    ],
    "apache": [
        { header: "server", pattern: /apache/i },
    ],
    "iis": [
        { header: "server", pattern: /microsoft-iis/i },
    ],
    "cloudflare": [
        { header: "server", pattern: /cloudflare/i },
        { header: "cf-ray", pattern: /.+/ },
    ],
    "aws": [
        { header: "server", pattern: /amazons3/i },
        { header: "x-amz-request-id", pattern: /.+/ },
    ],
    "express": [
        { header: "x-powered-by", pattern: /express/i },
    ],
    "php": [
        { header: "x-powered-by", pattern: /php/i },
    ],
    "asp.net": [
        { header: "x-powered-by", pattern: /asp\.net/i },
        { header: "x-aspnet-version", pattern: /.+/ },
    ],
    "django": [
        { header: "x-frame-options", pattern: /SAMEORIGIN/i },
    ],
    "wordpress": [
        { header: "link", pattern: /wp-json/i },
    ],
    "varnish": [
        { header: "via", pattern: /varnish/i },
        { header: "x-varnish", pattern: /.+/ },
    ],
    "akamai": [
        { header: "x-akamai-transformed", pattern: /.+/ },
    ],
};

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
                description: "List of targets to probe (domains, IPs, or URLs)"
            },
            ports: {
                type: "array",
                items: { type: "integer" },
                description: `Ports to probe. Default: ${DEFAULT_PORTS.join(", ")}`,
                default: DEFAULT_PORTS
            },
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: 10000,
                minimum: 1000,
                maximum: 60000
            },
            concurrency: {
                type: "integer",
                description: "Number of concurrent requests",
                default: 10,
                minimum: 1,
                maximum: 50
            },
            followRedirects: {
                type: "boolean",
                description: "Follow HTTP redirects",
                default: true
            },
            maxRedirects: {
                type: "integer",
                description: "Maximum number of redirects to follow",
                default: 5
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header",
                default: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            extractTitle: {
                type: "boolean",
                description: "Extract page title from HTML",
                default: true
            },
            extractHeaders: {
                type: "boolean",
                description: "Include response headers in results",
                default: false
            },
            checkHttps: {
                type: "boolean",
                description: "Check HTTPS protocol",
                default: true
            },
            checkHttp: {
                type: "boolean",
                description: "Check HTTP protocol",
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
                    targets: { type: "array", items: { type: "string" }, description: "Original target list" },
                    results: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                url: { type: "string", description: "Probed URL" },
                                alive: { type: "boolean" },
                                statusCode: { type: "integer" },
                                title: { type: "string" },
                                contentLength: { type: "integer" },
                                server: { type: "string" },
                                technologies: { type: "array", items: { type: "string" } }
                            }
                        },
                        description: "Probe results for alive hosts"
                    },
                    summary: {
                        type: "object",
                        properties: {
                            total: { type: "integer" },
                            alive: { type: "integer" },
                            dead: { type: "integer" }
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
 * Extract title from HTML content
 */
function extractTitle(html: string): string | undefined {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match ? match[1].trim() : undefined;
}

/**
 * Detect technologies from headers
 */
function detectTechnologies(headers: Record<string, string>): string[] {
    const detected: string[] = [];
    
    for (const [tech, signatures] of Object.entries(TECH_SIGNATURES)) {
        for (const sig of signatures) {
            if (sig.header) {
                const headerValue = headers[sig.header.toLowerCase()];
                if (headerValue && sig.pattern.test(headerValue)) {
                    if (!detected.includes(tech)) {
                        detected.push(tech);
                    }
                    break;
                }
            }
        }
    }
    
    return detected;
}

/**
 * Normalize target to URL
 */
function normalizeTarget(target: string, port: number, protocol: string): string {
    // If already a full URL, return as is
    if (target.startsWith("http://") || target.startsWith("https://")) {
        return target;
    }
    
    // Build URL from target
    const defaultPort = protocol === "https" ? 443 : 80;
    if (port === defaultPort) {
        return `${protocol}://${target}`;
    }
    return `${protocol}://${target}:${port}`;
}

/**
 * Probe a single URL
 */
async function probeUrl(
    url: string,
    options: {
        timeout: number;
        followRedirects: boolean;
        maxRedirects: number;
        userAgent: string;
        extractTitle: boolean;
        extractHeaders: boolean;
    }
): Promise<ProbeResult> {
    const startTime = performance.now();
    
    try {
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "User-Agent": options.userAgent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
            redirect: options.followRedirects ? "follow" : "manual",
            // @ts-ignore
            timeout: options.timeout,
        });
        
        const responseTime = Math.round(performance.now() - startTime);
        
        // Convert headers to object
        const headers: Record<string, string> = {};
        response.headers.forEach((value, key) => {
            headers[key.toLowerCase()] = value;
        });
        
        // Get response body for title extraction
        let title: string | undefined;
        let contentLength = parseInt(headers["content-length"] || "0", 10);
        
        if (options.extractTitle) {
            try {
                const text = await response.text();
                title = extractTitle(text);
                if (!contentLength) {
                    contentLength = text.length;
                }
            } catch {
                // Ignore body read errors
            }
        }
        
        // Detect technologies
        const technologies = detectTechnologies(headers);
        
        const result: ProbeResult = {
            url,
            alive: true,
            statusCode: response.status,
            statusText: response.statusText,
            title,
            contentLength,
            contentType: headers["content-type"],
            server: headers["server"],
            responseTime,
            technologies,
        };
        
        if (options.extractHeaders) {
            result.headers = headers;
        }
        
        // Check for redirect
        if (response.redirected) {
            result.redirectUrl = response.url;
        }
        
        return result;
        
    } catch (error: any) {
        const responseTime = Math.round(performance.now() - startTime);
        return {
            url,
            alive: false,
            responseTime,
            error: error.message || String(error),
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
    let index = 0;
    
    async function worker() {
        while (index < tasks.length) {
            const currentIndex = index++;
            const result = await tasks[currentIndex]();
            results[currentIndex] = result;
        }
    }
    
    const workers = Array(Math.min(concurrency, tasks.length))
        .fill(null)
        .map(() => worker());
    
    await Promise.all(workers);
    return results;
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        // Validate input
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
        
        const timeout = input.timeout || 10000;
        const concurrency = input.concurrency || 10;
        const followRedirects = input.followRedirects !== false;
        const maxRedirects = input.maxRedirects || 5;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const extractTitle = input.extractTitle !== false;
        const extractHeaders = input.extractHeaders === true;
        const checkHttps = input.checkHttps !== false;
        const checkHttp = input.checkHttp !== false;
        const ports = input.ports || DEFAULT_PORTS;
        
        // Build URL list
        const urls: string[] = [];
        
        for (const target of validTargets) {
            // If target is already a URL, add it directly
            if (target.startsWith("http://") || target.startsWith("https://")) {
                urls.push(target);
                continue;
            }
            
            // Otherwise, build URLs for each port and protocol
            for (const port of ports) {
                if (checkHttps && (port === 443 || port === 8443 || port !== 80)) {
                    urls.push(normalizeTarget(target, port, "https"));
                }
                if (checkHttp && (port === 80 || port === 8080 || port !== 443)) {
                    urls.push(normalizeTarget(target, port, "http"));
                }
            }
        }
        
        // Deduplicate URLs
        const uniqueUrls = [...new Set(urls)];
        
        // Create probe tasks
        const tasks = uniqueUrls.map(url => () => probeUrl(url, {
            timeout,
            followRedirects,
            maxRedirects,
            userAgent,
            extractTitle,
            extractHeaders,
        }));
        
        // Execute with concurrency
        const results = await runWithConcurrency(tasks, concurrency);
        
        // Calculate summary
        const aliveResults = results.filter(r => r.alive);
        const deadResults = results.filter(r => !r.alive);
        
        const byStatusCode: Record<string, number> = {};
        for (const result of aliveResults) {
            const code = String(result.statusCode || "unknown");
            byStatusCode[code] = (byStatusCode[code] || 0) + 1;
        }
        
        return {
            success: true,
            data: {
                targets: input.targets,
                results: results.filter(r => r.alive), // Only return alive results
                summary: {
                    total: uniqueUrls.length,
                    alive: aliveResults.length,
                    dead: deadResults.length,
                    byStatusCode,
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

globalThis.analyze = analyze;
