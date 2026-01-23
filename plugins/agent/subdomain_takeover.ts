/**
 * Subdomain Takeover Detector Tool
 * 
 * @plugin subdomain_takeover
 * @name Subdomain Takeover Detector
 * @version 1.0.0
 * @author Sentinel Team
 * @category vuln
 * @default_severity high
 * @tags subdomain, takeover, dns, vulnerability, security
 * @description Detect potential subdomain takeover vulnerabilities by checking DNS records and service fingerprints
 */

interface ToolInput {
    subdomains: string[];
    timeout?: number;
    concurrency?: number;
    checkCname?: boolean;
    checkHttp?: boolean;
    userAgent?: string;
}

interface TakeoverResult {
    subdomain: string;
    vulnerable: boolean;
    riskLevel: "critical" | "high" | "medium" | "low" | "info";
    service?: string;
    cname?: string;
    evidence?: string;
    httpStatus?: number;
    httpBody?: string;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        subdomains: string[];
        results: TakeoverResult[];
        summary: {
            total: number;
            vulnerable: number;
            byRiskLevel: Record<string, number>;
            byService: Record<string, number>;
        };
    };
    error?: string;
}

// Service fingerprints for subdomain takeover detection
interface ServiceFingerprint {
    name: string;
    cnames: RegExp[];
    httpFingerprints?: RegExp[];
    nxdomain?: boolean;
    riskLevel: "critical" | "high" | "medium" | "low";
}

const SERVICE_FINGERPRINTS: ServiceFingerprint[] = [
    // Cloud Platforms
    {
        name: "AWS S3",
        cnames: [/\.s3\.amazonaws\.com$/i, /\.s3-[a-z0-9-]+\.amazonaws\.com$/i, /\.s3\.[a-z0-9-]+\.amazonaws\.com$/i],
        httpFingerprints: [/NoSuchBucket/i, /The specified bucket does not exist/i],
        riskLevel: "high",
    },
    {
        name: "AWS Elastic Beanstalk",
        cnames: [/\.elasticbeanstalk\.com$/i],
        httpFingerprints: [/404 Not Found/i],
        nxdomain: true,
        riskLevel: "high",
    },
    {
        name: "Azure",
        cnames: [
            /\.azurewebsites\.net$/i,
            /\.cloudapp\.net$/i,
            /\.cloudapp\.azure\.com$/i,
            /\.azurefd\.net$/i,
            /\.blob\.core\.windows\.net$/i,
            /\.azure-api\.net$/i,
            /\.azureedge\.net$/i,
            /\.azurecontainer\.io$/i,
            /\.database\.windows\.net$/i,
            /\.azurehdinsight\.net$/i,
            /\.redis\.cache\.windows\.net$/i,
            /\.search\.windows\.net$/i,
            /\.servicebus\.windows\.net$/i,
            /\.trafficmanager\.net$/i,
        ],
        httpFingerprints: [
            /404 Web Site not found/i,
            /Web App - Pair Not Found/i,
            /The resource you are looking for has been removed/i,
        ],
        nxdomain: true,
        riskLevel: "high",
    },
    {
        name: "Google Cloud Storage",
        cnames: [/\.storage\.googleapis\.com$/i, /\.storage-download\.googleapis\.com$/i],
        httpFingerprints: [/NoSuchBucket/i, /The specified bucket does not exist/i],
        riskLevel: "high",
    },
    {
        name: "Google App Engine",
        cnames: [/\.appspot\.com$/i],
        httpFingerprints: [/404 Not Found/i],
        nxdomain: true,
        riskLevel: "medium",
    },
    
    // Hosting & CDN
    {
        name: "GitHub Pages",
        cnames: [/\.github\.io$/i, /\.githubusercontent\.com$/i],
        httpFingerprints: [/There isn't a GitHub Pages site here/i, /404 - File not found/i],
        riskLevel: "high",
    },
    {
        name: "GitLab Pages",
        cnames: [/\.gitlab\.io$/i],
        httpFingerprints: [/The page you're looking for could not be found/i],
        riskLevel: "high",
    },
    {
        name: "Bitbucket",
        cnames: [/\.bitbucket\.io$/i],
        httpFingerprints: [/Repository not found/i],
        riskLevel: "high",
    },
    {
        name: "Netlify",
        cnames: [/\.netlify\.app$/i, /\.netlify\.com$/i],
        httpFingerprints: [/Not Found - Request ID/i, /Page Not Found/i],
        nxdomain: true,
        riskLevel: "high",
    },
    {
        name: "Vercel",
        cnames: [/\.vercel\.app$/i, /\.now\.sh$/i],
        httpFingerprints: [/The deployment could not be found/i, /404: NOT_FOUND/i],
        nxdomain: true,
        riskLevel: "high",
    },
    {
        name: "Heroku",
        cnames: [/\.herokuapp\.com$/i, /\.herokussl\.com$/i],
        httpFingerprints: [/No such app/i, /There is no app configured at that hostname/i],
        nxdomain: true,
        riskLevel: "high",
    },
    {
        name: "Surge.sh",
        cnames: [/\.surge\.sh$/i],
        httpFingerprints: [/project not found/i],
        nxdomain: true,
        riskLevel: "high",
    },
    {
        name: "Pantheon",
        cnames: [/\.pantheonsite\.io$/i, /\.pantheon\.io$/i],
        httpFingerprints: [/404 error unknown site/i, /The gods are wise/i],
        riskLevel: "high",
    },
    {
        name: "Fastly",
        cnames: [/\.fastly\.net$/i, /\.fastlylb\.net$/i],
        httpFingerprints: [/Fastly error: unknown domain/i],
        riskLevel: "high",
    },
    {
        name: "Cloudflare",
        cnames: [/\.cloudflare\.com$/i, /\.cloudflaressl\.com$/i],
        httpFingerprints: [/Error 1001/i, /DNS resolution error/i],
        riskLevel: "medium",
    },
    {
        name: "CloudFront",
        cnames: [/\.cloudfront\.net$/i],
        httpFingerprints: [/ERROR: The request could not be satisfied/i, /Bad request/i],
        riskLevel: "high",
    },
    
    // Marketing & CMS
    {
        name: "WordPress.com",
        cnames: [/\.wordpress\.com$/i],
        httpFingerprints: [/Do you want to register/i],
        riskLevel: "medium",
    },
    {
        name: "Tumblr",
        cnames: [/\.tumblr\.com$/i],
        httpFingerprints: [/There's nothing here/i, /Whatever you were looking for doesn't currently exist/i],
        riskLevel: "medium",
    },
    {
        name: "Ghost",
        cnames: [/\.ghost\.io$/i],
        httpFingerprints: [/The thing you were looking for is no longer here/i],
        riskLevel: "high",
    },
    {
        name: "Shopify",
        cnames: [/\.myshopify\.com$/i],
        httpFingerprints: [/Sorry, this shop is currently unavailable/i, /Only one step left/i],
        riskLevel: "high",
    },
    {
        name: "Squarespace",
        cnames: [/\.squarespace\.com$/i],
        httpFingerprints: [/No Such Account/i],
        riskLevel: "medium",
    },
    {
        name: "Webflow",
        cnames: [/\.webflow\.io$/i],
        httpFingerprints: [/The page you are looking for doesn't exist/i, /Uh oh. That page doesn't exist/i],
        riskLevel: "high",
    },
    {
        name: "HubSpot",
        cnames: [/\.hubspot\.net$/i, /\.hs-sites\.com$/i],
        httpFingerprints: [/Domain not configured/i],
        riskLevel: "medium",
    },
    {
        name: "Unbounce",
        cnames: [/\.unbounce\.com$/i, /\.unbouncepages\.com$/i],
        httpFingerprints: [/The requested URL was not found on this server/i],
        riskLevel: "high",
    },
    {
        name: "Landingi",
        cnames: [/\.landingi\.com$/i],
        httpFingerprints: [/It looks like you're lost/i],
        riskLevel: "high",
    },
    
    // Communication & Support
    {
        name: "Zendesk",
        cnames: [/\.zendesk\.com$/i],
        httpFingerprints: [/Help Center Closed/i, /Oops, this help center no longer exists/i],
        riskLevel: "medium",
    },
    {
        name: "Freshdesk",
        cnames: [/\.freshdesk\.com$/i],
        httpFingerprints: [/There is no helpdesk here/i, /May be this is still fresh/i],
        riskLevel: "medium",
    },
    {
        name: "Intercom",
        cnames: [/\.intercom\.io$/i, /\.intercom\.help$/i],
        httpFingerprints: [/This page is reserved for artistic dogs/i, /Uh oh. That page doesn't exist/i],
        riskLevel: "medium",
    },
    {
        name: "Help Scout",
        cnames: [/\.helpscoutdocs\.com$/i],
        httpFingerprints: [/No settings were found for this company/i],
        riskLevel: "medium",
    },
    {
        name: "Tawk.to",
        cnames: [/\.tawk\.to$/i],
        httpFingerprints: [/The page you are looking for is no longer here/i],
        riskLevel: "medium",
    },
    
    // Other Services
    {
        name: "Cargo Collective",
        cnames: [/\.cargocollective\.com$/i],
        httpFingerprints: [/404 Not Found/i],
        riskLevel: "medium",
    },
    {
        name: "Feedpress",
        cnames: [/\.feedpress\.me$/i, /redirect\.feedpress\.me$/i],
        httpFingerprints: [/The feed has not been found/i],
        riskLevel: "medium",
    },
    {
        name: "Fly.io",
        cnames: [/\.fly\.dev$/i],
        httpFingerprints: [/404 Not Found/i],
        nxdomain: true,
        riskLevel: "high",
    },
    {
        name: "Readme.io",
        cnames: [/\.readme\.io$/i],
        httpFingerprints: [/Project doesnt exist/i],
        riskLevel: "medium",
    },
    {
        name: "Strikingly",
        cnames: [/\.strikinglydns\.com$/i, /\.s\.strikinglydns\.com$/i],
        httpFingerprints: [/page not found/i],
        riskLevel: "high",
    },
    {
        name: "Tilda",
        cnames: [/\.tilda\.ws$/i],
        httpFingerprints: [/Please renew your subscription/i],
        riskLevel: "medium",
    },
    {
        name: "UserVoice",
        cnames: [/\.uservoice\.com$/i],
        httpFingerprints: [/This UserVoice subdomain is currently available/i],
        riskLevel: "medium",
    },
    {
        name: "Wix",
        cnames: [/\.wixsite\.com$/i],
        httpFingerprints: [/Error connecting to the site/i],
        riskLevel: "medium",
    },
    {
        name: "Agile CRM",
        cnames: [/\.agilecrm\.com$/i],
        httpFingerprints: [/Sorry, this page is no longer available/i],
        riskLevel: "medium",
    },
    {
        name: "Aha!",
        cnames: [/\.ideas\.aha\.io$/i],
        httpFingerprints: [/There is no portal here/i],
        riskLevel: "medium",
    },
    {
        name: "Airee",
        cnames: [/\.airee\.ru$/i],
        httpFingerprints: [/Ошибка 402/i],
        riskLevel: "medium",
    },
    {
        name: "Anima",
        cnames: [/\.animaapp\.io$/i],
        httpFingerprints: [/If this is your website and you've just created it/i],
        riskLevel: "high",
    },
    {
        name: "Announcekit",
        cnames: [/\.announcekit\.app$/i],
        httpFingerprints: [/Error 404/i],
        riskLevel: "medium",
    },
    {
        name: "Canny",
        cnames: [/\.canny\.io$/i],
        httpFingerprints: [/Company Not Found/i, /There is no such company/i],
        riskLevel: "medium",
    },
    {
        name: "Desk",
        cnames: [/\.desk\.com$/i],
        httpFingerprints: [/Please try again or try Desk\.com free/i, /Sorry, We Couldn't Find That Page/i],
        riskLevel: "medium",
    },
    {
        name: "GetResponse",
        cnames: [/\.gr8\.com$/i],
        httpFingerprints: [/With GetResponse Landing Pages/i],
        riskLevel: "medium",
    },
    {
        name: "Kajabi",
        cnames: [/\.mykajabi\.com$/i],
        httpFingerprints: [/The page you were looking for doesn't exist/i],
        riskLevel: "medium",
    },
    {
        name: "Launchrock",
        cnames: [/\.launchrock\.com$/i],
        httpFingerprints: [/It looks like you may have taken a wrong turn somewhere/i],
        riskLevel: "medium",
    },
    {
        name: "Mashery",
        cnames: [/\.mashery\.com$/i],
        httpFingerprints: [/Unrecognized domain/i],
        riskLevel: "medium",
    },
    {
        name: "Ngrok",
        cnames: [/\.ngrok\.io$/i],
        httpFingerprints: [/Tunnel .* not found/i, /ngrok\.io not found/i],
        nxdomain: true,
        riskLevel: "high",
    },
    {
        name: "Pingdom",
        cnames: [/\.stats\.pingdom\.com$/i],
        httpFingerprints: [/This public report page has not been activated by the user/i],
        riskLevel: "low",
    },
    {
        name: "Proposify",
        cnames: [/\.proposify\.biz$/i],
        httpFingerprints: [/If you need immediate assistance/i],
        riskLevel: "medium",
    },
    {
        name: "Short.io",
        cnames: [/\.short\.io$/i],
        httpFingerprints: [/Link does not exist/i],
        riskLevel: "medium",
    },
    {
        name: "SmartJobBoard",
        cnames: [/\.smartjobboard\.com$/i],
        httpFingerprints: [/This job board website is either expired or its domain name is invalid/i],
        riskLevel: "medium",
    },
    {
        name: "Smugmug",
        cnames: [/\.smugmug\.com$/i],
        httpFingerprints: [/\{\"text\":\"Page Not Found\"\}/i],
        riskLevel: "medium",
    },
    {
        name: "Statuspage",
        cnames: [/\.statuspage\.io$/i],
        httpFingerprints: [/You are being redirected/i, /Status page pushed a b]ew update/i],
        riskLevel: "medium",
    },
    {
        name: "Surveygizmo",
        cnames: [/\.surveygizmo\.com$/i, /\.surveygizmo\.eu$/i],
        httpFingerprints: [/data-html-name/i],
        riskLevel: "medium",
    },
    {
        name: "Teamwork",
        cnames: [/\.teamwork\.com$/i],
        httpFingerprints: [/Oops - We didn't find your site/i],
        riskLevel: "medium",
    },
    {
        name: "Thinkific",
        cnames: [/\.thinkific\.com$/i],
        httpFingerprints: [/You may have mistyped the address or the page may have moved/i],
        riskLevel: "medium",
    },
    {
        name: "Uberflip",
        cnames: [/\.uberflip\.com$/i],
        httpFingerprints: [/Non-hub874 domain/i, /The URL you've accessed does not provide a hub/i],
        riskLevel: "medium",
    },
    {
        name: "Uptimerobot",
        cnames: [/\.stats\.uptimerobot\.com$/i],
        httpFingerprints: [/page not found/i],
        riskLevel: "low",
    },
    {
        name: "Worksites",
        cnames: [/\.worksites\.net$/i],
        httpFingerprints: [/Hello! Sorry, but the website you&rsquo;re looking for doesn't exist/i],
        riskLevel: "medium",
    },
];

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        required: ["subdomains"],
        properties: {
            subdomains: {
                type: "array",
                items: { type: "string" },
                description: "List of subdomains to check for takeover vulnerabilities"
            },
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: 10000,
                minimum: 1000,
                maximum: 30000
            },
            concurrency: {
                type: "integer",
                description: "Number of concurrent checks",
                default: 10,
                minimum: 1,
                maximum: 50
            },
            checkCname: {
                type: "boolean",
                description: "Check CNAME records",
                default: true
            },
            checkHttp: {
                type: "boolean",
                description: "Check HTTP responses for fingerprints",
                default: true
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
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
                    subdomains: { type: "array", items: { type: "string" }, description: "Checked subdomains" },
                    results: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                subdomain: { type: "string" },
                                vulnerable: { type: "boolean" },
                                riskLevel: { type: "string" },
                                service: { type: "string" },
                                cname: { type: "string" },
                                evidence: { type: "string" }
                            }
                        },
                        description: "Takeover check results"
                    },
                    summary: {
                        type: "object",
                        properties: {
                            total: { type: "integer" },
                            vulnerable: { type: "integer" },
                            byRiskLevel: { type: "object" },
                            byService: { type: "object" }
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
 * Resolve CNAME for a subdomain using DNS-over-HTTPS
 */
async function resolveCname(subdomain: string, timeout: number): Promise<string | null> {
    try {
        // Use Cloudflare DNS-over-HTTPS
        const response = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(subdomain)}&type=CNAME`,
            {
                headers: {
                    "Accept": "application/dns-json",
                },
                // @ts-ignore
                timeout,
            }
        );
        
        if (!response.ok) {
            return null;
        }
        
        const data = await response.json();
        
        // Check for CNAME record
        if (data.Answer && data.Answer.length > 0) {
            for (const answer of data.Answer) {
                if (answer.type === 5) { // CNAME record type
                    return answer.data.replace(/\.$/, ""); // Remove trailing dot
                }
            }
        }
        
        return null;
    } catch {
        return null;
    }
}

/**
 * Check if subdomain resolves (has A/AAAA record)
 */
async function checkResolution(subdomain: string, timeout: number): Promise<boolean> {
    try {
        const response = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(subdomain)}&type=A`,
            {
                headers: {
                    "Accept": "application/dns-json",
                },
                // @ts-ignore
                timeout,
            }
        );
        
        if (!response.ok) {
            return false;
        }
        
        const data = await response.json();
        
        // NXDOMAIN status is 3
        if (data.Status === 3) {
            return false;
        }
        
        // Check for A record
        return data.Answer && data.Answer.length > 0;
    } catch {
        return false;
    }
}

/**
 * Check HTTP response for takeover fingerprints
 */
async function checkHttpFingerprint(
    subdomain: string,
    service: ServiceFingerprint,
    options: { timeout: number; userAgent: string }
): Promise<{ matches: boolean; evidence?: string; status?: number; body?: string }> {
    if (!service.httpFingerprints || service.httpFingerprints.length === 0) {
        return { matches: false };
    }
    
    // Try both HTTP and HTTPS
    for (const protocol of ["https", "http"]) {
        try {
            const response = await fetch(`${protocol}://${subdomain}`, {
                method: "GET",
                headers: {
                    "User-Agent": options.userAgent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                redirect: "follow",
                // @ts-ignore
                timeout: options.timeout,
            });
            
            const body = await response.text();
            
            for (const fingerprint of service.httpFingerprints) {
                if (fingerprint.test(body)) {
                    const match = body.match(fingerprint);
                    return {
                        matches: true,
                        evidence: match ? match[0].substring(0, 100) : "Fingerprint matched",
                        status: response.status,
                        body: body.substring(0, 500),
                    };
                }
            }
            
            return { matches: false, status: response.status };
        } catch {
            // Continue to next protocol
        }
    }
    
    return { matches: false };
}

/**
 * Check a single subdomain for takeover vulnerability
 */
async function checkSubdomain(
    subdomain: string,
    options: {
        timeout: number;
        userAgent: string;
        checkCname: boolean;
        checkHttp: boolean;
    }
): Promise<TakeoverResult> {
    const result: TakeoverResult = {
        subdomain,
        vulnerable: false,
        riskLevel: "info",
    };
    
    try {
        // Step 1: Resolve CNAME
        let cname: string | null = null;
        if (options.checkCname) {
            cname = await resolveCname(subdomain, options.timeout);
            if (cname) {
                result.cname = cname;
            }
        }
        
        // Step 2: Check if CNAME matches known vulnerable services
        let matchedService: ServiceFingerprint | null = null;
        
        if (cname) {
            for (const service of SERVICE_FINGERPRINTS) {
                for (const cnamePattern of service.cnames) {
                    if (cnamePattern.test(cname)) {
                        matchedService = service;
                        result.service = service.name;
                        break;
                    }
                }
                if (matchedService) break;
            }
        }
        
        // Step 3: Check DNS resolution (NXDOMAIN indicates potential takeover)
        if (matchedService && matchedService.nxdomain) {
            const resolves = await checkResolution(cname || subdomain, options.timeout);
            if (!resolves) {
                result.vulnerable = true;
                result.riskLevel = matchedService.riskLevel;
                result.evidence = `CNAME points to ${cname} which does not resolve (NXDOMAIN)`;
                return result;
            }
        }
        
        // Step 4: Check HTTP fingerprint
        if (options.checkHttp && matchedService) {
            const httpResult = await checkHttpFingerprint(subdomain, matchedService, {
                timeout: options.timeout,
                userAgent: options.userAgent,
            });
            
            if (httpResult.matches) {
                result.vulnerable = true;
                result.riskLevel = matchedService.riskLevel;
                result.evidence = httpResult.evidence;
                result.httpStatus = httpResult.status;
                result.httpBody = httpResult.body;
                return result;
            }
            
            result.httpStatus = httpResult.status;
        }
        
        // Step 5: Even without CNAME, check HTTP for common fingerprints
        if (options.checkHttp && !matchedService) {
            for (const service of SERVICE_FINGERPRINTS) {
                const httpResult = await checkHttpFingerprint(subdomain, service, {
                    timeout: options.timeout,
                    userAgent: options.userAgent,
                });
                
                if (httpResult.matches) {
                    result.vulnerable = true;
                    result.riskLevel = service.riskLevel;
                    result.service = service.name;
                    result.evidence = httpResult.evidence;
                    result.httpStatus = httpResult.status;
                    result.httpBody = httpResult.body;
                    return result;
                }
            }
        }
        
        return result;
        
    } catch (error: any) {
        result.error = error.message || String(error);
        return result;
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
        if (!input.subdomains || !Array.isArray(input.subdomains)) {
            return {
                success: false,
                error: "Invalid input: subdomains array is required"
            };
        }
        
        // Filter out empty strings
        const validSubdomains = input.subdomains.filter(s => typeof s === 'string' && s.trim().length > 0);
        if (validSubdomains.length === 0) {
            return {
                success: false,
                error: "Invalid input: subdomains array must contain at least one non-empty string"
            };
        }
        
        const timeout = input.timeout || 10000;
        const concurrency = input.concurrency || 10;
        const checkCname = input.checkCname !== false;
        const checkHttp = input.checkHttp !== false;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        
        // Create check tasks
        const tasks = validSubdomains.map(subdomain => () => checkSubdomain(subdomain, {
            timeout,
            userAgent,
            checkCname,
            checkHttp,
        }));
        
        // Execute with concurrency
        const results = await runWithConcurrency(tasks, concurrency);
        
        // Build summary
        const vulnerableResults = results.filter(r => r.vulnerable);
        const byRiskLevel: Record<string, number> = {};
        const byService: Record<string, number> = {};
        
        for (const result of vulnerableResults) {
            byRiskLevel[result.riskLevel] = (byRiskLevel[result.riskLevel] || 0) + 1;
            if (result.service) {
                byService[result.service] = (byService[result.service] || 0) + 1;
            }
        }
        
        return {
            success: true,
            data: {
                subdomains: input.subdomains,
                results,
                summary: {
                    total: results.length,
                    vulnerable: vulnerableResults.length,
                    byRiskLevel,
                    byService,
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
