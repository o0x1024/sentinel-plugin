/**
 * Technology Fingerprinter Tool
 * 
 * @plugin tech_fingerprinter
 * @name Technology Fingerprinter
 * @version 1.0.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags fingerprint, technology, wappalyzer, detection, web
 * @description Identify technologies, frameworks, CMS, and libraries used by web applications through HTTP headers, HTML content, cookies, and JavaScript analysis
 */

interface ToolInput {
    url: string;
    timeout?: number;
    userAgent?: string;
    deepScan?: boolean;
}

interface Technology {
    name: string;
    category: string;
    version?: string;
    confidence: number;
    evidence: string[];
}

interface ToolOutput {
    success: boolean;
    data?: {
        url: string;
        technologies: Technology[];
        summary: {
            total: number;
            byCategory: Record<string, string[]>;
        };
    };
    error?: string;
}

// Technology signatures database
interface TechSignature {
    name: string;
    category: string;
    headers?: Record<string, RegExp>;
    cookies?: Record<string, RegExp>;
    html?: RegExp[];
    scripts?: RegExp[];
    meta?: Record<string, RegExp>;
    implies?: string[];
    versionPatterns?: { source: string; pattern: RegExp }[];
}

const TECH_SIGNATURES: TechSignature[] = [
    // Web Servers
    {
        name: "Nginx",
        category: "Web Server",
        headers: { "server": /nginx(?:\/([0-9.]+))?/i },
        versionPatterns: [{ source: "header:server", pattern: /nginx\/([0-9.]+)/i }],
    },
    {
        name: "Apache",
        category: "Web Server",
        headers: { "server": /apache(?:\/([0-9.]+))?/i },
        versionPatterns: [{ source: "header:server", pattern: /apache\/([0-9.]+)/i }],
    },
    {
        name: "Microsoft IIS",
        category: "Web Server",
        headers: { "server": /microsoft-iis(?:\/([0-9.]+))?/i },
        versionPatterns: [{ source: "header:server", pattern: /microsoft-iis\/([0-9.]+)/i }],
    },
    {
        name: "LiteSpeed",
        category: "Web Server",
        headers: { "server": /litespeed/i },
    },
    {
        name: "OpenResty",
        category: "Web Server",
        headers: { "server": /openresty/i },
    },
    
    // CDN & Proxy
    {
        name: "Cloudflare",
        category: "CDN",
        headers: { 
            "server": /cloudflare/i,
            "cf-ray": /.+/,
        },
        cookies: { "__cfduid": /.+/, "cf_clearance": /.+/ },
    },
    {
        name: "AWS CloudFront",
        category: "CDN",
        headers: { 
            "x-amz-cf-id": /.+/,
            "x-amz-cf-pop": /.+/,
        },
    },
    {
        name: "Akamai",
        category: "CDN",
        headers: { 
            "x-akamai-transformed": /.+/,
            "akamai-origin-hop": /.+/,
        },
    },
    {
        name: "Fastly",
        category: "CDN",
        headers: { 
            "x-served-by": /cache-.+\.fastly/i,
            "x-fastly-request-id": /.+/,
        },
    },
    {
        name: "Varnish",
        category: "Cache",
        headers: { 
            "x-varnish": /.+/,
            "via": /varnish/i,
        },
    },
    
    // Programming Languages
    {
        name: "PHP",
        category: "Programming Language",
        headers: { 
            "x-powered-by": /php(?:\/([0-9.]+))?/i,
        },
        cookies: { "PHPSESSID": /.+/ },
        html: [/<\?php/i],
        versionPatterns: [{ source: "header:x-powered-by", pattern: /php\/([0-9.]+)/i }],
    },
    {
        name: "ASP.NET",
        category: "Programming Language",
        headers: { 
            "x-powered-by": /asp\.net/i,
            "x-aspnet-version": /([0-9.]+)/,
        },
        cookies: { "ASP.NET_SessionId": /.+/, "ASPSESSIONID": /.+/ },
        versionPatterns: [{ source: "header:x-aspnet-version", pattern: /([0-9.]+)/ }],
    },
    {
        name: "Java",
        category: "Programming Language",
        cookies: { "JSESSIONID": /.+/ },
        headers: { "x-powered-by": /servlet/i },
    },
    {
        name: "Python",
        category: "Programming Language",
        headers: { "server": /python/i },
    },
    {
        name: "Ruby",
        category: "Programming Language",
        headers: { "x-powered-by": /phusion passenger/i },
        cookies: { "_session_id": /.+/ },
    },
    
    // JavaScript Frameworks
    {
        name: "React",
        category: "JavaScript Framework",
        html: [/data-reactroot/i, /data-reactid/i, /__NEXT_DATA__/],
        scripts: [/react(?:\.min)?\.js/i, /react-dom/i],
    },
    {
        name: "Vue.js",
        category: "JavaScript Framework",
        html: [/data-v-[a-f0-9]+/i, /v-cloak/i, /__VUE__/],
        scripts: [/vue(?:\.min)?\.js/i, /vue\.runtime/i],
    },
    {
        name: "Angular",
        category: "JavaScript Framework",
        html: [/ng-version/i, /ng-app/i, /_ngcontent/i, /\[\(ngModel\)\]/],
        scripts: [/angular(?:\.min)?\.js/i, /@angular\/core/i],
    },
    {
        name: "jQuery",
        category: "JavaScript Library",
        scripts: [/jquery(?:\.min)?\.js/i, /jquery-[0-9.]+/i],
        html: [/jquery/i],
        versionPatterns: [{ source: "script", pattern: /jquery[.-]([0-9.]+)/i }],
    },
    {
        name: "Bootstrap",
        category: "CSS Framework",
        html: [/class="[^"]*\bbootstrap\b/i, /bootstrap\.min\.css/i],
        scripts: [/bootstrap(?:\.min)?\.js/i],
    },
    {
        name: "Tailwind CSS",
        category: "CSS Framework",
        html: [/class="[^"]*\b(flex|grid|bg-|text-|p-|m-|w-|h-)[^"]*"/],
    },
    
    // Web Frameworks
    {
        name: "Next.js",
        category: "Web Framework",
        html: [/__NEXT_DATA__/, /_next\/static/],
        headers: { "x-powered-by": /next\.js/i },
        implies: ["React", "Node.js"],
    },
    {
        name: "Nuxt.js",
        category: "Web Framework",
        html: [/__NUXT__/, /_nuxt\//],
        implies: ["Vue.js", "Node.js"],
    },
    {
        name: "Express",
        category: "Web Framework",
        headers: { "x-powered-by": /express/i },
        implies: ["Node.js"],
    },
    {
        name: "Django",
        category: "Web Framework",
        cookies: { "csrftoken": /.+/, "django_language": /.+/ },
        html: [/csrfmiddlewaretoken/i],
        implies: ["Python"],
    },
    {
        name: "Flask",
        category: "Web Framework",
        headers: { "server": /werkzeug/i },
        implies: ["Python"],
    },
    {
        name: "Laravel",
        category: "Web Framework",
        cookies: { "laravel_session": /.+/, "XSRF-TOKEN": /.+/ },
        html: [/laravel/i],
        implies: ["PHP"],
    },
    {
        name: "Ruby on Rails",
        category: "Web Framework",
        headers: { "x-powered-by": /phusion passenger/i },
        cookies: { "_rails_session": /.+/ },
        meta: { "csrf-token": /.+/ },
        implies: ["Ruby"],
    },
    {
        name: "Spring",
        category: "Web Framework",
        headers: { "x-application-context": /.+/ },
        cookies: { "JSESSIONID": /.+/ },
        implies: ["Java"],
    },
    
    // CMS
    {
        name: "WordPress",
        category: "CMS",
        html: [/wp-content/i, /wp-includes/i, /wp-json/i],
        meta: { "generator": /wordpress/i },
        headers: { "link": /wp-json/i },
        implies: ["PHP", "MySQL"],
        versionPatterns: [{ source: "meta:generator", pattern: /wordpress\s*([0-9.]+)/i }],
    },
    {
        name: "Drupal",
        category: "CMS",
        html: [/drupal\.js/i, /sites\/default\/files/i],
        headers: { "x-drupal-cache": /.+/, "x-generator": /drupal/i },
        meta: { "generator": /drupal/i },
        implies: ["PHP"],
    },
    {
        name: "Joomla",
        category: "CMS",
        html: [/\/media\/jui\//i, /joomla/i],
        meta: { "generator": /joomla/i },
        implies: ["PHP"],
    },
    {
        name: "Shopify",
        category: "E-commerce",
        html: [/cdn\.shopify\.com/i, /shopify/i],
        cookies: { "_shopify_s": /.+/, "cart_sig": /.+/ },
    },
    {
        name: "Magento",
        category: "E-commerce",
        html: [/mage\/cookies/i, /magento/i],
        cookies: { "frontend": /.+/, "adminhtml": /.+/ },
        implies: ["PHP"],
    },
    {
        name: "WooCommerce",
        category: "E-commerce",
        html: [/woocommerce/i, /wc-ajax/i],
        implies: ["WordPress", "PHP"],
    },
    
    // Analytics & Marketing
    {
        name: "Google Analytics",
        category: "Analytics",
        html: [/google-analytics\.com\/analytics\.js/i, /gtag\(/i, /ga\('create'/i],
        scripts: [/googletagmanager\.com/i],
    },
    {
        name: "Google Tag Manager",
        category: "Tag Manager",
        html: [/googletagmanager\.com\/gtm\.js/i, /GTM-[A-Z0-9]+/],
    },
    {
        name: "Facebook Pixel",
        category: "Analytics",
        html: [/connect\.facebook\.net/i, /fbq\(/i],
    },
    {
        name: "Hotjar",
        category: "Analytics",
        html: [/static\.hotjar\.com/i, /hjid/i],
    },
    
    // Security
    {
        name: "reCAPTCHA",
        category: "Security",
        html: [/google\.com\/recaptcha/i, /g-recaptcha/i],
        scripts: [/recaptcha/i],
    },
    {
        name: "hCaptcha",
        category: "Security",
        html: [/hcaptcha\.com/i, /h-captcha/i],
    },
    
    // Hosting
    {
        name: "Amazon S3",
        category: "Cloud Storage",
        headers: { 
            "server": /amazons3/i,
            "x-amz-request-id": /.+/,
        },
    },
    {
        name: "Heroku",
        category: "PaaS",
        headers: { "via": /heroku/i },
    },
    {
        name: "Vercel",
        category: "PaaS",
        headers: { 
            "x-vercel-id": /.+/,
            "server": /vercel/i,
        },
    },
    {
        name: "Netlify",
        category: "PaaS",
        headers: { 
            "x-nf-request-id": /.+/,
            "server": /netlify/i,
        },
    },
    
    // Databases (indirect detection)
    {
        name: "MySQL",
        category: "Database",
        html: [/mysql/i],
    },
    {
        name: "PostgreSQL",
        category: "Database",
        html: [/postgresql/i, /postgres/i],
    },
    {
        name: "MongoDB",
        category: "Database",
        html: [/mongodb/i],
    },
    
    // Node.js
    {
        name: "Node.js",
        category: "Runtime",
        headers: { "x-powered-by": /express/i },
    },
];

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        required: ["url"],
        properties: {
            url: {
                type: "string",
                description: "Target URL to fingerprint"
            },
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: 15000,
                minimum: 5000,
                maximum: 60000
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header",
                default: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            deepScan: {
                type: "boolean",
                description: "Perform deep scan (fetch additional resources like robots.txt, sitemap.xml)",
                default: false
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
                    url: { type: "string", description: "Target URL" },
                    technologies: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                name: { type: "string", description: "Technology name" },
                                category: { type: "string", description: "Technology category" },
                                version: { type: "string" },
                                confidence: { type: "integer" }
                            }
                        },
                        description: "Detected technologies"
                    },
                    summary: {
                        type: "object",
                        properties: {
                            total: { type: "integer" },
                            byCategory: { type: "object" }
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
 * Parse cookies from Set-Cookie header
 */
function parseCookies(setCookieHeaders: string[]): Record<string, string> {
    const cookies: Record<string, string> = {};
    for (const header of setCookieHeaders) {
        const match = header.match(/^([^=]+)=([^;]*)/);
        if (match) {
            cookies[match[1].trim()] = match[2];
        }
    }
    return cookies;
}

/**
 * Extract meta tags from HTML
 */
function extractMetaTags(html: string): Record<string, string> {
    const meta: Record<string, string> = {};
    const regex = /<meta\s+(?:[^>]*?\s+)?(?:name|property)=["']([^"']+)["'][^>]*?\s+content=["']([^"']+)["']/gi;
    let match;
    while ((match = regex.exec(html)) !== null) {
        meta[match[1].toLowerCase()] = match[2];
    }
    // Also check content before name
    const regex2 = /<meta\s+(?:[^>]*?\s+)?content=["']([^"']+)["'][^>]*?\s+(?:name|property)=["']([^"']+)["']/gi;
    while ((match = regex2.exec(html)) !== null) {
        meta[match[2].toLowerCase()] = match[1];
    }
    return meta;
}

/**
 * Extract script sources from HTML
 */
function extractScripts(html: string): string[] {
    const scripts: string[] = [];
    const regex = /<script[^>]*\s+src=["']([^"']+)["']/gi;
    let match;
    while ((match = regex.exec(html)) !== null) {
        scripts.push(match[1]);
    }
    return scripts;
}

/**
 * Detect technologies from collected data
 */
function detectTechnologies(
    headers: Record<string, string>,
    cookies: Record<string, string>,
    html: string,
    meta: Record<string, string>,
    scripts: string[]
): Technology[] {
    const detected: Map<string, Technology> = new Map();
    
    for (const sig of TECH_SIGNATURES) {
        const evidence: string[] = [];
        let confidence = 0;
        let version: string | undefined;
        
        // Check headers
        if (sig.headers) {
            for (const [headerName, pattern] of Object.entries(sig.headers)) {
                const headerValue = headers[headerName.toLowerCase()];
                if (headerValue && pattern.test(headerValue)) {
                    evidence.push(`Header: ${headerName}`);
                    confidence += 30;
                }
            }
        }
        
        // Check cookies
        if (sig.cookies) {
            for (const [cookieName, pattern] of Object.entries(sig.cookies)) {
                const cookieValue = cookies[cookieName];
                if (cookieValue !== undefined && pattern.test(cookieValue)) {
                    evidence.push(`Cookie: ${cookieName}`);
                    confidence += 25;
                }
            }
        }
        
        // Check HTML patterns
        if (sig.html) {
            for (const pattern of sig.html) {
                if (pattern.test(html)) {
                    evidence.push(`HTML pattern: ${pattern.source.substring(0, 30)}`);
                    confidence += 20;
                }
            }
        }
        
        // Check scripts
        if (sig.scripts) {
            for (const pattern of sig.scripts) {
                for (const script of scripts) {
                    if (pattern.test(script)) {
                        evidence.push(`Script: ${script.substring(0, 50)}`);
                        confidence += 25;
                    }
                }
            }
        }
        
        // Check meta tags
        if (sig.meta) {
            for (const [metaName, pattern] of Object.entries(sig.meta)) {
                const metaValue = meta[metaName.toLowerCase()];
                if (metaValue && pattern.test(metaValue)) {
                    evidence.push(`Meta: ${metaName}`);
                    confidence += 30;
                }
            }
        }
        
        // Extract version if detected
        if (evidence.length > 0 && sig.versionPatterns) {
            for (const vp of sig.versionPatterns) {
                let source = "";
                if (vp.source.startsWith("header:")) {
                    source = headers[vp.source.substring(7).toLowerCase()] || "";
                } else if (vp.source.startsWith("meta:")) {
                    source = meta[vp.source.substring(5).toLowerCase()] || "";
                } else if (vp.source === "script") {
                    source = scripts.join(" ");
                }
                const match = source.match(vp.pattern);
                if (match && match[1]) {
                    version = match[1];
                    break;
                }
            }
        }
        
        // Add to detected if confidence is high enough
        if (confidence > 0) {
            detected.set(sig.name, {
                name: sig.name,
                category: sig.category,
                version,
                confidence: Math.min(confidence, 100),
                evidence,
            });
            
            // Add implied technologies
            if (sig.implies) {
                for (const implied of sig.implies) {
                    if (!detected.has(implied)) {
                        const impliedSig = TECH_SIGNATURES.find(s => s.name === implied);
                        if (impliedSig) {
                            detected.set(implied, {
                                name: implied,
                                category: impliedSig.category,
                                confidence: Math.min(confidence * 0.5, 50),
                                evidence: [`Implied by ${sig.name}`],
                            });
                        }
                    }
                }
            }
        }
    }
    
    return Array.from(detected.values()).sort((a, b) => b.confidence - a.confidence);
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        // Validate input
        if (!input.url || typeof input.url !== "string") {
            return {
                success: false,
                error: "Invalid input: url parameter is required"
            };
        }
        
        let url = input.url;
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = `https://${url}`;
        }
        
        const timeout = input.timeout || 15000;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        
        // Fetch the page
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "User-Agent": userAgent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
            redirect: "follow",
            // @ts-ignore
            timeout,
        });
        
        // Collect headers
        const headers: Record<string, string> = {};
        const setCookieHeaders: string[] = [];
        response.headers.forEach((value, key) => {
            const lowerKey = key.toLowerCase();
            if (lowerKey === "set-cookie") {
                setCookieHeaders.push(value);
            }
            headers[lowerKey] = value;
        });
        
        // Parse cookies
        const cookies = parseCookies(setCookieHeaders);
        
        // Get HTML content
        const html = await response.text();
        
        // Extract meta tags and scripts
        const meta = extractMetaTags(html);
        const scripts = extractScripts(html);
        
        // Deep scan: fetch additional resources
        if (input.deepScan) {
            try {
                const robotsUrl = new URL("/robots.txt", url).href;
                const robotsResponse = await fetch(robotsUrl, {
                    headers: { "User-Agent": userAgent },
                    // @ts-ignore
                    timeout: 5000,
                });
                if (robotsResponse.ok) {
                    const robotsText = await robotsResponse.text();
                    // Check for CMS-specific paths in robots.txt
                    if (/wp-admin|wp-content/i.test(robotsText)) {
                        scripts.push("wordpress-detected-robots");
                    }
                }
            } catch {
                // Ignore errors
            }
        }
        
        // Detect technologies
        const technologies = detectTechnologies(headers, cookies, html, meta, scripts);
        
        // Build summary
        const byCategory: Record<string, string[]> = {};
        for (const tech of technologies) {
            if (!byCategory[tech.category]) {
                byCategory[tech.category] = [];
            }
            byCategory[tech.category].push(tech.name);
        }
        
        return {
            success: true,
            data: {
                url,
                technologies,
                summary: {
                    total: technologies.length,
                    byCategory,
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
