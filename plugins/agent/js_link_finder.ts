/**
 * JavaScript Link Finder Tool
 * 
 * @plugin js_link_finder
 * @name JS Link Finder
 * @version 1.0.0
 * @author Sentinel Team
 * @category discovery
 * @default_severity info
 * @tags javascript, discovery, links, crawler, web
 * @description Find and collect all JavaScript file URLs from a web page, including inline scripts, external scripts, and dynamically loaded modules
 */

interface ToolInput {
    url: string;
    timeout?: number;
    userAgent?: string;
    recursive?: boolean;
    maxDepth?: number;
    maxFiles?: number;
    includeSameOriginOnly?: boolean;
    includeInline?: boolean;
    followSourceMaps?: boolean;
}

interface JsLink {
    url: string;
    type: 'external' | 'inline' | 'module' | 'dynamic' | 'sourcemap' | 'webpack';
    source: string;
    size?: number;
    hash?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        baseUrl: string;
        jsLinks: JsLink[];
        summary: {
            total: number;
            external: number;
            inline: number;
            modules: number;
            dynamic: number;
            sourcemaps: number;
            webpack: number;
            uniqueDomains: string[];
            totalSize: number;
        };
        crawledPages?: string[];
    };
    error?: string;
}

/**
 * Export input schema for agent
 */
export function get_input_schema() {
    return {
        type: "object",
        required: ["url"],
        properties: {
            url: {
                type: "string",
                description: "Target URL to find JavaScript files from"
            },
            timeout: {
                type: "number",
                description: "Request timeout in milliseconds (default: 15000)"
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            recursive: {
                type: "boolean",
                description: "Recursively crawl same-origin pages to find more JS (default: false)"
            },
            maxDepth: {
                type: "number",
                description: "Maximum crawl depth when recursive is enabled (default: 2)"
            },
            maxFiles: {
                type: "number",
                description: "Maximum JS files to collect (default: 100)"
            },
            includeSameOriginOnly: {
                type: "boolean",
                description: "Only include JS files from the same origin (default: false)"
            },
            includeInline: {
                type: "boolean",
                description: "Include inline <script> content hashes (default: true)"
            },
            followSourceMaps: {
                type: "boolean",
                description: "Follow sourceMappingURL to find source maps (default: true)"
            }
        }
    };
}

/**
 * Export output schema for agent
 */
export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean" },
            data: {
                type: "object",
                properties: {
                    baseUrl: { type: "string" },
                    jsLinks: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                url: { type: "string" },
                                type: { type: "string" },
                                source: { type: "string" },
                                size: { type: "number" },
                                hash: { type: "string" }
                            }
                        }
                    },
                    summary: { type: "object" }
                }
            },
            error: { type: "string" }
        }
    };
}

// Default config
const DEFAULT_TIMEOUT = 15000;
const DEFAULT_MAX_FILES = 100;
const DEFAULT_MAX_DEPTH = 2;
const DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

// Patterns to find JS files
const PATTERNS = {
    // <script src="...">
    scriptSrc: /<script[^>]*\ssrc\s*=\s*["']([^"']+\.js[^"']*?)["'][^>]*>/gi,
    // <script type="module" src="...">
    moduleSrc: /<script[^>]*\stype\s*=\s*["']module["'][^>]*\ssrc\s*=\s*["']([^"']+)["'][^>]*>/gi,
    // import ... from "..."
    esImport: /import\s+(?:[\w\s{},*]+\s+from\s+)?["']([^"']+\.(?:js|mjs|ts|tsx))["']/g,
    // dynamic import()
    dynamicImport: /import\s*\(\s*["']([^"']+\.(?:js|mjs))["']\s*\)/g,
    // require("...")
    requireCall: /require\s*\(\s*["']([^"']+\.js)["']\s*\)/g,
    // sourceMappingURL
    sourceMap: /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g,
    // Webpack chunk pattern
    webpackChunk: /["']([^"']*(?:chunk|bundle|vendor|main|app)[^"']*\.js[^"']*)["']/gi,
    // Generic .js URLs in strings
    genericJs: /["']((?:https?:)?\/\/[^"'\s]+\.js(?:\?[^"'\s]*)?)["']/gi,
    // Relative JS paths
    relativeJs: /["'](\.?\.?\/[^"'\s]+\.js(?:\?[^"'\s]*)?)["']/gi,
    // Inline script content
    inlineScript: /<script[^>]*>([^<]+)<\/script>/gi,
    // <link rel="modulepreload" href="...">
    modulePreload: /<link[^>]*\srel\s*=\s*["']modulepreload["'][^>]*\shref\s*=\s*["']([^"']+)["'][^>]*>/gi,
    // Same-origin links for crawling
    sameOriginLinks: /<a[^>]*\shref\s*=\s*["']([^"'#]+)["'][^>]*>/gi,
};

/**
 * Simple hash function for inline scripts
 */
function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
}

/**
 * Normalize and resolve URL
 */
function resolveUrl(base: string, relative: string): string {
    try {
        // Handle protocol-relative URLs
        if (relative.startsWith('//')) {
            const baseUrl = new URL(base);
            return `${baseUrl.protocol}${relative}`;
        }
        return new URL(relative, base).href;
    } catch {
        return '';
    }
}

/**
 * Get domain from URL
 */
function getDomain(url: string): string {
    try {
        return new URL(url).hostname;
    } catch {
        return '';
    }
}

/**
 * Check if URL is same origin
 */
function isSameOrigin(baseUrl: string, targetUrl: string): boolean {
    try {
        const base = new URL(baseUrl);
        const target = new URL(targetUrl);
        return base.origin === target.origin;
    } catch {
        return false;
    }
}

/**
 * Fetch URL with timeout
 */
async function fetchWithTimeout(url: string, timeout: number, userAgent: string): Promise<{ html: string; size: number } | null> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url, {
            headers: {
                'User-Agent': userAgent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            },
            signal: controller.signal,
            redirect: 'follow',
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            return null;
        }
        
        const contentType = response.headers.get('content-type') || '';
        // Accept HTML, JS, and JSON content
        if (!contentType.includes('text/html') && 
            !contentType.includes('javascript') && 
            !contentType.includes('application/json') &&
            !contentType.includes('text/plain')) {
            return null;
        }
        
        const html = await response.text();
        return { html, size: html.length };
    } catch (error) {
        clearTimeout(timeoutId);
        return null;
    }
}

/**
 * Extract JS links from HTML content
 */
function extractJsLinksFromHtml(html: string, baseUrl: string, includeInline: boolean): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    
    // External scripts
    let match;
    while ((match = PATTERNS.scriptSrc.exec(html)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'external', source: 'script_src' });
        }
    }
    PATTERNS.scriptSrc.lastIndex = 0;
    
    // Module scripts
    while ((match = PATTERNS.moduleSrc.exec(html)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'module', source: 'script_module' });
        }
    }
    PATTERNS.moduleSrc.lastIndex = 0;
    
    // Module preload
    while ((match = PATTERNS.modulePreload.exec(html)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'module', source: 'modulepreload' });
        }
    }
    PATTERNS.modulePreload.lastIndex = 0;
    
    // Webpack chunks
    while ((match = PATTERNS.webpackChunk.exec(html)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url) && url.endsWith('.js')) {
            seenUrls.add(url);
            links.push({ url, type: 'webpack', source: 'webpack_chunk' });
        }
    }
    PATTERNS.webpackChunk.lastIndex = 0;
    
    // Generic JS URLs
    while ((match = PATTERNS.genericJs.exec(html)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'dynamic', source: 'string_literal' });
        }
    }
    PATTERNS.genericJs.lastIndex = 0;
    
    // Relative JS paths
    while ((match = PATTERNS.relativeJs.exec(html)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'dynamic', source: 'relative_path' });
        }
    }
    PATTERNS.relativeJs.lastIndex = 0;
    
    // Inline scripts
    if (includeInline) {
        while ((match = PATTERNS.inlineScript.exec(html)) !== null) {
            const content = match[1].trim();
            if (content.length > 10) { // Skip very short scripts
                const hash = simpleHash(content);
                const inlineUrl = `inline://${hash}`;
                if (!seenUrls.has(inlineUrl)) {
                    seenUrls.add(inlineUrl);
                    links.push({ 
                        url: inlineUrl, 
                        type: 'inline', 
                        source: 'inline_script',
                        size: content.length,
                        hash 
                    });
                }
            }
        }
        PATTERNS.inlineScript.lastIndex = 0;
    }
    
    return links;
}

/**
 * Extract additional JS from JS content (imports, requires)
 */
function extractJsLinksFromJs(jsContent: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    
    let match;
    
    // ES imports
    while ((match = PATTERNS.esImport.exec(jsContent)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'module', source: 'es_import' });
        }
    }
    PATTERNS.esImport.lastIndex = 0;
    
    // Dynamic imports
    while ((match = PATTERNS.dynamicImport.exec(jsContent)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'dynamic', source: 'dynamic_import' });
        }
    }
    PATTERNS.dynamicImport.lastIndex = 0;
    
    // require calls
    while ((match = PATTERNS.requireCall.exec(jsContent)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'dynamic', source: 'require' });
        }
    }
    PATTERNS.requireCall.lastIndex = 0;
    
    // Source maps
    while ((match = PATTERNS.sourceMap.exec(jsContent)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'sourcemap', source: 'source_map' });
        }
    }
    PATTERNS.sourceMap.lastIndex = 0;
    
    return links;
}

/**
 * Get same-origin links for crawling
 */
function getSameOriginLinks(html: string, baseUrl: string): string[] {
    const links: string[] = [];
    const seenUrls = new Set<string>();
    let match;
    
    while ((match = PATTERNS.sameOriginLinks.exec(html)) !== null) {
        const url = resolveUrl(baseUrl, match[1]);
        if (url && !seenUrls.has(url) && isSameOrigin(baseUrl, url)) {
            // Only HTML pages
            const path = new URL(url).pathname;
            if (!path.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip)$/i)) {
                seenUrls.add(url);
                links.push(url);
            }
        }
    }
    PATTERNS.sameOriginLinks.lastIndex = 0;
    
    return links;
}

/**
 * Main execution function
 */
export async function run(input: ToolInput): Promise<ToolOutput> {
    const {
        url,
        timeout = DEFAULT_TIMEOUT,
        userAgent = DEFAULT_USER_AGENT,
        recursive = false,
        maxDepth = DEFAULT_MAX_DEPTH,
        maxFiles = DEFAULT_MAX_FILES,
        includeSameOriginOnly = false,
        includeInline = true,
        followSourceMaps = true,
    } = input;
    
    // Validate URL
    let baseUrl: string;
    try {
        baseUrl = new URL(url).href;
    } catch {
        return { success: false, error: 'Invalid URL provided' };
    }
    
    const allLinks: JsLink[] = [];
    const seenUrls = new Set<string>();
    const crawledPages: string[] = [];
    const pagesToCrawl: Array<{ url: string; depth: number }> = [{ url: baseUrl, depth: 0 }];
    const visitedPages = new Set<string>();
    
    // Crawl pages
    while (pagesToCrawl.length > 0 && allLinks.length < maxFiles) {
        const current = pagesToCrawl.shift()!;
        if (visitedPages.has(current.url)) continue;
        visitedPages.add(current.url);
        
        const result = await fetchWithTimeout(current.url, timeout, userAgent);
        if (!result) continue;
        
        crawledPages.push(current.url);
        
        // Extract JS links from HTML
        const htmlLinks = extractJsLinksFromHtml(result.html, current.url, includeInline);
        for (const link of htmlLinks) {
            if (!seenUrls.has(link.url)) {
                if (!includeSameOriginOnly || isSameOrigin(baseUrl, link.url) || link.type === 'inline') {
                    seenUrls.add(link.url);
                    allLinks.push(link);
                }
            }
        }
        
        // If recursive, add same-origin links to crawl
        if (recursive && current.depth < maxDepth) {
            const pageLinks = getSameOriginLinks(result.html, current.url);
            for (const pageUrl of pageLinks.slice(0, 20)) { // Limit links per page
                if (!visitedPages.has(pageUrl)) {
                    pagesToCrawl.push({ url: pageUrl, depth: current.depth + 1 });
                }
            }
        }
    }
    
    // Optionally fetch JS files to find more imports and source maps
    if (followSourceMaps && allLinks.length < maxFiles) {
        const externalLinks = allLinks.filter(l => l.type === 'external' || l.type === 'module' || l.type === 'webpack');
        const filesToCheck = externalLinks.slice(0, 20); // Limit to 20 files
        
        for (const link of filesToCheck) {
            if (allLinks.length >= maxFiles) break;
            
            const jsResult = await fetchWithTimeout(link.url, timeout, userAgent);
            if (jsResult) {
                link.size = jsResult.size;
                
                // Extract additional links from JS content
                const jsLinks = extractJsLinksFromJs(jsResult.html, link.url);
                for (const jsLink of jsLinks) {
                    if (!seenUrls.has(jsLink.url)) {
                        if (!includeSameOriginOnly || isSameOrigin(baseUrl, jsLink.url)) {
                            seenUrls.add(jsLink.url);
                            allLinks.push(jsLink);
                        }
                    }
                }
            }
        }
    }
    
    // Calculate summary
    const summary = {
        total: allLinks.length,
        external: allLinks.filter(l => l.type === 'external').length,
        inline: allLinks.filter(l => l.type === 'inline').length,
        modules: allLinks.filter(l => l.type === 'module').length,
        dynamic: allLinks.filter(l => l.type === 'dynamic').length,
        sourcemaps: allLinks.filter(l => l.type === 'sourcemap').length,
        webpack: allLinks.filter(l => l.type === 'webpack').length,
        uniqueDomains: [...new Set(allLinks.filter(l => l.type !== 'inline').map(l => getDomain(l.url)).filter(Boolean))],
        totalSize: allLinks.reduce((sum, l) => sum + (l.size || 0), 0),
    };
    
    return {
        success: true,
        data: {
            baseUrl,
            jsLinks: allLinks.slice(0, maxFiles),
            summary,
            crawledPages: recursive ? crawledPages : undefined,
        },
    };
}

// Entry point for plugin execution
const input = JSON.parse(process.argv[2] || '{}');
run(input).then(result => {
    console.log(JSON.stringify(result, null, 2));
}).catch(error => {
    console.log(JSON.stringify({ success: false, error: error.message }));
});
