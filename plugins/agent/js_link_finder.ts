/**
 * JavaScript Link Finder Tool (SPA Enhanced)
 * 
 * @plugin js_link_finder
 * @name JS Link Finder
 * @version 2.0.0
 * @author Sentinel Team
 * @category discovery
 * @default_severity info
 * @tags javascript, discovery, links, crawler, web, spa, vite, webpack, react, vue
 * @description Find and collect all JavaScript file URLs from a web page. Supports SPA frameworks (Vue/React/Vite/Webpack/Next.js), modulepreload, dynamic imports, and various bundle patterns.
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
    probeSpaManifests?: boolean;
}

interface JsLink {
    url: string;
    type: 'external' | 'inline' | 'module' | 'dynamic' | 'sourcemap' | 'webpack' | 'manifest';
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
            manifests: number;
            uniqueDomains: string[];
            totalSize: number;
        };
        crawledPages?: string[];
        debug?: any;
    };
    error?: string;
}

/**
 * Input schema for agent
 */
function get_input_schema() {
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
            },
            probeSpaManifests: {
                type: "boolean",
                description: "Probe common SPA manifest endpoints (default: true)"
            }
        }
    };
}

/**
 * Output schema for agent
 */
function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean" },
            data: {
                type: "object",
                properties: {
                    baseUrl: { type: "string" },
                    jsLinks: { type: "array" },
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
    if (!relative || typeof relative !== 'string') return '';
    relative = relative.trim();
    if (!relative) return '';
    
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
 * Check if a path looks like a JS file
 */
function looksLikeJs(path: string): boolean {
    if (!path) return false;
    // Remove query string and hash
    const clean = path.split('?')[0].split('#')[0];
    // Check extension
    if (/\.(?:js|mjs|cjs|jsx|ts|tsx)$/i.test(clean)) return true;
    // Check for SPA bundle patterns (hash in filename)
    if (/\.[a-f0-9]{6,10}\.js$/i.test(clean)) return true;
    if (/(?:chunk|bundle|vendor|app|main|index)\.[a-f0-9]+/i.test(clean)) return true;
    return false;
}

/**
 * Fetch URL with timeout
 */
async function fetchWithTimeout(url: string, timeout: number, userAgent: string): Promise<{ text: string; size: number; contentType: string } | null> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url, {
            headers: {
                'User-Agent': userAgent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,*/*;q=0.8',
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
        const text = await response.text();
        return { text, size: text.length, contentType };
    } catch (error) {
        clearTimeout(timeoutId);
        return null;
    }
}

/**
 * Extract all script tags and their src attributes (order-agnostic parsing)
 */
function extractScriptTags(html: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    
    // Match all <script ...> tags
    const scriptTagRegex = /<script\b([^>]*)>/gi;
    let match;
    
    while ((match = scriptTagRegex.exec(html)) !== null) {
        const attrs = match[1];
        
        // Extract src attribute (handles various quote styles and spacing)
        const srcMatch = attrs.match(/\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        if (srcMatch) {
            const src = srcMatch[1] || srcMatch[2] || srcMatch[3];
            if (src) {
                const url = resolveUrl(baseUrl, src);
                if (url && !seenUrls.has(url)) {
                    seenUrls.add(url);
                    // Check if it's a module
                    const isModule = /\btype\s*=\s*["']?module["']?/i.test(attrs);
                    links.push({
                        url,
                        type: isModule ? 'module' : 'external',
                        source: 'script_tag'
                    });
                }
            }
        }
        
        // Also check data-src for lazy loading
        const dataSrcMatch = attrs.match(/\bdata-src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        if (dataSrcMatch) {
            const src = dataSrcMatch[1] || dataSrcMatch[2] || dataSrcMatch[3];
            if (src) {
                const url = resolveUrl(baseUrl, src);
                if (url && !seenUrls.has(url)) {
                    seenUrls.add(url);
                    links.push({ url, type: 'external', source: 'script_data_src' });
                }
            }
        }
    }
    
    return links;
}

/**
 * Extract all link tags that reference JS (modulepreload, preload, prefetch)
 */
function extractLinkTags(html: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    
    // Match all <link ...> tags
    const linkTagRegex = /<link\b([^>]*)>/gi;
    let match;
    
    while ((match = linkTagRegex.exec(html)) !== null) {
        const attrs = match[1];
        
        // Extract href
        const hrefMatch = attrs.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        if (!hrefMatch) continue;
        
        const href = hrefMatch[1] || hrefMatch[2] || hrefMatch[3];
        if (!href) continue;
        
        // Extract rel
        const relMatch = attrs.match(/\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        const rel = (relMatch ? (relMatch[1] || relMatch[2] || relMatch[3]) : '').toLowerCase();
        
        // Extract as
        const asMatch = attrs.match(/\bas\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
        const as = (asMatch ? (asMatch[1] || asMatch[2] || asMatch[3]) : '').toLowerCase();
        
        const url = resolveUrl(baseUrl, href);
        if (!url || seenUrls.has(url)) continue;
        
        // modulepreload is always JS
        if (rel === 'modulepreload') {
            seenUrls.add(url);
            links.push({ url, type: 'module', source: 'modulepreload' });
        }
        // preload/prefetch with as="script"
        else if ((rel === 'preload' || rel === 'prefetch') && as === 'script') {
            seenUrls.add(url);
            links.push({ url, type: 'module', source: rel });
        }
        // Any link ending in .js
        else if (looksLikeJs(href)) {
            seenUrls.add(url);
            links.push({ url, type: 'dynamic', source: 'link_tag' });
        }
    }
    
    return links;
}

/**
 * Extract inline script content
 */
function extractInlineScripts(html: string): Array<{ content: string; hash: string }> {
    const scripts: Array<{ content: string; hash: string }> = [];
    
    // Match <script>...</script> (not external)
    const inlineRegex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
    let match;
    
    while ((match = inlineRegex.exec(html)) !== null) {
        const attrs = match[1];
        const content = match[2];
        
        // Skip if it has src (external script)
        if (/\bsrc\s*=/i.test(attrs)) continue;
        
        // Skip empty or very short scripts
        if (!content || content.trim().length < 10) continue;
        
        scripts.push({
            content: content.trim(),
            hash: simpleHash(content)
        });
    }
    
    return scripts;
}

/**
 * Extract JS URLs from JavaScript content (imports, requires, etc.)
 */
function extractJsFromContent(content: string, baseUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    
    // ES import: import ... from "..."
    const esImportRegex = /import\s+(?:[\w\s{},*]+\s+from\s+)?["']([^"']+)["']/g;
    let match;
    while ((match = esImportRegex.exec(content)) !== null) {
        const path = match[1];
        if (looksLikeJs(path) || !path.startsWith('.')) {
            const url = resolveUrl(baseUrl, path);
            if (url && !seenUrls.has(url) && looksLikeJs(url)) {
                seenUrls.add(url);
                links.push({ url, type: 'module', source: 'es_import' });
            }
        }
    }
    
    // Dynamic import: import("...")
    const dynamicImportRegex = /import\s*\(\s*["']([^"']+)["']\s*\)/g;
    while ((match = dynamicImportRegex.exec(content)) !== null) {
        const path = match[1];
        const url = resolveUrl(baseUrl, path);
        if (url && !seenUrls.has(url) && looksLikeJs(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'dynamic', source: 'dynamic_import' });
        }
    }
    
    // require("...")
    const requireRegex = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
    while ((match = requireRegex.exec(content)) !== null) {
        const path = match[1];
        const url = resolveUrl(baseUrl, path);
        if (url && !seenUrls.has(url) && looksLikeJs(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'dynamic', source: 'require' });
        }
    }
    
    // sourceMappingURL
    const sourceMapRegex = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
    while ((match = sourceMapRegex.exec(content)) !== null) {
        const path = match[1];
        const url = resolveUrl(baseUrl, path);
        if (url && !seenUrls.has(url)) {
            seenUrls.add(url);
            links.push({ url, type: 'sourcemap', source: 'sourcemap' });
        }
    }
    
    // Generic JS URLs in strings (like webpack chunks, lazy loads)
    // Pattern: "...xxx.js" or '/xxx.js' or "/assets/xxx.hash.js"
    const jsUrlRegex = /["']([^"'\s]*?(?:\/assets\/|\/static\/|\/js\/|\/dist\/|\/build\/|\/chunks?\/)?[^"'\s]*?\.[a-f0-9]{6,10}\.js(?:\?[^"'\s]*)?)["']/gi;
    while ((match = jsUrlRegex.exec(content)) !== null) {
        const path = match[1];
        if (path && !path.startsWith('data:') && !path.includes('{{')) {
            const url = resolveUrl(baseUrl, path);
            if (url && !seenUrls.has(url)) {
                seenUrls.add(url);
                links.push({ url, type: 'webpack', source: 'js_string' });
            }
        }
    }
    
    // Also catch simpler .js paths
    const simpleJsRegex = /["']((?:\/|\.\.?\/)[^"'\s]+\.js(?:\?[^"'\s]*)?)["']/g;
    while ((match = simpleJsRegex.exec(content)) !== null) {
        const path = match[1];
        if (path && !path.startsWith('data:')) {
            const url = resolveUrl(baseUrl, path);
            if (url && !seenUrls.has(url)) {
                seenUrls.add(url);
                links.push({ url, type: 'dynamic', source: 'js_path' });
            }
        }
    }
    
    return links;
}

/**
 * Parse manifest file content for JS files
 */
function parseManifest(content: string, manifestUrl: string): JsLink[] {
    const links: JsLink[] = [];
    const seenUrls = new Set<string>();
    
    // Try JSON parse
    try {
        const json = JSON.parse(content);
        const extractFromObj = (obj: any) => {
            if (typeof obj === 'string' && looksLikeJs(obj)) {
                const url = resolveUrl(manifestUrl, obj);
                if (url && !seenUrls.has(url)) {
                    seenUrls.add(url);
                    links.push({ url, type: 'manifest', source: 'manifest' });
                }
            } else if (Array.isArray(obj)) {
                obj.forEach(extractFromObj);
            } else if (obj && typeof obj === 'object') {
                Object.values(obj).forEach(extractFromObj);
            }
        };
        extractFromObj(json);
    } catch {
        // Fallback: regex for .js files
        const jsRegex = /["']([^"']+\.js(?:\?[^"']*)?)["']/gi;
        let match;
        while ((match = jsRegex.exec(content)) !== null) {
            const url = resolveUrl(manifestUrl, match[1]);
            if (url && !seenUrls.has(url)) {
                seenUrls.add(url);
                links.push({ url, type: 'manifest', source: 'manifest' });
            }
        }
    }
    
    return links;
}

/**
 * Get common SPA manifest URLs to probe
 */
function getManifestUrls(baseUrl: string): string[] {
    const paths = [
        '/asset-manifest.json',
        '/manifest.json',
        '/.vite/manifest.json',
        '/build/asset-manifest.json',
        '/static/asset-manifest.json',
    ];
    return paths.map(p => resolveUrl(baseUrl, p)).filter(Boolean);
}

/**
 * Get same-origin links for crawling
 */
function getSameOriginLinks(html: string, baseUrl: string): string[] {
    const links: string[] = [];
    const seenUrls = new Set<string>();
    
    const linkRegex = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
    let match;
    
    while ((match = linkRegex.exec(html)) !== null) {
        const href = match[1] || match[2] || match[3];
        if (!href || href.startsWith('#') || href.startsWith('javascript:')) continue;
        
        const url = resolveUrl(baseUrl, href);
        if (url && !seenUrls.has(url) && isSameOrigin(baseUrl, url)) {
            const path = new URL(url).pathname;
            if (!/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip)$/i.test(path)) {
                seenUrls.add(url);
                links.push(url);
            }
        }
    }
    
    return links;
}

/**
 * Main execution function
 */
async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        // Validate input
        if (!input || !input.url) {
            return { success: false, error: 'URL is required' };
        }

        // Parse config with proper defaults (handle 0 values)
        const url = input.url;
        const timeout = (input.timeout && input.timeout > 0) ? input.timeout : DEFAULT_TIMEOUT;
        const userAgent = input.userAgent || DEFAULT_USER_AGENT;
        const recursive = input.recursive === true;
        const maxDepth = (input.maxDepth && input.maxDepth > 0) ? input.maxDepth : DEFAULT_MAX_DEPTH;
        const maxFiles = (input.maxFiles && input.maxFiles > 0) ? input.maxFiles : DEFAULT_MAX_FILES;
        const includeSameOriginOnly = input.includeSameOriginOnly === true;
        const includeInline = input.includeInline !== false;
        const followSourceMaps = input.followSourceMaps !== false;
        const probeSpaManifests = input.probeSpaManifests !== false;
        
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
            
            // 1. Extract script tags
            const scriptLinks = extractScriptTags(result.text, current.url);
            for (const link of scriptLinks) {
                if (!seenUrls.has(link.url)) {
                    if (!includeSameOriginOnly || isSameOrigin(baseUrl, link.url)) {
                        seenUrls.add(link.url);
                        allLinks.push(link);
                    }
                }
            }
            
            // 2. Extract link tags (modulepreload, preload, prefetch)
            const linkTagLinks = extractLinkTags(result.text, current.url);
            for (const link of linkTagLinks) {
                if (!seenUrls.has(link.url)) {
                    if (!includeSameOriginOnly || isSameOrigin(baseUrl, link.url)) {
                        seenUrls.add(link.url);
                        allLinks.push(link);
                    }
                }
            }
            
            // 3. Extract from inline scripts
            if (includeInline) {
                const inlineScripts = extractInlineScripts(result.text);
                for (const script of inlineScripts) {
                    // Add inline script as entry
                    const inlineUrl = `inline://${script.hash}`;
                    if (!seenUrls.has(inlineUrl)) {
                        seenUrls.add(inlineUrl);
                        allLinks.push({
                            url: inlineUrl,
                            type: 'inline',
                            source: 'inline_script',
                            size: script.content.length,
                            hash: script.hash
                        });
                    }
                    
                    // Also extract JS URLs from inline content
                    const inlineLinks = extractJsFromContent(script.content, current.url);
                    for (const link of inlineLinks) {
                        if (!seenUrls.has(link.url)) {
                            if (!includeSameOriginOnly || isSameOrigin(baseUrl, link.url)) {
                                seenUrls.add(link.url);
                                allLinks.push(link);
                            }
                        }
                    }
                }
            }
            
            // 4. If recursive, add same-origin links to crawl
            if (recursive && current.depth < maxDepth) {
                const pageLinks = getSameOriginLinks(result.text, current.url);
                for (const pageUrl of pageLinks.slice(0, 20)) {
                    if (!visitedPages.has(pageUrl)) {
                        pagesToCrawl.push({ url: pageUrl, depth: current.depth + 1 });
                    }
                }
            }
        }
        
        // 5. Probe SPA manifests
        if (probeSpaManifests && allLinks.length < maxFiles) {
            const manifestUrls = getManifestUrls(baseUrl);
            for (const manifestUrl of manifestUrls) {
                const manifestResult = await fetchWithTimeout(manifestUrl, timeout, userAgent);
                if (manifestResult && manifestResult.contentType.includes('json')) {
                    const manifestLinks = parseManifest(manifestResult.text, manifestUrl);
                    for (const link of manifestLinks) {
                        if (!seenUrls.has(link.url)) {
                            if (!includeSameOriginOnly || isSameOrigin(baseUrl, link.url)) {
                                seenUrls.add(link.url);
                                allLinks.push(link);
                            }
                        }
                    }
                }
            }
        }
        
        // 6. Optionally fetch external JS to find more imports and sourcemaps
        if (followSourceMaps && allLinks.length < maxFiles) {
            const externalLinks = allLinks.filter(l => 
                l.type === 'external' || l.type === 'module' || l.type === 'webpack'
            ).slice(0, 10);
            
            for (const link of externalLinks) {
                if (allLinks.length >= maxFiles) break;
                
                const jsResult = await fetchWithTimeout(link.url, timeout, userAgent);
                if (jsResult) {
                    link.size = jsResult.size;
                    
                    const jsLinks = extractJsFromContent(jsResult.text, link.url);
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
            manifests: allLinks.filter(l => l.type === 'manifest').length,
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
    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

// Export for Deno runtime
globalThis.analyze = analyze;
globalThis.get_input_schema = get_input_schema;
globalThis.get_output_schema = get_output_schema;
