/**
 * CORS Misconfiguration Detector Tool
 * 
 * @plugin cors_misconfiguration
 * @name CORS Misconfiguration Detector
 * @version 1.0.0
 * @author Sentinel Team
 * @category vuln
 * @default_severity medium
 * @tags cors, vulnerability, security, web, headers
 * @description Detect CORS (Cross-Origin Resource Sharing) misconfigurations that could allow unauthorized cross-origin access
 */

interface ToolInput {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    timeout?: number;
    userAgent?: string;
    testOrigins?: string[];
    checkCredentials?: boolean;
    checkWildcard?: boolean;
    checkNullOrigin?: boolean;
    checkSubdomains?: boolean;
}

interface CorsTest {
    origin: string;
    testType: string;
    vulnerable: boolean;
    severity: "critical" | "high" | "medium" | "low" | "info";
    responseHeaders: {
        accessControlAllowOrigin?: string;
        accessControlAllowCredentials?: string;
        accessControlAllowMethods?: string;
        accessControlAllowHeaders?: string;
        accessControlExposeHeaders?: string;
        accessControlMaxAge?: string;
    };
    evidence?: string;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        url: string;
        tests: CorsTest[];
        summary: {
            totalTests: number;
            vulnerableCount: number;
            bySeverity: Record<string, number>;
            byTestType: Record<string, number>;
        };
    };
    error?: string;
}

// Test types and their descriptions
const TEST_TYPES = {
    reflected_origin: "Origin header is reflected back",
    wildcard_origin: "Wildcard (*) origin allowed",
    null_origin: "Null origin allowed",
    subdomain_bypass: "Subdomain bypass possible",
    prefix_bypass: "Prefix bypass possible",
    suffix_bypass: "Suffix bypass possible",
    special_chars: "Special characters bypass",
    credentials_with_wildcard: "Credentials allowed with wildcard",
    credentials_with_reflected: "Credentials allowed with reflected origin",
};

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
                description: "Target URL to test for CORS misconfigurations"
            },
            method: {
                type: "string",
                enum: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                description: "HTTP method to use",
                default: "GET"
            },
            headers: {
                type: "object",
                description: "Additional headers to include",
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
            testOrigins: {
                type: "array",
                items: { type: "string" },
                description: "Additional origins to test"
            },
            checkCredentials: {
                type: "boolean",
                description: "Check if credentials are allowed",
                default: true
            },
            checkWildcard: {
                type: "boolean",
                description: "Check for wildcard origin",
                default: true
            },
            checkNullOrigin: {
                type: "boolean",
                description: "Check for null origin",
                default: true
            },
            checkSubdomains: {
                type: "boolean",
                description: "Check for subdomain bypass",
                default: true
            }
        }
    };
}

globalThis.get_input_schema = get_input_schema;

/**
 * Extract domain from URL
 */
function extractDomain(url: string): string {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch {
        return url;
    }
}

/**
 * Extract base domain (e.g., example.com from sub.example.com)
 */
function extractBaseDomain(domain: string): string {
    const parts = domain.split(".");
    if (parts.length <= 2) {
        return domain;
    }
    // Handle common TLDs
    const commonTlds = ["co.uk", "com.au", "co.nz", "co.jp", "com.br", "com.cn"];
    const lastTwo = parts.slice(-2).join(".");
    if (commonTlds.includes(lastTwo)) {
        return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
}

/**
 * Generate test origins based on target URL
 */
function generateTestOrigins(targetUrl: string): { origin: string; testType: string }[] {
    const domain = extractDomain(targetUrl);
    const baseDomain = extractBaseDomain(domain);
    const protocol = targetUrl.startsWith("https") ? "https" : "http";
    
    const origins: { origin: string; testType: string }[] = [];
    
    // Reflected origin test - use attacker domain
    origins.push({
        origin: "https://evil.com",
        testType: "reflected_origin",
    });
    
    // Null origin
    origins.push({
        origin: "null",
        testType: "null_origin",
    });
    
    // Subdomain bypass attempts
    origins.push({
        origin: `${protocol}://attacker.${baseDomain}`,
        testType: "subdomain_bypass",
    });
    origins.push({
        origin: `${protocol}://evil.${domain}`,
        testType: "subdomain_bypass",
    });
    
    // Prefix bypass attempts
    origins.push({
        origin: `${protocol}://${domain}.evil.com`,
        testType: "prefix_bypass",
    });
    origins.push({
        origin: `${protocol}://evil${domain}`,
        testType: "prefix_bypass",
    });
    
    // Suffix bypass attempts
    origins.push({
        origin: `${protocol}://evil.com.${domain}`,
        testType: "suffix_bypass",
    });
    origins.push({
        origin: `${protocol}://${baseDomain}.evil.com`,
        testType: "suffix_bypass",
    });
    
    // Special character bypass attempts
    origins.push({
        origin: `${protocol}://${domain}%60.evil.com`,
        testType: "special_chars",
    });
    origins.push({
        origin: `${protocol}://${domain}_.evil.com`,
        testType: "special_chars",
    });
    origins.push({
        origin: `${protocol}://${domain}!.evil.com`,
        testType: "special_chars",
    });
    origins.push({
        origin: `${protocol}://${domain}@evil.com`,
        testType: "special_chars",
    });
    
    // Protocol variations
    origins.push({
        origin: `http://${domain}`,
        testType: "reflected_origin",
    });
    
    // Localhost variations
    origins.push({
        origin: "http://localhost",
        testType: "reflected_origin",
    });
    origins.push({
        origin: "http://127.0.0.1",
        testType: "reflected_origin",
    });
    
    return origins;
}

/**
 * Test CORS with a specific origin
 */
async function testCors(
    url: string,
    origin: string,
    testType: string,
    options: {
        method: string;
        headers: Record<string, string>;
        timeout: number;
    }
): Promise<CorsTest> {
    const result: CorsTest = {
        origin,
        testType,
        vulnerable: false,
        severity: "info",
        responseHeaders: {},
    };
    
    try {
        // Make request with Origin header
        const response = await fetch(url, {
            method: options.method,
            headers: {
                ...options.headers,
                "Origin": origin,
            },
            // @ts-ignore
            timeout: options.timeout,
        });
        
        // Extract CORS headers
        const acao = response.headers.get("access-control-allow-origin");
        const acac = response.headers.get("access-control-allow-credentials");
        const acam = response.headers.get("access-control-allow-methods");
        const acah = response.headers.get("access-control-allow-headers");
        const aceh = response.headers.get("access-control-expose-headers");
        const acma = response.headers.get("access-control-max-age");
        
        result.responseHeaders = {
            accessControlAllowOrigin: acao || undefined,
            accessControlAllowCredentials: acac || undefined,
            accessControlAllowMethods: acam || undefined,
            accessControlAllowHeaders: acah || undefined,
            accessControlExposeHeaders: aceh || undefined,
            accessControlMaxAge: acma || undefined,
        };
        
        // Check for vulnerabilities
        if (!acao) {
            // No CORS headers - not vulnerable but also not configured
            return result;
        }
        
        // Check for wildcard with credentials (critical)
        if (acao === "*" && acac === "true") {
            result.vulnerable = true;
            result.severity = "critical";
            result.evidence = "Wildcard origin (*) with credentials allowed - this is a critical misconfiguration";
            return result;
        }
        
        // Check for wildcard origin
        if (acao === "*") {
            result.vulnerable = true;
            result.severity = "low";
            result.evidence = "Wildcard origin (*) allowed - may expose data to any origin";
            return result;
        }
        
        // Check for null origin with credentials
        if (origin === "null" && acao === "null" && acac === "true") {
            result.vulnerable = true;
            result.severity = "high";
            result.evidence = "Null origin allowed with credentials - exploitable via sandboxed iframes";
            return result;
        }
        
        // Check for null origin
        if (origin === "null" && acao === "null") {
            result.vulnerable = true;
            result.severity = "medium";
            result.evidence = "Null origin allowed - exploitable via sandboxed iframes";
            return result;
        }
        
        // Check for reflected origin with credentials (critical)
        if (acao === origin && acac === "true" && origin !== extractDomain(url)) {
            result.vulnerable = true;
            result.severity = "critical";
            result.evidence = `Origin ${origin} is reflected with credentials allowed - full account takeover possible`;
            return result;
        }
        
        // Check for reflected origin
        if (acao === origin && origin !== extractDomain(url)) {
            // Check if it's a legitimate subdomain
            const targetDomain = extractBaseDomain(extractDomain(url));
            const originDomain = extractBaseDomain(extractDomain(origin));
            
            if (targetDomain !== originDomain) {
                result.vulnerable = true;
                result.severity = acac === "true" ? "high" : "medium";
                result.evidence = `Origin ${origin} is reflected - cross-origin access possible`;
                return result;
            }
        }
        
        return result;
        
    } catch (error: any) {
        result.error = error.message || String(error);
        return result;
    }
}

/**
 * Test preflight (OPTIONS) request
 */
async function testPreflight(
    url: string,
    origin: string,
    options: {
        headers: Record<string, string>;
        timeout: number;
    }
): Promise<CorsTest> {
    const result: CorsTest = {
        origin,
        testType: "preflight",
        vulnerable: false,
        severity: "info",
        responseHeaders: {},
    };
    
    try {
        const response = await fetch(url, {
            method: "OPTIONS",
            headers: {
                ...options.headers,
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-Custom-Header",
            },
            // @ts-ignore
            timeout: options.timeout,
        });
        
        const acao = response.headers.get("access-control-allow-origin");
        const acac = response.headers.get("access-control-allow-credentials");
        const acam = response.headers.get("access-control-allow-methods");
        const acah = response.headers.get("access-control-allow-headers");
        
        result.responseHeaders = {
            accessControlAllowOrigin: acao || undefined,
            accessControlAllowCredentials: acac || undefined,
            accessControlAllowMethods: acam || undefined,
            accessControlAllowHeaders: acah || undefined,
        };
        
        // Check for overly permissive methods
        if (acam && /\*|DELETE|PUT|PATCH/i.test(acam)) {
            if (acao === "*" || acao === origin) {
                result.vulnerable = true;
                result.severity = "medium";
                result.evidence = `Dangerous methods allowed: ${acam}`;
            }
        }
        
        // Check for overly permissive headers
        if (acah && /\*|authorization|cookie/i.test(acah)) {
            if (acao === "*" || acao === origin) {
                result.vulnerable = true;
                result.severity = "medium";
                result.evidence = `Sensitive headers allowed: ${acah}`;
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
        
        let url = input.url;
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = `https://${url}`;
        }
        
        const method = input.method || "GET";
        const timeout = input.timeout || 10000;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const checkCredentials = input.checkCredentials !== false;
        const checkWildcard = input.checkWildcard !== false;
        const checkNullOrigin = input.checkNullOrigin !== false;
        const checkSubdomains = input.checkSubdomains !== false;
        
        const headers: Record<string, string> = {
            "User-Agent": userAgent,
            "Accept": "*/*",
            ...(input.headers || {}),
        };
        
        // Generate test origins
        let testOrigins = generateTestOrigins(url);
        
        // Filter based on options
        if (!checkNullOrigin) {
            testOrigins = testOrigins.filter(t => t.testType !== "null_origin");
        }
        if (!checkSubdomains) {
            testOrigins = testOrigins.filter(t => t.testType !== "subdomain_bypass");
        }
        
        // Add custom test origins
        if (input.testOrigins && input.testOrigins.length > 0) {
            for (const origin of input.testOrigins) {
                testOrigins.push({
                    origin,
                    testType: "custom",
                });
            }
        }
        
        // Run tests
        const tests: CorsTest[] = [];
        
        // First, do a baseline request without Origin header
        try {
            const baselineResponse = await fetch(url, {
                method,
                headers,
                // @ts-ignore
                timeout,
            });
            
            const baselineAcao = baselineResponse.headers.get("access-control-allow-origin");
            
            // Check for wildcard in baseline
            if (checkWildcard && baselineAcao === "*") {
                tests.push({
                    origin: "(no origin)",
                    testType: "wildcard_origin",
                    vulnerable: true,
                    severity: "low",
                    responseHeaders: {
                        accessControlAllowOrigin: baselineAcao || undefined,
                    },
                    evidence: "Wildcard origin (*) returned without Origin header",
                });
            }
        } catch {
            // Ignore baseline errors
        }
        
        // Test each origin
        for (const { origin, testType } of testOrigins) {
            const result = await testCors(url, origin, testType, {
                method,
                headers,
                timeout,
            });
            tests.push(result);
        }
        
        // Test preflight
        const preflightResult = await testPreflight(url, "https://evil.com", {
            headers,
            timeout,
        });
        tests.push(preflightResult);
        
        // Build summary
        const vulnerableTests = tests.filter(t => t.vulnerable);
        const bySeverity: Record<string, number> = {};
        const byTestType: Record<string, number> = {};
        
        for (const test of vulnerableTests) {
            bySeverity[test.severity] = (bySeverity[test.severity] || 0) + 1;
            byTestType[test.testType] = (byTestType[test.testType] || 0) + 1;
        }
        
        return {
            success: true,
            data: {
                url,
                tests,
                summary: {
                    totalTests: tests.length,
                    vulnerableCount: vulnerableTests.length,
                    bySeverity,
                    byTestType,
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
