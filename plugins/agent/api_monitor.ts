/**
 * API Endpoint Change Monitor
 * 
 * @plugin api_monitor
 * @name API Monitor
 * @version 1.0.0
 * @author Sentinel Team
 * @category monitor
 * @default_severity high
 * @tags api, endpoint, monitor, change-detection, rest, graphql
 * @description Monitor API endpoints for changes (new endpoints, removed endpoints, response changes), generating ChangeEvents for workflow automation
 */

// Declare Sentinel API for JS analysis
declare const Sentinel: {
    AST: {
        parse: (code: string, filename?: string) => {
            success: boolean;
            literals: Array<{ value: string; line: number; column: number; type: string }>;
            errors: string[];
        };
    };
};

interface ToolInput {
    targets: string[];  // Base URLs or JS files to analyze
    timeout?: number;
    userAgent?: string;
    crawlDepth?: number;
    includeGraphQL?: boolean;
    includeOpenAPI?: boolean;
    previousSnapshots?: Record<string, ApiSnapshot>;
}

interface ApiEndpoint {
    path: string;
    method?: string;
    source: string;
    parameters?: string[];
}

interface ApiSnapshot {
    baseUrl: string;
    endpoints: ApiEndpoint[];
    graphqlEndpoint?: string;
    openApiSpec?: string;
    lastChecked: string;
}

interface ChangeEvent {
    id: string;
    assetId: string;
    eventType: string;
    severity: "low" | "medium" | "high" | "critical";
    title: string;
    description: string;
    oldValue?: string;
    newValue?: string;
    detectionMethod: string;
    tags: string[];
    autoTriggerEnabled: boolean;
    riskScore: number;
    metadata: Record<string, any>;
}

interface ApiResult {
    baseUrl: string;
    success: boolean;
    snapshot?: ApiSnapshot;
    addedEndpoints?: ApiEndpoint[];
    removedEndpoints?: ApiEndpoint[];
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: ApiResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, ApiSnapshot>;
        summary: {
            totalTargets: number;
            successfulChecks: number;
            failedChecks: number;
            totalEndpoints: number;
            addedEndpoints: number;
            removedEndpoints: number;
            apiChanges: number;
        };
    };
    error?: string;
}

// Generate UUID
function generateId(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// API endpoint patterns
const API_PATTERNS = [
    /^\/api\/[a-zA-Z0-9\/_-]+$/,
    /^\/v[0-9]+\/[a-zA-Z0-9\/_-]+$/,
    /^\/rest\/[a-zA-Z0-9\/_-]+$/,
    /^\/graphql\/?$/,
    /^\/gql\/?$/,
    /^\/(?:users?|auth|login|logout|register|signup|profile|account|settings|config|admin|dashboard|data|search|upload|download|export|import|webhook|token|oauth|callback|notify|events?|messages?|posts?|comments?|items?|products?|orders?|payments?|subscriptions?|notifications?)(?:\/[a-zA-Z0-9_-]*)*$/,
];

// Common API file paths to check
const COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/rest",
    "/graphql",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
];

// Extract API endpoints from JavaScript content
function extractApisFromJs(content: string, source: string): ApiEndpoint[] {
    const endpoints: ApiEndpoint[] = [];
    const seen = new Set<string>();
    
    // Try to use Sentinel AST API if available
    let literals: Array<{ value: string; line: number }> = [];
    
    try {
        if (typeof Sentinel !== "undefined" && Sentinel.AST) {
            const result = Sentinel.AST.parse(content, source);
            literals = result.literals;
        }
    } catch {
        // Fall back to regex
    }
    
    if (literals.length === 0) {
        // Regex fallback
        const stringPattern = /(['"`])([^'"`\n]{3,200})\1/g;
        let match;
        while ((match = stringPattern.exec(content)) !== null) {
            literals.push({ value: match[2], line: 0 });
        }
    }
    
    for (const literal of literals) {
        const value = literal.value.trim();
        if (seen.has(value)) continue;
        
        // Check API patterns
        for (const pattern of API_PATTERNS) {
            if (pattern.test(value)) {
                seen.add(value);
                endpoints.push({
                    path: value,
                    source,
                });
                break;
            }
        }
        
        // Check for full API URLs
        if (!seen.has(value) && /^https?:\/\/[^\/]+\/(?:api|v[0-9]+|rest|graphql)/i.test(value)) {
            seen.add(value);
            try {
                const url = new URL(value);
                endpoints.push({
                    path: url.pathname,
                    source,
                });
            } catch {
                // Invalid URL
            }
        }
    }
    
    // Extract from fetch/axios calls with method info
    const fetchPattern = /(?:fetch|axios)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
    let fetchMatch;
    while ((fetchMatch = fetchPattern.exec(content)) !== null) {
        const method = fetchMatch[1].toUpperCase();
        const path = fetchMatch[2];
        const key = `${method}:${path}`;
        if (!seen.has(key)) {
            seen.add(key);
            endpoints.push({
                path,
                method,
                source,
            });
        }
    }
    
    return endpoints;
}

// Extract script URLs from HTML
function extractScriptUrls(html: string, baseUrl: string): string[] {
    const scripts: string[] = [];
    const regex = /<script[^>]*\s+src=["']([^"']+)["']/gi;
    let match;
    
    while ((match = regex.exec(html)) !== null) {
        let src = match[1];
        if (src.startsWith("data:") || src.startsWith("javascript:")) continue;
        
        try {
            if (src.startsWith("//")) {
                src = `https:${src}`;
            } else if (src.startsWith("/")) {
                const url = new URL(baseUrl);
                src = `${url.origin}${src}`;
            } else if (!src.startsWith("http")) {
                const url = new URL(baseUrl);
                const basePath = url.pathname.substring(0, url.pathname.lastIndexOf("/") + 1);
                src = `${url.origin}${basePath}${src}`;
            }
            scripts.push(src);
        } catch {
            // Invalid URL
        }
    }
    
    return [...new Set(scripts)];
}

// Calculate risk score
function calculateRiskScore(severity: string, eventType: string, count: number): number {
    let score = 0;
    
    switch (severity) {
        case "critical": score += 40; break;
        case "high": score += 30; break;
        case "medium": score += 20; break;
        case "low": score += 10; break;
    }
    
    switch (eventType) {
        case "api_endpoints_added": score += 20; break;
        case "api_endpoints_removed": score += 15; break;
        case "api_change": score += 15; break;
        case "graphql_discovered": score += 20; break;
        case "openapi_discovered": score += 15; break;
    }
    
    // Bonus for multiple changes
    score += Math.min(count * 2, 20);
    
    return Math.min(score, 100);
}

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
                description: "List of base URLs to monitor for API changes"
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
                description: "Custom User-Agent header"
            },
            crawlDepth: {
                type: "integer",
                description: "Depth to crawl for JS files",
                default: 1,
                minimum: 0,
                maximum: 3
            },
            includeGraphQL: {
                type: "boolean",
                description: "Check for GraphQL endpoints",
                default: true
            },
            includeOpenAPI: {
                type: "boolean",
                description: "Check for OpenAPI/Swagger specs",
                default: true
            },
            previousSnapshots: {
                type: "object",
                description: "Previous API snapshots for comparison"
            }
        }
    };
}

globalThis.get_input_schema = get_input_schema;

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!input.targets || !Array.isArray(input.targets) || input.targets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets array is required"
            };
        }
        
        const timeout = input.timeout || 15000;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const crawlDepth = input.crawlDepth ?? 1;
        const includeGraphQL = input.includeGraphQL !== false;
        const includeOpenAPI = input.includeOpenAPI !== false;
        const previousSnapshots = input.previousSnapshots || {};
        
        const results: ApiResult[] = [];
        const changeEvents: ChangeEvent[] = [];
        const newSnapshots: Record<string, ApiSnapshot> = {};
        
        let successfulChecks = 0;
        let failedChecks = 0;
        let totalEndpoints = 0;
        let addedEndpointsCount = 0;
        let removedEndpointsCount = 0;
        let apiChanges = 0;
        
        for (const target of input.targets) {
            let baseUrl = target;
            if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
                baseUrl = `https://${baseUrl}`;
            }
            
            const result: ApiResult = {
                baseUrl,
                success: false,
            };
            
            try {
                const allEndpoints: ApiEndpoint[] = [];
                let graphqlEndpoint: string | undefined;
                let openApiSpec: string | undefined;
                
                // Fetch main page
                const response = await fetch(baseUrl, {
                    method: "GET",
                    headers: {
                        "User-Agent": userAgent,
                        "Accept": "text/html,application/xhtml+xml,*/*",
                    },
                    // @ts-ignore
                    timeout,
                });
                
                if (!response.ok) {
                    result.error = `HTTP ${response.status}`;
                    failedChecks++;
                    results.push(result);
                    continue;
                }
                
                const html = await response.text();
                successfulChecks++;
                
                // Extract endpoints from inline scripts
                const inlineScriptPattern = /<script[^>]*>([^]*?)<\/script>/gi;
                let scriptMatch;
                while ((scriptMatch = inlineScriptPattern.exec(html)) !== null) {
                    if (!scriptMatch[0].includes("src=")) {
                        const endpoints = extractApisFromJs(scriptMatch[1], "inline");
                        allEndpoints.push(...endpoints);
                    }
                }
                
                // Extract and analyze external JS files
                if (crawlDepth > 0) {
                    const scriptUrls = extractScriptUrls(html, baseUrl);
                    for (const scriptUrl of scriptUrls.slice(0, 20)) {
                        try {
                            const jsResponse = await fetch(scriptUrl, {
                                method: "GET",
                                headers: { "User-Agent": userAgent },
                                // @ts-ignore
                                timeout,
                            });
                            
                            if (jsResponse.ok) {
                                const jsContent = await jsResponse.text();
                                const source = scriptUrl.split("/").pop() || scriptUrl;
                                const endpoints = extractApisFromJs(jsContent, source);
                                allEndpoints.push(...endpoints);
                            }
                        } catch {
                            // Skip failed JS files
                        }
                    }
                }
                
                // Check common API paths
                const urlObj = new URL(baseUrl);
                for (const path of COMMON_API_PATHS) {
                    try {
                        const apiUrl = `${urlObj.origin}${path}`;
                        const apiResponse = await fetch(apiUrl, {
                            method: "GET",
                            headers: {
                                "User-Agent": userAgent,
                                "Accept": "application/json,*/*",
                            },
                            // @ts-ignore
                            timeout: 5000,
                        });
                        
                        if (apiResponse.ok) {
                            allEndpoints.push({
                                path,
                                source: "probe",
                            });
                            
                            // Check for OpenAPI spec
                            if (includeOpenAPI && (path.includes("swagger") || path.includes("openapi"))) {
                                const specContent = await apiResponse.text();
                                if (specContent.includes("openapi") || specContent.includes("swagger")) {
                                    openApiSpec = apiUrl;
                                }
                            }
                        }
                    } catch {
                        // Path doesn't exist
                    }
                }
                
                // Check GraphQL
                if (includeGraphQL) {
                    for (const gqlPath of ["/graphql", "/gql", "/api/graphql"]) {
                        try {
                            const gqlUrl = `${urlObj.origin}${gqlPath}`;
                            const gqlResponse = await fetch(gqlUrl, {
                                method: "POST",
                                headers: {
                                    "User-Agent": userAgent,
                                    "Content-Type": "application/json",
                                },
                                body: JSON.stringify({ query: "{ __typename }" }),
                                // @ts-ignore
                                timeout: 5000,
                            });
                            
                            if (gqlResponse.ok) {
                                const gqlResult = await gqlResponse.text();
                                if (gqlResult.includes("__typename") || gqlResult.includes("data")) {
                                    graphqlEndpoint = gqlPath;
                                    allEndpoints.push({
                                        path: gqlPath,
                                        method: "POST",
                                        source: "graphql-probe",
                                    });
                                    break;
                                }
                            }
                        } catch {
                            // GraphQL not available
                        }
                    }
                }
                
                // Deduplicate endpoints
                const uniqueEndpoints: ApiEndpoint[] = [];
                const seen = new Set<string>();
                for (const ep of allEndpoints) {
                    const key = `${ep.method || ""}:${ep.path}`;
                    if (!seen.has(key)) {
                        seen.add(key);
                        uniqueEndpoints.push(ep);
                    }
                }
                
                totalEndpoints += uniqueEndpoints.length;
                
                // Create snapshot
                const snapshot: ApiSnapshot = {
                    baseUrl,
                    endpoints: uniqueEndpoints,
                    graphqlEndpoint,
                    openApiSpec,
                    lastChecked: new Date().toISOString(),
                };
                
                result.success = true;
                result.snapshot = snapshot;
                newSnapshots[baseUrl] = snapshot;
                
                // Compare with previous snapshot
                const prevSnapshot = previousSnapshots[baseUrl];
                if (prevSnapshot) {
                    const prevPaths = new Set(prevSnapshot.endpoints.map(e => `${e.method || ""}:${e.path}`));
                    const newPaths = new Set(uniqueEndpoints.map(e => `${e.method || ""}:${e.path}`));
                    
                    // Find added endpoints
                    const addedEndpoints = uniqueEndpoints.filter(e => !prevPaths.has(`${e.method || ""}:${e.path}`));
                    const removedEndpoints = prevSnapshot.endpoints.filter(e => !newPaths.has(`${e.method || ""}:${e.path}`));
                    
                    result.addedEndpoints = addedEndpoints;
                    result.removedEndpoints = removedEndpoints;
                    
                    // Generate change events
                    if (addedEndpoints.length > 0) {
                        apiChanges++;
                        addedEndpointsCount += addedEndpoints.length;
                        
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_added",
                            severity: "high",
                            title: `New API Endpoints Discovered: ${urlObj.hostname}`,
                            description: `${addedEndpoints.length} new API endpoint(s) discovered: ${addedEndpoints.map(e => e.path).join(", ")}`,
                            newValue: JSON.stringify(addedEndpoints.map(e => e.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "new", "discovery"],
                            autoTriggerEnabled: true,
                            riskScore: 0,
                            metadata: {
                                addedEndpoints,
                                count: addedEndpoints.length,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, addedEndpoints.length);
                        changeEvents.push(event);
                    }
                    
                    if (removedEndpoints.length > 0) {
                        apiChanges++;
                        removedEndpointsCount += removedEndpoints.length;
                        
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_removed",
                            severity: "low",
                            title: `API Endpoints Removed: ${urlObj.hostname}`,
                            description: `${removedEndpoints.length} API endpoint(s) removed: ${removedEndpoints.map(e => e.path).join(", ")}`,
                            oldValue: JSON.stringify(removedEndpoints.map(e => e.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "removed"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                removedEndpoints,
                                count: removedEndpoints.length,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, removedEndpoints.length);
                        changeEvents.push(event);
                    }
                    
                    // GraphQL discovered
                    if (graphqlEndpoint && !prevSnapshot.graphqlEndpoint) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "graphql_discovered",
                            severity: "high",
                            title: `GraphQL Endpoint Discovered: ${urlObj.hostname}`,
                            description: `A GraphQL endpoint was discovered at ${graphqlEndpoint}. This is a high-value target for testing.`,
                            newValue: graphqlEndpoint,
                            detectionMethod: "api_monitor",
                            tags: ["api", "graphql", "discovery"],
                            autoTriggerEnabled: true,
                            riskScore: 0,
                            metadata: { graphqlEndpoint },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, 1);
                        changeEvents.push(event);
                    }
                    
                    // OpenAPI spec discovered
                    if (openApiSpec && !prevSnapshot.openApiSpec) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "openapi_discovered",
                            severity: "medium",
                            title: `OpenAPI Spec Discovered: ${urlObj.hostname}`,
                            description: `An OpenAPI/Swagger specification was discovered at ${openApiSpec}.`,
                            newValue: openApiSpec,
                            detectionMethod: "api_monitor",
                            tags: ["api", "openapi", "swagger", "discovery"],
                            autoTriggerEnabled: true,
                            riskScore: 0,
                            metadata: { openApiSpec },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, 1);
                        changeEvents.push(event);
                    }
                } else {
                    // First scan - report all as discovered
                    if (uniqueEndpoints.length > 0) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_discovered",
                            severity: "medium",
                            title: `API Endpoints Discovered: ${urlObj.hostname}`,
                            description: `Initial scan discovered ${uniqueEndpoints.length} API endpoint(s).`,
                            newValue: JSON.stringify(uniqueEndpoints.map(e => e.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "initial-scan"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                endpoints: uniqueEndpoints,
                                graphqlEndpoint,
                                openApiSpec,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, uniqueEndpoints.length);
                        changeEvents.push(event);
                    }
                }
                
            } catch (error: any) {
                result.error = error.message || String(error);
                failedChecks++;
            }
            
            results.push(result);
        }
        
        return {
            success: true,
            data: {
                results,
                changeEvents,
                snapshots: newSnapshots,
                summary: {
                    totalTargets: input.targets.length,
                    successfulChecks,
                    failedChecks,
                    totalEndpoints,
                    addedEndpoints: addedEndpointsCount,
                    removedEndpoints: removedEndpointsCount,
                    apiChanges,
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
