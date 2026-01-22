/**
 * Web Content Change Monitor
 * 
 * @plugin content_monitor
 * @name Content Monitor
 * @version 1.0.0
 * @author Sentinel Team
 * @category monitor
 * @default_severity low
 * @tags content, monitor, change-detection, fingerprint, hash
 * @description Monitor web pages for content changes, generating ChangeEvents for workflow automation
 */

interface ToolInput {
    targets: string[];  // List of URLs to monitor
    timeout?: number;
    userAgent?: string;
    includeHeaders?: boolean;
    excludePatterns?: string[];  // Patterns to exclude from hash (e.g., timestamps)
    previousSnapshots?: Record<string, ContentSnapshot>;
}

interface ContentSnapshot {
    url: string;
    contentHash: string;
    contentLength: number;
    statusCode: number;
    title?: string;
    headers?: Record<string, string>;
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

interface ContentResult {
    url: string;
    success: boolean;
    snapshot?: ContentSnapshot;
    changed?: boolean;
    changeType?: string;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: ContentResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, ContentSnapshot>;
        summary: {
            totalTargets: number;
            successfulChecks: number;
            failedChecks: number;
            contentChanges: number;
            statusChanges: number;
            newPages: number;
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

// Calculate content hash
async function calculateHash(content: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Extract page title
function extractTitle(html: string): string | undefined {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match ? match[1].trim() : undefined;
}

// Normalize content (remove dynamic parts)
function normalizeContent(content: string, excludePatterns: string[]): string {
    let normalized = content;
    
    // Remove common dynamic elements
    const defaultPatterns = [
        // Timestamps
        /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/g,
        /\b\d{10,13}\b/g,  // Unix timestamps
        // Session tokens
        /csrf[_-]?token["\s:=]+["'][^"']+["']/gi,
        /nonce["\s:=]+["'][^"']+["']/gi,
        // Random IDs
        /[a-f0-9]{32}/gi,  // MD5-like
        /[a-f0-9]{64}/gi,  // SHA256-like
        // Cache busters
        /\?v=[\d.]+/g,
        /\?t=\d+/g,
        /\?_=\d+/g,
    ];
    
    // Apply default patterns
    for (const pattern of defaultPatterns) {
        normalized = normalized.replace(pattern, '[DYNAMIC]');
    }
    
    // Apply custom patterns
    for (const patternStr of excludePatterns) {
        try {
            const pattern = new RegExp(patternStr, 'gi');
            normalized = normalized.replace(pattern, '[EXCLUDED]');
        } catch {
            // Invalid regex, skip
        }
    }
    
    // Normalize whitespace
    normalized = normalized.replace(/\s+/g, ' ').trim();
    
    return normalized;
}

// Calculate risk score
function calculateRiskScore(severity: string, eventType: string): number {
    let score = 0;
    
    switch (severity) {
        case "critical": score += 40; break;
        case "high": score += 30; break;
        case "medium": score += 20; break;
        case "low": score += 10; break;
    }
    
    switch (eventType) {
        case "content_change": score += 10; break;
        case "significant_change": score += 20; break;
        case "status_change": score += 15; break;
        case "title_change": score += 10; break;
        case "page_discovered": score += 15; break;
    }
    
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
                description: "List of URLs to monitor for content changes"
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
            includeHeaders: {
                type: "boolean",
                description: "Include response headers in snapshot",
                default: false
            },
            excludePatterns: {
                type: "array",
                items: { type: "string" },
                description: "Regex patterns to exclude from content hash (e.g., timestamps)"
            },
            previousSnapshots: {
                type: "object",
                description: "Previous content snapshots for comparison"
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
                    results: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                url: { type: "string" },
                                success: { type: "boolean" },
                                snapshot: { type: "object" },
                                changed: { type: "boolean" },
                                changeType: { type: "string" }
                            }
                        },
                        description: "Content check results"
                    },
                    changeEvents: { type: "array", description: "Change events detected" },
                    snapshots: { type: "object", description: "Content snapshots by URL" },
                    summary: {
                        type: "object",
                        properties: {
                            totalTargets: { type: "integer" },
                            contentChanges: { type: "integer" },
                            statusChanges: { type: "integer" },
                            newPages: { type: "integer" }
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
        const includeHeaders = input.includeHeaders || false;
        const excludePatterns = input.excludePatterns || [];
        const previousSnapshots = input.previousSnapshots || {};
        
        const results: ContentResult[] = [];
        const changeEvents: ChangeEvent[] = [];
        const newSnapshots: Record<string, ContentSnapshot> = {};
        
        let successfulChecks = 0;
        let failedChecks = 0;
        let contentChanges = 0;
        let statusChanges = 0;
        let newPages = 0;
        
        for (const target of input.targets) {
            let url = target;
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = `https://${url}`;
            }
            
            const result: ContentResult = {
                url,
                success: false,
            };
            
            try {
                const response = await fetch(url, {
                    method: "GET",
                    headers: {
                        "User-Agent": userAgent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                    // @ts-ignore
                    timeout,
                });
                
                const content = await response.text();
                const normalizedContent = normalizeContent(content, excludePatterns);
                const contentHash = await calculateHash(normalizedContent);
                const title = extractTitle(content);
                
                result.success = true;
                successfulChecks++;
                
                // Create snapshot
                const snapshot: ContentSnapshot = {
                    url,
                    contentHash,
                    contentLength: content.length,
                    statusCode: response.status,
                    title,
                    lastChecked: new Date().toISOString(),
                };
                
                if (includeHeaders) {
                    snapshot.headers = {};
                    response.headers.forEach((value, key) => {
                        snapshot.headers![key] = value;
                    });
                }
                
                result.snapshot = snapshot;
                newSnapshots[url] = snapshot;
                
                // Check for changes
                const prevSnapshot = previousSnapshots[url];
                if (prevSnapshot) {
                    // Content hash changed
                    if (prevSnapshot.contentHash !== contentHash) {
                        contentChanges++;
                        result.changed = true;
                        result.changeType = "content";
                        
                        // Calculate change magnitude
                        const sizeDiff = Math.abs(content.length - prevSnapshot.contentLength);
                        const sizeChangePercent = prevSnapshot.contentLength > 0 
                            ? (sizeDiff / prevSnapshot.contentLength) * 100 
                            : 100;
                        
                        const isSignificant = sizeChangePercent > 20;
                        const severity = isSignificant ? "medium" : "low";
                        const eventType = isSignificant ? "significant_change" : "content_change";
                        
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: url,
                            eventType,
                            severity,
                            title: `Content Changed: ${new URL(url).hostname}${new URL(url).pathname}`,
                            description: `The content of ${url} has changed. Size difference: ${sizeDiff} bytes (${sizeChangePercent.toFixed(1)}% change).`,
                            oldValue: prevSnapshot.contentHash,
                            newValue: contentHash,
                            detectionMethod: "content_monitor",
                            tags: ["content", "change", isSignificant ? "significant" : "minor"],
                            autoTriggerEnabled: isSignificant,
                            riskScore: 0,
                            metadata: {
                                previousSize: prevSnapshot.contentLength,
                                newSize: content.length,
                                sizeChangePercent: sizeChangePercent.toFixed(2),
                                previousTitle: prevSnapshot.title,
                                newTitle: title,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType);
                        changeEvents.push(event);
                    }
                    
                    // Status code changed
                    if (prevSnapshot.statusCode !== response.status) {
                        statusChanges++;
                        
                        let severity: "low" | "medium" | "high" | "critical" = "low";
                        if (response.status >= 500) {
                            severity = "high";
                        } else if (response.status >= 400) {
                            severity = "medium";
                        } else if (prevSnapshot.statusCode >= 400 && response.status < 400) {
                            severity = "medium"; // Recovered from error
                        }
                        
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: url,
                            eventType: "status_change",
                            severity,
                            title: `Status Code Changed: ${new URL(url).hostname}`,
                            description: `HTTP status code changed from ${prevSnapshot.statusCode} to ${response.status} for ${url}.`,
                            oldValue: prevSnapshot.statusCode.toString(),
                            newValue: response.status.toString(),
                            detectionMethod: "content_monitor",
                            tags: ["status", "http", "change"],
                            autoTriggerEnabled: severity !== "low",
                            riskScore: 0,
                            metadata: {
                                url,
                                previousStatus: prevSnapshot.statusCode,
                                newStatus: response.status,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType);
                        changeEvents.push(event);
                    }
                    
                    // Title changed
                    if (prevSnapshot.title !== title && prevSnapshot.title && title) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: url,
                            eventType: "title_change",
                            severity: "low",
                            title: `Page Title Changed: ${new URL(url).hostname}`,
                            description: `The page title changed from "${prevSnapshot.title}" to "${title}".`,
                            oldValue: prevSnapshot.title,
                            newValue: title,
                            detectionMethod: "content_monitor",
                            tags: ["title", "change"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: { url },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType);
                        changeEvents.push(event);
                    }
                } else {
                    // New page discovered
                    newPages++;
                    result.changed = true;
                    result.changeType = "new";
                    
                    const event: ChangeEvent = {
                        id: generateId(),
                        assetId: url,
                        eventType: "page_discovered",
                        severity: "low",
                        title: `New Page Discovered: ${new URL(url).hostname}${new URL(url).pathname}`,
                        description: `New page discovered at ${url}. Title: "${title || 'N/A'}". Size: ${content.length} bytes.`,
                        newValue: contentHash,
                        detectionMethod: "content_monitor",
                        tags: ["discovery", "new", "page"],
                        autoTriggerEnabled: false,
                        riskScore: 0,
                        metadata: {
                            title,
                            contentLength: content.length,
                            statusCode: response.status,
                        },
                    };
                    event.riskScore = calculateRiskScore(event.severity, event.eventType);
                    changeEvents.push(event);
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
                    contentChanges,
                    statusChanges,
                    newPages,
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
