/**
 * JavaScript Analyzer Tool (AST-based via oxc_parser)
 *
 * @plugin js_analyzer
 * @name JavaScript Analyzer
 * @version 3.1.8
 * @author Sentinel Team
 * @main_category bounty
 * @monitor_type api
 * @input_mode asset
 * @target_asset_types ["web"]
 * @category discovery
 * @seed_bindings []
 * @default_severity info
 * @tags javascript, endpoint, api, discovery, secrets, ast, capability:fetch, capability:ast-parse, capability:monitor-events, monitor:results-stream-v1
 * @description Analyze JavaScript files using AST parsing (oxc_parser) to extract all string literals, then identify API endpoints, secrets, and sensitive data
 */
import { createMonitorResultStream } from '../../shared/monitor_results.ts';
import { createMonitorTargetWriter } from '../../shared/monitor_target_writer.ts';


// Declare Sentinel global API
declare const Sentinel: {
    AST: {
        parse: (code: string, filename?: string) => {
            success: boolean;
            literals: Array<{ value: string; line: number; column: number; type: string }>;
            errors: string[];
        };
        extractLiterals: (code: string, options?: { minLength?: number; types?: string[] }) => Array<{ value: string; line: number; column: number; type: string }>;
        extractUniqueStrings: (code: string, options?: { minLength?: number }) => string[];
    };
    Dictionary: {
        getWords: (idOrName: string, limit?: number) => Promise<string[]>;
    };
    Monitor?: {
        reportProgress?(request: Record<string, unknown>): Promise<boolean> | boolean;
    };
};

interface ToolInput {
    url?: string;
    urls?: string[];
    concurrency?: number;
    userAgent?: string;
    maxFileSize?: number;
    extractEndpoints?: boolean;
    extractSecrets?: boolean;
    extractDomains?: boolean;
    followImports?: boolean;
    maxFiles?: number;
    __monitorExecution?: MonitorExecutionContext;
}

interface MonitorExecutionContext {
    task_id: string;
    task_name: string;
    program_id: string;
    execution_mode: string;
    started_at: string;
    current_plugin: string;
    current_plugin_index: number;
    completed_steps: number;
    total_steps: number;
    imported_assets?: number;
}

interface StringLiteral {
    value: string;
    line: number;
    column: number;
    type: string;
}

interface Endpoint {
    url: string;
    method?: string;
    source: string;
    line?: number;
}

interface Secret {
    type: string;
    value: string;
    source: string;
    line?: number;
    severity: "critical" | "high" | "medium" | "low";
}

interface Domain {
    domain: string;
    source: string;
    line?: number;
}

interface JsFile {
    url: string;
    size: number;
    literalsCount: number;
    endpoints: Endpoint[];
    secrets: Secret[];
    domains: Domain[];
    parseErrors?: string[];
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        baseUrls: string[];
        files: JsFile[];
        summary: {
            totalFiles: number;
            totalLiterals: number;
            totalEndpoints: number;
            totalSecrets: number;
            totalDomains: number;
            uniqueEndpoints: string[];
            uniqueDomains: string[];
            secretsBySeverity: Record<string, number>;
            urlsScanned: number;
        };
    };
    error?: string;
}

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;
const PAGE_FETCH_TIMEOUT_MS = 8000;
const JS_FETCH_TIMEOUT_MS = 12000;
const MIN_TIMEOUT_MS = 3000;
const MAX_TIMEOUT_MS = 3000;
const MIN_CONCURRENCY = 1;

async function reportMonitorProgress(
    monitorExecution: MonitorExecutionContext | undefined,
    update: Record<string, unknown>,
): Promise<boolean> {
    if (!monitorExecution) return false;
    try {
        return Boolean(await Sentinel.Monitor?.reportProgress?.({
            monitorProgress: {
                taskId: monitorExecution.task_id,
                taskName: monitorExecution.task_name,
                programId: monitorExecution.program_id,
                executionMode: monitorExecution.execution_mode,
                startedAt: monitorExecution.started_at,
                currentPlugin: monitorExecution.current_plugin,
                currentPluginIndex: monitorExecution.current_plugin_index,
                completedSteps: monitorExecution.completed_steps,
                totalSteps: monitorExecution.total_steps,
                importedAssets: monitorExecution.imported_assets,
            },
            ...update,
        }));
    } catch {
        return false;
    }
}

function clampInteger(value: unknown, fallback: number, min: number, max: number): number {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(Math.floor(parsed), max));
}

// Secret patterns with severity
const SECRET_PATTERNS: { name: string; pattern: RegExp; severity: "critical" | "high" | "medium" | "low" }[] = [
    // Cloud Provider Keys
    { name: "AWS Access Key", pattern: /^AKIA[0-9A-Z]{16}$/, severity: "critical" },
    { name: "AWS Secret Key", pattern: /^[0-9a-zA-Z\/+]{40}$/, severity: "critical" },
    { name: "Google API Key", pattern: /^AIza[0-9A-Za-z_-]{35}$/, severity: "high" },
    { name: "Google OAuth", pattern: /^[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com$/, severity: "high" },

    // Payment Services
    { name: "Stripe Live Key", pattern: /^sk_live_[0-9a-zA-Z]{24,}$/, severity: "critical" },
    { name: "Stripe Publishable Key", pattern: /^pk_live_[0-9a-zA-Z]{24,}$/, severity: "medium" },
    { name: "Stripe Test Key", pattern: /^sk_test_[0-9a-zA-Z]{24,}$/, severity: "low" },
    { name: "Square Access Token", pattern: /^sq0atp-[0-9A-Za-z_-]{22,}$/, severity: "critical" },
    { name: "Square OAuth Secret", pattern: /^sq0csp-[0-9A-Za-z_-]{43,}$/, severity: "critical" },
    { name: "PayPal Braintree Token", pattern: /^access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}$/, severity: "critical" },

    // Version Control & CI/CD
    { name: "GitHub Token", pattern: /^ghp_[0-9a-zA-Z]{36}$/, severity: "critical" },
    { name: "GitHub OAuth", pattern: /^gho_[0-9a-zA-Z]{36}$/, severity: "high" },
    { name: "GitHub App Token", pattern: /^ghu_[0-9a-zA-Z]{36}$/, severity: "high" },
    { name: "GitLab Token", pattern: /^glpat-[0-9a-zA-Z_-]{20,}$/, severity: "critical" },

    // Communication Services
    { name: "Slack Token", pattern: /^xox[baprs]-[0-9a-zA-Z-]{10,}$/, severity: "critical" },
    { name: "Slack Webhook", pattern: /hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-zA-Z0-9]+/, severity: "high" },
    { name: "Discord Webhook", pattern: /discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/, severity: "high" },
    { name: "Telegram Bot Token", pattern: /^[0-9]{8,10}:[A-Za-z0-9_-]{35}$/, severity: "high" },

    // Email Services
    { name: "SendGrid API Key", pattern: /^SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}$/, severity: "critical" },
    { name: "Mailchimp API Key", pattern: /^[0-9a-f]{32}-us[0-9]{1,2}$/, severity: "high" },
    { name: "Mailgun API Key", pattern: /^key-[0-9a-zA-Z]{32}$/, severity: "high" },

    // Phone/SMS Services
    { name: "Twilio API Key", pattern: /^SK[0-9a-fA-F]{32}$/, severity: "high" },
    { name: "Twilio Account SID", pattern: /^AC[0-9a-fA-F]{32}$/, severity: "medium" },

    // Social Media
    { name: "Facebook Access Token", pattern: /^EAACEdEose0cBA[0-9A-Za-z]+$/, severity: "high" },
    { name: "Twitter Bearer Token", pattern: /^AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]+$/, severity: "high" },

    // Database Connection Strings
    { name: "MongoDB URI", pattern: /^mongodb(?:\+srv)?:\/\/[^\s]+$/, severity: "critical" },
    { name: "PostgreSQL URI", pattern: /^postgres(?:ql)?:\/\/[^\s]+$/, severity: "critical" },
    { name: "MySQL URI", pattern: /^mysql:\/\/[^\s]+$/, severity: "critical" },
    { name: "Redis URI", pattern: /^redis:\/\/[^\s]+$/, severity: "critical" },
    { name: "MSSQL URI", pattern: /^mssql:\/\/[^\s]+$/, severity: "critical" },

    // Authentication
    { name: "JWT Token", pattern: /^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/, severity: "medium" },
    { name: "Bearer Token", pattern: /^Bearer\s+[A-Za-z0-9_-]{20,}$/, severity: "high" },
    { name: "Basic Auth", pattern: /^Basic\s+[A-Za-z0-9+\/=]{10,}$/, severity: "high" },

    // Private Keys
    { name: "Private Key", pattern: /^-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: "critical" },
    { name: "PGP Private Key", pattern: /^-----BEGIN PGP PRIVATE KEY BLOCK-----/, severity: "critical" },

    // Generic High-Entropy Secrets (32+ hex chars)
    { name: "Hex Secret (32+)", pattern: /^[0-9a-fA-F]{32,64}$/, severity: "medium" },

    // API Key patterns in common formats
    { name: "Generic API Key", pattern: /^[a-zA-Z0-9_-]{32,}$/, severity: "low" },
];

// Endpoint detection patterns
const ENDPOINT_PATTERNS: { pattern: RegExp; method?: string }[] = [
    // API paths
    { pattern: /^\/api\/[a-zA-Z0-9\/_-]+$/ },
    { pattern: /^\/v[0-9]+\/[a-zA-Z0-9\/_-]+$/ },
    { pattern: /^\/rest\/[a-zA-Z0-9\/_-]+$/ },
    { pattern: /^\/graphql\/?$/ },
    { pattern: /^\/gql\/?$/ },

    // Common REST endpoints
    { pattern: /^\/(?:users?|auth|login|logout|register|signup|signin|profile|account|settings|config|admin|dashboard|data|search|upload|download|export|import|webhook)(?:\/[a-zA-Z0-9_-]*)*$/ },

    // Full URLs with API paths
    { pattern: /^https?:\/\/[^\/]+\/api\/[^\s"']+$/ },
    { pattern: /^https?:\/\/[^\/]+\/v[0-9]+\/[^\s"']+$/ },
    { pattern: /^https?:\/\/[^\/]+\/rest\/[^\s"']+$/ },
    { pattern: /^https?:\/\/[^\/]+\/graphql\/?$/ },
];

// Domain extraction pattern
const DOMAIN_PATTERN = /^https?:\/\/([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)/;

// Skip domains (CDN, analytics, etc.)
const SKIP_DOMAINS = new Set([
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "google-analytics.com", "facebook.com", "facebook.net", "fbcdn.net",
    "twitter.com", "twimg.com", "youtube.com", "ytimg.com",
    "cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com", "jquery.com", "fontawesome.com", "esm.sh",
    "w3.org", "schema.org", "mozilla.org", "npmjs.com", "github.com",
]);

const DEFAULT_CONCURRENCY = 32;
const MAX_CONCURRENCY = 32;
const MAX_FILE_ANALYSIS_CONCURRENCY = 32;

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        properties: {
            url: {
                type: "string",
                description: "Single target URL (HTML page or JavaScript file, use 'urls' for multiple targets)"
            },
            urls: {
                type: "array",
                items: { type: "string" },
                description: "Array of target URLs to analyze (supports batch processing)"
            },
            concurrency: {
                type: "integer",
                description: "Maximum concurrent base URL analyses",
                default: DEFAULT_CONCURRENCY,
                minimum: MIN_CONCURRENCY,
                maximum: MAX_CONCURRENCY
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            maxFileSize: {
                type: "integer",
                description: "Maximum file size to analyze in bytes",
                default: 5242880,
                minimum: 102400,
                maximum: 52428800
            },
            extractEndpoints: {
                type: "boolean",
                description: "Extract API endpoints",
                default: true
            },
            extractSecrets: {
                type: "boolean",
                description: "Extract secrets and sensitive data",
                default: true
            },
            extractDomains: {
                type: "boolean",
                description: "Extract referenced domains",
                default: true
            },
            followImports: {
                type: "boolean",
                description: "Follow and analyze imported JS files",
                default: true
            },
            maxFiles: {
                type: "integer",
                description: "Maximum number of JS files to analyze per URL",
                default: 20,
                minimum: 1,
                maximum: 100
            },
        }
    };
}

pluginGlobals.get_input_schema = get_input_schema;

async function executeConcurrently<T, R>(
    items: T[],
    executor: (item: T) => Promise<R>,
    concurrency: number,
): Promise<R[]> {
    const results: R[] = new Array(items.length);
    let nextIndex = 0;
    const workerCount = Math.min(concurrency, items.length);

    async function worker() {
        while (nextIndex < items.length) {
            const index = nextIndex;
            nextIndex += 1;
            results[index] = await executor(items[index]);
        }
    }

    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    return results;
}

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
                    baseUrl: { type: "string", description: "Base URL analyzed" },
                    files: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                url: { type: "string" },
                                endpoints: { type: "array" },
                                secrets: { type: "array" },
                                domains: { type: "array" }
                            }
                        },
                        description: "Analyzed JS files"
                    },
                    summary: {
                        type: "object",
                        properties: {
                            totalFiles: { type: "integer" },
                            totalEndpoints: { type: "integer" },
                            totalSecrets: { type: "integer" },
                            uniqueEndpoints: { type: "array", items: { type: "string" } },
                            uniqueDomains: { type: "array", items: { type: "string" } }
                        }
                    }
                }
            },
            error: { type: "string", description: "Error message if failed" }
        }
    };
}

pluginGlobals.get_output_schema = get_output_schema;

/**
 * Extract literals from JavaScript code using Sentinel AST API (oxc_parser)
 */
function extractLiterals(code: string, filename?: string): { literals: StringLiteral[]; errors: string[] } {
    if (typeof Sentinel === "undefined" || !Sentinel.AST || typeof Sentinel.AST.parse !== "function") {
        throw new Error("JavaScript analysis requires Sentinel.AST.parse");
    }
    const result = Sentinel.AST.parse(code, filename);
    if (!result || !Array.isArray(result.literals) || !Array.isArray(result.errors)) {
        throw new Error("JavaScript AST parser returned an invalid result");
    }
    return { literals: result.literals, errors: result.errors };
}

/**
 * Fallback: Extract string literals using regex
 */

/**
 * Analyze literals to extract endpoints
 */
function analyzeEndpoints(literals: StringLiteral[], source: string): Endpoint[] {
    const endpoints: Endpoint[] = [];
    const seen = new Set<string>();

    for (const literal of literals) {
        const value = literal.value.trim();

        if (seen.has(value)) continue;

        // Check against endpoint patterns
        for (const { pattern, method } of ENDPOINT_PATTERNS) {
            if (pattern.test(value)) {
                seen.add(value);
                endpoints.push({
                    url: value,
                    method,
                    source,
                    line: literal.line,
                });
                break;
            }
        }

        // Check for URL-like strings that might be endpoints
        if (!seen.has(value) && value.startsWith("/") && value.length > 1) {
            const segments = value.split("/").filter(Boolean);
            if (segments.length >= 2 && !/\.[a-z]{2,4}$/i.test(value)) {
                if (!/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$/i.test(value)) {
                    seen.add(value);
                    endpoints.push({
                        url: value,
                        source,
                        line: literal.line,
                    });
                }
            }
        }
    }

    return endpoints;
}

/**
 * Calculate Shannon entropy of a string
 */
function calculateEntropy(str: string): number {
    const freq: Record<string, number> = {};
    for (const char of str) {
        freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

/**
 * Analyze literals to extract secrets
 */
function analyzeSecrets(literals: StringLiteral[], source: string): Secret[] {
    const secrets: Secret[] = [];
    const seen = new Set<string>();

    for (const literal of literals) {
        const value = literal.value.trim();

        // Skip if too short or too long
        if (value.length < 8 || value.length > 500) continue;

        // Skip common false positives
        if (/^(true|false|null|undefined|function|return|const|let|var|import|export|from|default|class|extends|constructor|this|super|new|delete|typeof|instanceof|void|yield|await|async|static|get|set|if|else|switch|case|break|continue|for|while|do|try|catch|finally|throw|with|debugger)$/i.test(value)) {
            continue;
        }

        if (seen.has(value)) continue;

        // Check against secret patterns
        for (const { name, pattern, severity } of SECRET_PATTERNS) {
            if (pattern.test(value)) {
                // Additional validation for generic patterns
                if (name === "Generic API Key" || name === "Hex Secret (32+)") {
                    if (/^[0-9a-f]{32}$/i.test(value) && !value.includes("-")) {
                        const entropy = calculateEntropy(value);
                        if (entropy < 3.5) continue;
                    }
                }

                seen.add(value);
                secrets.push({
                    type: name,
                    value: value.length > 80 ? value.substring(0, 80) + "..." : value,
                    source,
                    line: literal.line,
                    severity,
                });
                break;
            }
        }
    }

    return secrets;
}

/**
 * Analyze literals to extract domains
 */
function analyzeDomains(literals: StringLiteral[], source: string): Domain[] {
    const domains: Domain[] = [];
    const seen = new Set<string>();

    for (const literal of literals) {
        const value = literal.value.trim();

        const match = value.match(DOMAIN_PATTERN);
        if (match) {
            const domain = match[1].toLowerCase();

            // Skip common CDN/analytics domains
            if (SKIP_DOMAINS.has(domain)) continue;
            let skip = false;
            for (const skipDomain of SKIP_DOMAINS) {
                if (domain.endsWith(`.${skipDomain}`)) {
                    skip = true;
                    break;
                }
            }
            if (skip) continue;

            if (seen.has(domain)) continue;
            seen.add(domain);

            domains.push({
                domain,
                source,
                line: literal.line,
            });
        }
    }

    return domains;
}

/**
 * Extract script URLs from HTML
 */
function extractScriptUrls(html: string, baseUrl: string): string[] {
    const scripts: string[] = [];
    const regex = /<script[^>]*\s+src=["']([^"']+)["']/gi;
    let match;

    while ((match = regex.exec(html)) !== null) {
        let src = match[1];

        if (src.startsWith("data:") || src.startsWith("javascript:")) {
            continue;
        }

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
            // Skip invalid URLs
        }
    }

    return [...new Set(scripts)];
}

/**
 * Extract inline scripts from HTML
 */
function extractInlineScripts(html: string): string {
    const scripts: string[] = [];
    const regex = /<script[^>]*>([^]*?)<\/script>/gi;
    let match;

    while ((match = regex.exec(html)) !== null) {
        const content = match[1].trim();
        if (content && !match[0].includes("src=")) {
            scripts.push(content);
        }
    }

    return scripts.join("\n\n");
}

/**
 * Analyze a single JavaScript file
 */
async function analyzeJsFile(
    url: string,
    options: {
        userAgent: string;
        maxFileSize: number;
        extractEndpoints: boolean;
        extractSecrets: boolean;
        extractDomains: boolean;
    }
): Promise<JsFile> {
    const result: JsFile = {
        url,
        size: 0,
        literalsCount: 0,
        endpoints: [],
        secrets: [],
        domains: [],
    };

    try {
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "User-Agent": options.userAgent,
                "Accept": "*/*",
            },
            timeout: JS_FETCH_TIMEOUT_MS,
        });

        if (!response.ok) {
            result.error = `HTTP ${response.status}`;
            return result;
        }

        const contentLength = parseInt(response.headers.get("content-length") || "0", 10);
        if (contentLength > options.maxFileSize) {
            result.error = `File too large: ${contentLength} bytes`;
            return result;
        }

        const content = await response.text();
        result.size = content.length;

        if (content.length > options.maxFileSize) {
            result.error = `File too large: ${content.length} bytes`;
            return result;
        }

        // Extract literals using oxc_parser AST
        const filename = url.split("/").pop() || "script.js";
        const { literals, errors } = extractLiterals(content, filename);
        result.literalsCount = literals.length;

        if (errors.length > 0) {
            result.parseErrors = errors;
        }

        const source = filename;

        // Analyze literals
        if (options.extractEndpoints) {
            result.endpoints = analyzeEndpoints(literals, source);
        }

        if (options.extractSecrets) {
            result.secrets = analyzeSecrets(literals, source);
        }

        if (options.extractDomains) {
            result.domains = analyzeDomains(literals, source);
        }

    } catch (error: any) {
        result.error = error.message || String(error);
    }

    return result;
}

/**
 * Process a single URL (HTML page or JS file)
 */
async function processSingleUrl(
    baseUrl: string,
    options: {
        userAgent: string;
        maxFileSize: number;
        extractEndpoints: boolean;
        extractSecrets: boolean;
        extractDomains: boolean;
        followImports: boolean;
        maxFiles: number;
        retainFiles?: boolean;
        assertHealthy?: () => void;
        onPage?: (result: { url: string; status?: number; error?: string }) => Promise<void>;
        onFile?: (file: JsFile) => Promise<void>;
    }
): Promise<JsFile[]> {
    const jsUrls: string[] = [];
    const files: JsFile[] = [];
    const inlineFiles: JsFile[] = [];
    let inlineCount = 0;

    // Check if URL is a JS file or HTML page
    if (baseUrl.endsWith(".js") || baseUrl.endsWith(".mjs") || baseUrl.endsWith(".ts")) {
        jsUrls.push(baseUrl);
    } else {
        // Fetch HTML page and extract script URLs once; a page failure remains a failure.
        let pageError: string | undefined;
        let pageStatus: number | undefined;
        options.assertHealthy?.();
        try {
            const response = await fetch(baseUrl, {
                method: "GET",
                headers: {
                    "User-Agent": options.userAgent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                timeout: PAGE_FETCH_TIMEOUT_MS,
            });

            pageStatus = response.status;
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            if (response.ok) {
                const html = await response.text();

                // Analyze inline scripts
                const inlineContent = extractInlineScripts(html);
                if (inlineContent.length > 0) {
                    const { literals, errors } = extractLiterals(inlineContent, "inline.js");
                    const inlineResult: JsFile = {
                        url: `${baseUrl}#inline`,
                        size: inlineContent.length,
                        literalsCount: literals.length,
                        endpoints: options.extractEndpoints ? analyzeEndpoints(literals, "inline") : [],
                        secrets: options.extractSecrets ? analyzeSecrets(literals, "inline") : [],
                        domains: options.extractDomains ? analyzeDomains(literals, "inline") : [],
                        parseErrors: errors.length > 0 ? errors : undefined,
                    };
                    inlineCount++;
                    inlineFiles.push(inlineResult);
                    if (options.retainFiles !== false) files.push(inlineResult);
                }

                if (options.followImports) {
                    const scriptUrls = extractScriptUrls(html, baseUrl);
                    jsUrls.push(...scriptUrls);
                }
            }
        } catch (error) {
            pageError = error instanceof Error ? error.message : String(error);
        }
        // Persistence exceptions never enter the HTTP catch above.
        if (options.onPage) await options.onPage({ url: baseUrl, status: pageStatus, error: pageError });
        if (options.onFile) for (const file of inlineFiles) await options.onFile(file);
        inlineFiles.length = 0;
        if (pageError) {
            if (options.retainFiles !== false) files.push({ url: baseUrl, size: 0, literalsCount: 0, endpoints: [], secrets: [], domains: [], error: pageError });
            return files;
        }
    }

    // Limit number of files
    const urlsToAnalyze = [...new Set(jsUrls)].slice(0, options.maxFiles - inlineCount);

    // Analyze JS files with bounded plugin concurrency
    const jsFileResults = await executeConcurrently(urlsToAnalyze, async (url) => {
            options.assertHealthy?.();
            const file = await analyzeJsFile(url, {
                userAgent: options.userAgent,
                maxFileSize: options.maxFileSize,
                extractEndpoints: options.extractEndpoints,
                extractSecrets: options.extractSecrets,
                extractDomains: options.extractDomains,
            });
            if (options.onFile) await options.onFile(file);
            return options.retainFiles === false ? undefined : file;
        }, Math.min(MAX_FILE_ANALYSIS_CONCURRENCY, options.maxFiles));

    files.push(...jsFileResults.filter((file): file is JsFile => file !== undefined));

    return files;
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const stream = createMonitorResultStream(input);
        const normalizeBase = (value: string) => /^https?:\/\//.test(value) ? value : `https://${value}`;
        const writeTarget = createMonitorTargetWriter(input, stream, normalizeBase);
        // Build URL list from input (support both url and urls)
        let targetUrls: string[] = [];

        if (input.urls && Array.isArray(input.urls) && input.urls.length > 0) {
            targetUrls = input.urls.filter(u => typeof u === 'string' && u.trim().length > 0);
        }

        if (targetUrls.length === 0 && input.url && typeof input.url === "string" && input.url.trim().length > 0) {
            targetUrls = [input.url.trim()];
        }

        if (targetUrls.length === 0) {
            return {
                success: false,
                error: "At least one URL is required (use 'url' or 'urls' parameter)"
            };
        }

        // Normalize URLs
        const baseUrls = [...new Set(targetUrls.map(url => {
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                return `https://${url}`;
            }
            return url;
        }))];

        const concurrency = clampInteger(
            input.concurrency,
            DEFAULT_CONCURRENCY,
            MIN_CONCURRENCY,
            MAX_CONCURRENCY,
        );
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const maxFileSize = input.maxFileSize || 5242880;
        const extractEndpointsFlag = input.extractEndpoints !== false;
        const extractSecretsFlag = input.extractSecrets !== false;
        const extractDomainsFlag = input.extractDomains !== false;
        const followImports = input.followImports !== false;
        const maxFiles = input.maxFiles || 20;

        const monitorExecution = input.__monitorExecution;
        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: baseUrls.length,
            phase: "prepare",
            message: `Preparing JavaScript analysis (${baseUrls.length} base URLs, concurrency ${concurrency})`,
        });

        let completedBaseUrls = 0;
        const allFilesArrays = await executeConcurrently(baseUrls, async (baseUrl) => {
                stream.assertHealthy();
                let targetFailed = false;
                try {
                    const files = await processSingleUrl(baseUrl, {
                        userAgent, maxFileSize, extractEndpoints: extractEndpointsFlag,
                        extractSecrets: extractSecretsFlag, extractDomains: extractDomainsFlag,
                        followImports, maxFiles, retainFiles: !stream.enabled, assertHealthy: () => stream.assertHealthy(),
                        onPage: async result => {
                            if (result.error) targetFailed = true;
                            await writeTarget(baseUrl, `page:${baseUrl}`, { success: true, data: { results: [result] } },
                                { complete: false, status: result.error ? "failed" : "ok", error: result.error });
                        },
                        onFile: async file => {
                            if (file.error) targetFailed = true;
                            await writeTarget(baseUrl, `file:${file.url}`, { success: true, data: {
                                files: [file], summary: { totalFiles: 1, totalLiterals: file.literalsCount,
                                    totalEndpoints: file.endpoints.length, totalSecrets: file.secrets.length,
                                    totalDomains: file.domains.length },
                            } }, { complete: false, status: file.error ? "failed" : "ok", error: file.error });
                        },
                    });
                    await writeTarget(baseUrl, "target-complete", { success: true, data: {} }, {
                        complete: true, status: targetFailed ? "failed" : "ok",
                    });
                    return stream.enabled ? [] : files;
                } finally {
                    completedBaseUrls += 1;
                    await reportMonitorProgress(monitorExecution, {
                        current: completedBaseUrls, total: baseUrls.length, currentTarget: baseUrl,
                        phase: "analyze", message: `Analyzed JavaScript sources for ${baseUrl}`,
                    });
                }
            }, concurrency);

        // Flatten results
        const allFiles: JsFile[] = allFilesArrays.flat();

        // Build summary
        const allEndpoints: Endpoint[] = [];
        const allSecrets: Secret[] = [];
        const allDomains: Domain[] = [];
        let totalLiterals = 0;

        for (const file of allFiles) {
            totalLiterals += file.literalsCount;
            allEndpoints.push(...file.endpoints);
            allSecrets.push(...file.secrets);
            allDomains.push(...file.domains);
        }

        const uniqueEndpoints = [...new Set(allEndpoints.map(e => e.url))].sort();
        const uniqueDomains = [...new Set(allDomains.map(d => d.domain))].sort();

        const secretsBySeverity: Record<string, number> = {};
        for (const secret of allSecrets) {
            secretsBySeverity[secret.severity] = (secretsBySeverity[secret.severity] || 0) + 1;
        }

        return await stream.finish({
            success: true,
            data: {
                baseUrls,
                files: allFiles,
                summary: {
                    totalFiles: allFiles.length,
                    totalLiterals,
                    totalEndpoints: allEndpoints.length,
                    totalSecrets: allSecrets.length,
                    totalDomains: allDomains.length,
                    uniqueEndpoints,
                    uniqueDomains,
                    secretsBySeverity,
                    urlsScanned: baseUrls.length,
                },
            },
        });

    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
