/**
 * Directory Bruteforcer Tool
 * 
 * @plugin directory_bruteforcer
 * @name Directory Bruteforcer
 * @version 1.0.0
 * @author Sentinel Team
 * @category discovery
 * @default_severity info
 * @tags directory, bruteforce, discovery, fuzzing, web
 * @description Discover hidden directories, files, and endpoints on web servers using wordlist-based brute forcing
 */

// Sentinel Dictionary API declaration
declare const Sentinel: {
    Dictionary: {
        get(idOrName: string): Promise<any>;
        getWords(idOrName: string, limit?: number): Promise<string[]>;
        list(filter?: { dictType?: string; category?: string }): Promise<any[]>;
        getMergedWords(idsOrNames: string[], deduplicate?: boolean): Promise<string[]>;
    };
};

interface ToolInput {
    url: string;
    wordlist?: string;
    dictionaryId?: string;  // Use dictionary from DB by ID or name
    extensions?: string[];
    timeout?: number;
    concurrency?: number;
    userAgent?: string;
    followRedirects?: boolean;
    statusCodes?: number[];
    excludeStatusCodes?: number[];
    excludeLength?: number[];
    recursive?: boolean;
    maxDepth?: number;
    customWordlist?: string[];
}

interface DiscoveredPath {
    url: string;
    path: string;
    statusCode: number;
    contentLength: number;
    contentType?: string;
    redirectUrl?: string;
    responseTime: number;
}

interface ToolOutput {
    success: boolean;
    data?: {
        baseUrl: string;
        discovered: DiscoveredPath[];
        summary: {
            totalRequests: number;
            discovered: number;
            byStatusCode: Record<string, number>;
            scanTime: number;
        };
    };
    error?: string;
}

// Fallback wordlists (used when dictionary is not available)
const FALLBACK_WORDLISTS: Record<string, string[]> = {
    common: [
        "admin", "login", "dashboard", "api", "backup", "config", "upload", "test",
        "dev", "staging", "robots.txt", "sitemap.xml", ".git", ".env", "wp-admin",
    ],
    sensitive: [
        ".git/config", ".env", ".htaccess", "wp-config.php", "config.php",
        "backup.sql", "dump.sql", "phpinfo.php",
    ],
    api: [
        "api", "api/v1", "api/v2", "graphql", "swagger", "health", "status",
    ],
    backup: [
        "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql",
    ],
};

// Dictionary name mapping for built-in wordlist types
const DICTIONARY_NAMES: Record<string, string> = {
    common: "Directory Common",
    sensitive: "Directory Sensitive",
    api: "Directory API",
    backup: "Directory Backup",
};

/**
 * Load wordlist from dictionary or fallback
 */
async function loadWordlist(wordlistType: string): Promise<string[]> {
    const dictName = DICTIONARY_NAMES[wordlistType];
    if (!dictName) {
        return FALLBACK_WORDLISTS[wordlistType] || FALLBACK_WORDLISTS.common;
    }
    
    try {
        // Try to load from Sentinel Dictionary
        if (typeof Sentinel !== "undefined" && Sentinel.Dictionary) {
            const words = await Sentinel.Dictionary.getWords(dictName);
            if (words && words.length > 0) {
                return words;
            }
        }
    } catch (e) {
        console.debug(`Failed to load dictionary "${dictName}", using fallback`);
    }
    
    return FALLBACK_WORDLISTS[wordlistType] || FALLBACK_WORDLISTS.common;
}

/**
 * Load wordlist by dictionary ID or name
 */
async function loadDictionaryById(idOrName: string): Promise<string[]> {
    try {
        if (typeof Sentinel !== "undefined" && Sentinel.Dictionary) {
            const words = await Sentinel.Dictionary.getWords(idOrName);
            if (words && words.length > 0) {
                return words;
            }
        }
    } catch (e) {
        console.error(`Failed to load dictionary "${idOrName}": ${e}`);
    }
    return [];
}

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
                description: "Target base URL to scan"
            },
            wordlist: {
                type: "string",
                enum: ["common", "sensitive", "api", "backup", "all"],
                description: "Built-in wordlist type. Default: common",
                default: "common"
            },
            dictionaryId: {
                type: "string",
                description: "Dictionary ID or name from Sentinel dictionary module (overrides wordlist)"
            },
            extensions: {
                type: "array",
                items: { type: "string" },
                description: "File extensions to append (e.g., ['php', 'html', 'js'])",
                default: []
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
                default: 20,
                minimum: 1,
                maximum: 100
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            followRedirects: {
                type: "boolean",
                description: "Follow HTTP redirects",
                default: false
            },
            statusCodes: {
                type: "array",
                items: { type: "integer" },
                description: "Status codes to consider as found. Default: [200, 201, 204, 301, 302, 307, 308, 401, 403]",
                default: [200, 201, 204, 301, 302, 307, 308, 401, 403]
            },
            excludeStatusCodes: {
                type: "array",
                items: { type: "integer" },
                description: "Status codes to exclude from results",
                default: []
            },
            excludeLength: {
                type: "array",
                items: { type: "integer" },
                description: "Content lengths to exclude (for filtering false positives)",
                default: []
            },
            recursive: {
                type: "boolean",
                description: "Recursively scan discovered directories",
                default: false
            },
            maxDepth: {
                type: "integer",
                description: "Maximum recursion depth",
                default: 2,
                minimum: 1,
                maximum: 5
            },
            customWordlist: {
                type: "array",
                items: { type: "string" },
                description: "Custom wordlist to use instead of built-in"
            }
        }
    };
}

globalThis.get_input_schema = get_input_schema;

/**
 * Build URL from base and path
 */
function buildUrl(baseUrl: string, path: string): string {
    const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
    const p = path.startsWith("/") ? path : `/${path}`;
    return `${base}${p}`;
}

/**
 * Probe a single path
 */
async function probePath(
    baseUrl: string,
    path: string,
    options: {
        timeout: number;
        userAgent: string;
        followRedirects: boolean;
    }
): Promise<DiscoveredPath | null> {
    const url = buildUrl(baseUrl, path);
    const startTime = performance.now();
    
    try {
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "User-Agent": options.userAgent,
                "Accept": "*/*",
            },
            redirect: options.followRedirects ? "follow" : "manual",
            // @ts-ignore
            timeout: options.timeout,
        });
        
        const responseTime = Math.round(performance.now() - startTime);
        
        // Get content length
        let contentLength = parseInt(response.headers.get("content-length") || "0", 10);
        if (!contentLength) {
            try {
                const text = await response.text();
                contentLength = text.length;
            } catch {
                // Ignore
            }
        }
        
        return {
            url,
            path,
            statusCode: response.status,
            contentLength,
            contentType: response.headers.get("content-type") || undefined,
            redirectUrl: response.redirected ? response.url : undefined,
            responseTime,
        };
        
    } catch {
        return null;
    }
}

/**
 * Run tasks with concurrency limit
 */
async function runWithConcurrency<T>(
    tasks: (() => Promise<T>)[],
    concurrency: number,
    onProgress?: (completed: number, total: number) => void
): Promise<T[]> {
    const results: T[] = [];
    let index = 0;
    let completed = 0;
    
    async function worker() {
        while (index < tasks.length) {
            const currentIndex = index++;
            const result = await tasks[currentIndex]();
            results[currentIndex] = result;
            completed++;
            if (onProgress) {
                onProgress(completed, tasks.length);
            }
        }
    }
    
    const workers = Array(Math.min(concurrency, tasks.length))
        .fill(null)
        .map(() => worker());
    
    await Promise.all(workers);
    return results;
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
        
        const timeout = input.timeout || 10000;
        const concurrency = input.concurrency || 20;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const followRedirects = input.followRedirects === true;
        const statusCodes = input.statusCodes || [200, 201, 204, 301, 302, 307, 308, 401, 403];
        const excludeStatusCodes = input.excludeStatusCodes || [];
        const excludeLength = input.excludeLength || [];
        const extensions = input.extensions || [];
        
        // Build wordlist
        let words: string[] = [];
        if (input.customWordlist && input.customWordlist.length > 0) {
            // Use custom wordlist provided in input
            words = input.customWordlist;
        } else if (input.dictionaryId) {
            // Load from specified dictionary
            words = await loadDictionaryById(input.dictionaryId);
            if (words.length === 0) {
                return {
                    success: false,
                    error: `Dictionary "${input.dictionaryId}" not found or empty`
                };
            }
        } else {
            // Load from built-in wordlist type (with dictionary fallback)
            const wordlistName = input.wordlist || "common";
            if (wordlistName === "all") {
                const [common, sensitive, api, backup] = await Promise.all([
                    loadWordlist("common"),
                    loadWordlist("sensitive"),
                    loadWordlist("api"),
                    loadWordlist("backup"),
                ]);
                words = [...common, ...sensitive, ...api, ...backup];
            } else {
                words = await loadWordlist(wordlistName);
            }
        }
        
        // Deduplicate
        words = [...new Set(words)];
        
        // Build paths with extensions
        const paths: string[] = [];
        for (const word of words) {
            paths.push(word);
            for (const ext of extensions) {
                const e = ext.startsWith(".") ? ext : `.${ext}`;
                paths.push(`${word}${e}`);
            }
        }
        
        // Create probe tasks
        const tasks = paths.map(path => () => probePath(baseUrl, path, {
            timeout,
            userAgent,
            followRedirects,
        }));
        
        // Execute with concurrency
        const results = await runWithConcurrency(tasks, concurrency);
        
        // Filter results
        const discovered: DiscoveredPath[] = [];
        const byStatusCode: Record<string, number> = {};
        
        for (const result of results) {
            if (!result) continue;
            
            // Check status code
            if (!statusCodes.includes(result.statusCode)) continue;
            if (excludeStatusCodes.includes(result.statusCode)) continue;
            
            // Check content length
            if (excludeLength.includes(result.contentLength)) continue;
            
            discovered.push(result);
            
            const code = String(result.statusCode);
            byStatusCode[code] = (byStatusCode[code] || 0) + 1;
        }
        
        // Sort by status code, then by path
        discovered.sort((a, b) => {
            if (a.statusCode !== b.statusCode) {
                return a.statusCode - b.statusCode;
            }
            return a.path.localeCompare(b.path);
        });
        
        const scanTime = Math.round(performance.now() - startTime);
        
        return {
            success: true,
            data: {
                baseUrl,
                discovered,
                summary: {
                    totalRequests: paths.length,
                    discovered: discovered.length,
                    byStatusCode,
                    scanTime,
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
