/**
 * SQL Injection Detector with Active Verification
 * 
 * @plugin sql_injection_detector
 * @name SQL Injection Detector
 * @version 2.0.0
 * @author Sentinel Team
 * @category sqli
 * @default_severity critical
 * @tags sql, injection, security, owasp, active
 * @description Detects SQL injection vulnerabilities by pattern matching and active payload verification
 */

// Type definitions
interface RequestContext {
  id: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: number[];
  content_type?: string;
  query_params: Record<string, string>;
  is_https: boolean;
  timestamp: string;
}

interface ResponseContext {
  request_id: string;
  status: number;
  headers: Record<string, string>;
  body: number[];
  content_type?: string;
  timestamp: string;
}

interface HttpTransaction {
  request: RequestContext;
  response?: ResponseContext;
}

declare const Sentinel: {
  emitFinding: (finding: any) => void;
  log: (level: string, message: string) => void;
};

declare function sleep(ms: number): Promise<void>;

// Helper: Convert byte array to UTF-8 string
function bytesToString(bytes: number[]): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
  } catch {
    return '';
  }
}

// SQL injection payloads for active verification
const SQL_PAYLOADS = {
  // Error-based payloads
  errorBased: [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "1' AND '1'='1",
    "1\" AND \"1\"=\"1",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
  ],
  // Union-based payloads
  unionBased: [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "\" UNION SELECT NULL--",
    "1 UNION SELECT NULL--",
  ],
  // Time-based blind payloads
  timeBased: [
    "' AND SLEEP(3)--",
    "\" AND SLEEP(3)--",
    "1 AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
  ],
  // Boolean-based blind payloads
  booleanBased: [
    "' AND 1=1--",
    "' AND 1=2--",
    "\" AND 1=1--",
    "\" AND 1=2--",
    "1 AND 1=1",
    "1 AND 1=2",
  ],
};

// SQL error patterns for different databases
const SQL_ERROR_PATTERNS = [
  // MySQL
  { pattern: /SQL syntax.*MySQL/i, db: 'MySQL' },
  { pattern: /Warning.*mysql_/i, db: 'MySQL' },
  { pattern: /MySqlException/i, db: 'MySQL' },
  { pattern: /valid MySQL result/i, db: 'MySQL' },
  { pattern: /MySqlClient\./i, db: 'MySQL' },
  { pattern: /com\.mysql\.jdbc/i, db: 'MySQL' },
  // PostgreSQL
  { pattern: /PostgreSQL.*ERROR/i, db: 'PostgreSQL' },
  { pattern: /Warning.*pg_/i, db: 'PostgreSQL' },
  { pattern: /Npgsql\./i, db: 'PostgreSQL' },
  { pattern: /org\.postgresql/i, db: 'PostgreSQL' },
  // Microsoft SQL Server
  { pattern: /OLE DB.*SQL Server/i, db: 'MSSQL' },
  { pattern: /SQL Server.*Driver/i, db: 'MSSQL' },
  { pattern: /Warning.*mssql_/i, db: 'MSSQL' },
  { pattern: /Msg \d+, Level \d+/i, db: 'MSSQL' },
  { pattern: /SqlException/i, db: 'MSSQL' },
  { pattern: /System\.Data\.SqlClient/i, db: 'MSSQL' },
  { pattern: /Unclosed quotation mark/i, db: 'MSSQL' },
  // Oracle
  { pattern: /ORA-\d{5}/i, db: 'Oracle' },
  { pattern: /Oracle error/i, db: 'Oracle' },
  { pattern: /oracle\.jdbc/i, db: 'Oracle' },
  // SQLite
  { pattern: /SQLite.*error/i, db: 'SQLite' },
  { pattern: /Warning.*sqlite_/i, db: 'SQLite' },
  { pattern: /SQLITE_ERROR/i, db: 'SQLite' },
  { pattern: /sqlite3\.OperationalError/i, db: 'SQLite' },
  // Generic
  { pattern: /quoted string not properly terminated/i, db: 'Unknown' },
  { pattern: /syntax error at or near/i, db: 'Unknown' },
  { pattern: /you have an error in your sql syntax/i, db: 'Unknown' },
];

// Parameter extraction from URL and body
function extractParameters(
  url: string,
  body: string,
  contentType?: string
): Map<string, { value: string; location: 'query' | 'body' }> {
  const params = new Map<string, { value: string; location: 'query' | 'body' }>();
  
  // Extract URL query parameters
  try {
    const urlObj = new URL(url);
    urlObj.searchParams.forEach((value, key) => {
      params.set(key, { value, location: 'query' });
    });
  } catch {
    const match = url.match(/\?(.+)/);
    if (match) {
      match[1].split('&').forEach(pair => {
        const [key, ...rest] = pair.split('=');
        if (key) {
          params.set(key, { 
            value: decodeURIComponent(rest.join('=')),
            location: 'query'
          });
        }
      });
    }
  }
  
  // Extract body parameters
  if (body) {
    if (contentType?.includes('application/json')) {
      try {
        const json = JSON.parse(body);
        const flatten = (obj: any, prefix = '') => {
          for (const [key, value] of Object.entries(obj)) {
            const fullKey = prefix ? `${prefix}.${key}` : key;
            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
              flatten(value, fullKey);
            } else if (typeof value === 'string' || typeof value === 'number') {
              params.set(fullKey, { value: String(value), location: 'body' });
            }
          }
        };
        flatten(json);
      } catch { /* ignore */ }
    } else if (contentType?.includes('application/x-www-form-urlencoded') || !contentType) {
      body.split('&').forEach(pair => {
        const [key, ...rest] = pair.split('=');
        if (key) {
          params.set(key, {
            value: decodeURIComponent(rest.join('=')),
            location: 'body'
          });
        }
      });
    }
  }
  
  return params;
}

// Build URL with modified parameter
function buildUrlWithPayload(baseUrl: string, paramName: string, payload: string): string {
  try {
    const url = new URL(baseUrl);
    url.searchParams.set(paramName, payload);
    return url.toString();
  } catch {
    return baseUrl;
  }
}

// Check if response contains SQL error
function checkSqlError(body: string): { found: boolean; db: string; match: string } {
  for (const { pattern, db } of SQL_ERROR_PATTERNS) {
    const match = body.match(pattern);
    if (match) {
      return { found: true, db, match: match[0] };
    }
  }
  return { found: false, db: '', match: '' };
}

// Active verification result
interface VerificationResult {
  vulnerable: boolean;
  type: 'error' | 'time' | 'boolean' | 'union' | 'none';
  payload: string;
  evidence: string;
  database?: string;
}

// Verify SQL injection with active testing
async function verifyWithPayloads(
  baseUrl: string,
  paramName: string,
  originalValue: string,
  method: string,
  headers: Record<string, string>
): Promise<VerificationResult> {
  const testHeaders = { ...headers };
  delete testHeaders['content-length'];
  testHeaders['X-Sentinel-Test'] = 'true';
  
  // 1. Test error-based payloads
  for (const payload of SQL_PAYLOADS.errorBased) {
    try {
      const testUrl = buildUrlWithPayload(baseUrl, paramName, originalValue + payload);
      const response = await fetch(testUrl, {
        method: 'GET',
        headers: testHeaders,
        timeout: 10000,
      });
      const body = await response.text();
      
      const sqlError = checkSqlError(body);
      if (sqlError.found) {
        return {
          vulnerable: true,
          type: 'error',
          payload,
          evidence: `SQL error detected: ${sqlError.match}`,
          database: sqlError.db,
        };
      }
    } catch (e) {
      Sentinel.log('debug', `Error testing payload: ${e}`);
    }
  }
  
  // 2. Test time-based payloads
  for (const payload of SQL_PAYLOADS.timeBased) {
    try {
      const testUrl = buildUrlWithPayload(baseUrl, paramName, originalValue + payload);
      const startTime = performance.now();
      
      await fetch(testUrl, {
        method: 'GET',
        headers: testHeaders,
        timeout: 15000,
      });
      
      const elapsed = performance.now() - startTime;
      
      // 3 second delay payloads should result in > 2.5s response time
      if (elapsed > 2500) {
        return {
          vulnerable: true,
          type: 'time',
          payload,
          evidence: `Time-based SQLi: response took ${elapsed.toFixed(0)}ms (expected delay: 3000ms)`,
        };
      }
    } catch (e) {
      // Timeout might indicate time-based SQLi
      if (String(e).includes('timeout') || String(e).includes('Timeout')) {
        return {
          vulnerable: true,
          type: 'time',
          payload,
          evidence: 'Request timed out, indicating successful time-based SQL injection',
        };
      }
    }
    
    // Rate limiting between time-based tests
    await sleep(100);
  }
  
  // 3. Test boolean-based payloads
  const truthyPayloads = SQL_PAYLOADS.booleanBased.filter((_, i) => i % 2 === 0);
  const falseyPayloads = SQL_PAYLOADS.booleanBased.filter((_, i) => i % 2 === 1);
  
  for (let i = 0; i < truthyPayloads.length; i++) {
    try {
      const truthyUrl = buildUrlWithPayload(baseUrl, paramName, originalValue + truthyPayloads[i]);
      const falseyUrl = buildUrlWithPayload(baseUrl, paramName, originalValue + falseyPayloads[i]);
      
      const [truthyResp, falseyResp] = await Promise.all([
        fetch(truthyUrl, { method: 'GET', headers: testHeaders, timeout: 10000 }),
        fetch(falseyUrl, { method: 'GET', headers: testHeaders, timeout: 10000 }),
      ]);
      
      const [truthyBody, falseyBody] = await Promise.all([
        truthyResp.text(),
        falseyResp.text(),
      ]);
      
      // Significant difference in response length might indicate boolean-based SQLi
      const lengthDiff = Math.abs(truthyBody.length - falseyBody.length);
      if (lengthDiff > 100 && (truthyResp.status === 200 || falseyResp.status === 200)) {
        return {
          vulnerable: true,
          type: 'boolean',
          payload: `${truthyPayloads[i]} vs ${falseyPayloads[i]}`,
          evidence: `Boolean-based SQLi: response length difference ${lengthDiff} chars (truthy: ${truthyBody.length}, falsy: ${falseyBody.length})`,
        };
      }
    } catch (e) {
      Sentinel.log('debug', `Error testing boolean payloads: ${e}`);
    }
  }
  
  return {
    vulnerable: false,
    type: 'none',
    payload: '',
    evidence: '',
  };
}

// Main entry point
export async function scan_transaction(transaction: HttpTransaction): Promise<void> {
  const { request, response } = transaction;
  
  // Skip non-applicable methods
  if (!['GET', 'POST', 'PUT', 'PATCH'].includes(request.method)) {
    return;
  }
  
  // Skip static resources
  const staticExt = /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)(\?|$)/i;
  if (staticExt.test(request.url)) {
    return;
  }
  
  const bodyText = bytesToString(request.body);
  const params = extractParameters(request.url, bodyText, request.content_type);
  
  // Skip if no parameters
  if (params.size === 0) {
    return;
  }
  
  Sentinel.log('info', `SQL injection scan started: ${request.url} (${params.size} params)`);
  
  // First: Check response for existing SQL errors (passive detection)
  if (response?.body) {
    const responseBody = bytesToString(response.body);
    const sqlError = checkSqlError(responseBody);
    
    if (sqlError.found) {
      Sentinel.emitFinding({
        title: 'SQL Error Detected in Response',
        description: `Response contains SQL database error messages from ${sqlError.db}. This may indicate SQL injection vulnerability or improper error handling.`,
        severity: 'high',
        vuln_type: 'sqli',
        confidence: 'high',
        url: request.url,
        method: request.method,
        evidence: sqlError.match,
        cwe: 'CWE-89',
        owasp: 'A03:2021',
        remediation: 'Implement proper error handling and never expose database errors to users. Use parameterized queries.',
      });
    }
  }
  
  // Second: Active verification for each parameter
  for (const [paramName, { value, location }] of params) {
    // Skip parameters that look like they already contain injection attempts
    if (/['";-]{2,}|UNION|SELECT|SLEEP|WAITFOR/i.test(value)) {
      continue;
    }
    
    // Skip parameters with very long values (likely not injectable)
    if (value.length > 500) {
      continue;
    }
    
    Sentinel.log('debug', `Testing parameter: ${paramName} (${location})`);
    
    const result = await verifyWithPayloads(
      request.url,
      paramName,
      value,
      request.method,
      request.headers
    );
    
    if (result.vulnerable) {
      const severityMap = {
        error: 'critical',
        time: 'critical',
        boolean: 'high',
        union: 'critical',
        none: 'info',
      };
      
      Sentinel.emitFinding({
        title: `SQL Injection Confirmed (${result.type}-based)`,
        description: `Parameter "${paramName}" (${location}) is vulnerable to ${result.type}-based SQL injection.${result.database ? ` Database: ${result.database}` : ''}\n\nPayload used: ${result.payload}`,
        severity: severityMap[result.type] || 'high',
        vuln_type: 'sqli',
        confidence: result.type === 'boolean' ? 'medium' : 'high',
        url: request.url,
        method: request.method,
        param_name: paramName,
        param_value: value,
        evidence: result.evidence,
        cwe: 'CWE-89',
        owasp: 'A03:2021',
        remediation: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
      });
      
      // Found vulnerability, continue to next parameter
    }
    
    // Rate limiting between parameter tests
    await sleep(200);
  }
  
  Sentinel.log('info', `SQL injection scan completed: ${request.url}`);
}

// Required: bind to globalThis
globalThis.scan_transaction = scan_transaction;
