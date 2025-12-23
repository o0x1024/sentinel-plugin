/**
 * @plugin sql_injection_detector
 * @name SQL Injection Detector
 * @version 1.0.0
 * @author Sentinel Team
 * @category sqli
 * @default_severity high
 * @tags sql, injection, security, owasp
 * @description Detects potential SQL injection vulnerabilities by analyzing HTTP transactions
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

// Helper: Convert byte array to UTF-8 string
function bytesToString(bytes: number[]): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
  } catch {
    return '';
  }
}

// SQL injection patterns in requests
const SQL_INJECTION_PATTERNS = [
  /('|")\s*(OR|AND)\s*('|")?1('|")?\s*=\s*('|")?1/i,
  /UNION\s+(ALL\s+)?SELECT/i,
  /;\s*(DROP|DELETE|UPDATE|INSERT)\s+/i,
  /\bEXEC\s*\(/i,
  /\bXP_\w+/i,
  /\/\*.*\*\//,
  /--\s*$/m,
  /\bSLEEP\s*\(\s*\d+\s*\)/i,
  /\bBENCHMARK\s*\(/i,
  /\bWAITFOR\s+DELAY/i,
];

// SQL error patterns in responses
const SQL_ERROR_PATTERNS = [
  /SQL\s*syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /MySqlException/i,
  /valid MySQL result/i,
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /Npgsql\./i,
  /OLE DB.*SQL Server/i,
  /SQL Server.*Driver/i,
  /Warning.*mssql_/i,
  /Msg \d+, Level \d+/i,
  /SqlException/i,
  /ORA-\d{5}/i,
  /Oracle error/i,
  /SQLite.*error/i,
  /Warning.*sqlite_/i,
  /SQLITE_ERROR/i,
];

// Extract parameters from URL and body
function extractParameters(url: string, body: string, contentType?: string): Record<string, string> {
  const params: Record<string, string> = {};
  
  // Extract URL query parameters
  try {
    const urlObj = new URL(url);
    urlObj.searchParams.forEach((value, key) => {
      params[`query:${key}`] = value;
    });
  } catch {
    const match = url.match(/\?(.+)/);
    if (match) {
      match[1].split('&').forEach(pair => {
        const [key, value] = pair.split('=');
        if (key) params[`query:${key}`] = decodeURIComponent(value || '');
      });
    }
  }
  
  // Extract body parameters
  if (body) {
    if (contentType?.includes('application/json')) {
      try {
        const json = JSON.parse(body);
        const flatten = (obj: any, prefix = 'body') => {
          for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'object' && value !== null) {
              flatten(value, `${prefix}.${key}`);
            } else {
              params[`${prefix}.${key}`] = String(value);
            }
          }
        };
        flatten(json);
      } catch { /* ignore */ }
    } else {
      // form-urlencoded
      body.split('&').forEach(pair => {
        const [key, value] = pair.split('=');
        if (key) params[`body:${key}`] = decodeURIComponent(value || '');
      });
    }
  }
  
  return params;
}

// Main scan function - entry point for passive plugins
export function scan_transaction(transaction: HttpTransaction): void {
  const { request, response } = transaction;
  
  const bodyText = bytesToString(request.body);
  const params = extractParameters(request.url, bodyText, request.content_type);
  
  // Check for SQL injection patterns in parameters
  for (const [paramName, paramValue] of Object.entries(params)) {
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(paramValue)) {
        (globalThis as any).Sentinel.emitFinding({
          title: 'Potential SQL Injection in Request',
          description: `Parameter "${paramName}" contains SQL injection pattern.\nValue: ${paramValue.substring(0, 100)}${paramValue.length > 100 ? '...' : ''}\nPattern: ${pattern.toString()}`,
          severity: 'high',
          vuln_type: 'sqli',
          confidence: 'medium',
          url: request.url,
          method: request.method,
          evidence: paramValue.substring(0, 200),
          cwe: 'CWE-89',
          owasp: 'A03:2021',
          remediation: 'Use parameterized queries or prepared statements to prevent SQL injection.'
        });
        break;
      }
    }
  }
  
  // Check for SQL errors in response
  if (response?.body) {
    const responseBody = bytesToString(response.body);
    for (const pattern of SQL_ERROR_PATTERNS) {
      if (pattern.test(responseBody)) {
        (globalThis as any).Sentinel.emitFinding({
          title: 'SQL Error Detected in Response',
          description: `The response contains SQL database error messages, indicating potential SQL injection vulnerability or improper error handling.\nPattern: ${pattern.toString()}`,
          severity: 'high',
          vuln_type: 'sqli',
          confidence: 'high',
          url: request.url,
          method: request.method,
          evidence: responseBody.match(pattern)?.[0] || '',
          cwe: 'CWE-89',
          owasp: 'A03:2021',
          remediation: 'Implement proper error handling and never expose database errors to users.'
        });
        break;
      }
    }
  }
}

// Required: bind to globalThis for plugin engine
globalThis.scan_transaction = scan_transaction;
