/**
 * @plugin sensitive_info_detector
 * @name Sensitive Information Detector
 * @version 1.0.0
 * @author Sentinel Team
 * @category info_leak
 * @default_severity medium
 * @tags information-disclosure, secrets, api-keys, credentials
 * @description Detects sensitive information leakage in HTTP responses
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

// Pattern configuration
interface PatternConfig {
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe?: string;
}

const SENSITIVE_PATTERNS: PatternConfig[] = [
  // API Keys
  { name: 'AWS Access Key', pattern: /\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'Google API Key', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/, severity: 'high', cwe: 'CWE-798' },
  { name: 'GitHub Token', pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'Slack Token', pattern: /\bxox[baprs]-[0-9]{10,12}-[0-9]{10,12}[a-zA-Z0-9-]*\b/, severity: 'high', cwe: 'CWE-798' },
  { name: 'Stripe Key', pattern: /\b(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}\b/, severity: 'critical', cwe: 'CWE-798' },
  
  // Secrets in JSON
  { name: 'Password in JSON', pattern: /"(password|passwd|pwd|secret|api_?key)":\s*"([^"]{3,})"/, severity: 'high', cwe: 'CWE-312' },
  
  // JWT Token
  { name: 'JWT Token', pattern: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b/, severity: 'medium', cwe: 'CWE-200' },
  
  // Private Keys
  { name: 'RSA Private Key', pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical', cwe: 'CWE-321' },
  
  // Database Connection Strings
  { name: 'Database Connection', pattern: /(mongodb|mysql|postgresql|postgres|mssql):\/\/[^\s'"]+/, severity: 'critical', cwe: 'CWE-312' },
  
  // Credit Card (basic pattern)
  { name: 'Credit Card Number', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/, severity: 'critical', cwe: 'CWE-311' },
  
  // Internal IP
  { name: 'Internal IP Address', pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/, severity: 'low', cwe: 'CWE-200' },
  
  // Stack Trace
  { name: 'Stack Trace', pattern: /at\s+[\w.$]+\([\w.]+:\d+:\d+\)|Traceback \(most recent call last\)/, severity: 'medium', cwe: 'CWE-209' },
];

// Sensitive headers to check
const SENSITIVE_HEADERS = ['x-powered-by', 'server', 'x-aspnet-version', 'x-aspnetmvc-version'];

// Main scan function
export function scan_transaction(transaction: HttpTransaction): void {
  const { request, response } = transaction;
  
  if (!response?.body) return;
  
  const responseBody = bytesToString(response.body);
  const foundPatterns = new Set<string>();
  
  // Check for sensitive patterns in response body
  for (const config of SENSITIVE_PATTERNS) {
    if (foundPatterns.has(config.name)) continue;
    
    const match = responseBody.match(config.pattern);
    if (match) {
      foundPatterns.add(config.name);
      
      // Mask sensitive data
      let evidence = match[0];
      if (evidence.length > 10) {
        evidence = evidence.substring(0, 5) + '***' + evidence.substring(evidence.length - 3);
      }
      
      (globalThis as any).Sentinel.emitFinding({
        title: `${config.name} Detected`,
        description: `Sensitive information detected in response body.\nType: ${config.name}`,
        severity: config.severity,
        vuln_type: 'info_leak',
        confidence: 'high',
        url: request.url,
        method: request.method,
        evidence: evidence,
        cwe: config.cwe,
        owasp: 'A01:2021',
        remediation: 'Remove sensitive information from responses or implement proper access controls.'
      });
    }
  }
  
  // Check response headers for server information disclosure
  for (const [header, value] of Object.entries(response.headers)) {
    if (SENSITIVE_HEADERS.includes(header.toLowerCase()) && value) {
      (globalThis as any).Sentinel.emitFinding({
        title: 'Server Information Disclosure',
        description: `Response header "${header}" reveals server information: ${value}`,
        severity: 'info',
        vuln_type: 'info_leak',
        confidence: 'high',
        url: request.url,
        method: request.method,
        evidence: `${header}: ${value}`,
        cwe: 'CWE-200',
        remediation: 'Remove or obfuscate server version headers.'
      });
    }
  }
}

// Required: bind to globalThis
globalThis.scan_transaction = scan_transaction;
