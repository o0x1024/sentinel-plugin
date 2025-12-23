/**
 * @plugin xss_detector
 * @name XSS Vulnerability Detector
 * @version 1.0.0
 * @author Sentinel Team
 * @category xss
 * @default_severity high
 * @tags xss, cross-site-scripting, security, owasp
 * @description Detects potential Cross-Site Scripting vulnerabilities in HTTP transactions
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

// XSS payload patterns
const XSS_PATTERNS = [
  /<script\b[^>]*>[\s\S]*?<\/script>/i,
  /<script\b[^>]*>/i,
  /javascript\s*:/i,
  /on\w+\s*=/i,
  /<img\b[^>]*\bonerror\s*=/i,
  /<svg\b[^>]*\bonload\s*=/i,
  /<iframe\b[^>]*>/i,
  /<object\b[^>]*>/i,
  /<embed\b[^>]*>/i,
  /expression\s*\(/i,
  /data:\s*text\/html/i,
  /vbscript\s*:/i,
];

// DOM XSS sinks
const DOM_XSS_SINKS = [
  /document\.write\s*\(/i,
  /document\.writeln\s*\(/i,
  /\.innerHTML\s*=/i,
  /\.outerHTML\s*=/i,
  /eval\s*\(/i,
  /setTimeout\s*\([^,]*['"]/i,
  /setInterval\s*\([^,]*['"]/i,
  /new\s+Function\s*\(/i,
];

// Extract parameters
function extractParameters(url: string, body: string): Record<string, string> {
  const params: Record<string, string> = {};
  
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
  
  if (body) {
    body.split('&').forEach(pair => {
      const [key, value] = pair.split('=');
      if (key) params[`body:${key}`] = decodeURIComponent(value || '');
    });
  }
  
  return params;
}

// Check for reflected XSS
function checkReflection(params: Record<string, string>, responseBody: string): { param: string; value: string } | null {
  for (const [name, value] of Object.entries(params)) {
    if (value.length > 3 && responseBody.includes(value)) {
      if (/<|>|'|"|javascript|on\w+\s*=/.test(value)) {
        return { param: name, value };
      }
    }
  }
  return null;
}

// Check missing security headers
function checkMissingHeaders(headers: Record<string, string>): string[] {
  const missing: string[] = [];
  const headerNames = Object.keys(headers).map(h => h.toLowerCase());
  
  if (!headerNames.some(h => h.includes('content-security-policy'))) {
    missing.push('Content-Security-Policy');
  }
  if (!headerNames.includes('x-xss-protection')) {
    missing.push('X-XSS-Protection');
  }
  if (!headerNames.includes('x-content-type-options')) {
    missing.push('X-Content-Type-Options');
  }
  
  return missing;
}

// Main scan function
export function scan_transaction(transaction: HttpTransaction): void {
  const { request, response } = transaction;
  
  const bodyText = bytesToString(request.body);
  const params = extractParameters(request.url, bodyText);
  
  // Check for XSS patterns in request parameters
  for (const [paramName, paramValue] of Object.entries(params)) {
    for (const pattern of XSS_PATTERNS) {
      if (pattern.test(paramValue)) {
        (globalThis as any).Sentinel.emitFinding({
          title: 'XSS Payload Detected in Request',
          description: `Parameter "${paramName}" contains XSS payload.\nValue: ${paramValue.substring(0, 100)}${paramValue.length > 100 ? '...' : ''}`,
          severity: 'high',
          vuln_type: 'xss',
          confidence: 'medium',
          url: request.url,
          method: request.method,
          evidence: paramValue.substring(0, 200),
          cwe: 'CWE-79',
          owasp: 'A03:2021',
          remediation: 'Encode all user input before rendering in HTML context.'
        });
        break;
      }
    }
  }
  
  if (!response?.body) return;
  
  const responseBody = bytesToString(response.body);
  
  // Check for reflected XSS
  const reflected = checkReflection(params, responseBody);
  if (reflected) {
    (globalThis as any).Sentinel.emitFinding({
      title: 'Potential Reflected XSS',
      description: `Parameter "${reflected.param}" is reflected in response without proper encoding.\nValue: ${reflected.value.substring(0, 100)}`,
      severity: 'high',
      vuln_type: 'xss',
      confidence: 'high',
      url: request.url,
      method: request.method,
      evidence: reflected.value.substring(0, 200),
      cwe: 'CWE-79',
      owasp: 'A03:2021',
      remediation: 'Implement output encoding for all user-controlled data.'
    });
  }
  
  // Check for DOM XSS sinks
  for (const pattern of DOM_XSS_SINKS) {
    if (pattern.test(responseBody)) {
      (globalThis as any).Sentinel.emitFinding({
        title: 'DOM XSS Sink Detected',
        description: `Response contains potentially dangerous JavaScript sink: ${pattern.toString()}`,
        severity: 'medium',
        vuln_type: 'xss',
        confidence: 'low',
        url: request.url,
        method: request.method,
        evidence: responseBody.match(pattern)?.[0] || '',
        cwe: 'CWE-79',
        owasp: 'A03:2021',
        remediation: 'Avoid using dangerous DOM APIs with user-controlled data.'
      });
      break;
    }
  }
  
  // Check for missing security headers
  const isHtml = response.content_type?.includes('text/html');
  if (isHtml) {
    const missingHeaders = checkMissingHeaders(response.headers);
    if (missingHeaders.length > 0) {
      (globalThis as any).Sentinel.emitFinding({
        title: 'Missing XSS Protection Headers',
        description: `Response is missing security headers: ${missingHeaders.join(', ')}`,
        severity: 'low',
        vuln_type: 'xss',
        confidence: 'high',
        url: request.url,
        method: request.method,
        evidence: `Missing: ${missingHeaders.join(', ')}`,
        remediation: 'Add Content-Security-Policy, X-XSS-Protection, and X-Content-Type-Options headers.'
      });
    }
  }
}

// Required: bind to globalThis
globalThis.scan_transaction = scan_transaction;
