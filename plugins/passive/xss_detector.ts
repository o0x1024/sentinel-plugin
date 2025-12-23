/**
 * XSS Detector with Active Verification
 * 
 * @plugin xss_detector
 * @name XSS Detector
 * @version 2.0.0
 * @author Sentinel Team
 * @category xss
 * @default_severity high
 * @tags xss, cross-site-scripting, security, owasp, active
 * @description Detects Cross-Site Scripting (XSS) vulnerabilities with passive analysis and active payload verification
 */

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

declare const SecurityUtils: {
  randomString: (length: number, charset?: string) => string;
};

declare function sleep(ms: number): Promise<void>;

function bytesToString(bytes: number[]): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
  } catch {
    return '';
  }
}

// XSS payload templates with unique markers
function generatePayloads(marker: string): Array<{ payload: string; type: string; context: string }> {
  return [
    // Basic script injection
    { 
      payload: `<script>alert('${marker}')</script>`,
      type: 'reflected',
      context: 'html'
    },
    // Event handler injection
    { 
      payload: `"><img src=x onerror=alert('${marker}')>`,
      type: 'reflected',
      context: 'attribute'
    },
    { 
      payload: `'><img src=x onerror=alert('${marker}')>`,
      type: 'reflected',
      context: 'attribute'
    },
    // SVG injection
    { 
      payload: `<svg onload=alert('${marker}')>`,
      type: 'reflected',
      context: 'html'
    },
    // JavaScript URL injection
    { 
      payload: `javascript:alert('${marker}')`,
      type: 'reflected',
      context: 'href'
    },
    // Breaking out of attributes
    { 
      payload: `" onfocus=alert('${marker}') autofocus="`,
      type: 'reflected',
      context: 'attribute'
    },
    // Template literal injection
    { 
      payload: `\${alert('${marker}')}`,
      type: 'reflected',
      context: 'template'
    },
    // Breaking out of script context
    { 
      payload: `</script><script>alert('${marker}')</script>`,
      type: 'reflected',
      context: 'script'
    },
    // Style-based (older browsers)
    { 
      payload: `<div style="background:url(javascript:alert('${marker}'))">`,
      type: 'reflected',
      context: 'style'
    },
    // Data URI injection
    { 
      payload: `<a href="data:text/html,<script>alert('${marker}')</script>">click</a>`,
      type: 'reflected',
      context: 'data-uri'
    },
    // DOM-based payloads
    { 
      payload: `#<script>alert('${marker}')</script>`,
      type: 'dom',
      context: 'fragment'
    },
    // Polyglot
    {
      payload: `jaVasCript:/*-/*\`/*\\'\`/*"/**/(/* */oNcLiCk=alert('${marker}') )//`,
      type: 'reflected',
      context: 'polyglot'
    },
  ];
}

// Dangerous patterns indicating reflection without proper encoding
const REFLECTION_PATTERNS = [
  /<script[^>]*>[^<]*<\/script>/gi,
  /on\w+\s*=\s*["'][^"']*["']/gi,
  /<img[^>]+onerror\s*=/gi,
  /<svg[^>]+onload\s*=/gi,
  /javascript\s*:/gi,
];

// Security headers that mitigate XSS
const SECURITY_HEADERS = [
  'content-security-policy',
  'x-xss-protection',
  'x-content-type-options',
];

// Parameter extraction
function extractParameters(
  url: string,
  body: string,
  contentType?: string
): Map<string, { value: string; location: 'query' | 'body' }> {
  const params = new Map<string, { value: string; location: 'query' | 'body' }>();
  
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
  
  if (body) {
    if (contentType?.includes('application/json')) {
      try {
        const json = JSON.parse(body);
        const flatten = (obj: any, prefix = '') => {
          for (const [key, value] of Object.entries(obj)) {
            const fullKey = prefix ? `${prefix}.${key}` : key;
            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
              flatten(value, fullKey);
            } else if (typeof value === 'string') {
              params.set(fullKey, { value, location: 'body' });
            }
          }
        };
        flatten(json);
      } catch { /* ignore */ }
    } else {
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

// Build test URL
function buildUrlWithPayload(baseUrl: string, paramName: string, payload: string): string {
  try {
    const url = new URL(baseUrl);
    url.searchParams.set(paramName, payload);
    return url.toString();
  } catch {
    return baseUrl;
  }
}

// Check if payload is reflected in response
function isPayloadReflected(responseBody: string, marker: string, payload: string): {
  reflected: boolean;
  encoded: boolean;
  context: string;
} {
  // Check for exact marker reflection
  if (responseBody.includes(marker)) {
    // Check if payload is reflected unencoded
    if (responseBody.includes(payload)) {
      return { reflected: true, encoded: false, context: 'unencoded' };
    }
    
    // Check for dangerous patterns around the marker
    const markerIndex = responseBody.indexOf(marker);
    const contextStart = Math.max(0, markerIndex - 100);
    const contextEnd = Math.min(responseBody.length, markerIndex + marker.length + 100);
    const context = responseBody.substring(contextStart, contextEnd);
    
    // Check if inside script tag
    if (/<script[^>]*>.*$/i.test(context) || /^.*<\/script>/i.test(context)) {
      return { reflected: true, encoded: false, context: 'script' };
    }
    
    // Check if inside event handler
    if (/on\w+\s*=\s*["'][^"']*$/i.test(context)) {
      return { reflected: true, encoded: false, context: 'event-handler' };
    }
    
    // Check if inside href/src attribute
    if (/(?:href|src)\s*=\s*["'][^"']*$/i.test(context)) {
      return { reflected: true, encoded: false, context: 'attribute' };
    }
    
    return { reflected: true, encoded: true, context: 'html' };
  }
  
  return { reflected: false, encoded: false, context: '' };
}

// Active XSS verification
interface VerificationResult {
  vulnerable: boolean;
  payload: string;
  type: string;
  context: string;
  evidence: string;
}

async function verifyXss(
  baseUrl: string,
  paramName: string,
  originalValue: string,
  headers: Record<string, string>
): Promise<VerificationResult> {
  const marker = SecurityUtils.randomString(8, 'abcdefghijklmnopqrstuvwxyz');
  const payloads = generatePayloads(marker);
  
  const testHeaders = { ...headers };
  delete testHeaders['content-length'];
  testHeaders['X-Sentinel-Test'] = 'true';
  
  for (const { payload, type, context } of payloads) {
    try {
      const testUrl = buildUrlWithPayload(baseUrl, paramName, payload);
      
      const response = await fetch(testUrl, {
        method: 'GET',
        headers: testHeaders,
        timeout: 10000,
      });
      
      // Skip non-HTML responses
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
        continue;
      }
      
      const body = await response.text();
      const reflection = isPayloadReflected(body, marker, payload);
      
      if (reflection.reflected && !reflection.encoded) {
        // Check for dangerous reflection
        const dangerousPatterns = [
          new RegExp(`<script[^>]*>[^<]*${marker}[^<]*</script>`, 'i'),
          new RegExp(`on\\w+\\s*=\\s*["'][^"']*${marker}`, 'i'),
          new RegExp(`<[^>]+\\s+on\\w+\\s*=`, 'i'),
          new RegExp(`<img[^>]+onerror`, 'i'),
          new RegExp(`<svg[^>]+onload`, 'i'),
        ];
        
        for (const pattern of dangerousPatterns) {
          if (pattern.test(body)) {
            return {
              vulnerable: true,
              payload,
              type,
              context: reflection.context,
              evidence: `Payload reflected in dangerous context: ${reflection.context}`,
            };
          }
        }
        
        // Payload reflected, might still be exploitable
        return {
          vulnerable: true,
          payload,
          type,
          context: reflection.context,
          evidence: `XSS payload reflected without encoding in ${reflection.context} context`,
        };
      }
    } catch (e) {
      Sentinel.log('debug', `XSS test failed for ${paramName}: ${e}`);
    }
    
    // Rate limiting
    await sleep(50);
  }
  
  return {
    vulnerable: false,
    payload: '',
    type: '',
    context: '',
    evidence: '',
  };
}

// Check security headers
function checkSecurityHeaders(headers: Record<string, string>): string[] {
  const missing: string[] = [];
  const headerKeys = Object.keys(headers).map(k => k.toLowerCase());
  
  for (const header of SECURITY_HEADERS) {
    if (!headerKeys.includes(header)) {
      missing.push(header);
    }
  }
  
  return missing;
}

// Main entry point
export async function scan_transaction(transaction: HttpTransaction): Promise<void> {
  const { request, response } = transaction;
  
  // Skip non-applicable methods
  if (!['GET', 'POST'].includes(request.method)) {
    return;
  }
  
  // Skip static resources
  const staticExt = /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|json)(\?|$)/i;
  if (staticExt.test(request.url)) {
    return;
  }
  
  // Skip non-HTML responses for reflection testing
  if (response) {
    const contentType = response.headers?.['content-type'] || '';
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
      return;
    }
  }
  
  const bodyText = bytesToString(request.body);
  const params = extractParameters(request.url, bodyText, request.content_type);
  
  if (params.size === 0) {
    return;
  }
  
  Sentinel.log('info', `XSS scan started: ${request.url} (${params.size} params)`);
  
  // Check for missing security headers
  if (response?.headers) {
    const missingHeaders = checkSecurityHeaders(response.headers);
    if (missingHeaders.includes('content-security-policy')) {
      Sentinel.emitFinding({
        title: 'Missing Content-Security-Policy Header',
        description: `The response lacks a Content-Security-Policy header, which helps prevent XSS attacks by restricting script sources.`,
        severity: 'medium',
        vuln_type: 'security_misconfiguration',
        confidence: 'high',
        url: request.url,
        method: request.method,
        evidence: 'Content-Security-Policy header not found',
        cwe: 'CWE-693',
        owasp: 'A05:2021',
        remediation: 'Implement a strict Content-Security-Policy header.',
      });
    }
  }
  
  // Passive check: Look for existing XSS patterns in response
  if (response?.body) {
    const responseBody = bytesToString(response.body);
    
    for (const pattern of REFLECTION_PATTERNS) {
      if (pattern.test(responseBody)) {
        // Check if any parameter value is reflected unsanitized
        for (const [paramName, { value }] of params) {
          if (value.length >= 3 && responseBody.includes(value)) {
            // Check context of reflection
            const index = responseBody.indexOf(value);
            const contextStart = Math.max(0, index - 50);
            const contextEnd = Math.min(responseBody.length, index + value.length + 50);
            const context = responseBody.substring(contextStart, contextEnd);
            
            if (/<script|on\w+=|javascript:/i.test(context)) {
              Sentinel.emitFinding({
                title: 'Potential XSS via Parameter Reflection',
                description: `Parameter "${paramName}" is reflected in response near potentially dangerous HTML context.`,
                severity: 'medium',
                vuln_type: 'xss',
                confidence: 'low',
                url: request.url,
                method: request.method,
                param_name: paramName,
                evidence: context.substring(0, 200),
                cwe: 'CWE-79',
                owasp: 'A03:2021',
                remediation: 'Properly encode all user input before including in HTML output.',
              });
              break;
            }
          }
        }
        break;
      }
    }
  }
  
  // Active verification for each parameter
  for (const [paramName, { value, location }] of params) {
    // Skip very long values
    if (value.length > 200) {
      continue;
    }
    
    // Skip values that look like encoded data
    if (/^[A-Za-z0-9+/=]{50,}$/.test(value)) {
      continue;
    }
    
    Sentinel.log('debug', `Testing XSS for parameter: ${paramName}`);
    
    const result = await verifyXss(
      request.url,
      paramName,
      value,
      request.headers
    );
    
    if (result.vulnerable) {
      Sentinel.emitFinding({
        title: `XSS Vulnerability Confirmed (${result.type})`,
        description: `Parameter "${paramName}" (${location}) is vulnerable to ${result.type} Cross-Site Scripting.\n\nPayload: ${result.payload}\nContext: ${result.context}`,
        severity: 'high',
        vuln_type: 'xss',
        confidence: 'high',
        url: request.url,
        method: request.method,
        param_name: paramName,
        param_value: value,
        evidence: result.evidence,
        cwe: 'CWE-79',
        owasp: 'A03:2021',
        remediation: 'Implement proper output encoding based on the context (HTML, JavaScript, URL, CSS). Use Content-Security-Policy headers.',
      });
    }
    
    // Rate limiting
    await sleep(100);
  }
  
  Sentinel.log('info', `XSS scan completed: ${request.url}`);
}

// Required: bind to globalThis
globalThis.scan_transaction = scan_transaction;
