/**
 * Sensitive Information Detector
 * 
 * @plugin sensitive_info_detector
 * @name Sensitive Information Detector
 * @version 2.0.0
 * @author Sentinel Team
 * @category info_leak
 * @default_severity medium
 * @tags sensitive, information, leakage, privacy, security
 * @description Detects sensitive information disclosure in HTTP responses (API keys, credentials, PII, etc.)
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

function bytesToString(bytes: number[]): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
  } catch {
    return '';
  }
}

// Pattern definitions for sensitive information
interface SensitivePattern {
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  cwe: string;
  description: string;
  validate?: (match: string) => boolean;
}

const SENSITIVE_PATTERNS: SensitivePattern[] = [
  // API Keys and Tokens
  {
    name: 'AWS Access Key ID',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'AWS Access Key ID exposed',
  },
  {
    name: 'AWS Secret Key',
    pattern: /(?:aws_secret|secret_key|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'AWS Secret Access Key exposed',
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'GitHub personal access token exposed',
  },
  {
    name: 'GitHub OAuth',
    pattern: /gho_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'GitHub OAuth token exposed',
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'Slack API token exposed',
  },
  {
    name: 'Stripe API Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'Stripe live API key exposed',
  },
  {
    name: 'Stripe Publishable Key',
    pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'medium',
    category: 'api_key',
    cwe: 'CWE-200',
    description: 'Stripe publishable key exposed',
  },
  {
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'high',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'Google API key exposed',
  },
  {
    name: 'Google OAuth Token',
    pattern: /ya29\.[0-9A-Za-z\-_]+/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'Google OAuth access token exposed',
  },
  {
    name: 'Firebase Key',
    pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
    severity: 'high',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'Firebase Cloud Messaging key exposed',
  },
  {
    name: 'Twilio API Key',
    pattern: /SK[0-9a-fA-F]{32}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'Twilio API key exposed',
  },
  {
    name: 'Mailgun API Key',
    pattern: /key-[0-9a-zA-Z]{32}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'Mailgun API key exposed',
  },
  {
    name: 'SendGrid API Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'SendGrid API key exposed',
  },
  {
    name: 'Heroku API Key',
    pattern: /[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/gi,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'Heroku API key exposed',
  },
  {
    name: 'NPM Token',
    pattern: /npm_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'NPM access token exposed',
  },
  {
    name: 'PyPI Token',
    pattern: /pypi-[A-Za-z0-9_-]{150,}/g,
    severity: 'critical',
    category: 'api_key',
    cwe: 'CWE-798',
    description: 'PyPI API token exposed',
  },
  
  // Authentication Credentials
  {
    name: 'Generic Password in URL',
    pattern: /(?:password|passwd|pwd|pass)\s*[=:]\s*["']?([^\s"'&]{3,30})["']?/gi,
    severity: 'high',
    category: 'credential',
    cwe: 'CWE-798',
    description: 'Password exposed in URL or response',
    validate: (match: string) => !['password', 'passwd', 'pwd', 'pass', 'null', 'undefined', '***', 'xxx'].includes(match.toLowerCase()),
  },
  {
    name: 'Basic Auth Header',
    pattern: /Authorization:\s*Basic\s+([A-Za-z0-9+/=]{10,})/gi,
    severity: 'high',
    category: 'credential',
    cwe: 'CWE-798',
    description: 'Basic authentication credentials exposed',
  },
  {
    name: 'Bearer Token',
    pattern: /Authorization:\s*Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)/gi,
    severity: 'high',
    category: 'credential',
    cwe: 'CWE-798',
    description: 'Bearer token (likely JWT) exposed',
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'credential',
    cwe: 'CWE-321',
    description: 'Private key exposed in response',
  },
  {
    name: 'Database Connection String',
    pattern: /(?:mongodb|mysql|postgres|postgresql|redis|mssql|oracle):\/\/[^\s"'<>]{10,}/gi,
    severity: 'critical',
    category: 'credential',
    cwe: 'CWE-798',
    description: 'Database connection string with credentials exposed',
  },
  
  // Personally Identifiable Information (PII)
  {
    name: 'Email Address',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    severity: 'low',
    category: 'pii',
    cwe: 'CWE-200',
    description: 'Email address exposed',
    validate: (match: string) => !match.includes('example.com') && !match.includes('test.com'),
  },
  {
    name: 'US Social Security Number',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: 'critical',
    category: 'pii',
    cwe: 'CWE-359',
    description: 'US Social Security Number exposed',
    validate: (match: string) => {
      const parts = match.split('-');
      const first = parseInt(parts[0]);
      return first !== 0 && first !== 666 && first < 900;
    },
  },
  {
    name: 'Credit Card Number',
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    severity: 'critical',
    category: 'pii',
    cwe: 'CWE-359',
    description: 'Credit card number exposed',
    validate: (match: string) => {
      // Luhn algorithm check
      let sum = 0;
      let isEven = false;
      for (let i = match.length - 1; i >= 0; i--) {
        let digit = parseInt(match[i], 10);
        if (isEven) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        isEven = !isEven;
      }
      return sum % 10 === 0;
    },
  },
  {
    name: 'Phone Number (US)',
    pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    severity: 'low',
    category: 'pii',
    cwe: 'CWE-200',
    description: 'US phone number exposed',
  },
  {
    name: 'IP Address (Private)',
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    severity: 'info',
    category: 'infrastructure',
    cwe: 'CWE-200',
    description: 'Private IP address exposed',
  },
  
  // Debug and Development Information
  {
    name: 'Stack Trace',
    pattern: /(?:at\s+[\w.<>$]+\([\w.]+:\d+:\d+\)|Traceback \(most recent call last\)|Exception in thread|^\s+File "[^"]+", line \d+)/gm,
    severity: 'medium',
    category: 'debug',
    cwe: 'CWE-209',
    description: 'Stack trace or debug information exposed',
  },
  {
    name: 'SQL Query',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\s+(?:INTO|FROM|TABLE|DATABASE|INDEX)\s+[\w.`"]+/gi,
    severity: 'medium',
    category: 'debug',
    cwe: 'CWE-209',
    description: 'SQL query exposed in response',
  },
  {
    name: 'Debug Mode Indicator',
    pattern: /(?:debug\s*[=:]\s*(?:true|1|on)|DEBUG_MODE|DEVELOPMENT_MODE|development\.[\w.]+)/gi,
    severity: 'low',
    category: 'debug',
    cwe: 'CWE-489',
    description: 'Debug mode indicator found',
  },
  {
    name: 'Server Path Disclosure',
    pattern: /(?:\/(?:home|var|usr|opt|www|web|app|srv)\/[^\s"'<>]+)|(?:[C-Z]:\\(?:Users|Program Files|Windows|inetpub)[^\s"'<>]+)/gi,
    severity: 'low',
    category: 'infrastructure',
    cwe: 'CWE-200',
    description: 'Server file path disclosed',
  },
  
  // Version and Technology Disclosure
  {
    name: 'Server Version Header',
    pattern: /(?:Server|X-Powered-By):\s*([^\r\n]+)/gi,
    severity: 'info',
    category: 'technology',
    cwe: 'CWE-200',
    description: 'Server version information disclosed',
  },
  {
    name: 'Framework Version',
    pattern: /(?:Laravel|Django|Rails|Express|Spring|ASP\.NET|Symfony)\s*(?:version\s*)?(\d+(?:\.\d+)+)/gi,
    severity: 'info',
    category: 'technology',
    cwe: 'CWE-200',
    description: 'Web framework version disclosed',
  },
];

// Check response headers for sensitive info
function checkResponseHeaders(headers: Record<string, string>): SensitivePattern[] {
  const findings: SensitivePattern[] = [];
  
  // Security headers that should NOT be present with certain values
  const badHeaders: Record<string, { pattern: RegExp; severity: 'high' | 'medium'; desc: string }> = {
    'x-powered-by': {
      pattern: /.+/,
      severity: 'medium',
      desc: 'X-Powered-By header exposes technology stack',
    },
    'server': {
      pattern: /[a-z]+\/\d+/i,
      severity: 'medium',
      desc: 'Server header exposes version information',
    },
  };
  
  for (const [headerName, { pattern, severity, desc }] of Object.entries(badHeaders)) {
    const headerValue = headers[headerName] || headers[headerName.toLowerCase()];
    if (headerValue && pattern.test(headerValue)) {
      findings.push({
        name: `Insecure Header: ${headerName}`,
        pattern: pattern,
        severity,
        category: 'headers',
        cwe: 'CWE-200',
        description: `${desc}: ${headerValue}`,
      });
    }
  }
  
  return findings;
}

// Main scan function
export function scan_transaction(transaction: HttpTransaction): Promise<any[]> {
  const findings: any[] = [];
  const { request, response } = transaction;
  
  if (!response?.body) {
    return;
  }
  
  // Skip binary responses
  const contentType = response.content_type || '';
  if (
    contentType.includes('image/') ||
    contentType.includes('audio/') ||
    contentType.includes('video/') ||
    contentType.includes('font/') ||
    contentType.includes('application/octet-stream')
  ) {
    return;
  }
  
  const responseBody = bytesToString(response.body);
  
  // Skip empty or very short responses
  if (responseBody.length < 10) {
    return;
  }
  
  const foundPatterns = new Map<string, { matches: string[]; pattern: SensitivePattern }>();
  
  // Scan response body for sensitive patterns
  for (const patternDef of SENSITIVE_PATTERNS) {
    const matches: string[] = [];
    let match: RegExpExecArray | null;
    
    // Reset regex state
    patternDef.pattern.lastIndex = 0;
    
    while ((match = patternDef.pattern.exec(responseBody)) !== null) {
      const matchedText = match[1] || match[0];
      
      // Validate if validator exists
      if (patternDef.validate && !patternDef.validate(matchedText)) {
        continue;
      }
      
      // Avoid duplicates
      if (!matches.includes(matchedText)) {
        matches.push(matchedText);
      }
      
      // Limit matches per pattern
      if (matches.length >= 5) {
        break;
      }
    }
    
    if (matches.length > 0) {
      foundPatterns.set(patternDef.name, { matches, pattern: patternDef });
    }
  }
  
  // Check response headers
  if (response.headers) {
    const headerFindings = checkResponseHeaders(response.headers);
    for (const finding of headerFindings) {
      findings.push({
        title: finding.name,
        description: finding.description,
        severity: finding.severity,
        vuln_type: 'info_leak',
        confidence: 'high',
        url: request.url,
        method: request.method,
        evidence: finding.description,
        cwe: finding.cwe,
        owasp: 'A01:2021',
        remediation: 'Remove or sanitize sensitive headers in production.',
      });
    }
  }
  
  // Emit findings for body patterns
  for (const [name, { matches, pattern }] of foundPatterns) {
    // Mask sensitive parts of the evidence
    const maskedMatches = matches.map(m => {
      if (pattern.category === 'credential' || pattern.category === 'api_key') {
        if (m.length > 8) {
          return m.substring(0, 4) + '****' + m.substring(m.length - 4);
        }
        return '****';
      }
      if (pattern.category === 'pii') {
        if (m.includes('@')) {
          const [local, domain] = m.split('@');
          return local.substring(0, 2) + '****@' + domain;
        }
        if (m.includes('-')) {
          return '***-**-' + m.slice(-4);
        }
      }
      return m;
    });
    
    findings.push({
      title: `Sensitive Information: ${name}`,
      description: `${pattern.description}\n\nFound ${matches.length} occurrence(s) in the response body.`,
      severity: pattern.severity,
      vuln_type: 'info_leak',
      confidence: pattern.category === 'api_key' || pattern.category === 'credential' ? 'high' : 'medium',
      url: request.url,
      method: request.method,
      evidence: maskedMatches.join(', '),
      cwe: pattern.cwe,
      owasp: 'A01:2021',
      remediation: getRemediation(pattern.category),
    });
  }
}

function getRemediation(category: string): string {
  switch (category) {
    case 'api_key':
      return 'Remove API keys from responses. Use environment variables and never expose secrets to clients. Rotate compromised keys immediately.';
    case 'credential':
      return 'Never expose credentials in HTTP responses. Use secure credential storage and proper authentication mechanisms.';
    case 'pii':
      return 'Implement proper data masking for PII. Apply principle of least privilege for data access. Review data handling policies.';
    case 'debug':
      return 'Disable debug mode in production. Implement proper error handling that does not expose internal details.';
    case 'infrastructure':
      return 'Remove or sanitize internal infrastructure details from responses. Use reverse proxies to hide backend information.';
    case 'technology':
      return 'Remove or obfuscate technology version headers. Configure web server to hide version information.';
    default:
      return 'Review and remove sensitive information from responses.';
  }
  return findings;
}

// Required: bind to globalThis
globalThis.scan_transaction = scan_transaction;
