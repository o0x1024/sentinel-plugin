# Sentinel Plugin Store

Official plugin repository for [Sentinel AI](https://github.com/o0x1024/sentinel-ai) security testing platform.

**[English](README.md)** | **[中文](README_ZH.md)**

## Introduction

This repository contains community-contributed and official plugins for Sentinel AI, including:
- **Passive Scan Plugins** - Analyze HTTP traffic and actively verify vulnerabilities
- **Agent Tool Plugins** - Provide tools for AI agents to perform security tasks

## Directory Structure

```
sentinel-plugin/
├── README.md              # English documentation
├── README_ZH.md           # Chinese documentation
├── plugins.json           # Plugin manifest (required)
└── plugins/
    ├── passive/           # Passive scan plugins
    │   ├── sql_injection_detector.ts
    │   ├── xss_detector.ts
    │   └── sensitive_info_detector.ts
    └── agent/             # Agent tool plugins
        ├── url_encoder.ts
        └── hash_calculator.ts
```

## Plugin Runtime Environment

Sentinel plugins run in a Deno-based JavaScript/TypeScript runtime with full Web API support and additional security testing utilities.

### Available APIs

#### Core APIs

| API | Description |
|-----|-------------|
| `Sentinel.emitFinding(finding)` | Report a security vulnerability finding |
| `Sentinel.log(level, message)` | Log messages (level: "debug", "info", "warn", "error") |
| `fetch(url, options)` | HTTP client with timeout support |

#### Web Standard APIs

| API | Description |
|-----|-------------|
| `URL`, `URLSearchParams` | URL parsing and manipulation |
| `TextEncoder`, `TextDecoder` | Text encoding/decoding (UTF-8, etc.) |
| `atob`, `btoa` | Base64 encoding/decoding |
| `crypto.subtle` | Web Crypto API (SHA-256, AES, RSA, etc.) |
| `crypto.getRandomValues()` | Cryptographically secure random numbers |
| `Headers`, `Request`, `Response` | Fetch API primitives |
| `Blob`, `File` | Binary data handling |
| `AbortController`, `AbortSignal` | Request cancellation |
| `setTimeout`, `setInterval` | Timers |
| `ReadableStream`, `WritableStream` | Streams API |
| `CompressionStream`, `DecompressionStream` | gzip/deflate compression |
| `performance.now()` | High-resolution timing |
| `console.log/warn/error` | Console output |

#### Deno Network APIs

| API | Description |
|-----|-------------|
| `Deno.connect(options)` | TCP connection |
| `Deno.connectTls(options)` | TLS connection |
| `Deno.listen(options)` | TCP server |
| `Deno.resolveDns(hostname, type)` | DNS resolution |

#### Utility Functions

| Function | Description |
|----------|-------------|
| `sleep(ms)` / `delay(ms)` | Async delay |
| `timeout(promise, ms)` | Promise timeout wrapper |
| `retry(fn, options)` | Retry with exponential backoff |
| `chunk(array, size)` | Split array into chunks |
| `parallelLimit(tasks, limit)` | Parallel execution with concurrency limit |

#### Security Testing Utilities (`SecurityUtils`)

| Function | Description |
|----------|-------------|
| `SecurityUtils.urlEncode(str)` | URL encoding |
| `SecurityUtils.urlDecode(str)` | URL decoding |
| `SecurityUtils.htmlEncode(str)` | HTML entity encoding |
| `SecurityUtils.htmlDecode(str)` | HTML entity decoding |
| `SecurityUtils.hexEncode(str)` | Hex encoding |
| `SecurityUtils.hexDecode(hex)` | Hex decoding |
| `SecurityUtils.unicodeEscape(str)` | Unicode escape encoding |
| `SecurityUtils.randomString(len, charset)` | Random string generation |
| `SecurityUtils.randomBytes(len)` | Random bytes generation |
| `SecurityUtils.parseCookies(header)` | Parse Cookie header |
| `SecurityUtils.buildCookieHeader(cookies)` | Build Cookie header |
| `SecurityUtils.parseQuery(qs)` | Parse query string |
| `SecurityUtils.buildQuery(params)` | Build query string |
| `SecurityUtils.extractUrls(text)` | Extract URLs from text |
| `SecurityUtils.extractEmails(text)` | Extract emails from text |
| `SecurityUtils.extractIPs(text)` | Extract IP addresses from text |

### Remote Module Imports

Plugins can import external TypeScript/JavaScript modules from URLs:

```typescript
// Import from deno.land
import { encode as base64Encode } from "https://deno.land/std@0.208.0/encoding/base64.ts";

// Import from esm.sh
import lodash from "https://esm.sh/lodash@4.17.21";

// Import from unpkg
import axios from "https://unpkg.com/axios/dist/axios.min.js";
```

**Note:** Remote modules are cached locally for performance.

---

## Plugin Development

### Passive Scan Plugin

Passive plugins intercept HTTP transactions from the proxy. Unlike simple pattern matching, **effective passive plugins should actively send payloads to verify vulnerabilities**.

#### Plugin Modes

1. **Pattern Detection** - Analyze existing request/response for suspicious patterns
2. **Active Verification** - Send additional requests with payloads to confirm vulnerabilities

#### Example: SQL Injection Detector with Active Verification

```typescript
/**
 * SQL Injection Detector with Active Verification
 * @plugin sql_injection_detector
 */

interface HttpTransaction {
  request: {
    id: string;
    method: string;
    url: string;
    headers: Record<string, string>;
    body: number[];
    content_type?: string;
    query_params: Record<string, string>;
    is_https: boolean;
    timestamp: string;
  };
  response?: {
    request_id: string;
    status: number;
    headers: Record<string, string>;
    body: number[];
    content_type?: string;
    timestamp: string;
  };
}

// SQL injection payloads for verification
const SQL_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "1' AND '1'='1",
  "1 AND 1=1",
  "' UNION SELECT NULL--",
  "1; WAITFOR DELAY '0:0:5'--",  // Time-based
  "1' AND SLEEP(5)--",           // Time-based MySQL
];

// SQL error patterns
const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLITE_ERROR/i,
  /SqlException/i,
];

function bytesToString(bytes: number[]): string {
  return new TextDecoder().decode(new Uint8Array(bytes));
}

// Active verification: send payload and check response
async function verifyInjection(
  baseUrl: string,
  paramName: string,
  originalValue: string,
  method: string,
  headers: Record<string, string>
): Promise<{ vulnerable: boolean; payload: string; evidence: string }> {
  
  for (const payload of SQL_PAYLOADS) {
    try {
      const testValue = originalValue + payload;
      const url = new URL(baseUrl);
      url.searchParams.set(paramName, testValue);
      
      const startTime = performance.now();
      const response = await fetch(url.toString(), {
        method,
        headers: { ...headers, 'X-Sentinel-Test': 'true' },
        timeout: 10000,
      });
      const elapsed = performance.now() - startTime;
      
      const body = await response.text();
      
      // Check for error-based SQLi
      for (const pattern of SQL_ERROR_PATTERNS) {
        if (pattern.test(body)) {
          return {
            vulnerable: true,
            payload,
            evidence: `SQL error in response: ${body.match(pattern)?.[0]}`
          };
        }
      }
      
      // Check for time-based SQLi (response > 4.5s for 5s delay)
      if (payload.includes('SLEEP') || payload.includes('DELAY')) {
        if (elapsed > 4500) {
          return {
            vulnerable: true,
            payload,
            evidence: `Time-based SQLi: response took ${elapsed.toFixed(0)}ms`
          };
        }
      }
      
    } catch (e) {
      Sentinel.log('debug', `Verification failed for ${paramName}: ${e}`);
    }
  }
  
  return { vulnerable: false, payload: '', evidence: '' };
}

export async function scan_transaction(transaction: HttpTransaction): Promise<void> {
  const { request, response } = transaction;
  
  // Skip non-applicable requests
  if (!['GET', 'POST'].includes(request.method)) return;
  
  // Extract parameters
  const url = new URL(request.url);
  const params = new Map<string, string>();
  
  url.searchParams.forEach((value, key) => {
    params.set(key, value);
  });
  
  // Test each parameter
  for (const [paramName, paramValue] of params) {
    // Quick check: skip if value looks like injection already
    if (/['";]/.test(paramValue)) continue;
    
    const result = await verifyInjection(
      request.url,
      paramName,
      paramValue,
      request.method,
      request.headers
    );
    
    if (result.vulnerable) {
      Sentinel.emitFinding({
        title: 'SQL Injection Vulnerability Confirmed',
        description: `Parameter "${paramName}" is vulnerable to SQL injection.\nPayload: ${result.payload}`,
        severity: 'critical',
        vuln_type: 'sqli',
        confidence: 'high',
        url: request.url,
        method: request.method,
        param_name: paramName,
        evidence: result.evidence,
        cwe: 'CWE-89',
        owasp: 'A03:2021',
        remediation: 'Use parameterized queries or prepared statements.'
      });
    }
    
    // Rate limiting
    await sleep(100);
  }
}

globalThis.scan_transaction = scan_transaction;
```

### Agent Tool Plugin

Agent plugins provide tools for AI agents. **The recommended way to expose parameters is through a `get_input_schema()` function.**

#### Parameter Schema Definition

**Method 1: `get_input_schema()` Function (Recommended ⭐)**

The most elegant way: plugin tells the engine what parameters it needs at runtime.

```typescript
/**
 * URL Encoder/Decoder Tool
 */

interface ToolInput {
  text: string;
  mode: "encode" | "decode";
  encoding?: "url" | "base64" | "html";
}

interface ToolOutput {
  success: boolean;
  data?: any;
  error?: string;
}

/**
 * Export this function to tell the engine what parameters this plugin accepts.
 * The engine will call this function after loading the plugin.
 */
export function get_input_schema() {
  return {
    type: "object",
    required: ["text", "mode"],
    properties: {
      text: {
        type: "string",
        description: "The text to encode or decode"
      },
      mode: {
        type: "string",
        enum: ["encode", "decode"],
        description: "Operation mode",
        default: "encode"
      },
      encoding: {
        type: "string",
        enum: ["url", "base64", "html"],
        description: "Encoding type",
        default: "url"
      }
    }
  };
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
  const { text, mode, encoding = "url" } = input;
  
  try {
    let result: string;
    
    if (encoding === "url") {
      result = mode === "encode" 
        ? encodeURIComponent(text)
        : decodeURIComponent(text);
    } else if (encoding === "base64") {
      result = mode === "encode" ? btoa(text) : atob(text);
    } else {
      result = mode === "encode"
        ? SecurityUtils.htmlEncode(text)
        : SecurityUtils.htmlDecode(text);
    }
    
    return { success: true, data: { result, mode, encoding } };
  } catch (e) {
    return { success: false, error: String(e) };
  }
}

// Bind to globalThis for engine access
globalThis.get_input_schema = get_input_schema;
globalThis.analyze = analyze;
```

**Why this method is better:**
- ✅ No regex parsing needed - engine directly calls the function
- ✅ Type-safe - you define the schema in code
- ✅ Dynamic - can generate schema based on runtime conditions
- ✅ Self-documenting - schema lives with the code
- ✅ Easy to understand - even beginners can read it

**Method 2: Header Schema Block (for complex schemas, fallback)**

```typescript
/* @sentinel_schema
{
  "type": "object",
  "required": ["targets"],
  "properties": {
    "targets": {
      "type": "array",
      "items": { "type": "string" },
      "description": "List of URLs or hosts to scan"
    },
    "concurrency": {
      "type": "integer",
      "default": 10,
      "minimum": 1,
      "maximum": 100,
      "description": "Number of concurrent requests"
    }
  }
}
*/

interface ToolInput {
  targets: string[];
  concurrency?: number;
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
  // Implementation
}

globalThis.analyze = analyze;
```

> ⚠️ Method 2 is a fallback for plugins that don't export `get_input_schema()`. New plugins should use Method 1.

---

## Plugin Manifest (plugins.json)

```json
{
  "version": "1.0.0",
  "plugins": [
    {
      "id": "unique_plugin_id",
      "name": "Plugin Display Name",
      "version": "1.0.0",
      "author": "Author Name",
      "main_category": "passive|agent",
      "category": "sqli|xss|utility|...",
      "description": "Plugin description",
      "default_severity": "critical|high|medium|low|info",
      "tags": ["tag1", "tag2"],
      "download_url": ""
    }
  ]
}
```

## Emitting Findings

```typescript
Sentinel.emitFinding({
  title: "Vulnerability Title",
  description: "Detailed description",
  severity: "critical|high|medium|low|info",
  vuln_type: "sqli|xss|ssrf|...",
  confidence: "high|medium|low",
  url: "https://example.com/page",
  method: "GET|POST|...",
  param_name: "affected_parameter",
  param_value: "parameter_value",
  evidence: "Proof of vulnerability",
  cwe: "CWE-89",
  owasp: "A03:2021",
  remediation: "How to fix"
});
```

## Plugin Categories

### Passive Scan Categories
- `sqli` - SQL Injection
- `xss` - Cross-Site Scripting
- `command_injection` - Command Injection
- `path_traversal` - Path Traversal
- `info_leak` - Information Disclosure
- `csrf` - Cross-Site Request Forgery
- `ssrf` - Server-Side Request Forgery
- `xxe` - XML External Entity
- `idor` - Insecure Direct Object Reference
- `auth_bypass` - Authentication Bypass
- `custom` - Custom

### Agent Tool Categories
- `scanner` - Scanning Tools
- `analyzer` - Analysis Tools
- `recon` - Reconnaissance
- `exploit` - Exploitation
- `utility` - Utility Tools
- `custom` - Custom

## Contributing

1. Fork this repository
2. Create your plugin in `plugins/passive/` or `plugins/agent/`
3. Add your plugin entry to `plugins.json`
4. Submit a Pull Request

## License

MIT License
