# Sentinel Plugin Store

Official plugin repository for [Sentinel AI](https://github.com/o0x1024/sentinel-ai) security testing platform.

**[English](README.md)** | **[中文](README_ZH.md)**

## Introduction

This repository contains community-contributed and official plugins for Sentinel AI, including:
- **Passive Scan Plugins** - Analyze HTTP traffic for security vulnerabilities
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
        └── url_encoder.ts
```

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

## Plugin Development

### Passive Scan Plugin

Passive plugins analyze HTTP transactions. They must export a `scan_transaction` function:

```typescript
interface HttpTransaction {
  request: {
    id: string;
    method: string;
    url: string;
    headers: Record<string, string>;
    body: number[];  // Uint8Array as number[]
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

// Main entry point for passive plugins
export function scan_transaction(transaction: HttpTransaction): void {
  // Analyze and emit findings via Sentinel.emitFinding()
}

// Required: bind to globalThis
globalThis.scan_transaction = scan_transaction;
```

### Agent Tool Plugin

Agent plugins provide tools for AI. They must export an `analyze` function:

```typescript
interface ToolInput {
  [key: string]: any;
}

interface ToolOutput {
  success: boolean;
  data?: any;
  error?: string;
}

// Main entry point for agent plugins
export async function analyze(input: ToolInput): Promise<ToolOutput> {
  // Process input and return result
  return { success: true, data: { result: "..." } };
}

// Required: bind to globalThis
globalThis.analyze = analyze;
```

### Emitting Findings (Passive Plugins)

Use the global `Sentinel.emitFinding()` API:

```typescript
Sentinel.emitFinding({
  title: "SQL Injection Detected",
  description: "Found SQL injection pattern in parameter",
  severity: "high",
  vuln_type: "sqli",
  confidence: "high",
  url: transaction.request.url,
  method: transaction.request.method,
  evidence: "' OR 1=1 --"
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
