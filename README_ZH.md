# Sentinel 插件商店

[Sentinel AI](https://github.com/o0x1024/sentinel-ai) 安全测试平台的官方插件仓库。

**[English](README.md)** | **[中文](README_ZH.md)**

## 简介

本仓库包含社区贡献和官方开发的 Sentinel AI 插件，包括：
- **被动扫描插件** - 分析 HTTP 流量并主动验证漏洞
- **Agent 工具插件** - 为 AI Agent 提供安全测试工具

## 目录结构

```
sentinel-plugin/
├── README.md              # 英文文档
├── README_ZH.md           # 中文文档
├── plugins.json           # 插件清单（必需）
└── plugins/
    ├── passive/           # 被动扫描插件
    │   ├── sql_injection_detector.ts
    │   ├── xss_detector.ts
    │   └── sensitive_info_detector.ts
    └── agent/             # Agent 工具插件
        ├── url_encoder.ts
        └── hash_calculator.ts
```

## 插件运行环境

Sentinel 插件运行在基于 Deno 的 JavaScript/TypeScript 运行时中，完整支持 Web API 和额外的安全测试工具函数。

### 可用 API

#### 核心 API

| API | 描述 |
|-----|------|
| `Sentinel.emitFinding(finding)` | 上报安全漏洞发现 |
| `Sentinel.log(level, message)` | 日志输出 (level: "debug", "info", "warn", "error") |
| `fetch(url, options)` | HTTP 客户端，支持超时设置 |

#### Web 标准 API

| API | 描述 |
|-----|------|
| `URL`, `URLSearchParams` | URL 解析和操作 |
| `TextEncoder`, `TextDecoder` | 文本编码/解码 (UTF-8 等) |
| `atob`, `btoa` | Base64 编码/解码 |
| `crypto.subtle` | Web Crypto API (SHA-256, AES, RSA 等) |
| `crypto.getRandomValues()` | 加密安全随机数 |
| `Headers`, `Request`, `Response` | Fetch API 原语 |
| `Blob`, `File` | 二进制数据处理 |
| `AbortController`, `AbortSignal` | 请求取消 |
| `setTimeout`, `setInterval` | 定时器 |
| `ReadableStream`, `WritableStream` | 流 API |
| `CompressionStream`, `DecompressionStream` | gzip/deflate 压缩 |
| `performance.now()` | 高精度计时 |
| `console.log/warn/error` | 控制台输出 |

#### Deno 网络 API

| API | 描述 |
|-----|------|
| `Deno.connect(options)` | TCP 连接 |
| `Deno.connectTls(options)` | TLS 连接 |
| `Deno.listen(options)` | TCP 服务器 |
| `Deno.resolveDns(hostname, type)` | DNS 解析 |

#### 工具函数

| 函数 | 描述 |
|------|------|
| `sleep(ms)` / `delay(ms)` | 异步延迟 |
| `timeout(promise, ms)` | Promise 超时包装器 |
| `retry(fn, options)` | 指数退避重试 |
| `chunk(array, size)` | 数组分块 |
| `parallelLimit(tasks, limit)` | 限制并发的并行执行 |

#### 安全测试工具 (`SecurityUtils`)

| 函数 | 描述 |
|------|------|
| `SecurityUtils.urlEncode(str)` | URL 编码 |
| `SecurityUtils.urlDecode(str)` | URL 解码 |
| `SecurityUtils.htmlEncode(str)` | HTML 实体编码 |
| `SecurityUtils.htmlDecode(str)` | HTML 实体解码 |
| `SecurityUtils.hexEncode(str)` | 十六进制编码 |
| `SecurityUtils.hexDecode(hex)` | 十六进制解码 |
| `SecurityUtils.unicodeEscape(str)` | Unicode 转义编码 |
| `SecurityUtils.randomString(len, charset)` | 随机字符串生成 |
| `SecurityUtils.randomBytes(len)` | 随机字节生成 |
| `SecurityUtils.parseCookies(header)` | 解析 Cookie 头 |
| `SecurityUtils.buildCookieHeader(cookies)` | 构建 Cookie 头 |
| `SecurityUtils.parseQuery(qs)` | 解析查询字符串 |
| `SecurityUtils.buildQuery(params)` | 构建查询字符串 |
| `SecurityUtils.extractUrls(text)` | 从文本提取 URL |
| `SecurityUtils.extractEmails(text)` | 从文本提取邮箱 |
| `SecurityUtils.extractIPs(text)` | 从文本提取 IP 地址 |

### 远程模块导入

插件可以从 URL 导入外部 TypeScript/JavaScript 模块：

```typescript
// 从 deno.land 导入
import { encode as base64Encode } from "https://deno.land/std@0.208.0/encoding/base64.ts";

// 从 esm.sh 导入
import lodash from "https://esm.sh/lodash@4.17.21";

// 从 unpkg 导入
import axios from "https://unpkg.com/axios/dist/axios.min.js";
```

**注意:** 远程模块会被本地缓存以提高性能。

---

## 插件开发

### 被动扫描插件

被动插件从代理拦截 HTTP 事务。与简单的模式匹配不同，**有效的被动插件应该主动发送 payload 来验证漏洞**。

#### 插件模式

1. **模式检测** - 分析现有请求/响应中的可疑模式
2. **主动验证** - 发送带 payload 的额外请求来确认漏洞

#### 示例：带主动验证的 SQL 注入检测器

```typescript
/**
 * 带主动验证的 SQL 注入检测器
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

// SQL 注入验证 payload
const SQL_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "1' AND '1'='1",
  "1 AND 1=1",
  "' UNION SELECT NULL--",
  "1; WAITFOR DELAY '0:0:5'--",  // 基于时间
  "1' AND SLEEP(5)--",           // MySQL 基于时间
];

// SQL 错误模式
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

// 主动验证：发送 payload 并检查响应
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
      
      // 检查基于错误的 SQLi
      for (const pattern of SQL_ERROR_PATTERNS) {
        if (pattern.test(body)) {
          return {
            vulnerable: true,
            payload,
            evidence: `响应中包含 SQL 错误: ${body.match(pattern)?.[0]}`
          };
        }
      }
      
      // 检查基于时间的 SQLi (响应 > 4.5s 表示 5s 延迟生效)
      if (payload.includes('SLEEP') || payload.includes('DELAY')) {
        if (elapsed > 4500) {
          return {
            vulnerable: true,
            payload,
            evidence: `基于时间的 SQLi: 响应耗时 ${elapsed.toFixed(0)}ms`
          };
        }
      }
      
    } catch (e) {
      Sentinel.log('debug', `${paramName} 验证失败: ${e}`);
    }
  }
  
  return { vulnerable: false, payload: '', evidence: '' };
}

export async function scan_transaction(transaction: HttpTransaction): Promise<void> {
  const { request, response } = transaction;
  
  // 跳过不适用的请求
  if (!['GET', 'POST'].includes(request.method)) return;
  
  // 提取参数
  const url = new URL(request.url);
  const params = new Map<string, string>();
  
  url.searchParams.forEach((value, key) => {
    params.set(key, value);
  });
  
  // 测试每个参数
  for (const [paramName, paramValue] of params) {
    // 快速检查：如果值已包含注入特征则跳过
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
        title: 'SQL 注入漏洞已确认',
        description: `参数 "${paramName}" 存在 SQL 注入漏洞。\nPayload: ${result.payload}`,
        severity: 'critical',
        vuln_type: 'sqli',
        confidence: 'high',
        url: request.url,
        method: request.method,
        param_name: paramName,
        evidence: result.evidence,
        cwe: 'CWE-89',
        owasp: 'A03:2021',
        remediation: '使用参数化查询或预编译语句。'
      });
    }
    
    // 速率限制
    await sleep(100);
  }
}

globalThis.scan_transaction = scan_transaction;
```

### Agent 工具插件

Agent 插件为 AI 代理提供工具。**推荐使用 `get_input_schema()` 函数来暴露参数说明。**

#### 参数 Schema 定义

**方法 1: `get_input_schema()` 函数（推荐 ⭐）**

最优雅的方式：插件自己告诉引擎它需要什么参数。引擎加载插件后会调用这个函数。

```typescript
/**
 * URL 编码/解码工具
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
 * 导出这个函数来告诉引擎插件接受哪些参数。
 * 引擎加载插件后会自动调用它。
 */
export function get_input_schema() {
  return {
    type: "object",
    required: ["text", "mode"],
    properties: {
      text: {
        type: "string",
        description: "要编码或解码的文本"
      },
      mode: {
        type: "string",
        enum: ["encode", "decode"],
        description: "操作模式",
        default: "encode"
      },
      encoding: {
        type: "string",
        enum: ["url", "base64", "html"],
        description: "编码类型",
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

// 绑定到 globalThis 供引擎访问
globalThis.get_input_schema = get_input_schema;
globalThis.analyze = analyze;
```

**为什么这个方法更好：**
- ✅ 不需要正则解析 - 引擎直接调用函数
- ✅ 类型安全 - 在代码中定义 schema
- ✅ 动态灵活 - 可以根据运行时条件生成 schema
- ✅ 自文档化 - schema 和代码在一起
- ✅ 简单易懂 - 小学生都能看懂

**方法 2: Header Schema Block（备选，用于复杂 schema）**

```typescript
/* @sentinel_schema
{
  "type": "object",
  "required": ["targets"],
  "properties": {
    "targets": {
      "type": "array",
      "items": { "type": "string" },
      "description": "要扫描的 URL 或主机列表"
    },
    "concurrency": {
      "type": "integer",
      "default": 10,
      "minimum": 1,
      "maximum": 100,
      "description": "并发请求数"
    }
  }
}
*/

interface ToolInput {
  targets: string[];
  concurrency?: number;
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
  // 实现
}

globalThis.analyze = analyze;
```

> ⚠️ 方法 2 是备选方案，用于插件没有导出 `get_input_schema()` 时的静态解析。新插件应该使用方法 1。

---

## 插件清单 (plugins.json)

```json
{
  "version": "1.0.0",
  "plugins": [
    {
      "id": "唯一插件ID",
      "name": "插件显示名称",
      "version": "1.0.0",
      "author": "作者名称",
      "main_category": "passive|agent",
      "category": "sqli|xss|utility|...",
      "description": "插件功能描述",
      "default_severity": "critical|high|medium|low|info",
      "tags": ["标签1", "标签2"],
      "download_url": ""
    }
  ]
}
```

## 上报漏洞发现

```typescript
Sentinel.emitFinding({
  title: "漏洞标题",
  description: "详细描述",
  severity: "critical|high|medium|low|info",
  vuln_type: "sqli|xss|ssrf|...",
  confidence: "high|medium|low",
  url: "https://example.com/page",
  method: "GET|POST|...",
  param_name: "受影响参数",
  param_value: "参数值",
  evidence: "漏洞证据",
  cwe: "CWE-89",
  owasp: "A03:2021",
  remediation: "修复建议"
});
```

## 插件分类

### 被动扫描分类
- `sqli` - SQL 注入
- `xss` - 跨站脚本
- `command_injection` - 命令注入
- `path_traversal` - 目录穿越
- `info_leak` - 信息泄露
- `csrf` - 跨站请求伪造
- `ssrf` - 服务端请求伪造
- `xxe` - XML 外部实体注入
- `idor` - 越权访问
- `auth_bypass` - 认证绕过
- `custom` - 自定义

### Agent 工具分类
- `scanner` - 扫描工具
- `analyzer` - 分析工具
- `recon` - 信息收集
- `exploit` - 漏洞利用
- `utility` - 实用工具
- `custom` - 自定义

## 贡献插件

1. Fork 本仓库
2. 在 `plugins/passive/` 或 `plugins/agent/` 创建插件
3. 在 `plugins.json` 中添加插件信息
4. 提交 Pull Request

## 许可证

MIT License
