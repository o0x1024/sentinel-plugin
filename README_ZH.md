# Sentinel 插件商店

[Sentinel AI](https://github.com/o0x1024/sentinel-ai) 安全测试平台的官方插件仓库。

**[English](README.md)** | **[中文](README_ZH.md)**

## 简介

本仓库包含社区贡献和官方开发的 Sentinel AI 插件，包括：
- **被动扫描插件** - 分析 HTTP 流量发现安全漏洞
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
        └── url_encoder.ts
```

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

## 插件开发

### 被动扫描插件

被动插件分析 HTTP 事务，必须导出 `scan_transaction` 函数：

```typescript
interface HttpTransaction {
  request: {
    id: string;
    method: string;
    url: string;
    headers: Record<string, string>;
    body: number[];  // Uint8Array 序列化为 number[]
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

// 被动插件主入口
export function scan_transaction(transaction: HttpTransaction): void {
  // 分析事务并通过 Sentinel.emitFinding() 上报发现
}

// 必需：绑定到 globalThis
globalThis.scan_transaction = scan_transaction;
```

### Agent 工具插件

Agent 插件为 AI 提供工具，必须导出 `analyze` 函数：

```typescript
interface ToolInput {
  [key: string]: any;
}

interface ToolOutput {
  success: boolean;
  data?: any;
  error?: string;
}

// Agent 插件主入口
export async function analyze(input: ToolInput): Promise<ToolOutput> {
  // 处理输入并返回结果
  return { success: true, data: { result: "..." } };
}

// 必需：绑定到 globalThis
globalThis.analyze = analyze;
```

### 上报漏洞发现（被动插件）

使用全局 `Sentinel.emitFinding()` API：

```typescript
Sentinel.emitFinding({
  title: "检测到 SQL 注入",
  description: "在参数中发现 SQL 注入特征",
  severity: "high",
  vuln_type: "sqli",
  confidence: "high",
  url: transaction.request.url,
  method: transaction.request.method,
  evidence: "' OR 1=1 --"
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

