# Sentinel 插件开发标准与规范

为了确保插件返回的数据能够被 Sentinel AI 系统自动解析、入库并用于后续自动化流程（如资产发现、漏洞扫描），所有插件开发应遵循以下输入输出规范。

## 1. 通用 Agent 工具接口

所有 Agent 工具插件（`scan` / `recon` / `utility`）必须导出 `analyze` 函数，并返回 `ToolOutput` 格式。

```typescript
interface ToolOutput {
  success: boolean;       // 执行是否成功
  data?: any;            // 插件返回的核心数据（结构见下文）
  error?: string;        // 错误信息（仅当 success=false 时）
}
```

## 2. 资产发现类插件返回规范 (Recon)

对于 **信息收集 (Recon)** 和 **资产发现** 类插件（如子域名枚举、端口扫描、API 探测），`data` 字段应严格遵循以下结构，以便系统自动发现新资产。

### 推荐返回结构

```json
{
  "success": true,
  "data": {
    "subdomains": [
      "api.example.com",
      "dev.example.com"
    ],
    "urls": [
      "https://example.com/login",
      "https://api.example.com/v1/user"
    ],
    "ips": [
      "10.0.0.1",
      "192.168.1.1"
    ],
    "assets": [
      {
        "type": "domain",
        "value": "admin.example.com",
        "metadata": {
          "source": "virustotal",
          "ip": "1.2.3.4"
        }
      },
      {
        "type": "service",
        "value": "10.0.0.1:8080",
        "metadata": {
          "service": "http",
          "product": "nginx"
        }
      }
    ]
  }
}
```

### 字段说明

Sentinel 监控调度器会自动解析以下字段并将其入库为 "Bug Bounty 资产"：

| 字段名 | 类型 | 描述 | 入库行为 |
| :--- | :--- | :--- | :--- |
| `subdomains` | `string[]` | 发现的子域名列表 | 自动创建 `domain` 类型资产 |
| `urls` | `string[]` | 发现的完整 URL 列表 | 自动创建 `url` 类型资产或提取域名 |
| `ips` | `string[]` | 发现的 IP 地址列表 | 自动创建 `ip` 类型资产 |
| `assets` | `Asset[]` | 包含元数据的复杂资产列表 | 根据 `type` 创建对应资产，并保存 `metadata` |

### 示例代码

```typescript
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    // ... 执行逻辑 ...
    const domains = ["a.com", "b.com"];
    
    return {
        success: true,
        data: {
            subdomains: domains,
            count: domains.length
        }
    };
}
```

## 3. 漏洞扫描类插件返回规范 (Scanner/Passive)

漏洞扫描主要通过 `Sentinel.emitFinding()` 上报漏洞，但也建议在 `ToolOutput` 中返回概览。

### 上报漏洞 (emitFinding)

系统会自动捕获通过 `Sentinel.emitFinding` 发出的所有漏洞，并将其存入 Bug Bounty 的 Findings 表。

```typescript
Sentinel.emitFinding({
  title: "Git 信息泄露",
  description: "发现 .git 目录暴露",
  severity: "high",             // critical, high, medium, low, info
  vuln_type: "info_leak",
  url: "https://example.com/.git/config",
  evidence: "Response body detected...",
  confidence: "high"
});
```

### 返回结果 (ToolOutput)

```json
{
  "success": true,
  "data": {
    "status": "vulnerable",
    "targets_scanned": 15,
    "findings_count": 2,
    "findings": [ ... ] // 可选，系统会自动聚合 emitFinding 的内容到这里
  }
}
```

## 4. 插件元数据与输入定义

一定要导出 `get_input_schema()`，这对 AI Agent 正确调用工具至关重要。

```typescript
export function get_input_schema() {
  return {
    type: "object",
    required: ["domain"],
    properties: {
      domain: {
        type: "string",
        description: "Target domain to scan"
      }
    }
  };
}
```
