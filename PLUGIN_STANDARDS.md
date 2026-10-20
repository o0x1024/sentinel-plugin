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

### 监控插件的商店声明

`plugins.json` 中声明 `monitor_type` 的 `agent` / `bounty` 插件，必须同时声明完整的输入所有权：

- `input_mode: "asset"`：必须有非空的 `target_asset_types`，不得配置 `seed_bindings`。
- `input_mode: "seed"`：必须有非空的 `seed_bindings`，不得配置资产类型。
- `input_mode: "hybrid"`：资产类型和种子绑定都必须配置。

例如 DNS Resolver 使用 `"monitor_type": "ip"`、`"input_mode": "asset"` 和
`"target_asset_types": ["domain", "web"]`。`monitor_type` 表示调度阶段；资产类型表示实际输入，二者不必同名。
种子绑定的 `input_key` 必须对应插件输入 Schema 中的字符串数组。

资产模式下，监控器注入 `targets`、`domains`、`urls`、`ips`、`target_objects` 和 `service_targets`；
非空域名、URL、IP 列表另提供首项别名 `domain`、`url`、`ip`。API 资产可额外提供 `api_paths`。
插件应使用对应的标准字段，避免要求监控器不会注入的字段。单值插件每次使用对应列表的首项。
目标和种子由监控器管理，不应写入全局默认配置。

修改商店声明后，同步插件头部声明与版本号，并运行：

```bash
deno test --allow-read scripts/plugin_manifest_test.ts
deno run --allow-read scripts/plugin_catalog_smoke.ts
deno run --allow-read scripts/bounty_functional_test.ts
```

以上功能测试使用本地桩，不需要网络访问。输入所有权规则对应 Sentinel 的
`sentinel-contracts/src/monitor_plugin.rs`，规则变更时应同步本仓库的 `scripts/plugin_monitor_contract.ts`。

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
