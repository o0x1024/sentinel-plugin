/**
 * SQL Injection Detector
 *
 * @plugin sql_injection_detector
 * @name SQL Injection Detector
 * @version 2.0.1
 * @author Sentinel Team
 * @category sqli
 * @default_severity critical
 * @tags sql, injection, security, owasp, passive, traffic
 * @description Detects likely SQL injection vulnerabilities from request payloads and SQL error disclosure in HTTP responses
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

interface ExtractedParam {
  location: "query" | "body";
  value: string;
}

declare const Sentinel: {
  log: (level: string, message: string) => void;
};

const SUSPICIOUS_SQL_PATTERNS: RegExp[] = [
  /(?:'|"|`)\s*(?:or|and)\s*(?:'?\d+'?\s*=\s*'?\d+'?|true|false)\b/i,
  /(?:union\s+all\s+select|union\s+select)\b/i,
  /(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay)\b/i,
  /(?:information_schema|pg_sleep|xp_cmdshell|load_file|into\s+outfile)\b/i,
  /(?:--|#|\/\*)\s*$/i,
  /(?:'\s*;|"\s*;|`\s*;)\s*(?:select|insert|update|delete|drop|exec)\b/i,
];

const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax.*?MySQL/i,
  /Warning.*?\Wmysqli?_/i,
  /You have an error in your SQL syntax/i,
  /PostgreSQL.*?ERROR/i,
  /Warning.*?\Wpg_/i,
  /org\.postgresql\.util\.PSQLException/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /ODBC SQL Server Driver/i,
  /System\.Data\.SqlClient\.SqlException/i,
  /Unclosed quotation mark after the character string/i,
  /ORA-\d{5}/i,
  /Oracle error/i,
  /SQLite\/JDBCDriver/i,
  /\[SQLITE_ERROR\]/i,
  /sqlite3\.OperationalError/i,
];

function bytesToString(bytes: number[]): string {
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
  } catch {
    return "";
  }
}

function truncate(value: string, maxLength = 220): string {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength)}...`;
}

function decodeMaybe(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, "%20"));
  } catch {
    return value;
  }
}

function extractParameters(
  url: string,
  bodyText: string,
  contentType?: string,
): Map<string, ExtractedParam> {
  const params = new Map<string, ExtractedParam>();

  try {
    const parsed = new URL(url);
    parsed.searchParams.forEach((value, key) => {
      params.set(key, {
        location: "query",
        value,
      });
    });
  } catch {
    const queryStart = url.indexOf("?");
    if (queryStart >= 0) {
      const query = url.slice(queryStart + 1);
      for (const pair of query.split("&")) {
        if (!pair) {
          continue;
        }
        const [rawKey, ...rest] = pair.split("=");
        if (!rawKey) {
          continue;
        }
        params.set(decodeMaybe(rawKey), {
          location: "query",
          value: decodeMaybe(rest.join("=")),
        });
      }
    }
  }

  if (!bodyText) {
    return params;
  }

  if (contentType?.includes("application/json")) {
    try {
      const json = JSON.parse(bodyText);
      const walk = (value: unknown, prefix = ""): void => {
        if (typeof value === "string") {
          params.set(prefix, {
            location: "body",
            value,
          });
          return;
        }
        if (!value || typeof value !== "object" || Array.isArray(value)) {
          return;
        }
        for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
          const fullKey = prefix ? `${prefix}.${key}` : key;
          walk(nested, fullKey);
        }
      };
      walk(json);
      return params;
    } catch {
      return params;
    }
  }

  if (contentType?.includes("application/x-www-form-urlencoded")) {
    for (const pair of bodyText.split("&")) {
      if (!pair) {
        continue;
      }
      const [rawKey, ...rest] = pair.split("=");
      if (!rawKey) {
        continue;
      }
      params.set(decodeMaybe(rawKey), {
        location: "body",
        value: decodeMaybe(rest.join("=")),
      });
    }
  }

  return params;
}

function findSqlError(responseBody: string): string | null {
  for (const pattern of SQL_ERROR_PATTERNS) {
    const match = responseBody.match(pattern);
    if (match?.[0]) {
      return match[0];
    }
  }
  return null;
}

function buildEvidence(parts: string[]): string {
  return truncate(parts.filter(Boolean).join(" | "));
}

export function scan_transaction(transaction: HttpTransaction): Promise<any[]> {
  const findings: any[] = [];
  const { request, response } = transaction;

  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(request.method)) {
    return Promise.resolve(findings);
  }

  const requestBody = bytesToString(request.body);
  const responseBody = response?.body ? bytesToString(response.body) : "";
  const params = extractParameters(request.url, requestBody, request.content_type);
  const sqlError = responseBody ? findSqlError(responseBody) : null;

  if (params.size === 0 && !sqlError) {
    return Promise.resolve(findings);
  }

  const suspiciousParams: Array<{
    name: string;
    value: string;
    location: "query" | "body";
    reflected: boolean;
  }> = [];

  for (const [name, param] of params) {
    if (!param.value || param.value.length < 2) {
      continue;
    }

    for (const pattern of SUSPICIOUS_SQL_PATTERNS) {
      if (!pattern.test(param.value)) {
        continue;
      }
      suspiciousParams.push({
        name,
        value: param.value,
        location: param.location,
        reflected: Boolean(responseBody && responseBody.includes(param.value)),
      });
      break;
    }
  }

  for (const param of suspiciousParams) {
    const severity = sqlError ? "critical" : "medium";
    const confidence = sqlError ? "high" : param.reflected ? "medium" : "low";
    const evidenceParts = [
      `parameter=${param.name}`,
      `location=${param.location}`,
      `payload=${truncate(param.value, 120)}`,
      sqlError ? `sql_error=${sqlError}` : "",
      param.reflected ? "response_reflection=true" : "",
    ];

    findings.push({
      title: sqlError
        ? "Confirmed SQL Injection Signal"
        : "Potential SQL Injection Payload",
      description: sqlError
        ? `Parameter "${param.name}" contains SQL injection syntax and the response returned a database error signature.`
        : `Parameter "${param.name}" contains SQL injection syntax commonly associated with exploit payloads.`,
      severity,
      vuln_type: "sqli",
      confidence,
      url: request.url,
      method: request.method,
      param_name: param.name,
      param_value: truncate(param.value, 120),
      evidence: buildEvidence(evidenceParts),
      cwe: "CWE-89",
      owasp: "A03:2021",
      remediation: "Use parameterized queries or prepared statements and suppress database error details in production responses.",
    });
  }

  if (sqlError && suspiciousParams.length === 0) {
    findings.push({
      title: "SQL Error Message Disclosure",
      description: "The response contains a recognizable database error signature. This may indicate SQL injection or unsafe query handling.",
      severity: "high",
      vuln_type: "sqli",
      confidence: "medium",
      url: request.url,
      method: request.method,
      evidence: buildEvidence([`sql_error=${sqlError}`, `status=${String(response?.status ?? "")}`]),
      cwe: "CWE-209",
      owasp: "A05:2021",
      remediation: "Return generic server errors to clients and review SQL query construction for untrusted input handling.",
    });
  }

  if (findings.length > 0) {
    Sentinel.log("info", `SQL injection detector produced ${findings.length} finding(s) for ${request.url}`);
  }

  return Promise.resolve(findings);
}
