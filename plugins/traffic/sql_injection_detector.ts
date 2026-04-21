/**
 * SQL Injection Detector
 *
 * @plugin sql_injection_detector
 * @name SQL Injection Detector
 * @version 2.1.0
 * @author Sentinel Team
 * @category sqli
 * @default_severity high
 * @tags sql, injection, security, owasp, active-probe, traffic
 * @description Replays every safe parameter with a simple single-quote probe under bounded active verification controls
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

type ParameterLocation = "query" | "body";

interface MutationTarget {
  name: string;
  location: ParameterLocation;
  originalValue: string;
}

interface ReplayOutcome {
  status: number;
  body: string;
  contentType: string;
}

declare const Sentinel: {
  log: (level: string, message: string) => void;
};

declare global {
  interface RequestInit {
    activeProbe?: boolean | {
      jitterRange?: [number, number];
      minHostCooldownMs?: number;
      cooldownKey?: string;
    };
  }
}

const ACTIVE_PROBE_OPTIONS = {
  activeProbe: {
    jitterRange: [300, 1000] as [number, number],
    minHostCooldownMs: 1000,
  },
  timeout: 8000,
};

const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax.*?MySQL/i,
  /Warning.*?\Wmysqli?_/i,
  /You have an error in your SQL syntax/i,
  /PostgreSQL.*?ERROR/i,
  /org\.postgresql\.util\.PSQLException/i,
  /Warning.*?\Wpg_/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /ODBC SQL Server Driver/i,
  /System\.Data\.SqlClient\.SqlException/i,
  /Unclosed quotation mark after the character string/i,
  /ORA-\d{5}/i,
  /Oracle error/i,
  /\[SQLITE_ERROR\]/i,
  /sqlite3\.OperationalError/i,
];

const SQL_ERROR_TOKENS = [
  "sql syntax",
  "mysql",
  "postgresql",
  "psqlexception",
  "sql server",
  "ora-",
  "sqlite",
  "odbc",
  "database error",
  "syntax error",
];

const HIGH_RISK_ROUTE_HINTS = [
  "logout",
  "delete",
  "remove",
  "destroy",
  "payment",
  "purchase",
  "submit",
  "transfer",
  "checkout",
  "order",
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

function encodeMaybe(value: string): string {
  try {
    return encodeURIComponent(value);
  } catch {
    return value;
  }
}

function isSafeReplayCandidate(request: RequestContext): boolean {
  if (!["GET", "POST"].includes(request.method)) {
    return false;
  }

  const normalizedUrl = request.url.toLowerCase();
  if (HIGH_RISK_ROUTE_HINTS.some(hint => normalizedUrl.includes(hint))) {
    return false;
  }

  const contentType = (request.content_type || "").toLowerCase();
  if (request.method === "POST") {
    if (contentType.includes("multipart/form-data")) {
      return false;
    }
    if (
      contentType &&
      !contentType.includes("application/json") &&
      !contentType.includes("application/x-www-form-urlencoded")
    ) {
      return false;
    }
  }

  return true;
}

function extractMutationTargets(request: RequestContext): MutationTarget[] {
  const targets: MutationTarget[] = [];

  for (const [name, value] of Object.entries(request.query_params || {})) {
    targets.push({
      name,
      location: "query",
      originalValue: String(value ?? ""),
    });
  }

  if (request.method !== "POST") {
    return targets;
  }

  const contentType = (request.content_type || "").toLowerCase();
  const bodyText = bytesToString(request.body);
  if (!bodyText) {
    return targets;
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    for (const pair of bodyText.split("&")) {
      if (!pair) {
        continue;
      }
      const [rawKey, ...rest] = pair.split("=");
      if (!rawKey) {
        continue;
      }
      targets.push({
        name: decodeMaybe(rawKey),
        location: "body",
        originalValue: decodeMaybe(rest.join("=")),
      });
    }
    return targets;
  }

  if (contentType.includes("application/json")) {
    try {
      const parsed = JSON.parse(bodyText);
      const walk = (value: unknown, path = ""): void => {
        if (value === null || value === undefined) {
          return;
        }
        if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
          targets.push({
            name: path,
            location: "body",
            originalValue: String(value),
          });
          return;
        }
        if (Array.isArray(value)) {
          value.forEach((item, index) => {
            walk(item, `${path}[${index}]`);
          });
          return;
        }
        if (typeof value === "object") {
          for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
            walk(nested, path ? `${path}.${key}` : key);
          }
        }
      };
      walk(parsed);
    } catch {
      // Ignore malformed JSON bodies and keep query targets only.
    }
  }

  return targets;
}

function setJsonPath(root: unknown, path: string, nextValue: string): unknown {
  const segments = path
    .replace(/\[(\d+)\]/g, ".$1")
    .split(".")
    .filter(Boolean);
  if (segments.length === 0) {
    return root;
  }

  let cursor: any = root;
  for (let index = 0; index < segments.length - 1; index += 1) {
    const segment = segments[index];
    if (cursor == null || typeof cursor !== "object" || !(segment in cursor)) {
      return root;
    }
    cursor = cursor[segment];
  }

  const leaf = segments[segments.length - 1];
  if (cursor == null || typeof cursor !== "object" || !(leaf in cursor)) {
    return root;
  }

  cursor[leaf] = nextValue;
  return root;
}

function buildReplayRequest(request: RequestContext, target: MutationTarget): {
  url: string;
  init: RequestInit;
  probeValue: string;
} | null {
  const probeValue = `${target.originalValue}'`;
  const headers = { ...request.headers };
  delete headers["content-length"];
  delete headers["Content-Length"];
  headers["x-sentinel-active-probe"] = "sql_injection_detector";

  if (target.location === "query") {
    try {
      const url = new URL(request.url);
      url.searchParams.set(target.name, probeValue);
      return {
        url: url.toString(),
        init: {
          method: request.method,
          headers,
          ...ACTIVE_PROBE_OPTIONS,
        },
        probeValue,
      };
    } catch {
      return null;
    }
  }

  const contentType = (request.content_type || "").toLowerCase();
  const bodyText = bytesToString(request.body);

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const pairs: string[] = [];
    let updated = false;
    for (const pair of bodyText.split("&")) {
      if (!pair) {
        continue;
      }
      const [rawKey, ...rest] = pair.split("=");
      const decodedKey = decodeMaybe(rawKey);
      if (decodedKey === target.name && !updated) {
        pairs.push(`${encodeMaybe(decodedKey)}=${encodeMaybe(probeValue)}`);
        updated = true;
      } else {
        pairs.push(`${encodeMaybe(decodedKey)}=${rest.join("=")}`);
      }
    }
    if (!updated) {
      return null;
    }
    return {
      url: request.url,
      init: {
        method: request.method,
        headers,
        body: pairs.join("&"),
        ...ACTIVE_PROBE_OPTIONS,
      },
      probeValue,
    };
  }

  if (contentType.includes("application/json")) {
    try {
      const cloned = JSON.parse(bodyText);
      const mutated = setJsonPath(cloned, target.name, probeValue);
      return {
        url: request.url,
        init: {
          method: request.method,
          headers,
          body: JSON.stringify(mutated),
          ...ACTIVE_PROBE_OPTIONS,
        },
        probeValue,
      };
    } catch {
      return null;
    }
  }

  return null;
}

function findSqlError(text: string): string | null {
  for (const pattern of SQL_ERROR_PATTERNS) {
    const match = text.match(pattern);
    if (match?.[0]) {
      return match[0];
    }
  }
  return null;
}

function countSqlErrorTokens(text: string): number {
  const normalized = text.toLowerCase();
  return SQL_ERROR_TOKENS.filter(token => normalized.includes(token)).length;
}

function classifyReplay(
  baselineStatus: number,
  baselineBody: string,
  replay: ReplayOutcome,
): { severity: string; confidence: string; evidence: string; description: string } | null {
  const sqlError = findSqlError(replay.body);
  if (sqlError) {
    return {
      severity: "high",
      confidence: "high",
      evidence: `sql_error=${sqlError}`,
      description: `Replay response exposed a database error signature after appending a single quote probe.`,
    };
  }

  const statusChanged = baselineStatus > 0 && baselineStatus !== replay.status;
  const baselineLength = baselineBody.length;
  const replayLength = replay.body.length;
  const lengthDelta = Math.abs(replayLength - baselineLength);
  const significantLengthShift = baselineLength > 0 && lengthDelta >= Math.max(120, Math.floor(baselineLength * 0.3));
  const tokenDelta = countSqlErrorTokens(replay.body) - countSqlErrorTokens(baselineBody);

  if (!statusChanged && !significantLengthShift && tokenDelta <= 0) {
    return null;
  }

  const evidenceParts = [];
  if (statusChanged) {
    evidenceParts.push(`status=${baselineStatus}->${replay.status}`);
  }
  if (significantLengthShift) {
    evidenceParts.push(`length=${baselineLength}->${replayLength}`);
  }
  if (tokenDelta > 0) {
    evidenceParts.push(`sql_token_delta=${tokenDelta}`);
  }

  return {
    severity: "medium",
    confidence: tokenDelta > 0 || statusChanged ? "medium" : "low",
    evidence: evidenceParts.join(" | "),
    description: `Replay response deviated materially from the baseline after appending a single quote probe.`,
  };
}

async function replayTarget(
  request: RequestContext,
  target: MutationTarget,
): Promise<ReplayOutcome | null> {
  const replayRequest = buildReplayRequest(request, target);
  if (!replayRequest) {
    return null;
  }

  try {
    const response = await fetch(replayRequest.url, replayRequest.init);
    const body = await response.text();
    return {
      status: response.status,
      body,
      contentType: response.headers.get("content-type") || "",
    };
  } catch (error) {
    Sentinel.log("debug", `SQL injection replay failed for ${target.name}: ${String(error)}`);
    return null;
  }
}

export async function scan_transaction(transaction: HttpTransaction): Promise<any[]> {
  const findings: any[] = [];
  const { request, response } = transaction;

  if (!response || !isSafeReplayCandidate(request)) {
    return findings;
  }

  const baselineBody = bytesToString(response.body);
  const targets = extractMutationTargets(request);
  if (targets.length === 0) {
    return findings;
  }

  Sentinel.log("info", `SQL injection detector actively replaying ${targets.length} parameter(s) for ${request.url}`);

  for (const target of targets) {
    const replay = await replayTarget(request, target);
    if (!replay) {
      continue;
    }

    const verdict = classifyReplay(response.status, baselineBody, replay);
    if (!verdict) {
      continue;
    }

    findings.push({
      title: verdict.severity === "high"
        ? "Confirmed SQL Injection Signal"
        : "Potential SQL Injection Signal",
      description: `${verdict.description} Parameter "${target.name}" was replayed with a single quote suffix.`,
      severity: verdict.severity,
      vuln_type: "sqli",
      confidence: verdict.confidence,
      url: request.url,
      method: request.method,
      param_name: target.name,
      param_value: truncate(target.originalValue, 120),
      evidence: truncate(
        [
          `location=${target.location}`,
          `probe=${truncate(`${target.originalValue}'`, 120)}`,
          verdict.evidence,
        ].filter(Boolean).join(" | "),
      ),
      cwe: "CWE-89",
      owasp: "A03:2021",
      remediation: "Use parameterized queries or prepared statements and avoid returning database error details to clients.",
    });
  }

  return findings;
}

globalThis.scan_transaction = scan_transaction;
