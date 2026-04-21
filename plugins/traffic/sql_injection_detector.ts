/**
 * SQL Injection Detector
 *
 * @plugin sql_injection_detector
 * @name SQL Injection Detector
 * @version 2.2.0
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

interface NormalizedResponse {
  status: number;
  contentType: string;
  title: string;
  normalizedBody: string;
  normalizedLength: number;
  sqlError: string | null;
  sqlTokenCount: number;
  wafHint: boolean;
  validationHint: boolean;
}

interface ReplayComparison {
  statusChanged: boolean;
  normalizedLengthDelta: number;
  significantLengthShift: boolean;
  sqlTokenDelta: number;
  titleChanged: boolean;
}

interface ReplayVerdict {
  kind: "confirmed" | "possible" | "discard";
  severity?: "high" | "medium";
  confidence?: "high" | "medium";
  evidence?: string;
  description?: string;
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

const SKIP_PARAM_NAME_HINTS = [
  "csrf",
  "xsrf",
  "token",
  "jwt",
  "signature",
  "sig",
  "nonce",
  "timestamp",
  "session",
  "phpsessid",
  "jsessionid",
];

const WAF_HINT_PATTERNS: RegExp[] = [
  /access denied/i,
  /request blocked/i,
  /forbidden/i,
  /attention required/i,
  /incident id/i,
  /web application firewall/i,
  /cloudflare/i,
  /cf-ray/i,
];

const VALIDATION_HINT_PATTERNS: RegExp[] = [
  /invalid parameter/i,
  /validation failed/i,
  /must be (?:a|string|number|boolean)/i,
  /invalid type/i,
  /bad request/i,
  /unprocessable entity/i,
  /schema/i,
  /failed to deserialize/i,
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

function shouldSkipTarget(name: string, value: string): boolean {
  const normalizedName = name.toLowerCase();
  const trimmedValue = value.trim();
  if (!trimmedValue) {
    return true;
  }
  if (trimmedValue.length > 256) {
    return true;
  }
  return SKIP_PARAM_NAME_HINTS.some(hint => normalizedName.includes(hint));
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
    const normalizedValue = String(value ?? "");
    if (shouldSkipTarget(name, normalizedValue)) {
      continue;
    }
    targets.push({
      name,
      location: "query",
      originalValue: normalizedValue,
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
      const decodedKey = decodeMaybe(rawKey);
      const decodedValue = decodeMaybe(rest.join("="));
      if (shouldSkipTarget(decodedKey, decodedValue)) {
        continue;
      }
      targets.push({
        name: decodedKey,
        location: "body",
        originalValue: decodedValue,
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
        if (typeof value === "string") {
          if (!path || shouldSkipTarget(path, value)) {
            return;
          }
          targets.push({
            name: path,
            location: "body",
            originalValue: value,
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
  const headers = buildReplayHeaders(request, "sql_injection_detector");

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

function buildReplayHeaders(request: RequestContext, probeLabel: string): Record<string, string> {
  const headers = { ...request.headers };
  delete headers["content-length"];
  delete headers["Content-Length"];
  headers["x-sentinel-active-probe"] = probeLabel;
  return headers;
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

function parseTitle(text: string): string {
  const match = text.match(/<title[^>]*>([^<]{0,200})<\/title>/i);
  return match?.[1]?.trim() || "";
}

function stripDynamicArtifacts(text: string): string {
  return text
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi, "<uuid>")
    .replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b/g, "<iso-ts>")
    .replace(/\b(trace|request|correlation)[-_ ]?id\b[:= ]+[A-Za-z0-9._-]+/gi, "$1=<id>")
    .replace(/\b\d{10,}\b/g, "<num>");
}

function stripReflections(text: string, values: string[]): string {
  let normalized = text;
  for (const value of values) {
    if (!value) {
      continue;
    }
    normalized = normalized.split(value).join("<ref>");
    normalized = normalized.split(encodeMaybe(value)).join("<ref>");
  }
  return normalized;
}

function normalizeResponseBody(body: string, reflectedValues: string[]): string {
  return stripDynamicArtifacts(stripReflections(body, reflectedValues))
    .replace(/\s+/g, " ")
    .trim();
}

function isLikelyWafBlock(replay: ReplayOutcome): boolean {
  if ([403, 406, 429].includes(replay.status)) {
    return true;
  }
  return WAF_HINT_PATTERNS.some(pattern => pattern.test(replay.body));
}

function isLikelyValidationErrorBody(body: string): boolean {
  return VALIDATION_HINT_PATTERNS.some(pattern => pattern.test(body));
}

function buildNormalizedResponse(
  replay: ReplayOutcome,
  reflectedValues: string[],
): NormalizedResponse {
  const normalizedBody = normalizeResponseBody(replay.body, reflectedValues);
  return {
    status: replay.status,
    contentType: replay.contentType || "",
    title: parseTitle(replay.body),
    normalizedBody,
    normalizedLength: normalizedBody.length,
    sqlError: findSqlError(replay.body),
    sqlTokenCount: countSqlErrorTokens(replay.body),
    wafHint: isLikelyWafBlock(replay),
    validationHint: isLikelyValidationErrorBody(replay.body),
  };
}

function isDynamicBaseline(a: NormalizedResponse, b: NormalizedResponse): boolean {
  if (a.status !== b.status) {
    return true;
  }
  const delta = Math.abs(a.normalizedLength - b.normalizedLength);
  return delta >= Math.max(80, Math.floor(Math.max(a.normalizedLength, 1) * 0.2));
}

function compareResponses(
  baseline: NormalizedResponse,
  replay: NormalizedResponse,
): ReplayComparison {
  const normalizedLengthDelta = Math.abs(replay.normalizedLength - baseline.normalizedLength);
  return {
    statusChanged: baseline.status > 0 && baseline.status !== replay.status,
    normalizedLengthDelta,
    significantLengthShift:
      baseline.normalizedLength > 0
      && normalizedLengthDelta >= Math.max(100, Math.floor(baseline.normalizedLength * 0.25)),
    sqlTokenDelta: replay.sqlTokenCount - baseline.sqlTokenCount,
    titleChanged: baseline.title !== replay.title,
  };
}

function classifyReplay(
  baseline: NormalizedResponse,
  replay: NormalizedResponse,
): ReplayVerdict {
  if (replay.sqlError) {
    return {
      kind: "confirmed",
      severity: "high",
      confidence: "high",
      evidence: `sql_error=${replay.sqlError}`,
      description: "Replay response exposed an explicit database error signature.",
    };
  }

  if (replay.wafHint || replay.validationHint) {
    return { kind: "discard" };
  }

  const delta = compareResponses(baseline, replay);
  if (!delta.statusChanged && !delta.significantLengthShift && delta.sqlTokenDelta <= 0 && !delta.titleChanged) {
    return { kind: "discard" };
  }

  if (delta.sqlTokenDelta > 0 || (delta.statusChanged && delta.significantLengthShift) || (delta.statusChanged && delta.titleChanged)) {
    return {
      kind: "possible",
      severity: "medium",
      confidence: "medium",
      evidence: [
        delta.statusChanged ? `status=${baseline.status}->${replay.status}` : "",
        delta.significantLengthShift ? `normalized_length_delta=${delta.normalizedLengthDelta}` : "",
        delta.sqlTokenDelta > 0 ? `sql_token_delta=${delta.sqlTokenDelta}` : "",
        delta.titleChanged ? `title=${truncate(baseline.title, 80)}->${truncate(replay.title, 80)}` : "",
      ].filter(Boolean).join(" | "),
      description: "Replay response deviated from a stable baseline after a low-impact SQL syntax probe.",
    };
  }

  return { kind: "discard" };
}

function buildBaselineReplayRequest(request: RequestContext): { url: string; init: RequestInit } {
  const method = request.method.toUpperCase();
  const bodyText = bytesToString(request.body);
  return {
    url: request.url,
    init: {
      method,
      headers: buildReplayHeaders(request, "sql_injection_detector:baseline"),
      body: method === "POST" ? bodyText : undefined,
      ...ACTIVE_PROBE_OPTIONS,
    },
  };
}

async function executeReplay(url: string, init: RequestInit, targetName?: string): Promise<ReplayOutcome | null> {
  try {
    const response = await fetch(url, init);
    const body = await response.text();
    return {
      status: response.status,
      body,
      contentType: response.headers.get("content-type") || "",
    };
  } catch (error) {
    if (targetName) {
      Sentinel.log("debug", `SQL injection replay failed for ${targetName}: ${String(error)}`);
    } else {
      Sentinel.log("debug", `SQL injection replay failed: ${String(error)}`);
    }
    return null;
  }
}

async function replayTarget(
  request: RequestContext,
  target: MutationTarget,
): Promise<ReplayOutcome | null> {
  const replayRequest = buildReplayRequest(request, target);
  if (!replayRequest) {
    return null;
  }
  return executeReplay(replayRequest.url, replayRequest.init, target.name);
}

export async function scan_transaction(transaction: HttpTransaction): Promise<any[]> {
  const findings: any[] = [];
  const { request, response } = transaction;

  if (!response || !isSafeReplayCandidate(request)) {
    return findings;
  }

  const baselineBody = bytesToString(response.body);
  const passiveBaseline = buildNormalizedResponse({
    status: response.status,
    body: baselineBody,
    contentType: response.content_type || "",
  }, []);
  const baselineReplayRequest = buildBaselineReplayRequest(request);
  const baselineReplay = await executeReplay(baselineReplayRequest.url, baselineReplayRequest.init);
  if (!baselineReplay) {
    return findings;
  }

  const activeBaseline = buildNormalizedResponse(baselineReplay, []);
  if (isDynamicBaseline(passiveBaseline, activeBaseline)) {
    Sentinel.log("debug", `SQL injection detector skipped unstable baseline for ${request.url}`);
    return findings;
  }

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

    const reflectedValues = [target.originalValue, `${target.originalValue}'`];
    let normalizedReplay = buildNormalizedResponse(replay, reflectedValues);
    let verdict = classifyReplay(activeBaseline, normalizedReplay);
    if (verdict.kind === "discard") {
      continue;
    }

    if (verdict.kind === "possible") {
      const confirmReplay = await replayTarget(request, target);
      if (!confirmReplay) {
        continue;
      }
      const confirmedReplay = buildNormalizedResponse(confirmReplay, reflectedValues);
      const confirmVerdict = classifyReplay(activeBaseline, confirmedReplay);
      if (confirmVerdict.kind === "discard") {
        continue;
      }
      verdict = confirmVerdict;
      normalizedReplay = confirmedReplay;
    }

    findings.push({
      title: verdict.kind === "confirmed"
        ? "Confirmed SQL Error Disclosure"
        : "Possible SQL Injection Behavior",
      description: `${verdict.description} Parameter "${target.name}" was replayed with a single quote suffix.`,
      severity: verdict.severity || "medium",
      vuln_type: "sqli",
      confidence: verdict.confidence || "medium",
      url: request.url,
      method: request.method,
      param_name: target.name,
      param_value: truncate(target.originalValue, 120),
      evidence: truncate(
        [
          `location=${target.location}`,
          `baseline_status=${activeBaseline.status}`,
          `probe_status=${normalizedReplay.status}`,
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
