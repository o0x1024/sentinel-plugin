/**
 * SQL Injection Detector
 *
 * @plugin sql_injection_detector
 * @name SQL Injection Detector
 * @version 2.3.1
 * @author Sentinel Team
 * @category sqli
 * @default_severity high
 * @tags sql, injection, security, owasp, active-probe, traffic
 * @description Replays safe parameters with multi-signal SQL probes under bounded active verification controls
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
type BodyMutationKind = "form" | "json" | "multipart";
type MutationValueKind = "string" | "numeric";
type JsonPathSegment = string | number;

interface MutationTarget {
  name: string;
  location: ParameterLocation;
  originalValue: string;
  valueKind: MutationValueKind;
  bodyKind?: BodyMutationKind;
  pathSegments?: JsonPathSegment[];
  occurrenceIndex?: number;
  multipartIndex?: number;
}

interface ActiveProbeReplayMetadata {
  target_name: string;
  target_path: string;
  target_location: ParameterLocation;
  probe_value: string;
  technique: "error-based" | "blind-boolean" | "time-based";
}

interface ReplayOutcome {
  status: number;
  body: string;
  contentType: string;
  headers: string;
  elapsedMs: number;
}

type ResponseContentClass = "json" | "html" | "text" | "binary";

interface ReplayRequestArtifact {
  method: string;
  url: string;
  headers: string;
  body: string;
}

interface ReplayArtifact {
  request: ReplayRequestArtifact;
  response: ReplayOutcome;
}

interface ReplayProbeCandidate {
  probeValue: string;
  replayArtifact: ReplayArtifact;
  normalizedReplay: NormalizedResponse;
}

interface NormalizedResponse {
  status: number;
  contentType: string;
  responseClass: ResponseContentClass;
  title: string;
  normalizedBody: string;
  normalizedLength: number;
  sqlError: string | null;
  sqlSignalScore: number;
  wafHint: boolean;
  validationHint: boolean;
}

interface ReplayComparison {
  statusChanged: boolean;
  normalizedLengthDelta: number;
  significantLengthShift: boolean;
  sqlSignalDelta: number;
  significantSqlSignalShift: boolean;
  titleChanged: boolean;
}

interface SqlSignalTokenWeight {
  token: string;
  weight: number;
}

interface ReplayVerdict {
  kind: "confirmed" | "possible" | "discard";
  severity?: "high" | "medium";
  confidence?: "high" | "medium";
  evidence?: string;
  description?: string;
}

interface ReplayBudget {
  totalRemaining: number;
  remainingByTechnique: Record<"error-based" | "blind-boolean" | "time-based", number>;
}

interface BooleanProbePair {
  trueProbe: string;
  falseProbe: string;
}

interface BooleanBlindResult {
  trueArtifact: ReplayArtifact;
  falseArtifact: ReplayArtifact;
  trueResponse: NormalizedResponse;
  falseResponse: NormalizedResponse;
}

interface TimeBlindResult {
  artifact: ReplayArtifact;
  normalizedResponse: NormalizedResponse;
  probeValue: string;
  delayDeltaMs: number;
}

interface MultipartPart {
  headersBytes: Uint8Array;
  contentBytes: Uint8Array;
  fieldName: string | null;
  fileName: string | null;
}

interface ParsedMultipartBody {
  boundary: string;
  parts: MultipartPart[];
}

type PluginGlobals = typeof globalThis & {
  scan_transaction?: typeof scan_transaction;
};

declare const Sentinel: {
  log: (level: string, message: string) => void;
  emitFinding?: (finding: Record<string, unknown>) => boolean;
};

declare global {
  interface RequestInit {
    activeProbe?: boolean | {
      target_name?: string;
      target_path?: string;
      target_location?: ParameterLocation;
      probe_value?: string;
      technique?: "error-based" | "blind-boolean" | "time-based";
      probeLabel?: string;
    };
  }
}

// Hard-coded technique toggles. Flip these booleans to control which SQLi
// verification paths run for each request.
const ENABLE_ERROR_BASED_TESTS = true;
const ENABLE_BOOLEAN_BLIND_TESTS = false;
const ENABLE_TIME_BLIND_TESTS = false;

const SUPPORTED_REPLAY_METHODS = ["GET", "POST", "PUT", "PATCH"];
const MAX_MUTATION_TARGETS_PER_REQUEST = 6;
const MAX_REPLAYS_PER_REQUEST = 18;
const MAX_ERROR_REPLAYS_PER_REQUEST = 8;
const MAX_BOOLEAN_REPLAYS_PER_REQUEST = 6;
const MAX_TIME_REPLAYS_PER_REQUEST = 3;
const RESPONSE_LENGTH_SHIFT_MIN = 80;
const RESPONSE_LENGTH_SHIFT_RATIO = 0.12;
const BOOLEAN_PAIR_LENGTH_DELTA_MIN = 60;
const TIME_PROBE_DELAY_MS = 4000;
const TIME_BLIND_THRESHOLD_MS = 3000;
const SQL_SIGNAL_SCORE_MIN = 4;
const SQL_SIGNAL_DELTA_MIN = 2;

const SQL_ERROR_PATTERNS: RegExp[] = [
  // MySQL / MariaDB
  /SQL syntax.*?MySQL/i,
  /Warning.*?\Wmysql_/i,
  /Warning.*?\Wmysqli?_/i,
  /MySQLSyntaxErrorException/i,
  /You have an error in your SQL syntax/i,
  /mysql_fetch_array\(\)/i,
  /mysql_num_rows\(\)/i,
  /mysql_query\(\)/i,
  /MariaDB server version for the right syntax/i,
  /MariaDBSyntaxErrorException/i,
  /supplied argument is not a valid MySQL/i,

  // PostgreSQL / openGauss
  /PostgreSQL.*?ERROR/i,
  /org\.postgresql\.util\.PSQLException/i,
  /Npgsql\.PostgresException/i,
  /Warning.*?\Wpg_/i,
  /PG::SyntaxError/i,
  /pg_query\(\)/i,
  /pg_exec\(\)/i,
  /ERROR:\s+syntax error at or near/i,
  /openGauss/i,

  // SQL Server / Sybase
  /Incorrect syntax near/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /ODBC SQL Server Driver/i,
  /ODBC Driver \d+ for SQL Server/i,
  /System\.Data\.SqlClient\.SqlException/i,
  /com\.microsoft\.sqlserver\.jdbc/i,
  /Unclosed quotation mark after the character string/i,
  /SQLServerException/i,
  /Warning.*?\Wmssql_/i,
  /Sybase message/i,
  /Adaptive Server/i,

  // Oracle / Oracle-compatible
  /ORA-\d{5}/i,
  /Oracle error/i,
  /quoted string not properly terminated/i,
  /SQL command not properly ended/i,
  /OracleException/i,

  // SQLite / embedded Java databases
  /\[SQLITE_ERROR\]/i,
  /sqlite3\.OperationalError/i,
  /SQLiteException/i,
  /near ".*?": syntax error/i,
  /org\.h2\.jdbc/i,
  /JdbcSQLSyntaxErrorException/i,
  /HSQLDB/i,
  /org\.hsqldb/i,
  /Apache Derby/i,

  // DB2 / Informix / Firebird / Tibero / GBase / other engines
  /DB2 SQL Error/i,
  /SQLCODE=-?\d+/i,
  /SQLSTATE=[0-9A-Z]{5}/i,
  /com\.ibm\.db2/i,
  /Informix/i,
  /IBM Informix/i,
  /Firebird/i,
  /Dynamic SQL Error/i,
  /Tibero/i,
  /GBase/i,

  // Distributed / analytical / cloud-native engines
  /OceanBase/i,
  /OBException/i,
  /GaussDB/i,
  /ClickHouse/i,
  /DB::Exception/i,
  /Vertica/i,
  /PrestoException/i,
  /TrinoException/i,

  // Language drivers and framework exceptions
  /java\.sql\.SQLException/i,
  /BatchUpdateException/i,
  /PersistenceException/i,
  /JDBCException/i,
  /EntityCommandExecutionException/i,
  /DbUpdateException/i,
  /sqlalchemy\.exc\.(ProgrammingError|OperationalError)/i,
  /psycopg2\.errors\.SyntaxError/i,
  /pymysql\.err\.ProgrammingError/i,
  /MySQLdb\._exceptions/i,
  /PDOException/i,
  /mysqli_sql_exception/i,
  /SequelizeDatabaseError/i,
  /QueryFailedError/i,
  /PrismaClientKnownRequestError/i,
  /PrismaClientUnknownRequestError/i,
  /\bpq:\s+syntax error/i,
  /\bpgx\b/i,
  /Error 1064/i,
  /sql:\s+Scan error/i,

  // ORM / framework wrappers
  /org\.hibernate\.exception\.SQLGrammarException/i,
  /could not extract ResultSet/i,
  /JDBC exception executing SQL/i,
  /BadSqlGrammarException/i,
  /InvalidDataAccessResourceUsageException/i,
  /django\.db\.utils\.(ProgrammingError|OperationalError)/i,
  /ActiveRecord::StatementInvalid/i,
  /Mysql2::Error/i,
  /Illuminate\\Database\\QueryException/i,

  // Generic fallback signatures
  /DB:/i,
];

const SQL_ERROR_TOKENS: SqlSignalTokenWeight[] = [
  // Engines and vendors
  { token: "sql syntax", weight: 2 },
  { token: "mysql", weight: 2 },
  { token: "mariadb", weight: 2 },
  { token: "mysql_fetch", weight: 4 },
  { token: "mysql_num_rows", weight: 4 },
  { token: "mysql_query", weight: 4 },
  { token: "postgresql", weight: 2 },
  { token: "psqlexception", weight: 4 },
  { token: "postgres exception", weight: 3 },
  { token: "pg::syntaxerror", weight: 4 },
  { token: "pg_query", weight: 4 },
  { token: "opengauss", weight: 2 },
  { token: "sql server", weight: 2 },
  { token: "sqlserverexception", weight: 4 },
  { token: "incorrect syntax near", weight: 3 },
  { token: "unclosed quotation mark", weight: 3 },
  { token: "ora-", weight: 3 },
  { token: "oracleexception", weight: 4 },
  { token: "sqlite", weight: 2 },
  { token: "sqlite_error", weight: 4 },
  { token: "db2 sql error", weight: 4 },
  { token: "sqlcode=", weight: 3 },
  { token: "sqlstate=", weight: 2 },
  { token: "odbc", weight: 2 },
  { token: "informix", weight: 2 },
  { token: "firebird", weight: 2 },
  { token: "tibero", weight: 2 },
  { token: "gbase", weight: 2 },
  { token: "oceanbase", weight: 2 },
  { token: "obexception", weight: 4 },
  { token: "gaussdb", weight: 2 },
  { token: "clickhouse", weight: 2 },
  { token: "db::exception", weight: 4 },
  { token: "vertica", weight: 2 },
  { token: "prestoexception", weight: 4 },
  { token: "trinoexception", weight: 4 },

  // Driver and ORM layers
  { token: "java.sql.sqlexception", weight: 4 },
  { token: "sqlsyntaxerrorexception", weight: 4 },
  { token: "batchupdateexception", weight: 3 },
  { token: "persistenceexception", weight: 3 },
  { token: "jdbcexception", weight: 4 },
  { token: "dbupdateexception", weight: 3 },
  { token: "sqlalchemy.exc.programmingerror", weight: 4 },
  { token: "sqlalchemy.exc.operationalerror", weight: 4 },
  { token: "psycopg2.errors.syntaxerror", weight: 4 },
  { token: "pymysql.err.programmingerror", weight: 4 },
  { token: "pdoexception", weight: 4 },
  { token: "mysqli_sql_exception", weight: 4 },
  { token: "sequelizedatabaseerror", weight: 4 },
  { token: "queryfailederror", weight: 4 },
  { token: "prismaclientknownrequesterror", weight: 4 },
  { token: "prismaclientunknownrequesterror", weight: 4 },
  { token: "pq: syntax error", weight: 3 },
  { token: "sql: scan error", weight: 3 },
  { token: "sqlgrammarexception", weight: 4 },
  { token: "badsqlgrammarexception", weight: 4 },
  { token: "invaliddataaccessresourceusageexception", weight: 4 },
  { token: "django.db.utils.programmingerror", weight: 4 },
  { token: "activerecord::statementinvalid", weight: 4 },
  { token: "mysql2::error", weight: 4 },
  { token: "illuminate\\database\\queryexception", weight: 4 },

  // Generic SQL failure language
  { token: "database error", weight: 1 },
  { token: "sql error", weight: 1 },
  { token: "query failed", weight: 1 },
  { token: "statement failed", weight: 1 },
  { token: "syntax error", weight: 1 },
  { token: "invalid query", weight: 1 },
  { token: "unterminated quoted string", weight: 2 },
  { token: "unexpected end of sql command", weight: 2 },
  { token: "invalid identifier", weight: 2 },
  { token: "unknown column", weight: 2 },
  { token: "unknown table", weight: 2 },
  { token: "column count doesn't match", weight: 2 },
  { token: "operand should contain", weight: 2 },
  { token: "conversion failed when converting", weight: 2 },
  { token: "data type mismatch", weight: 2 },
];

const HIGH_RISK_ROUTE_PATTERNS: RegExp[] = [
  /(^|\/)(logout|signout)(\/|$)/i,
  /(^|\/)(delete|remove|destroy)(\/|$)/i,
  /(^|\/)(payment|purchase|transfer|checkout|submit)(\/|$)/i,
  /(^|\/)order(\/|$)/i,
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

const STRING_ERROR_PROBES = [
  (originalValue: string) => `${originalValue}'`,
  (originalValue: string) => `${originalValue}"`,
  (originalValue: string) => `${originalValue}'-- -`,
];

const NUMERIC_ERROR_PROBES = [
  (originalValue: string) => `${originalValue}'`,
  (originalValue: string) => `${originalValue} AND 1=1`,
  (originalValue: string) => `${originalValue} AND 1=2`,
  (originalValue: string) => `${originalValue} OR 1=1`,
];

const UTF8_ENCODER = new TextEncoder();
const CRLF_BYTES = new Uint8Array([13, 10]);
const HEADER_SEPARATOR_BYTES = new Uint8Array([13, 10, 13, 10]);
const pluginGlobals = globalThis as PluginGlobals;
type SerializedHeaderEntry = { name: string; value: string };

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

function byteLength(value: string): number {
  return UTF8_ENCODER.encode(value).length;
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

function stringifyJsonPath(segments: JsonPathSegment[]): string {
  let path = "";
  for (const segment of segments) {
    if (typeof segment === "number") {
      path += `[${segment}]`;
    } else {
      path += path ? `.${segment}` : segment;
    }
  }
  return path;
}

function formatMutationTargetPath(target: MutationTarget): string {
  if (target.location === "query") {
    return target.name;
  }

  if (target.bodyKind === "json" && target.pathSegments?.length) {
    return stringifyJsonPath(target.pathSegments);
  }

  if (
    target.bodyKind === "form"
    && typeof target.occurrenceIndex === "number"
    && target.occurrenceIndex > 0
  ) {
    return `${target.name}[${target.occurrenceIndex}]`;
  }

  return target.name;
}

function formatMutationTargetIdentifier(target: MutationTarget): string {
  const path = formatMutationTargetPath(target);
  if (!path) {
    return target.name;
  }

  if (target.location === "query") {
    return path;
  }

  return `${target.location}:${path}`;
}

function buildActiveProbeReplayMetadata(
  target: MutationTarget,
  probeValue: string,
  technique: "error-based" | "blind-boolean" | "time-based",
): ActiveProbeReplayMetadata {
  return {
    target_name: target.name,
    target_path: formatMutationTargetPath(target),
    target_location: target.location,
    probe_value: probeValue,
    technique,
  };
}

function serializeRequestBody(body: unknown): string {
  if (typeof body === "string") {
    return body;
  }
  if (body instanceof ArrayBuffer) {
    return bytesToString(Array.from(new Uint8Array(body)));
  }
  if (body instanceof Uint8Array) {
    return bytesToString(Array.from(body));
  }
  return "";
}

function getRequestContentType(request: RequestContext): string {
  return (
    request.content_type
    || request.headers["content-type"]
    || request.headers["Content-Type"]
    || ""
  ).toLowerCase();
}

function getHeaderValue(headers: Record<string, string>, name: string): string {
  const normalizedName = name.toLowerCase();
  for (const [headerName, value] of Object.entries(headers)) {
    if (headerName.toLowerCase() === normalizedName) {
      return value;
    }
  }
  return "";
}

function hasRequestBody(method: string): boolean {
  return !["GET", "HEAD"].includes(method.toUpperCase());
}

function parsePathname(urlValue: string): string {
  try {
    return new URL(urlValue).pathname.toLowerCase();
  } catch {
    return urlValue.split("?")[0].toLowerCase();
  }
}

function inferValueKind(value: string): MutationValueKind {
  return /^-?\d+(?:\.\d+)?$/.test(value.trim()) ? "numeric" : "string";
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
  const method = request.method.toUpperCase();
  if (!SUPPORTED_REPLAY_METHODS.includes(method)) {
    return false;
  }

  if (HIGH_RISK_ROUTE_PATTERNS.some(pattern => pattern.test(parsePathname(request.url)))) {
    return false;
  }

  if (!hasRequestBody(method)) {
    return true;
  }

  const contentType = getRequestContentType(request);
  return (
    !contentType
    || contentType.includes("application/json")
    || contentType.includes("application/x-www-form-urlencoded")
    || contentType.includes("multipart/form-data")
  );
}

function extractMultipartBoundary(contentType: string): string | null {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  return match?.[1] || match?.[2]?.trim() || null;
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, fromIndex = 0): number {
  if (needle.length === 0) {
    return fromIndex;
  }

  outer: for (let index = fromIndex; index <= haystack.length - needle.length; index += 1) {
    for (let offset = 0; offset < needle.length; offset += 1) {
      if (haystack[index + offset] !== needle[offset]) {
        continue outer;
      }
    }
    return index;
  }

  return -1;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(totalLength);
  let cursor = 0;
  for (const chunk of chunks) {
    merged.set(chunk, cursor);
    cursor += chunk.length;
  }
  return merged;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function parseMultipartBody(bodyBytes: number[], contentType: string): ParsedMultipartBody | null {
  const boundary = extractMultipartBoundary(contentType);
  if (!boundary) {
    return null;
  }

  const bytes = new Uint8Array(bodyBytes);
  const boundaryBytes = UTF8_ENCODER.encode(`--${boundary}`);
  const nextBoundaryBytes = UTF8_ENCODER.encode(`\r\n--${boundary}`);

  if (indexOfBytes(bytes, boundaryBytes, 0) !== 0) {
    return null;
  }

  const parts: MultipartPart[] = [];
  let cursor = 0;

  while (cursor < bytes.length) {
    const boundaryStart = indexOfBytes(bytes, boundaryBytes, cursor);
    if (boundaryStart !== cursor) {
      return null;
    }

    let afterBoundary = boundaryStart + boundaryBytes.length;
    if (afterBoundary + 1 < bytes.length && bytes[afterBoundary] === 45 && bytes[afterBoundary + 1] === 45) {
      return { boundary, parts };
    }

    if (afterBoundary + 1 >= bytes.length || bytes[afterBoundary] !== 13 || bytes[afterBoundary + 1] !== 10) {
      return null;
    }

    const headersStart = afterBoundary + CRLF_BYTES.length;
    const headersEnd = indexOfBytes(bytes, HEADER_SEPARATOR_BYTES, headersStart);
    if (headersEnd === -1) {
      return null;
    }

    const headersBytes = bytes.slice(headersStart, headersEnd);
    const contentStart = headersEnd + HEADER_SEPARATOR_BYTES.length;
    const nextBoundaryMarker = indexOfBytes(bytes, nextBoundaryBytes, contentStart);
    if (nextBoundaryMarker === -1) {
      return null;
    }

    const headersText = bytesToString(Array.from(headersBytes));
    const fieldNameMatch = headersText.match(/content-disposition:[^\r\n]*;\s*name="([^"]+)"/i);
    const fileNameMatch = headersText.match(/filename="([^"]*)"/i);

    parts.push({
      headersBytes,
      contentBytes: bytes.slice(contentStart, nextBoundaryMarker),
      fieldName: fieldNameMatch?.[1] || null,
      fileName: fileNameMatch?.[1] || null,
    });

    cursor = nextBoundaryMarker + CRLF_BYTES.length;
  }

  return null;
}

function buildMultipartBody(parsed: ParsedMultipartBody, targetIndex: number, nextValue: string): Uint8Array {
  const chunks: Uint8Array[] = [];

  parsed.parts.forEach((part, index) => {
    chunks.push(UTF8_ENCODER.encode(`--${parsed.boundary}\r\n`));
    chunks.push(part.headersBytes);
    chunks.push(HEADER_SEPARATOR_BYTES);
    chunks.push(index === targetIndex ? UTF8_ENCODER.encode(nextValue) : part.contentBytes);
    chunks.push(CRLF_BYTES);
  });

  chunks.push(UTF8_ENCODER.encode(`--${parsed.boundary}--`));
  return concatBytes(chunks);
}

function cloneJsonWithMutation(
  node: unknown,
  segments: JsonPathSegment[],
  nextValue: string,
  depth = 0,
): unknown {
  if (depth >= segments.length) {
    return nextValue;
  }

  const segment = segments[depth];
  if (Array.isArray(node)) {
    return node.map((item, index) => (
      index === segment
        ? cloneJsonWithMutation(item, segments, nextValue, depth + 1)
        : item
    ));
  }

  if (node && typeof node === "object") {
    const record = node as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(record).map(([key, value]) => (
        key === segment
          ? [key, cloneJsonWithMutation(value, segments, nextValue, depth + 1)]
          : [key, value]
      )),
    );
  }

  return node;
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
      valueKind: inferValueKind(normalizedValue),
    });
  }

  if (!hasRequestBody(request.method)) {
    return targets;
  }

  const contentType = getRequestContentType(request);
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const bodyText = bytesToString(request.body);
    if (!bodyText) {
      return targets;
    }

    const seen = new Map<string, number>();
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

      const occurrenceIndex = seen.get(decodedKey) || 0;
      seen.set(decodedKey, occurrenceIndex + 1);

      targets.push({
        name: decodedKey,
        location: "body",
        originalValue: decodedValue,
        valueKind: inferValueKind(decodedValue),
        bodyKind: "form",
        occurrenceIndex,
      });
    }

    return targets;
  }

  if (contentType.includes("application/json")) {
    const bodyText = bytesToString(request.body);
    if (!bodyText) {
      return targets;
    }

    try {
      const parsed = JSON.parse(bodyText);
      const walk = (value: unknown, pathSegments: JsonPathSegment[] = []): void => {
        if (value === null || value === undefined) {
          return;
        }

        if (typeof value === "string" || typeof value === "number") {
          const normalizedValue = String(value);
          const name = stringifyJsonPath(pathSegments);
          if (!name || shouldSkipTarget(name, normalizedValue)) {
            return;
          }

          targets.push({
            name,
            location: "body",
            originalValue: normalizedValue,
            valueKind: inferValueKind(normalizedValue),
            bodyKind: "json",
            pathSegments,
          });
          return;
        }

        if (Array.isArray(value)) {
          if (value.length > 0) {
            walk(value[0], [...pathSegments, 0]);
          }
          return;
        }

        if (typeof value === "object") {
          for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
            walk(nested, [...pathSegments, key]);
          }
        }
      };

      walk(parsed);
    } catch {
      return targets;
    }

    return targets;
  }

  if (contentType.includes("multipart/form-data")) {
    const parsed = parseMultipartBody(request.body, contentType);
    if (!parsed) {
      return targets;
    }

    parsed.parts.forEach((part, multipartIndex) => {
      if (!part.fieldName || part.fileName !== null) {
        return;
      }

      const normalizedValue = bytesToString(Array.from(part.contentBytes));
      if (shouldSkipTarget(part.fieldName, normalizedValue)) {
        return;
      }

      targets.push({
        name: part.fieldName,
        location: "body",
        originalValue: normalizedValue,
        valueKind: inferValueKind(normalizedValue),
        bodyKind: "multipart",
        multipartIndex,
      });
    });
  }

  return targets;
}

function scoreTargetPriority(target: MutationTarget): number {
  const path = formatMutationTargetPath(target).toLowerCase();
  let score = target.location === "query" ? 40 : 20;

  if (path.includes("id") || path.includes("name") || path.includes("query") || path.includes("search")) {
    score += 20;
  }
  if (path.includes("filter") || path.includes("sort") || path.includes("property")) {
    score += 15;
  }
  if (target.valueKind === "string") {
    score += 10;
  }
  if (target.bodyKind === "json") {
    score += 5;
  }

  return score;
}

function prioritizeMutationTargets(targets: MutationTarget[]): MutationTarget[] {
  return [...targets]
    .sort((left, right) => scoreTargetPriority(right) - scoreTargetPriority(left))
    .slice(0, MAX_MUTATION_TARGETS_PER_REQUEST);
}

const REPLAY_HEADER_ALLOWLIST = new Set([
  "accept",
  "accept-language",
  "authorization",
  "content-type",
  "cookie",
  "origin",
  "referer",
  "user-agent",
  "x-csrf-token",
  "x-xsrf-token",
  "x-api-key",
  "x-auth-token",
  "x-requested-with",
]);

function shouldForwardReplayHeader(normalizedName: string): boolean {
  if (REPLAY_HEADER_ALLOWLIST.has(normalizedName)) {
    return true;
  }

  if (!normalizedName.startsWith("x-")) {
    return false;
  }

  return [
    "auth",
    "token",
    "api-key",
    "apikey",
    "csrf",
    "xsrf",
    "session",
    "tenant",
    "project",
    "workspace",
    "org",
  ].some(hint => normalizedName.includes(hint));
}

function buildReplayHeaders(request: RequestContext, probeLabel: string): Record<string, string> {
  const headers: Record<string, string> = {};

  for (const [name, value] of Object.entries(request.headers)) {
    const normalizedName = name.toLowerCase();
    if (!shouldForwardReplayHeader(normalizedName)) {
      continue;
    }

    headers[name] = value;
  }

  const contentType = getRequestContentType(request);
  if (contentType && !getHeaderValue(headers, "content-type")) {
    headers["content-type"] = contentType;
  }

  headers["x-sentinel-active-probe"] = probeLabel;
  return headers;
}

function buildReplayRequest(
  request: RequestContext,
  target: MutationTarget,
  probeValue: string,
  probeLabel: string,
  technique: "error-based" | "blind-boolean" | "time-based",
): {
  url: string;
  init: RequestInit;
  probeValue: string;
} | null {
  const headers = buildReplayHeaders(request, probeLabel);
  const method = request.method.toUpperCase();
  const activeProbeMetadata = buildActiveProbeReplayMetadata(target, probeValue, technique);

  if (target.location === "query") {
    try {
      const url = new URL(request.url);
      url.searchParams.set(target.name, probeValue);
      const init: RequestInit = {
        method,
        headers,
        activeProbe: activeProbeMetadata,
      };

      if (hasRequestBody(method) && request.body.length > 0) {
        init.body = toArrayBuffer(new Uint8Array(request.body));
      }

      return {
        url: url.toString(),
        init,
        probeValue,
      };
    } catch {
      return null;
    }
  }

  const contentType = getRequestContentType(request);
  if (target.bodyKind === "form" && contentType.includes("application/x-www-form-urlencoded")) {
    const bodyText = bytesToString(request.body);
    const pairs: string[] = [];
    const seen = new Map<string, number>();
    let updated = false;

    for (const pair of bodyText.split("&")) {
      if (!pair) {
        continue;
      }

      const [rawKey, ...rest] = pair.split("=");
      const decodedKey = decodeMaybe(rawKey);
      const nextOccurrence = seen.get(decodedKey) || 0;
      seen.set(decodedKey, nextOccurrence + 1);

      if (decodedKey === target.name && nextOccurrence === (target.occurrenceIndex || 0)) {
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
          method,
          headers,
          body: pairs.join("&"),
          activeProbe: activeProbeMetadata,
        },
        probeValue,
      };
  }

  if (target.bodyKind === "json" && contentType.includes("application/json")) {
    const bodyText = bytesToString(request.body);
    if (!bodyText || !target.pathSegments) {
      return null;
    }

    try {
      const parsed = JSON.parse(bodyText);
      const mutated = cloneJsonWithMutation(parsed, target.pathSegments, probeValue);
      return {
        url: request.url,
        init: {
          method,
          headers,
          body: JSON.stringify(mutated),
          activeProbe: activeProbeMetadata,
        },
        probeValue,
      };
    } catch {
      return null;
    }
  }

  if (target.bodyKind === "multipart" && contentType.includes("multipart/form-data")) {
    const parsed = parseMultipartBody(request.body, contentType);
    if (!parsed || target.multipartIndex === undefined) {
      return null;
    }

    const multipartBody = buildMultipartBody(parsed, target.multipartIndex, probeValue);

    return {
      url: request.url,
        init: {
          method,
          headers,
          body: toArrayBuffer(multipartBody),
          activeProbe: activeProbeMetadata,
        },
        probeValue,
      };
  }

  return null;
}

function serializeHeaderMap(headers: Record<string, string>): string {
  return JSON.stringify(
    Object.entries(headers).map(([name, value]) => ({
      name,
      value,
    })),
  );
}

function parseRawHeaderEntries(headers: string): SerializedHeaderEntry[] {
  return headers.split(/\r?\n/)
    .map((line) => {
      const separatorIndex = line.indexOf(":");
      if (separatorIndex <= 0) {
        return null;
      }

      return {
        name: line.slice(0, separatorIndex).trim(),
        value: line.slice(separatorIndex + 1).trim(),
      };
    })
    .filter((entry): entry is SerializedHeaderEntry => Boolean(entry?.name));
}

function parseSerializedHeaderEntries(headers: string): SerializedHeaderEntry[] {
  const trimmedHeaders = headers.trim();
  if (!trimmedHeaders) {
    return [];
  }

  try {
    const parsed = JSON.parse(trimmedHeaders) as Array<{ name?: unknown; value?: unknown }>;
    if (Array.isArray(parsed)) {
      return parsed
        .map(({ name, value }) => ({
          name: String(name || "").trim(),
          value: String(value || ""),
        }))
        .filter(({ name }) => Boolean(name));
    }
  } catch {
    return parseRawHeaderEntries(trimmedHeaders);
  }

  return parseRawHeaderEntries(trimmedHeaders);
}

function hasSerializedHeader(entries: SerializedHeaderEntry[], name: string): boolean {
  const normalizedName = name.toLowerCase();
  return entries.some(entry => entry.name.toLowerCase() === normalizedName);
}

function serializeHeaderEntries(entries: SerializedHeaderEntry[]): string {
  return JSON.stringify(entries.map(({ name, value }) => ({ name, value })));
}

function inferEvidenceContentType(target: MutationTarget): string {
  if (target.bodyKind === "json") {
    return "application/json";
  }
  if (target.bodyKind === "form") {
    return "application/x-www-form-urlencoded";
  }
  return "";
}

function buildEvidenceRequestHeaders(replayArtifact: ReplayArtifact, target: MutationTarget): string {
  const entries = parseSerializedHeaderEntries(replayArtifact.request.headers);
  const requestBody = replayArtifact.request.body;

  if (requestBody && !hasSerializedHeader(entries, "content-type")) {
    const inferredContentType = inferEvidenceContentType(target);
    if (inferredContentType) {
      entries.push({ name: "Content-Type", value: inferredContentType });
    }
  }

  if (requestBody && !hasSerializedHeader(entries, "content-length")) {
    entries.push({ name: "Content-Length", value: String(byteLength(requestBody)) });
  }

  if (!hasSerializedHeader(entries, "x-sentinel-active-probe")) {
    entries.push({ name: "X-Sentinel-Active-Probe", value: "sql_injection_detector" });
  }

  return serializeHeaderEntries(entries);
}

function serializeResponseHeaders(headers: Headers): string {
  return JSON.stringify(
    Array.from(headers.entries()).map(([name, value]) => ({
      name,
      value,
    })),
  );
}

function headersToSearchText(headers: string): string {
  try {
    const parsed = JSON.parse(headers) as Array<{ name: string; value: string }>;
    return parsed.map(({ name, value }) => `${name}: ${value}`).join("\n");
  } catch {
    return headers;
  }
}

function getSerializedHeaderValue(headers: string, name: string): string {
  const normalizedName = name.toLowerCase();
  try {
    const parsed = JSON.parse(headers) as Array<{ name: string; value: string }>;
    for (const header of parsed) {
      if (header.name.toLowerCase() === normalizedName) {
        return header.value;
      }
    }
  } catch {
    const lines = headers.split(/\r?\n/);
    for (const line of lines) {
      const separatorIndex = line.indexOf(":");
      if (separatorIndex <= 0) {
        continue;
      }
      if (line.slice(0, separatorIndex).trim().toLowerCase() === normalizedName) {
        return line.slice(separatorIndex + 1).trim();
      }
    }
  }
  return "";
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

function findSqlErrorInHeaders(headers: string): string | null {
  try {
    const parsed = JSON.parse(headers) as Array<{ name: string; value: string }>;
    for (const { name, value } of parsed) {
      const combined = `${name}: ${value}`;
      const match = findSqlError(combined);
      if (match) {
        return match;
      }
    }
  } catch {
    return findSqlError(headers);
  }
  return null;
}

function scoreSqlSignals(text: string): number {
  const normalized = text.toLowerCase();
  return SQL_ERROR_TOKENS.reduce((score, { token, weight }) => (
    normalized.includes(token) ? score + weight : score
  ), 0);
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
  const combined = `${replay.body}\n${headersToSearchText(replay.headers)}`;
  return WAF_HINT_PATTERNS.some(pattern => pattern.test(combined));
}

function isLikelyValidationErrorBody(body: string): boolean {
  return VALIDATION_HINT_PATTERNS.some(pattern => pattern.test(body));
}

function isTextualResponseClass(responseClass: ResponseContentClass): boolean {
  return responseClass === "json" || responseClass === "html" || responseClass === "text";
}

function isTextualContentType(contentType: string): boolean {
  const normalizedType = contentType.toLowerCase().split(";")[0].trim();
  if (!normalizedType) {
    return false;
  }
  return normalizedType.startsWith("text/")
    || normalizedType === "application/json"
    || normalizedType.endsWith("+json")
    || normalizedType === "application/xml"
    || normalizedType.endsWith("+xml")
    || normalizedType === "application/javascript"
    || normalizedType === "application/x-javascript"
    || normalizedType === "application/graphql";
}

function isBinaryContentType(contentType: string): boolean {
  const normalizedType = contentType.toLowerCase().split(";")[0].trim();
  if (!normalizedType) {
    return false;
  }
  return normalizedType.startsWith("image/")
    || normalizedType.startsWith("audio/")
    || normalizedType.startsWith("video/")
    || normalizedType.startsWith("font/")
    || normalizedType === "application/octet-stream"
    || normalizedType === "application/pdf"
    || normalizedType === "application/zip"
    || normalizedType === "application/x-zip-compressed"
    || normalizedType === "application/gzip"
    || normalizedType === "application/x-gzip"
    || normalizedType === "application/x-tar"
    || normalizedType === "application/x-7z-compressed"
    || normalizedType === "application/x-rar-compressed";
}

function classifyResponseContent(body: string, contentType: string, headers = ""): ResponseContentClass {
  const normalizedType = contentType.toLowerCase();
  const contentDisposition = getSerializedHeaderValue(headers, "content-disposition").toLowerCase();
  if (contentDisposition.includes("attachment")) {
    return "binary";
  }
  if (normalizedType.includes("application/json") || normalizedType.includes("+json")) {
    return "json";
  }
  if (normalizedType.includes("text/html")) {
    return "html";
  }
  if (isTextualContentType(normalizedType)) {
    return "text";
  }
  if (isBinaryContentType(normalizedType) || !normalizedType.trim()) {
    return "binary";
  }

  const sample = body.slice(0, 512);
  const suspiciousBinaryChars = sample.match(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffd]/g)?.length || 0;
  if (sample.length > 0 && suspiciousBinaryChars / sample.length > 0.08) {
    return "binary";
  }

  return "binary";
}

function buildNormalizedResponse(
  replay: ReplayOutcome,
  reflectedValues: string[],
): NormalizedResponse {
  const headerText = headersToSearchText(replay.headers);
  const contentType = replay.contentType || getSerializedHeaderValue(replay.headers, "content-type");
  const responseClass = classifyResponseContent(replay.body, contentType, replay.headers);
  const isTextualResponse = isTextualResponseClass(responseClass);
  const normalizedBody = isTextualResponse ? normalizeResponseBody(replay.body, reflectedValues) : "";
  const searchableText = !isTextualResponse
    ? headerText
    : `${replay.body}\n${headerText}`;
  return {
    status: replay.status,
    contentType,
    responseClass,
    title: isTextualResponse ? parseTitle(replay.body) : "",
    normalizedBody,
    normalizedLength: normalizedBody.length,
    sqlError: !isTextualResponse ? findSqlErrorInHeaders(replay.headers) : (findSqlError(replay.body) || findSqlErrorInHeaders(replay.headers)),
    sqlSignalScore: scoreSqlSignals(searchableText),
    wafHint: isLikelyWafBlock(replay),
    validationHint: isTextualResponse && isLikelyValidationErrorBody(replay.body),
  };
}

function getLengthShiftThreshold(reference: NormalizedResponse): number {
  return Math.max(
    RESPONSE_LENGTH_SHIFT_MIN,
    Math.ceil(reference.normalizedLength * RESPONSE_LENGTH_SHIFT_RATIO),
  );
}

async function executeReplay(url: string, init: RequestInit, targetName?: string): Promise<ReplayOutcome | null> {
  const startedAt = Date.now();
  try {
    const response = await fetch(url, init);
    const contentType = response.headers.get("content-type") || "";
    const headers = serializeResponseHeaders(response.headers);
    const responseClass = classifyResponseContent("", contentType, headers);
    const body = isTextualResponseClass(responseClass) ? await response.text() : "";
    return {
      status: response.status,
      body,
      contentType,
      headers,
      elapsedMs: Date.now() - startedAt,
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

function compareResponses(
  reference: NormalizedResponse,
  replay: NormalizedResponse,
): ReplayComparison {
  const normalizedLengthDelta = Math.abs(replay.normalizedLength - reference.normalizedLength);
  const sqlSignalDelta = replay.sqlSignalScore - reference.sqlSignalScore;
  return {
    statusChanged: reference.status > 0 && reference.status !== replay.status,
    normalizedLengthDelta,
    significantLengthShift: normalizedLengthDelta >= getLengthShiftThreshold(reference),
    sqlSignalDelta,
    significantSqlSignalShift: replay.sqlSignalScore >= SQL_SIGNAL_SCORE_MIN && sqlSignalDelta >= SQL_SIGNAL_DELTA_MIN,
    titleChanged: reference.title !== replay.title,
  };
}

function matchesReference(reference: NormalizedResponse, replay: NormalizedResponse): boolean {
  const delta = compareResponses(reference, replay);
  return !delta.statusChanged
    && !delta.significantLengthShift
    && !delta.significantSqlSignalShift
    && !delta.titleChanged;
}

function classifyReplay(
  reference: NormalizedResponse,
  replay: NormalizedResponse,
): ReplayVerdict {
  if (!isTextualResponseClass(reference.responseClass) || !isTextualResponseClass(replay.responseClass)) {
    return { kind: "discard" };
  }

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

  const delta = compareResponses(reference, replay);
  if (!delta.statusChanged && !delta.significantLengthShift && !delta.significantSqlSignalShift && !delta.titleChanged) {
    return { kind: "discard" };
  }

  if (delta.significantSqlSignalShift || (delta.statusChanged && delta.significantLengthShift) || (delta.statusChanged && delta.titleChanged)) {
    return {
      kind: "possible",
      severity: "medium",
      confidence: "medium",
      evidence: [
        delta.statusChanged ? `status=${reference.status}->${replay.status}` : "",
        delta.significantLengthShift ? `normalized_length_delta=${delta.normalizedLengthDelta}` : "",
        delta.significantSqlSignalShift ? `sql_signal_delta=${delta.sqlSignalDelta}` : "",
        delta.titleChanged ? `title=${truncate(reference.title, 80)}->${truncate(replay.title, 80)}` : "",
      ].filter(Boolean).join(" | "),
      description: "Replay response deviated from the original response after a SQL syntax probe.",
    };
  }

  return { kind: "discard" };
}

function buildErrorProbeValues(target: MutationTarget): string[] {
  const factories = target.valueKind === "numeric" ? NUMERIC_ERROR_PROBES : STRING_ERROR_PROBES;
  return Array.from(new Set(factories.map(factory => factory(target.originalValue))));
}

function buildBooleanProbePair(target: MutationTarget): BooleanProbePair {
  if (target.valueKind === "numeric") {
    return {
      trueProbe: `${target.originalValue} AND 1=1`,
      falseProbe: `${target.originalValue} AND 1=2`,
    };
  }

  return {
    trueProbe: `${target.originalValue}' AND '1'='1`,
    falseProbe: `${target.originalValue}' AND '1'='2`,
  };
}

function buildTimeProbeValues(target: MutationTarget): string[] {
  if (target.valueKind === "numeric") {
    return [
      `${target.originalValue} AND SLEEP(${TIME_PROBE_DELAY_MS / 1000})`,
      `${target.originalValue} AND pg_sleep(${TIME_PROBE_DELAY_MS / 1000})`,
      `${target.originalValue}; WAITFOR DELAY '0:0:${TIME_PROBE_DELAY_MS / 1000}'--`,
    ];
  }

  return [
    `${target.originalValue}' AND SLEEP(${TIME_PROBE_DELAY_MS / 1000})-- `,
    `${target.originalValue}' AND pg_sleep(${TIME_PROBE_DELAY_MS / 1000})-- `,
    `${target.originalValue}'; WAITFOR DELAY '0:0:${TIME_PROBE_DELAY_MS / 1000}'--`,
  ];
}

function createReplayBudget(): ReplayBudget {
  return {
    totalRemaining: MAX_REPLAYS_PER_REQUEST,
    remainingByTechnique: {
      "error-based": MAX_ERROR_REPLAYS_PER_REQUEST,
      "blind-boolean": MAX_BOOLEAN_REPLAYS_PER_REQUEST,
      "time-based": MAX_TIME_REPLAYS_PER_REQUEST,
    },
  };
}

function consumeReplayBudget(
  budget: ReplayBudget,
  technique: "error-based" | "blind-boolean" | "time-based",
): boolean {
  if (budget.totalRemaining <= 0) {
    return false;
  }
  if (budget.remainingByTechnique[technique] <= 0) {
    return false;
  }

  budget.totalRemaining -= 1;
  budget.remainingByTechnique[technique] -= 1;
  return true;
}

async function replayProbe(
  request: RequestContext,
  target: MutationTarget,
  probeValue: string,
  probeLabel: string,
  technique: "error-based" | "blind-boolean" | "time-based",
  budget: ReplayBudget,
): Promise<ReplayArtifact | null> {
  if (!consumeReplayBudget(budget, technique)) {
    return null;
  }

  const replayRequest = buildReplayRequest(request, target, probeValue, probeLabel, technique);
  if (!replayRequest) {
    return null;
  }

  const replayResponse = await executeReplay(replayRequest.url, replayRequest.init, target.name);
  if (!replayResponse) {
    return null;
  }

  return {
    request: {
      method: request.method.toUpperCase(),
      url: replayRequest.url,
      headers: serializeHeaderMap(replayRequest.init.headers as Record<string, string>),
      body: serializeRequestBody(replayRequest.init.body),
    },
    response: replayResponse,
  };
}

async function replayProbeBatch(
  request: RequestContext,
  target: MutationTarget,
  probeValues: string[],
  probeLabel: string,
  technique: "error-based" | "blind-boolean" | "time-based",
  budget: ReplayBudget,
): Promise<ReplayProbeCandidate[]> {
  const replayArtifacts = await Promise.all(
    probeValues.map(probeValue => replayProbe(
      request,
      target,
      probeValue,
      probeLabel,
      technique,
      budget,
    )),
  );

  const candidates: ReplayProbeCandidate[] = [];
  probeValues.forEach((probeValue, index) => {
    const replayArtifact = replayArtifacts[index];
    if (!replayArtifact) {
      return;
    }

    candidates.push({
      probeValue,
      replayArtifact,
      normalizedReplay: buildNormalizedResponse(
        replayArtifact.response,
        [target.originalValue, probeValue],
      ),
    });
  });

  return candidates;
}

function formatComparisonEvidence(reference: NormalizedResponse, replay: NormalizedResponse): string {
  const delta = compareResponses(reference, replay);
  return [
    delta.statusChanged ? `status=${reference.status}->${replay.status}` : "",
    delta.significantLengthShift ? `normalized_length_delta=${delta.normalizedLengthDelta}` : "",
    delta.significantSqlSignalShift ? `sql_signal_delta=${delta.sqlSignalDelta}` : "",
    delta.titleChanged ? `title_changed=true` : "",
  ].filter(Boolean).join(" | ");
}

function buildFinding(
  target: MutationTarget,
  technique: "error-based" | "blind-boolean" | "time-based",
  title: string,
  description: string,
  severity: "high" | "medium",
  confidence: "high" | "medium",
  evidence: string,
  probeValue: string,
  replayArtifact: ReplayArtifact,
  normalizedReplay: NormalizedResponse,
  reference: NormalizedResponse,
): any {
  const requestHeaders = buildEvidenceRequestHeaders(replayArtifact, target);
  const evidenceSnippet = [
    `location=${target.location}`,
    `target_path=${formatMutationTargetPath(target)}`,
    `target_original=${truncate(target.originalValue, 120)}`,
    `technique=${technique}`,
    `reference_status=${reference.status}`,
    `probe_status=${normalizedReplay.status}`,
    `probe_response_class=${normalizedReplay.responseClass}`,
    `probe_sql_signal_score=${normalizedReplay.sqlSignalScore}`,
    `probe_elapsed_ms=${replayArtifact.response.elapsedMs}`,
    `probe=${truncate(probeValue, 180)}`,
    `probe_value=${truncate(probeValue, 180)}`,
    normalizedReplay.sqlError ? `sql_error=${truncate(normalizedReplay.sqlError, 180)}` : "",
    evidence,
  ].filter(Boolean).join(" | ");

  return {
    title,
    description: `${description} Target "${formatMutationTargetIdentifier(target)}" was replayed with probe "${truncate(probeValue, 120)}".`,
    severity,
    vuln_type: "sqli",
    confidence,
    url: replayArtifact.request.url,
    method: replayArtifact.request.method,
    param_name: formatMutationTargetIdentifier(target),
    param_value: truncate(probeValue, 120),
    evidence: truncate(evidenceSnippet, 1200),
    cwe: "CWE-89",
    owasp: "A03:2021",
    remediation: "Use parameterized queries or prepared statements and avoid returning database error details to clients.",
    request: {
      method: replayArtifact.request.method,
      url: replayArtifact.request.url,
      headers: requestHeaders,
      body: replayArtifact.request.body,
    },
    response: {
      status: replayArtifact.response.status,
      headers: replayArtifact.response.headers,
      body: replayArtifact.response.body,
    },
  };
}

function reportFinding(findings: any[], finding: any): void {
  if (Sentinel.emitFinding?.(finding)) {
    return;
  }

  findings.push(finding);
}

async function detectErrorBasedFinding(
  request: RequestContext,
  target: MutationTarget,
  reference: NormalizedResponse,
  budget: ReplayBudget,
): Promise<any | null> {
  const probeCandidates = await replayProbeBatch(
    request,
    target,
    buildErrorProbeValues(target),
    "sql_injection_detector:error",
    "error-based",
    budget,
  );

  for (const candidate of probeCandidates) {
    const { probeValue } = candidate;
    let { replayArtifact, normalizedReplay } = candidate;
    let verdict = classifyReplay(reference, normalizedReplay);
    if (verdict.kind === "discard") {
      continue;
    }

    if (verdict.kind === "possible") {
      const confirmReplayArtifact = await replayProbe(request, target, probeValue, "sql_injection_detector:error:confirm", "error-based", budget);
      if (!confirmReplayArtifact) {
        continue;
      }

      const confirmedReplay = buildNormalizedResponse(confirmReplayArtifact.response, [target.originalValue, probeValue]);
      const confirmVerdict = classifyReplay(reference, confirmedReplay);
      if (confirmVerdict.kind === "discard") {
        continue;
      }

      replayArtifact = confirmReplayArtifact;
      normalizedReplay = confirmedReplay;
      verdict = confirmVerdict;
    }

    return buildFinding(
      target,
      "error-based",
      verdict.kind === "confirmed" ? "Confirmed SQL Error Disclosure" : "Possible SQL Injection Behavior",
      `${verdict.description} Parameter "${target.name}" was replayed with an error-oriented SQL probe.`,
      verdict.severity || "medium",
      verdict.confidence || "medium",
      verdict.evidence || formatComparisonEvidence(reference, normalizedReplay),
      probeValue,
      replayArtifact,
      normalizedReplay,
      reference,
    );
  }

  return null;
}

async function runBooleanProbePair(
  request: RequestContext,
  target: MutationTarget,
  reference: NormalizedResponse,
  pair: BooleanProbePair,
  budget: ReplayBudget,
): Promise<BooleanBlindResult | null> {
  const [trueArtifact, falseArtifact] = await Promise.all([
    replayProbe(request, target, pair.trueProbe, "sql_injection_detector:boolean:true", "blind-boolean", budget),
    replayProbe(request, target, pair.falseProbe, "sql_injection_detector:boolean:false", "blind-boolean", budget),
  ]);

  if (!trueArtifact || !falseArtifact) {
    return null;
  }

  const trueResponse = buildNormalizedResponse(trueArtifact.response, [target.originalValue, pair.trueProbe]);
  const falseResponse = buildNormalizedResponse(falseArtifact.response, [target.originalValue, pair.falseProbe]);

  if (
    !isTextualResponseClass(reference.responseClass)
    || !isTextualResponseClass(trueResponse.responseClass)
    || !isTextualResponseClass(falseResponse.responseClass)
    || trueResponse.wafHint
    || falseResponse.wafHint
    || trueResponse.validationHint
    || falseResponse.validationHint
    || trueResponse.sqlError
    || falseResponse.sqlError
  ) {
    return null;
  }

  const trueMatchesReference = matchesReference(reference, trueResponse);
  const falseDelta = compareResponses(reference, falseResponse);
  const falseDeviates = (
    falseDelta.statusChanged
    || falseDelta.significantLengthShift
    || falseDelta.significantSqlSignalShift
    || falseDelta.titleChanged
  );
  const pairSeparated = (
    trueArtifact.response.status !== falseArtifact.response.status
    || trueResponse.title !== falseResponse.title
    || Math.abs(trueResponse.normalizedLength - falseResponse.normalizedLength)
      >= Math.max(BOOLEAN_PAIR_LENGTH_DELTA_MIN, Math.floor(getLengthShiftThreshold(reference) / 2))
    || trueResponse.normalizedBody !== falseResponse.normalizedBody
  );

  if (!trueMatchesReference || !falseDeviates || !pairSeparated) {
    return null;
  }

  return {
    trueArtifact,
    falseArtifact,
    trueResponse,
    falseResponse,
  };
}

async function detectBooleanBlindFinding(
  request: RequestContext,
  target: MutationTarget,
  reference: NormalizedResponse,
  budget: ReplayBudget,
): Promise<any | null> {
  const pair = buildBooleanProbePair(target);
  const initialResult = await runBooleanProbePair(request, target, reference, pair, budget);
  if (!initialResult) {
    return null;
  }

  const confirmResult = await runBooleanProbePair(request, target, reference, pair, budget);
  if (!confirmResult) {
    return null;
  }

  const falseEvidence = formatComparisonEvidence(reference, confirmResult.falseResponse);
  return buildFinding(
    target,
    "blind-boolean",
    "Possible Boolean Blind SQL Injection",
    `The true-condition probe matched the original response while the false-condition probe changed it for parameter "${target.name}".`,
    "medium",
    "medium",
    [
      `true_probe_status=${confirmResult.trueArtifact.response.status}`,
      `false_probe_status=${confirmResult.falseArtifact.response.status}`,
      `false_probe_delta=${falseEvidence}`,
    ].filter(Boolean).join(" | "),
    pair.falseProbe,
    confirmResult.falseArtifact,
    confirmResult.falseResponse,
    reference,
  );
}

function isTimeBlindDelay(elapsedMs: number): boolean {
  return elapsedMs >= TIME_BLIND_THRESHOLD_MS;
}

async function detectTimeBlindFinding(
  request: RequestContext,
  target: MutationTarget,
  reference: NormalizedResponse,
  budget: ReplayBudget,
): Promise<any | null> {
  const probeCandidates = await replayProbeBatch(
    request,
    target,
    buildTimeProbeValues(target),
    "sql_injection_detector:time",
    "time-based",
    budget,
  );

  for (const candidate of probeCandidates) {
    const { probeValue, replayArtifact, normalizedReplay } = candidate;
    if (
      !isTextualResponseClass(reference.responseClass)
      || !isTextualResponseClass(normalizedReplay.responseClass)
      || normalizedReplay.wafHint
      || normalizedReplay.validationHint
      || normalizedReplay.sqlError
      || !matchesReference(reference, normalizedReplay)
      || !isTimeBlindDelay(replayArtifact.response.elapsedMs)
    ) {
      continue;
    }

    const confirmArtifact = await replayProbe(request, target, probeValue, "sql_injection_detector:time:confirm", "time-based", budget);
    if (!confirmArtifact) {
      continue;
    }

    const confirmReplay = buildNormalizedResponse(confirmArtifact.response, [target.originalValue, probeValue]);
    if (
      !isTextualResponseClass(confirmReplay.responseClass)
      || confirmReplay.wafHint
      || confirmReplay.validationHint
      || confirmReplay.sqlError
      || !matchesReference(reference, confirmReplay)
      || !isTimeBlindDelay(confirmArtifact.response.elapsedMs)
    ) {
      continue;
    }

    return buildFinding(
      target,
      "time-based",
      "Possible Time Blind SQL Injection",
      `The time-based SQL probe produced a repeatable response delay without changing the response shape for parameter "${target.name}".`,
      "medium",
      confirmArtifact.response.elapsedMs >= TIME_PROBE_DELAY_MS ? "high" : "medium",
      `probe_elapsed_ms=${confirmArtifact.response.elapsedMs} | delay_threshold_ms=${TIME_BLIND_THRESHOLD_MS}`,
      probeValue,
      confirmArtifact,
      confirmReplay,
      reference,
    );
  }

  return null;
}

export async function scan_transaction(transaction: HttpTransaction): Promise<any[]> {
  const findings: any[] = [];
  const { request, response } = transaction;

  if (!ENABLE_ERROR_BASED_TESTS && !ENABLE_BOOLEAN_BLIND_TESTS && !ENABLE_TIME_BLIND_TESTS) {
    return findings;
  }

  if (!response) {
    return findings;
  }

  if (!isSafeReplayCandidate(request)) {
    return findings;
  }

  const referenceResponse = buildNormalizedResponse({
    status: response.status,
    body: bytesToString(response.body),
    contentType: response.content_type || getHeaderValue(response.headers, "content-type"),
    headers: serializeHeaderMap(response.headers),
    elapsedMs: 0,
  }, []);

  if (!isTextualResponseClass(referenceResponse.responseClass)) {
    Sentinel.log("debug", `SQL injection detector skipped non-text response for ${request.url}`);
    return findings;
  }

  const targets = prioritizeMutationTargets(extractMutationTargets(request));
  if (targets.length === 0) {
    return findings;
  }

  Sentinel.log("info", `SQL injection detector actively replaying ${targets.length} parameter(s) for ${request.url}`);
  const replayBudget = createReplayBudget();

  for (const target of targets) {
    if (ENABLE_ERROR_BASED_TESTS) {
      const errorFinding = await detectErrorBasedFinding(request, target, referenceResponse, replayBudget);
      if (errorFinding) {
        reportFinding(findings, errorFinding);
        continue;
      }
    }

    if (ENABLE_BOOLEAN_BLIND_TESTS) {
      const booleanBlindFinding = await detectBooleanBlindFinding(request, target, referenceResponse, replayBudget);
      if (booleanBlindFinding) {
        reportFinding(findings, booleanBlindFinding);
        continue;
      }
    }

    if (ENABLE_TIME_BLIND_TESTS) {
      const timeBlindFinding = await detectTimeBlindFinding(request, target, referenceResponse, replayBudget);
      if (timeBlindFinding) {
        reportFinding(findings, timeBlindFinding);
      }
    }

    if (replayBudget.totalRemaining <= 0) {
      break;
    }
  }

  return findings;
}

pluginGlobals.scan_transaction = scan_transaction;
