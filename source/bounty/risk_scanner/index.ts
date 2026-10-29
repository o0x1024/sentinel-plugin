/**
 * Risk Scanner Tool
 *
 * @plugin risk_scanner
 * @name Risk Scanner
 * @version 2.2.13
 * @author Sentinel Team
 * @main_category bounty
 * @monitor_type risk
 * @input_mode asset
 * @target_asset_types ["web"]
 * @category risk
 * @seed_bindings []
 * @default_severity medium
 * @tags risk, poc, verification, dictionary, web, capability:fetch, capability:dictionary, capability:monitor-events, monitor:results-stream-v1
 * @description Execute all applicable Risk Scanner Rules with bounded concurrency, lazy task scheduling, chained requests and durable evidence.
 */
import { createMonitorResultStream } from '../../shared/monitor_results.ts';
import { confirmedMonitorFinding } from '../../shared/monitor_finding.ts';
import { createMonitorTargetWriter } from '../../shared/monitor_target_writer.ts';
import { runTaskPool } from './task_pool.ts';


declare const Sentinel: {
  Dictionary?: {
    get?(idOrName: string): Promise<any>;
    getDefaultId?(dictType: string): Promise<string | null>;
    getEntries?(idOrName: string, limit?: number | null): Promise<any[]>;
  };
};

interface MonitorExecutionContext {
  task_id: string;
  task_name: string;
  program_id: string;
  execution_mode: string;
  started_at: string;
  current_plugin: string;
  current_plugin_index: number;
  completed_steps: number;
  total_steps: number;
  imported_assets?: number;
}

async function reportMonitorProgress(
  monitorExecution: MonitorExecutionContext | undefined,
  update: Record<string, unknown>,
): Promise<boolean> {
  if (!monitorExecution) return false;
  try {
    return Boolean(
      await Sentinel.Monitor?.reportProgress?.({
        monitorProgress: {
          taskId: monitorExecution.task_id,
          taskName: monitorExecution.task_name,
          programId: monitorExecution.program_id,
          executionMode: monitorExecution.execution_mode,
          startedAt: monitorExecution.started_at,
          currentPlugin: monitorExecution.current_plugin,
          currentPluginIndex: monitorExecution.current_plugin_index,
          completedSteps: monitorExecution.completed_steps,
          totalSteps: monitorExecution.total_steps,
          importedAssets: monitorExecution.imported_assets,
        },
        ...update,
      }),
    );
  } catch {
    return false;
  }
}

interface ToolInput {
  url?: string;
  base_url?: string;
  targets?: string[];
  technologies?: Array<string | { name?: string }>;
  fingerprints?: string[];
  dictionaryId?: string;
  dictionaryEntries?: RuleEntry[];
  safe_mode?: boolean;
  concurrency?: number;
  userAgent?: string;
  stopOnFirstHit?: boolean;
  variables?: Record<string, any>;
  __monitorExecution?: MonitorExecutionContext;
}

interface RuleEntry {
  word: string;
  category?: string | null;
  metadata?: any;
}

interface Finding {
  title: string;
  severity: string;
  url: string;
  description: string;
  impact?: string;
  remediation?: string;
  cwe?: string;
}

interface ExecutionStep {
  id: string;
  method: string;
  url: string;
  status?: number;
  matched: boolean;
  extracted: Record<string, any>;
}

interface ToolOutput {
  success: boolean;
  data?: {
    findings: Finding[];
    evidence: any[];
    summary: {
      totalTargets: number;
      executedRules: number;
      matchedRules: number;
      diagnostics: {
        loaded_rules: number;
        applicable_rules: number;
        planned_rule_tasks: number;
        completed_rule_tasks: number;
      };
    };
    surface_artifacts?: Record<string, any[]>;
  };
  error?: string;
}

type PluginGlobals = typeof globalThis & {
  get_input_schema?: typeof get_input_schema;
  get_output_schema?: typeof get_output_schema;
  analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST"]);

const DEFAULT_CONCURRENCY = 32;
const MAX_CONCURRENCY = 1000;

export function get_input_schema() {
  return {
    type: "object",
    required: [],
    properties: {
      url: {
        type: "string",
        description:
          "Single target URL to verify with dictionary-driven risk rules",
      },
      base_url: {
        type: "string",
        description: "Base URL alias for a single target",
      },
      targets: {
        type: "array",
        items: { type: "string" },
        description: "List of target URLs or hostnames to verify",
      },
      technologies: {
        type: "array",
        description: "Observed technologies used to scope matching rules",
        items: {
          anyOf: [
            { type: "string" },
            {
              type: "object",
              properties: {
                name: {
                  type: "string",
                  description: "Technology name",
                },
              },
            },
          ],
        },
      },
      fingerprints: {
        type: "array",
        items: { type: "string" },
        description: "Observed fingerprint names used for rule filtering",
      },
      dictionaryId: {
        type: "string",
        "x-control": "dictionary-picker",
        "x-dictionary-type": "poc_rule",
        description:
          "Structured dictionary ID or name used to load verification rules",
      },
      dictionaryEntries: {
        type: "array",
        description: "Inline rule entries that override dictionary loading",
        items: {
          type: "object",
          required: ["word"],
          properties: {
            word: {
              type: "string",
              description: "Rule identifier",
            },
            category: {
              type: "string",
              description: "Rule category used for normalized finding type",
            },
            metadata: {
              description:
                "Rule metadata object or JSON string with requests, matchers and finding fields",
            },
          },
        },
      },
      variables: {
        type: "object",
        description: "Variables injected into rule templates and request paths",
      },
      safe_mode: {
        type: "boolean",
        description: "Skip rules explicitly marked as unsafe",
        default: true,
      },
      concurrency: {
        type: "integer",
        description: "Maximum concurrent target/rule verifications per execution. Requests also share the host global direct-fetch concurrency limit.",
        default: DEFAULT_CONCURRENCY,
        minimum: 1,
        maximum: MAX_CONCURRENCY,
      },
      userAgent: {
        type: "string",
        description: "User-Agent header used for outbound requests",
        default: "Sentinel-Risk-Scanner/2.0",
      },
      stopOnFirstHit: {
        type: "boolean",
        description:
          "Stop executing more rules after the first positive finding",
        default: false,
      },
    },
  };
}

export function get_output_schema() {
  return {
    type: "object",
    properties: {
      success: {
        type: "boolean",
        description: "Whether the risk verification run completed successfully",
      },
      data: {
        type: "object",
        properties: {
          findings: {
            type: "array",
            description: "Matched risk findings produced by the executed rules",
            items: {
              type: "object",
              properties: {
                title: { type: "string" },
                severity: { type: "string" },
                url: { type: "string" },
                description: { type: "string" },
                impact: { type: "string" },
                remediation: { type: "string" },
                cwe: { type: "string" },
              },
            },
          },
          evidence: {
            type: "array",
            description:
              "Structured execution evidence captured during rule evaluation",
          },
          summary: {
            type: "object",
            description: "High-level execution summary",
            properties: {
              totalTargets: { type: "integer" },
              executedRules: { type: "integer" },
              matchedRules: { type: "integer" },
              diagnostics: {
                type: "object",
                description: "Loaded and applicable rule counts, planned and completed target/rule tasks",
                properties: {
                  loaded_rules: { type: "integer" },
                  applicable_rules: { type: "integer" },
                  planned_rule_tasks: { type: "integer" },
                  completed_rule_tasks: { type: "integer" },
                },
              },
            },
          },
          surface_artifacts: {
            type: "object",
            description:
              "Normalized findings and evidences prepared for upper-layer ingestion",
            properties: {
              findings: {
                type: "array",
                description: "Normalized vulnerability findings",
              },
              evidences: {
                type: "array",
                description: "Normalized evidence records",
              },
            },
          },
        },
      },
      error: {
        type: "string",
        description: "Error message if the risk verification run fails",
      },
    },
  };
}

pluginGlobals.get_input_schema = get_input_schema;
pluginGlobals.get_output_schema = get_output_schema;

const RULE_FETCH_TIMEOUT_MS = 10000;
const PROGRESS_INTERVAL_MS = 250;

function normalizeTarget(raw?: string): string | null {
  if (!raw || typeof raw !== "string") return null;
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!trimmed) return null;
  return trimmed.startsWith("http://") || trimmed.startsWith("https://")
    ? trimmed
    : `https://${trimmed}`;
}

function getInputBoolean(
  input: ToolInput,
  camelKey: keyof ToolInput,
  snakeKey: string,
  fallback: boolean,
): boolean {
  const snakeValue = (input as any)?.[snakeKey];
  const camelValue = input?.[camelKey];
  return typeof snakeValue === "boolean"
    ? snakeValue
    : typeof camelValue === "boolean"
      ? camelValue
      : fallback;
}

function getInputString(
  input: ToolInput,
  camelKey: keyof ToolInput,
  snakeKey: string,
  fallback = "",
): string {
  const snakeValue = (input as any)?.[snakeKey];
  const camelValue = input?.[camelKey];
  const value = snakeValue ?? camelValue;
  return typeof value === "string" && value.trim().length > 0
    ? value
    : fallback;
}

function parseMetadata(value: any): Record<string, any> {
  if (!value) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return {};
    }
  }
  return typeof value === "object" ? value : {};
}

function asArray<T>(value: T[] | T | undefined | null): T[] {
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

function parseTitle(html: string): string {
  const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match?.[1]?.trim() || "";
}

function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl}/${String(path || "").replace(/^\/+/, "")}`;
}

function deepGet(source: any, path: string): any {
  if (!path) return source;
  return path.split(".").reduce((acc, key) => {
    if (acc == null) return undefined;
    if (key.endsWith("]")) {
      const match = key.match(/^([^[\]]+)\[(\d+)\]$/);
      if (!match) return acc?.[key];
      const [, arrayKey, indexText] = match;
      return acc?.[arrayKey]?.[Number(indexText)];
    }
    return acc?.[key];
  }, source);
}

function renderTemplate(value: any, context: Record<string, any>): any {
  if (typeof value !== "string") return value;
  return value.replace(/\{\{\s*([^}]+?)\s*\}\}/g, (_, expr) => {
    const resolved = deepGet(context, String(expr).trim());
    if (resolved == null) return "";
    return typeof resolved === "string" ? resolved : JSON.stringify(resolved);
  });
}

function tryParseJson(body: string): any {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

function matcherHit(ctx: Record<string, any>, matcher: any): boolean {
  const part = String(matcher?.part || "body").toLowerCase();
  const type = String(matcher?.type || "contains").toLowerCase();
  const expected = matcher?.value;

  if (part === "status") {
    if (type === "in" && Array.isArray(expected)) {
      return expected.includes(ctx.status);
    }
    return ctx.status === expected;
  }

  const source =
    part === "header"
      ? String(ctx.headers[String(matcher?.key || "").toLowerCase()] || "")
      : part === "title"
        ? ctx.title
        : part === "json"
          ? deepGet(ctx.json || {}, String(matcher?.path || matcher?.key || ""))
          : ctx.body;

  if (type === "exists") {
    return source !== undefined && source !== null && String(source).length > 0;
  }
  if (type === "equals") return String(source) === String(expected ?? "");
  if (type === "in" && Array.isArray(expected)) {
    return expected.map(String).includes(String(source));
  }
  if (type === "regex") {
    try {
      return new RegExp(String(expected || ""), "i").test(String(source || ""));
    } catch {
      return false;
    }
  }
  return String(source || "")
    .toLowerCase()
    .includes(String(expected || "").toLowerCase());
}

function matchAll(
  ctx: Record<string, any>,
  matchers: any[],
  operator?: string,
): boolean {
  if (!Array.isArray(matchers) || matchers.length === 0) return false;
  return String(operator || "and").toLowerCase() === "or"
    ? matchers.some((matcher) => matcherHit(ctx, matcher))
    : matchers.every((matcher) => matcherHit(ctx, matcher));
}

function evaluateCondition(
  condition: any,
  context: Record<string, any>,
): boolean {
  if (condition?.matchers) {
    return matchAll(
      context,
      asArray(condition.matchers),
      condition.operator || "and",
    );
  }

  const field = String(condition?.field || "");
  const op = String(condition?.op || "equals").toLowerCase();
  const actual = deepGet(context, field);
  const expected = condition?.value;

  if (op === "exists") {
    return actual !== undefined && actual !== null && String(actual).length > 0;
  }
  if (op === "contains") {
    return String(actual || "")
      .toLowerCase()
      .includes(String(expected || "").toLowerCase());
  }
  if (op === "in" && Array.isArray(expected)) {
    return expected.map(String).includes(String(actual));
  }
  if (op === "regex") {
    try {
      return new RegExp(String(expected || ""), "i").test(String(actual || ""));
    } catch {
      return false;
    }
  }
  return String(actual) === String(expected);
}

function evaluatePreconditions(
  preconditions: any[],
  context: Record<string, any>,
): boolean {
  if (!Array.isArray(preconditions) || preconditions.length === 0) return true;
  return preconditions.every((condition) =>
    evaluateCondition(condition, context),
  );
}

function getObservedFingerprints(input: ToolInput): string[] {
  return [
    ...asArray(input.fingerprints),
    ...asArray(input.technologies).map((item) =>
      typeof item === "string" ? item : item?.name || "",
    ),
  ]
    .filter(Boolean)
    .map((item) => String(item).toLowerCase());
}

function ruleMatchesFingerprintScope(
  rule: RuleEntry,
  observedFingerprints: string[],
): boolean {
  const metadata = parseMetadata(rule.metadata);
  if (metadata.enabled === false) return false;

  const scope = metadata.match_scope || {};
  const expectedFingerprints = asArray(scope.fingerprints).map((item) =>
    String(item).toLowerCase(),
  );

  if (
    expectedFingerprints.length > 0 &&
    !expectedFingerprints.some((item) => observedFingerprints.includes(item))
  ) {
    return false;
  }

  return true;
}

function ruleApplies(
  rule: RuleEntry,
  input: ToolInput,
  targetContext: Record<string, any>,
): boolean {
  if (!ruleMatchesFingerprintScope(rule, getObservedFingerprints(input))) {
    return false;
  }

  return evaluatePreconditions(
    asArray(parseMetadata(rule.metadata).preconditions),
    targetContext,
  );
}

function dedupeRules(rules: RuleEntry[]): RuleEntry[] {
  const seen = new Set<string>();
  const deduped: RuleEntry[] = [];

  for (const rule of rules) {
    const metadata = parseMetadata(rule.metadata);
    const ruleId = String(rule.word || metadata.name || "")
      .trim()
      .toLowerCase();
    if (!ruleId || seen.has(ruleId)) continue;
    seen.add(ruleId);
    deduped.push({ ...rule, metadata });
  }

  return deduped;
}

async function loadStructuredDictionary(
  idOrName: string,
): Promise<RuleEntry[]> {
  if (typeof Sentinel?.Dictionary?.getEntries !== "function") {
    throw new Error("Risk Scanner requires Sentinel.Dictionary.getEntries");
  }
  // Explicit JSON null selects the host's existing unbounded dictionary query.
  const entries = await Sentinel.Dictionary.getEntries(idOrName, null);
  if (!Array.isArray(entries)) throw new Error("Risk Scanner dictionary entries must be an array");
  return entries
    .filter((item: any) => item && typeof item.word === "string")
    .map((item: any) => ({
      word: item.word,
      category: item.category || null,
      metadata: parseMetadata(item.metadata),
    }));
}

async function loadRules(input: ToolInput): Promise<RuleEntry[]> {
  if (Array.isArray(input.dictionaryEntries)) {
    return input.dictionaryEntries.map((entry) => ({
      ...entry,
      metadata: parseMetadata(entry.metadata),
    }));
  }

  const dictionaryId = input.dictionaryId || await Sentinel?.Dictionary?.getDefaultId?.("poc_rule");
  if (typeof dictionaryId !== "string" || !dictionaryId.trim()) {
    throw new Error("Configure a Risk Scanner Rules dictionary or provide dictionaryEntries");
  }
  return loadStructuredDictionary(dictionaryId);
}

function normalizeRequests(metadata: Record<string, any>): any[] {
  const requests = Array.isArray(metadata.requests)
    ? metadata.requests
    : metadata.request
      ? [metadata.request]
      : [];
  return requests.map((request, index) => ({
    id: request?.id || `step_${index + 1}`,
    method: String(request?.method || "GET").toUpperCase(),
    path: request?.path || "/",
    headers: request?.headers || {},
    body: request?.body,
    matchers: Array.isArray(request?.matchers) ? request.matchers : undefined,
    extractors: Array.isArray(request?.extractors) ? request.extractors : [],
  }));
}

function buildRequestContext(
  baseContext: Record<string, any>,
  executionContext: Record<string, any>,
): Record<string, any> {
  return {
    ...baseContext,
    ...executionContext,
    steps: executionContext.steps || {},
    extracted: executionContext.extracted || {},
  };
}

function applyExtractors(
  extractors: any[],
  responseContext: Record<string, any>,
): Record<string, any> {
  const extracted: Record<string, any> = {};
  for (const extractor of extractors) {
    const name = String(extractor?.name || "").trim();
    if (!name) continue;
    const sourcePart = String(extractor?.part || "body").toLowerCase();
    const source =
      sourcePart === "header"
        ? String(
            responseContext.headers[
              String(extractor?.key || "").toLowerCase()
            ] || "",
          )
        : sourcePart === "title"
          ? responseContext.title
          : sourcePart === "json"
            ? deepGet(
                responseContext.json || {},
                String(extractor?.path || extractor?.key || ""),
              )
            : responseContext.body;

    if (extractor?.type === "regex") {
      try {
        const match = String(source || "").match(
          new RegExp(String(extractor?.pattern || extractor?.value || ""), "i"),
        );
        if (match?.[1]) extracted[name] = match[1];
      } catch {
        continue;
      }
      continue;
    }

    if (extractor?.type === "json_path") {
      extracted[name] = deepGet(
        responseContext.json || {},
        String(extractor?.path || ""),
      );
      continue;
    }

    extracted[name] = source;
  }
  return extracted;
}

async function executeRule(
  target: string,
  rule: RuleEntry,
  input: ToolInput,
  onStep?: (step: ExecutionStep, index: number) => Promise<void>,
): Promise<{ finding?: Finding; evidence?: any; matched: boolean }> {
  const metadata = parseMetadata(rule.metadata);
  const baseContext: Record<string, any> = {
    target,
    base_url: target,
    url: target,
    rule_id: rule.word,
    category: rule.category || "",
    variables: input.variables || {},
    fingerprints: asArray(input.fingerprints),
    technologies: asArray(input.technologies).map((item) =>
      typeof item === "string" ? item : item?.name || "",
    ),
  };

  if (!ruleApplies(rule, input, baseContext)) {
    return { matched: false };
  }

  const requests = normalizeRequests(metadata);
  if (requests.length === 0) return { matched: false };

  const executionContext: Record<string, any> = { steps: {}, extracted: {} };
  const evidenceSteps: ExecutionStep[] = [];
  let lastResponseContext: Record<string, any> | null = null;

  for (const request of requests) {
    const context = buildRequestContext(baseContext, executionContext);
    const method = String(request.method || "GET").toUpperCase();

    if (input.safe_mode !== false && !SAFE_METHODS.has(method)) {
      return { matched: false };
    }

    const renderedPath = renderTemplate(request.path, context);
    const url = joinUrl(target, renderedPath);
    const headers = Object.fromEntries(
      Object.entries(request.headers || {}).map(([key, value]) => [
        key,
        renderTemplate(value, context),
      ]),
    );
    const body =
      request.body == null ? undefined : renderTemplate(request.body, context);

    try {
      const response = await fetch(url, {
        method,
        headers: {
          "User-Agent": input.userAgent || "Sentinel-Risk-Scanner/2.0",
          ...headers,
        },
        body: body == null ? undefined : String(body),
        timeout: RULE_FETCH_TIMEOUT_MS,
      });

      const responseBody = await response.text();
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[String(key).toLowerCase()] = value;
      });
      const responseContext = {
        status: response.status,
        body: responseBody,
        headers: responseHeaders,
        title: parseTitle(responseBody),
        json: tryParseJson(responseBody),
        url,
      };

      const extracted = applyExtractors(
        asArray(request.extractors),
        responseContext,
      );
      executionContext.steps[request.id] = responseContext;
      executionContext.extracted = {
        ...executionContext.extracted,
        ...extracted,
      };
      lastResponseContext = responseContext;

      const stepMatchers = Array.isArray(request.matchers)
        ? request.matchers
        : [];
      const hasStepMatchers = stepMatchers.length > 0;
      const stepMatched = hasStepMatchers
        ? matchAll(responseContext, stepMatchers, request.operator || "and")
        : false;

      evidenceSteps.push({
        id: request.id,
        method,
        url,
        status: response.status,
        matched: hasStepMatchers ? stepMatched : undefined,
        extracted,
      });

      if (hasStepMatchers && !stepMatched) {
        return {
          matched: false,
          evidence: { rule_id: rule.word, target, steps: evidenceSteps },
        };
      }
    } catch (error: any) {
      evidenceSteps.push({
        id: request.id,
        method,
        url,
        matched: false,
        extracted: {},
      });
      return {
        matched: false,
        evidence: {
          rule_id: rule.word,
          target,
          steps: evidenceSteps,
          error: error instanceof Error ? error.message : String(error),
        },
      };
    }
    // A real completed request is durable progress even for multi-step rules.
    // Keep persistence outside the network catch: a failed ACK must stop the scan.
    if (onStep) await onStep(evidenceSteps[evidenceSteps.length - 1], evidenceSteps.length - 1);
  }

  const finalMatchers = Array.isArray(metadata.matchers)
    ? metadata.matchers
    : [];
  const finalMatched =
    finalMatchers.length === 0
      ? true
      : lastResponseContext != null &&
        matchAll(
          lastResponseContext,
          finalMatchers,
          metadata.operator || "and",
        );

  const evidence = {
    rule_id: rule.word,
    target,
    steps: evidenceSteps,
    final_matchers: finalMatchers,
    extracted: executionContext.extracted,
  };

  if (!finalMatched || !lastResponseContext) {
    return { matched: false, evidence };
  }

  const finding: Finding = {
    title: metadata.name || rule.word,
    severity: metadata.severity || "medium",
    url: lastResponseContext.url,
    description:
      metadata.description || `Risk verification rule ${rule.word} matched.`,
    impact: metadata.impact || "",
    remediation:
      metadata.remediation ||
      "Restrict access and harden the affected component.",
    cwe: metadata.cwe || "",
  };

  return { matched: true, finding, evidence };
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
  try {
    if (!input || typeof input !== "object") {
      return {
        success: false,
        error: "Invalid input: expected an object payload",
      };
    }

    const concurrency = input.concurrency === undefined ? DEFAULT_CONCURRENCY : input.concurrency;
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > MAX_CONCURRENCY) {
      return {
        success: false,
        error: `concurrency must be an integer between 1 and ${MAX_CONCURRENCY}`,
      };
    }
    const stream = createMonitorResultStream(input);
    const writeTarget = createMonitorTargetWriter(input, stream, normalizeTarget);
    const safeMode = getInputBoolean(input, "safe_mode", "safe_mode", true);
    const userAgent = getInputString(
      input,
      "userAgent",
      "user_agent",
      "Sentinel-Risk-Scanner/2.0",
    );
    const stopOnFirstHit = getInputBoolean(
      input,
      "stopOnFirstHit",
      "stop_on_first_hit",
      false,
    );
    const normalizedInput: ToolInput = {
      ...input,
      safe_mode: safeMode,
      userAgent,
      stopOnFirstHit,
      dictionaryId:
        getInputString(input, "dictionaryId", "dictionary_id") ||
        input.dictionaryId,
    };
    const monitorExecution = input.__monitorExecution;
    const targets = Array.from(
      new Set(
        [
          normalizeTarget(input.url),
          normalizeTarget(input.base_url),
          ...asArray(input.targets).map(normalizeTarget),
        ].filter((value): value is string => Boolean(value)),
      ),
    );

    if (targets.length === 0) {
      return { success: false, error: "At least one target URL is required" };
    }

    const observedFingerprints = getObservedFingerprints(normalizedInput);
    const allRules = dedupeRules(await loadRules(normalizedInput));
    if (allRules.length === 0) {
      return {
        success: false,
        error:
          "No risk verification rules loaded. Configure dictionaryEntries or a poc_rule dictionary with explicit requests and matchers.",
      };
    }
    const rules = allRules
      .filter((rule) => {
        const metadata = parseMetadata(rule.metadata);
        if (metadata.enabled === false) return false;
        if (safeMode && metadata.safe_mode === false) return false;
        return ruleMatchesFingerprintScope(rule, observedFingerprints);
      });
    const taskCount = targets.length * rules.length;
    const totalProgressUnits = taskCount + 2;

    await reportMonitorProgress(monitorExecution, {
      current: 0,
      total: totalProgressUnits,
      phase: "prepare",
      message: "Preparing risk verification",
    });

    const findings: Finding[] = [];
    const evidence: any[] = [];
    const vulnerabilityFindings: any[] = [];

    let stopRequested = false;
    let executedRuleCount = 0;
    let completedRuleCount = 0;
    let lastProgressAt = Date.now();
    const failedTargets = new Set<string>();
    await runTaskPool(
      taskCount,
      concurrency,
      async index => {
        stream.assertHealthy();
        const target = targets[Math.floor(index / rules.length)];
        const rule = rules[index % rules.length];
        executedRuleCount += 1;
        const ruleKey = `rule:${rule.word}`;
        const result = await executeRule(target, rule, normalizedInput, async (step, index) => {
          await writeTarget(target, `${ruleKey}:step:${index}`, { success: true, data: {
            results: [{ target, rule_id: rule.word, step }],
          } }, { complete: false });
        });
        const metadata = parseMetadata(rule.metadata);
        const finding = result.matched && result.finding ? result.finding : undefined;
        const surfaceFinding = finding ? {
          title: finding.title, severity: finding.severity, target: finding.url,
          vulnerability_type: metadata.finding_type || rule.category || "risk_verification",
          description: finding.description, source: "risk_scanner",
        } : undefined;
        const surfaceEvidence = result.evidence ? {
          asset_type: "web", asset_key: target, evidence_type: "risk_verification",
          title: `Risk verification: ${metadata.name || rule.word}`,
          content_json: result.evidence, source: "risk_scanner",
        } : undefined;
        const error = result.evidence?.error as string | undefined;
        if (error) failedTargets.add(target);
        await writeTarget(target, ruleKey, { success: true, data: {
          results: [{ target, rule_id: rule.word, matched: result.matched, error }],
          findings: finding ? [confirmedMonitorFinding(finding,
            metadata.finding_type || rule.category || "risk_verification", result.evidence)] : [],
          surface_artifacts: { evidences: surfaceEvidence ? [surfaceEvidence] : [] },
          summary: { executedRules: 1, matchedRules: finding ? 1 : 0 },
        } }, { complete: false, status: error ? "failed" : "ok", error });
        if (!stream.enabled) {
          if (result.evidence) evidence.push(result.evidence);
          if (finding) findings.push(finding);
          if (surfaceFinding) vulnerabilityFindings.push(surfaceFinding);
        }
        if (finding && stopOnFirstHit) stopRequested = true;
        completedRuleCount += 1;
        const now = Date.now();
        if (completedRuleCount === taskCount || now - lastProgressAt >= PROGRESS_INTERVAL_MS) {
          lastProgressAt = now;
          await reportMonitorProgress(monitorExecution, {
            current: completedRuleCount, total: totalProgressUnits, currentTarget: target,
            phase: "probe", message: `Executing verification rules for ${target}`,
          });
        }
      },
      () => stopRequested,
    );
    for (const target of targets) await writeTarget(target, "target-complete", { success: true, data: {} }, {
      complete: true, status: failedTargets.has(target) ? "failed" : stopRequested ? "skipped" : "ok",
    });

    await reportMonitorProgress(monitorExecution, {
      current: totalProgressUnits - 1,
      total: totalProgressUnits,
      phase: "compare",
      message: "Summarizing risk verification results",
    });

    await reportMonitorProgress(monitorExecution, {
      current: totalProgressUnits,
      total: totalProgressUnits,
      phase: "build",
      message: "Building risk scan results",
    });

    return await stream.finish({
      success: true,
      data: {
        findings,
        evidence,
        summary: {
          totalTargets: targets.length,
          executedRules: executedRuleCount,
          matchedRules: findings.length,
          diagnostics: {
            loaded_rules: allRules.length,
            applicable_rules: rules.length,
            planned_rule_tasks: taskCount,
            completed_rule_tasks: completedRuleCount,
          },
        },
        surface_artifacts: {
          findings: vulnerabilityFindings,
          evidences: evidence.map(item => ({ asset_type: "web", asset_key: item.target,
            evidence_type: "risk_verification", title: `Risk verification: ${item.rule_id}`,
            content_json: item, source: "risk_scanner" })) ,
        },
      },
    });
  } catch (error: any) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

pluginGlobals.analyze = analyze;
