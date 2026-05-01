/**
 * Intruder HMAC Request Signer
 *
 * @plugin intruder_hmac_request_signer
 * @name Intruder HMAC Request Signer
 * @version 1.0.0
 * @author Sentinel Team
 * @main_category intruder
 * @category request_processor
 * @default_severity info
 * @tags intruder, request-processor, hmac, signing
 * @description Sign Intruder requests locally with an HMAC header after payload substitution and before dispatch.
 */

interface ToolInput {
    rawRequest: string;
    payloadValues?: string[];
    payloadSummary?: string;
    requestIndex?: number;
    config?: {
        secret?: string;
        algorithm?: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
        headerName?: string;
        headerPrefix?: string;
        encoding?: "hex" | "base64";
        signedParts?: string[];
        includeTimestamp?: boolean;
        timestampHeaderName?: string;
        timestamp?: string;
    };
}

interface ParsedRequest {
    requestLine: string;
    method: string;
    target: string;
    headers: string[];
    body: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        rawRequest: string;
        signature: string;
        signedString: string;
        algorithm: string;
    };
    error?: string;
}

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;

const DEFAULT_SIGNED_PARTS = ["method", "path", "query", "body"];

function splitRawRequest(rawRequest: string): ParsedRequest {
    const separator = rawRequest.includes("\r\n\r\n") ? "\r\n\r\n" : "\n\n";
    const separatorIndex = rawRequest.indexOf(separator);
    const head = separatorIndex >= 0 ? rawRequest.slice(0, separatorIndex) : rawRequest;
    const body = separatorIndex >= 0 ? rawRequest.slice(separatorIndex + separator.length) : "";
    const lines = head.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
    const requestLine = lines.shift() || "GET / HTTP/1.1";
    const [method = "GET", target = "/"] = requestLine.split(/\s+/);

    return {
        requestLine,
        method: method.toUpperCase(),
        target,
        headers: lines.filter(line => line.length > 0),
        body,
    };
}

function parseTarget(target: string): { path: string; query: string } {
    const queryIndex = target.indexOf("?");
    if (queryIndex === -1) {
        return { path: target || "/", query: "" };
    }

    return {
        path: target.slice(0, queryIndex) || "/",
        query: target.slice(queryIndex + 1),
    };
}

function upsertHeader(headers: string[], headerName: string, headerValue: string): string[] {
    const lowerName = headerName.toLowerCase();
    let replaced = false;
    const nextHeaders = headers.map((line) => {
        const colon = line.indexOf(":");
        if (colon <= 0) return line;
        const currentName = line.slice(0, colon).trim().toLowerCase();
        if (currentName !== lowerName) return line;
        replaced = true;
        return `${headerName}: ${headerValue}`;
    });

    if (!replaced) {
        nextHeaders.push(`${headerName}: ${headerValue}`);
    }

    return nextHeaders;
}

function buildSignedString(input: ToolInput, parsed: ParsedRequest, timestamp: string | null): string {
    const config = input.config || {};
    const signedParts = Array.isArray(config.signedParts) && config.signedParts.length > 0
        ? config.signedParts
        : DEFAULT_SIGNED_PARTS;
    const target = parseTarget(parsed.target);
    const values: string[] = [];

    for (const part of signedParts) {
        switch (part) {
            case "requestLine":
                values.push(parsed.requestLine);
                break;
            case "method":
                values.push(parsed.method);
                break;
            case "target":
                values.push(parsed.target);
                break;
            case "path":
                values.push(target.path);
                break;
            case "query":
                values.push(target.query);
                break;
            case "body":
                values.push(parsed.body);
                break;
            case "payloads":
                values.push((input.payloadValues || []).join(","));
                break;
            case "payloadSummary":
                values.push(input.payloadSummary || "");
                break;
            case "requestIndex":
                values.push(String(input.requestIndex ?? ""));
                break;
            case "timestamp":
                values.push(timestamp || "");
                break;
            default:
                values.push("");
                break;
        }
    }

    return values.join("\n");
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

async function hmacSign(secret: string, algorithm: string, message: string, encoding: "hex" | "base64"): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: { name: algorithm } },
        false,
        ["sign"],
    );
    const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
    return encoding === "base64" ? bytesToBase64(signature) : bytesToHex(signature);
}

function rebuildRequest(parsed: ParsedRequest, headers: string[]): string {
    return [parsed.requestLine, ...headers, "", parsed.body].join("\r\n");
}

export function get_input_schema() {
    return {
        type: "object",
        required: ["rawRequest"],
        properties: {
            rawRequest: {
                type: "string",
                description: "HTTP request after Intruder payload substitution",
            },
            config: {
                type: "object",
                required: ["secret"],
                properties: {
                    secret: {
                        type: "string",
                        description: "HMAC secret key",
                    },
                    algorithm: {
                        type: "string",
                        enum: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"],
                        default: "SHA-256",
                    },
                    headerName: {
                        type: "string",
                        default: "X-Signature",
                        description: "Header receiving the signature",
                    },
                    headerPrefix: {
                        type: "string",
                        description: "Optional value prefix, for example sha256=",
                    },
                    encoding: {
                        type: "string",
                        enum: ["hex", "base64"],
                        default: "hex",
                    },
                    signedParts: {
                        type: "array",
                        items: {
                            type: "string",
                            enum: [
                                "requestLine",
                                "method",
                                "target",
                                "path",
                                "query",
                                "body",
                                "payloads",
                                "payloadSummary",
                                "requestIndex",
                                "timestamp",
                            ],
                        },
                        description: "Ordered fields joined with newline before signing",
                    },
                    includeTimestamp: {
                        type: "boolean",
                        default: false,
                        description: "Add timestamp header and make timestamp available to signedParts",
                    },
                    timestampHeaderName: {
                        type: "string",
                        default: "X-Timestamp",
                    },
                    timestamp: {
                        type: "string",
                        description: "Explicit timestamp value; current epoch milliseconds are used when omitted",
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
                    rawRequest: { type: "string" },
                    signature: { type: "string" },
                    signedString: { type: "string" },
                    algorithm: { type: "string" },
                },
            },
            error: { type: "string" },
        },
    };
}

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        const config = input.config || {};
        const secret = String(config.secret || "");
        if (!secret) {
            return { success: false, error: "config.secret is required" };
        }

        const algorithm = config.algorithm || "SHA-256";
        const encoding = config.encoding || "hex";
        const headerName = config.headerName || "X-Signature";
        const headerPrefix = config.headerPrefix || "";
        const timestamp = config.includeTimestamp
            ? (config.timestamp || String(Date.now()))
            : null;
        const parsed = splitRawRequest(input.rawRequest || "");
        const signedString = buildSignedString(input, parsed, timestamp);
        const signature = await hmacSign(secret, algorithm, signedString, encoding);
        let headers = parsed.headers;

        if (timestamp) {
            headers = upsertHeader(headers, config.timestampHeaderName || "X-Timestamp", timestamp);
        }
        headers = upsertHeader(headers, headerName, `${headerPrefix}${signature}`);

        return {
            success: true,
            data: {
                rawRequest: rebuildRequest(parsed, headers),
                signature,
                signedString,
                algorithm,
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
