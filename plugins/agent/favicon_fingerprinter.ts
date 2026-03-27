/**
 * Favicon Fingerprinter Tool
 *
 * @plugin favicon_fingerprinter
 * @name Favicon Fingerprinter
 * @version 1.0.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags favicon, fingerprint, web, asm, surface
 * @description Fetch favicons from web targets and emit favicon fingerprint and evidence artifacts for ASM and network asset mapping workflows
 */

interface ToolInput {
    targets: string[];
    timeout?: number;
    concurrency?: number;
    followRedirects?: boolean;
}

interface FingerprintResult {
    target: string;
    success: boolean;
    iconUrl?: string;
    faviconSha256?: string;
    contentType?: string;
    bytes?: number;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        targets: string[];
        results: FingerprintResult[];
        summary: {
            totalTargets: number;
            successfulFingerprints: number;
            failedFingerprints: number;
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

function normalizeTarget(value: string): string {
    const trimmed = String(value || "").trim();
    if (!trimmed) return "";
    try {
        return new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`).toString();
    } catch {
        return "";
    }
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    return bytesToHex(new Uint8Array(digest));
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, {
            ...init,
            signal: controller.signal,
        });
    } finally {
        clearTimeout(timeoutId);
    }
}

function extractIconCandidates(baseUrl: URL, html: string): string[] {
    const candidates: string[] = [];
    const pattern = /<link\b[^>]*rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["'][^>]*>/gi;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(html)) !== null) {
        const rawHref = match[1]?.trim();
        if (!rawHref) continue;
        try {
            candidates.push(new URL(rawHref, baseUrl).toString());
        } catch {
            continue;
        }
    }

    candidates.push(new URL("/favicon.ico", baseUrl).toString());
    return Array.from(new Set(candidates));
}

async function fingerprintTarget(
    target: string,
    timeout: number,
    followRedirects: boolean,
): Promise<FingerprintResult & { fingerprint?: any; evidence?: any }> {
    const canonicalUrl = new URL(target);
    try {
        const pageResponse = await fetchWithTimeout(
            canonicalUrl.toString(),
            {
                method: "GET",
                redirect: followRedirects ? "follow" : "manual",
            },
            timeout,
        );
        const html = await pageResponse.text();
        const candidates = extractIconCandidates(canonicalUrl, html);

        for (const iconUrl of candidates) {
            try {
                const iconResponse = await fetchWithTimeout(
                    iconUrl,
                    {
                        method: "GET",
                        redirect: followRedirects ? "follow" : "manual",
                    },
                    timeout,
                );
                if (!iconResponse.ok) continue;
                const buffer = await iconResponse.arrayBuffer();
                if (!buffer || buffer.byteLength === 0) continue;

                const faviconSha256 = await sha256Hex(buffer);
                return {
                    target: canonicalUrl.toString(),
                    success: true,
                    iconUrl,
                    faviconSha256,
                    contentType: iconResponse.headers.get("content-type") || undefined,
                    bytes: buffer.byteLength,
                    fingerprint: {
                        asset_type: "web",
                        asset_key: canonicalUrl.toString(),
                        fingerprint_type: "favicon_sha256",
                        fingerprint_key: iconUrl,
                        fingerprint_value: faviconSha256,
                        confidence: 0.95,
                        evidence: `Fetched favicon from ${iconUrl}`,
                    },
                    evidence: {
                        asset_type: "web",
                        asset_key: canonicalUrl.toString(),
                        evidence_type: "favicon_fetch",
                        title: `Favicon fingerprint for ${canonicalUrl.hostname}`,
                        content_json: {
                            icon_url: iconUrl,
                            sha256: faviconSha256,
                            content_type: iconResponse.headers.get("content-type"),
                            size_bytes: buffer.byteLength,
                        },
                    },
                };
            } catch {
                continue;
            }
        }

        return {
            target: canonicalUrl.toString(),
            success: false,
            error: "No favicon could be fetched",
        };
    } catch (error) {
        return {
            target: canonicalUrl.toString(),
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

async function runWithConcurrency<T>(tasks: Array<() => Promise<T>>, concurrency: number): Promise<T[]> {
    const results: T[] = [];
    const workers = Array.from({ length: Math.max(1, concurrency) }, async () => {
        while (tasks.length > 0) {
            const task = tasks.shift();
            if (!task) break;
            results.push(await task());
        }
    });
    await Promise.all(workers);
    return results;
}

export function get_input_schema() {
    return {
        type: "object",
        required: ["targets"],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "HTTP or HTTPS URLs to fingerprint via favicon",
            },
            timeout: {
                type: "integer",
                description: "Network timeout in milliseconds",
                default: 10000,
                minimum: 1000,
                maximum: 60000,
            },
            concurrency: {
                type: "integer",
                description: "Concurrent favicon fetches",
                default: 10,
                minimum: 1,
                maximum: 50,
            },
            followRedirects: {
                type: "boolean",
                description: "Follow HTTP redirects",
                default: true,
            },
        },
    };
}

pluginGlobals.get_input_schema = get_input_schema;

export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean" },
            data: {
                type: "object",
                properties: {
                    targets: { type: "array", items: { type: "string" } },
                    results: { type: "array" },
                    summary: { type: "object" },
                    surface_artifacts: {
                        type: "object",
                        description: "Favicon fingerprint and evidence artifacts for surface graph ingestion",
                    },
                },
            },
            error: { type: "string" },
        },
    };
}

pluginGlobals.get_output_schema = get_output_schema;

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!Array.isArray(input.targets) || input.targets.length === 0) {
            return { success: false, error: "Invalid input: targets array is required" };
        }

        const targets = Array.from(new Set(input.targets.map(normalizeTarget).filter(Boolean)));
        if (targets.length === 0) {
            return { success: false, error: "No valid web targets provided" };
        }

        const timeout = Math.max(1000, Math.min(input.timeout || 10000, 60000));
        const concurrency = Math.max(1, Math.min(input.concurrency || 10, 50));

        const tasks = targets.map((target) => () => fingerprintTarget(target, timeout, input.followRedirects !== false));
        const fingerprints = await runWithConcurrency(tasks, concurrency);

        return {
            success: true,
            data: {
                targets,
                results: fingerprints.map(({ fingerprint, evidence, ...result }) => result),
                summary: {
                    totalTargets: targets.length,
                    successfulFingerprints: fingerprints.filter((item) => item.success).length,
                    failedFingerprints: fingerprints.filter((item) => !item.success).length,
                },
                surface_artifacts: {
                    fingerprints: fingerprints
                        .map((item) => item.fingerprint)
                        .filter(Boolean),
                    evidences: fingerprints
                        .map((item) => item.evidence)
                        .filter(Boolean),
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

pluginGlobals.analyze = analyze;
