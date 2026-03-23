/**
 * Service Fingerprinter Tool
 *
 * @plugin service_fingerprinter
 * @name Service Fingerprinter
 * @version 1.0.0
 * @author Sentinel Team
 * @category recon
 * @default_severity info
 * @tags service, fingerprint, banner, port, asm
 * @description Fingerprint exposed services from host/port targets and produce typed service, fingerprint, evidence, and relation artifacts
 */

interface PortLikeTarget {
    host_key?: string;
    ip_or_host?: string;
    port?: number;
    port_number?: number;
    transport_protocol?: string;
}

interface ToolInput {
    targets: Array<string | PortLikeTarget>;
    timeout?: number;
    concurrency?: number;
    followHttpRedirects?: boolean;
    readBanner?: boolean;
}

interface FingerprintResult {
    target: string;
    success: boolean;
    host: string;
    port: number;
    protocol: string;
    serviceName: string;
    productName?: string;
    vendor?: string;
    version?: string;
    banner?: string;
    serverHeader?: string;
    title?: string;
    statusCode?: number;
    error?: string;
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: FingerprintResult[];
        summary: {
            totalTargets: number;
            successfulFingerprints: number;
            failedFingerprints: number;
            identifiedProducts: number;
        };
        surface_artifacts?: Record<string, any[]>;
    };
    error?: string;
}

const HTTP_PORTS = new Set([80, 81, 443, 8000, 8080, 8081, 8443, 8888, 9000]);
const TLS_PORTS = new Set([443, 8443, 9443]);

const DEFAULT_SERVICE_NAMES: Record<number, string> = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
    9200: "elasticsearch",
    27017: "mongodb",
};

function normalizeTarget(raw: string | PortLikeTarget): { host: string; port: number; protocol: string } | null {
    if (typeof raw === "string") {
        const trimmed = raw.trim();
        if (!trimmed) return null;

        try {
            const normalized = trimmed.includes("://") ? trimmed : `tcp://${trimmed}`;
            const parsed = new URL(normalized);
            const protocol = parsed.protocol.replace(":", "") || "tcp";
            const port = Number(parsed.port || (protocol === "https" ? 443 : protocol === "http" ? 80 : 0));
            if (!parsed.hostname || !port) return null;
            return { host: parsed.hostname, port, protocol };
        } catch {
            const [hostPart, portPart] = trimmed.split(":");
            const port = Number(portPart || 0);
            if (!hostPart || !port) return null;
            return { host: hostPart, port, protocol: "tcp" };
        }
    }

    const host = String(raw.ip_or_host || raw.host_key || "").trim();
    const port = Number(raw.port ?? raw.port_number ?? 0);
    const protocol = String(raw.transport_protocol || "tcp").trim().toLowerCase();
    if (!host || !port) return null;
    return { host, port, protocol };
}

function serviceKey(host: string, port: number, protocol: string): string {
    return `${host}:${port}/${protocol}`;
}

function inferServiceName(port: number, protocol: string, banner?: string, serverHeader?: string): string {
    const normalizedBanner = `${banner || ""} ${serverHeader || ""}`.toLowerCase();
    if (normalizedBanner.includes("ssh")) return "ssh";
    if (normalizedBanner.includes("smtp")) return "smtp";
    if (normalizedBanner.includes("redis")) return "redis";
    if (normalizedBanner.includes("mysql")) return "mysql";
    if (normalizedBanner.includes("postgres")) return "postgresql";
    if (normalizedBanner.includes("mongodb")) return "mongodb";
    if (normalizedBanner.includes("elasticsearch")) return "elasticsearch";
    if (HTTP_PORTS.has(port) || normalizedBanner.includes("http")) {
        return TLS_PORTS.has(port) || protocol === "https" ? "https" : "http";
    }
    return DEFAULT_SERVICE_NAMES[port] || protocol || "unknown";
}

function extractProductInfo(banner?: string, serverHeader?: string): {
    productName?: string;
    vendor?: string;
    version?: string;
} {
    const source = `${serverHeader || ""} ${banner || ""}`.trim();
    if (!source) return {};

    const patterns = [
        /(?<product>nginx)\/(?<version>[\d.]+)/i,
        /(?<product>apache(?: httpd)?)\/(?<version>[\d.]+)/i,
        /(?<product>microsoft-iis)\/(?<version>[\d.]+)/i,
        /(?<product>openssh)[-_](?<version>[\d.p]+)/i,
        /(?<product>redis)[-_ ]server v=(?<version>[\d.]+)/i,
        /(?<product>postgres(?:ql)?)\s+(?<version>[\d.]+)/i,
        /(?<product>mysql)[-_ ](?<version>[\d.]+)/i,
        /(?<product>elasticsearch)\/(?<version>[\d.]+)/i,
    ];

    for (const pattern of patterns) {
        const match = source.match(pattern);
        if (!match?.groups?.product) continue;
        const productName = match.groups.product.toLowerCase();
        let vendor: string | undefined;
        if (productName.includes("nginx")) vendor = "NGINX";
        if (productName.includes("apache")) vendor = "Apache";
        if (productName.includes("iis")) vendor = "Microsoft";
        if (productName.includes("openssh")) vendor = "OpenSSH";
        if (productName.includes("redis")) vendor = "Redis";
        if (productName.includes("mysql")) vendor = "Oracle";
        if (productName.includes("postgres")) vendor = "PostgreSQL";
        if (productName.includes("elasticsearch")) vendor = "Elastic";
        return {
            productName,
            vendor,
            version: match.groups.version,
        };
    }

    return {
        productName: source.split(/[ /]/)[0]?.toLowerCase(),
    };
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

async function fingerprintHttp(
    host: string,
    port: number,
    timeout: number,
    followRedirects: boolean,
): Promise<Partial<FingerprintResult>> {
    const protocol = TLS_PORTS.has(port) ? "https" : "http";
    const url = `${protocol}://${host}:${port}/`;
    const response = await fetchWithTimeout(
        url,
        {
            method: "GET",
            redirect: followRedirects ? "follow" : "manual",
        },
        timeout,
    );

    const serverHeader = response.headers.get("server") || undefined;
    const titleMatch = (await response.text()).match(/<title[^>]*>([^<]+)<\/title>/i);
    return {
        protocol,
        serverHeader,
        statusCode: response.status,
        title: titleMatch?.[1]?.trim(),
    };
}

async function fingerprintTcp(
    host: string,
    port: number,
    timeout: number,
    readBanner: boolean,
): Promise<Partial<FingerprintResult>> {
    // @ts-ignore
    const conn = await Deno.connect({ hostname: host, port, transport: "tcp" });
    try {
        const buffer = new Uint8Array(512);
        // @ts-ignore
        conn.setReadDeadline(Date.now() + timeout);

        if (!readBanner) {
            return {};
        }

        const bytesRead = await conn.read(buffer);
        if (!bytesRead || bytesRead <= 0) {
            return {};
        }

        const banner = new TextDecoder().decode(buffer.subarray(0, bytesRead))
            .replace(/[\x00-\x08\x0b-\x1f]/g, " ")
            .trim()
            .slice(0, 240);

        return { banner };
    } finally {
        conn.close();
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
                description: "Port targets as strings like host:port or surface port objects",
            },
            timeout: {
                type: "integer",
                default: 5000,
                minimum: 1000,
                maximum: 30000,
            },
            concurrency: {
                type: "integer",
                default: 10,
                minimum: 1,
                maximum: 50,
            },
            followHttpRedirects: {
                type: "boolean",
                default: true,
            },
            readBanner: {
                type: "boolean",
                default: true,
            },
        },
    };
}

globalThis.get_input_schema = get_input_schema;

export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean" },
            data: {
                type: "object",
                properties: {
                    results: { type: "array" },
                    summary: { type: "object" },
                    surface_artifacts: {
                        type: "object",
                        description: "Typed network surface artifacts for surface graph ingestion",
                    },
                },
            },
            error: { type: "string" },
        },
    };
}

globalThis.get_output_schema = get_output_schema;

export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!Array.isArray(input.targets) || input.targets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets array is required",
            };
        }

        const normalizedTargets = input.targets
            .map(normalizeTarget)
            .filter((target): target is NonNullable<typeof target> => Boolean(target));

        if (normalizedTargets.length === 0) {
            return {
                success: false,
                error: "No valid service targets provided",
            };
        }

        const timeout = Math.max(1000, Math.min(input.timeout || 5000, 30000));
        const concurrency = Math.max(1, Math.min(input.concurrency || 10, 50));
        const followHttpRedirects = input.followHttpRedirects !== false;
        const readBanner = input.readBanner !== false;

        const tasks = normalizedTargets.map((target) => async (): Promise<FingerprintResult> => {
            const key = serviceKey(target.host, target.port, target.protocol);
            try {
                let details: Partial<FingerprintResult> = {};
                if (HTTP_PORTS.has(target.port) || target.protocol === "http" || target.protocol === "https") {
                    details = await fingerprintHttp(target.host, target.port, timeout, followHttpRedirects);
                } else {
                    details = await fingerprintTcp(target.host, target.port, timeout, readBanner);
                }

                const serviceName = inferServiceName(
                    target.port,
                    String(details.protocol || target.protocol || "tcp"),
                    details.banner,
                    details.serverHeader,
                );
                const productInfo = extractProductInfo(details.banner, details.serverHeader);

                return {
                    target: key,
                    success: true,
                    host: target.host,
                    port: target.port,
                    protocol: String(details.protocol || target.protocol || "tcp"),
                    serviceName,
                    banner: details.banner,
                    serverHeader: details.serverHeader,
                    title: details.title,
                    statusCode: details.statusCode,
                    productName: productInfo.productName,
                    vendor: productInfo.vendor,
                    version: productInfo.version,
                };
            } catch (error: any) {
                return {
                    target: key,
                    success: false,
                    host: target.host,
                    port: target.port,
                    protocol: target.protocol,
                    serviceName: DEFAULT_SERVICE_NAMES[target.port] || target.protocol || "unknown",
                    error: error instanceof Error ? error.message : String(error),
                };
            }
        });

        const results = await runWithConcurrency(tasks, concurrency);
        const successful = results.filter((result) => result.success);

        const services = successful.map((result) => ({
            host_key: result.host,
            ip_or_host: result.host,
            port: result.port,
            transport_protocol: result.protocol,
            protocol_name: result.serviceName,
            application_service_name: result.serviceName,
            product_name: result.productName,
            vendor: result.vendor,
            version: result.version,
            banner: result.banner || result.serverHeader,
            source: "service_fingerprinter",
            confidence: 0.92,
        }));

        const fingerprints = successful.flatMap((result) => {
            const key = serviceKey(result.host, result.port, result.protocol);
            const items: any[] = [];
            if (result.banner) {
                items.push({
                    asset_type: "service",
                    asset_key: key,
                    fingerprint_type: "banner",
                    fingerprint_value: result.banner,
                    confidence: 0.85,
                    evidence: result.banner,
                });
            }
            if (result.serverHeader) {
                items.push({
                    asset_type: "service",
                    asset_key: key,
                    fingerprint_type: "server_header",
                    fingerprint_value: result.serverHeader,
                    confidence: 0.9,
                    evidence: result.serverHeader,
                });
            }
            if (result.productName) {
                items.push({
                    asset_type: "service",
                    asset_key: key,
                    fingerprint_type: "product",
                    fingerprint_value: `${result.productName}${result.version ? ` ${result.version}` : ""}`,
                    confidence: 0.9,
                });
            }
            return items;
        });

        const evidences = successful.map((result) => ({
            asset_type: "service",
            asset_key: serviceKey(result.host, result.port, result.protocol),
            evidence_type: "service_probe",
            title: `Service Fingerprint: ${result.host}:${result.port}`,
            content_text: result.banner || result.serverHeader || result.serviceName,
            content_json: result,
            source: "service_fingerprinter",
        }));

        const relations = successful.map((result) => ({
            from_type: "host",
            from_key: result.host,
            to_type: "service",
            to_key: serviceKey(result.host, result.port, result.protocol),
            relation_type: "hosts_service",
            source: "service_fingerprinter",
            confidence: 0.95,
        }));

        return {
            success: true,
            data: {
                results,
                summary: {
                    totalTargets: normalizedTargets.length,
                    successfulFingerprints: successful.length,
                    failedFingerprints: normalizedTargets.length - successful.length,
                    identifiedProducts: successful.filter((result) => Boolean(result.productName)).length,
                },
                surface_artifacts: {
                    services,
                    fingerprints,
                    evidences,
                    relations,
                },
            },
        };
    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

globalThis.analyze = analyze;
