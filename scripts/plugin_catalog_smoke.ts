interface ManifestPlugin {
    id: string;
    name: string;
    main_category: string;
    download_url: string;
}

interface ManifestFile {
    version: string;
    updated_at: string;
    plugins: ManifestPlugin[];
}

interface SmokeResult {
    id: string;
    name: string;
    mainCategory: string;
    localPath: string | null;
    status: "passed" | "failed";
    detail: string;
}

type TrafficTransaction = {
    request: {
        id: string;
        method: string;
        url: string;
        headers: Record<string, string>;
        body: number[];
        content_type?: string;
        query_params: Record<string, string>;
        is_https: boolean;
        timestamp: string;
    };
    response?: {
        request_id: string;
        status: number;
        headers: Record<string, string>;
        body: number[];
        content_type?: string;
        timestamp: string;
    };
};

const manifestUrl = new URL("../plugins.json", import.meta.url);
const repoRootUrl = new URL("../", import.meta.url);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const iconBytes = Uint8Array.from([0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0, 104, 4, 0, 0, 22, 0, 0, 0]);
const nowIso = new Date().toISOString();

const dictionaryEntriesById: Record<string, Array<Record<string, unknown>>> = {
    builtin_web_fingerprint_rules: [
        {
            id: "fingerprint-nextjs",
            word: "nextjs",
            category: "framework",
            metadata: {
                name: "Next.js",
                product: "Next.js",
                asset_category: "framework",
                matchers: [
                    { part: "body", type: "contains", value: "__NEXT_DATA__" },
                ],
            },
        },
    ],
    builtin_favicon_fingerprint_rules: [
        {
            id: "favicon-example",
            word: "-361114133",
            category: "web",
            metadata: {
                name: "Example Favicon",
                product: "Example",
                asset_category: "website",
                matchers: [{ part: "hash", type: "contains", value: "-" }],
            },
        },
    ],
    builtin_safe_poc_rules: [
        {
            id: "risk-health",
            word: "health-check",
            category: "verification",
            metadata: {
                severity: "low",
                requests: [
                    {
                        method: "GET",
                        path: "/health",
                        matchers: [
                            { part: "status", type: "equals", value: 200 },
                            { part: "body", type: "contains", value: "status=ok" },
                        ],
                    },
                ],
            },
        },
    ],
    builtin_sensitive_files_web: [
        {
            id: "sensitive-env",
            word: ".env",
            category: "config",
            metadata: {
                path: ".env",
                severity: "medium",
                matchers: [
                    { part: "status", type: "equals", value: 200 },
                    { part: "body", type: "contains", value: "DB_PASSWORD=" },
                ],
            },
        },
    ],
    "Favicon Fingerprint Rules": [],
    "Safe POC Rules": [],
    "Sensitive Files Web": [],
    "Web Fingerprint Rules": [],
};

function bytes(text: string): Uint8Array {
    return encoder.encode(text);
}

function normalizePathname(pathname: string): string {
    return pathname.endsWith("/") && pathname !== "/" ? pathname.slice(0, -1) : pathname;
}

function readBodyText(body: BodyInit | null | undefined): string {
    if (typeof body === "string") return body;
    if (body instanceof Uint8Array) return decoder.decode(body);
    if (body instanceof ArrayBuffer) return decoder.decode(new Uint8Array(body));
    return "";
}

function activeProbeMetadata(init?: RequestInit): Record<string, unknown> | null {
    const probe = (init as RequestInit & { activeProbe?: unknown })?.activeProbe;
    if (!probe || probe === true) return {};
    if (typeof probe === "object") {
        const metadata = probe as Record<string, unknown>;
        if (metadata.probeLabel != null && metadata.probe_label == null) {
            return { ...metadata, probe_label: metadata.probeLabel };
        }
        return metadata;
    }
    return {};
}

function buildHtml(url: URL): string {
    const reflectedValues = [...url.searchParams.entries()]
        .map(([key, value]) => `<div data-param="${key}">${value}</div>`)
        .join("");
    return `
<!doctype html>
<html>
  <head>
    <title>Smoke App</title>
    <meta name="generator" content="Next.js">
    <link rel="icon" href="/static/font/favicon.ico">
    <script src="/assets/app.js"></script>
    <script id="__NEXT_DATA__" type="application/json">{"buildId":"smoke-build","page":"/"}</script>
  </head>
  <body>
    <h1>Smoke App</h1>
    <a href="/dashboard">Dashboard</a>
    ${reflectedValues}
  </body>
</html>`.trim();
}

function buildJsBundle(): string {
    return `
window.__APP_CONFIG__ = {
  apiBase: "/api",
  graphql: "/graphql",
  auth: "/api/auth/login",
  upload: "/api/upload",
  githubToken: "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
  stripeKey: "pk_live_abcdefghijklmnopqrstuvwxyz"
};
fetch("/api/health");
fetch("/api/users");
fetch("/rest/v1/projects");
`.trim();
}

async function fetchStub(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const requestUrl = typeof input === "string"
        ? input
        : input instanceof URL
            ? input.toString()
            : input.url;
    const url = new URL(requestUrl);
    const pathname = normalizePathname(url.pathname);
    const bodyText = readBodyText(init?.body);
    const probe = activeProbeMetadata(init);
    const probeValue = String(probe?.probe_value || "");
    const originHeader = String(init?.headers instanceof Headers
        ? init.headers.get("Origin") || ""
        : (init?.headers as Record<string, string> | undefined)?.Origin
            || (init?.headers as Record<string, string> | undefined)?.origin
            || "");

    if (url.hostname === "fofa.info" && pathname === "/api/v1/search/all") {
        return Response.json({
            error: false,
            size: 1,
            page: 1,
            mode: "extended",
            query: url.searchParams.get("qbase64") || "",
            results: [
                {
                    host: "app.example.com",
                    ip: "203.0.113.10",
                    port: 443,
                    protocol: "https",
                    title: "Smoke App",
                    domain: "example.com",
                    lastupdatetime: "2026-05-09 10:00:00",
                    country_name: "CN",
                    region: "Shanghai",
                    city: "Shanghai",
                    server: "nginx/1.25.3",
                    product: "Next.js",
                    product_category: "framework",
                    version: "14.2.0",
                    cname: "edge.example.net",
                },
            ],
        });
    }

    if (url.hostname === "crt.sh") {
        return Response.json([
            { name_value: "app.example.com\napi.example.com" },
        ]);
    }

    if (pathname === "/favicon.ico" || pathname.endsWith(".ico")) {
        return new Response(iconBytes, {
            status: 200,
            headers: {
                "content-type": "image/x-icon",
                "content-length": String(iconBytes.byteLength),
            },
        });
    }

    if (pathname === "/assets/app.js" || pathname.endsWith(".js")) {
        return new Response(buildJsBundle(), {
            status: 200,
            headers: {
                "content-type": "application/javascript",
                "server": "nginx/1.25.3",
            },
        });
    }

    if (pathname.endsWith(".map")) {
        return Response.json({
            version: 3,
            file: "app.js",
            sources: ["app.ts"],
            sourcesContent: [buildJsBundle()],
            names: [],
            mappings: "",
        });
    }

    if (pathname === "/manifest.json" || pathname === "/asset-manifest.json" || pathname === "/.vite/manifest.json") {
        return Response.json({
            "app.js": "/assets/app.js",
            "vendor.js": "/assets/vendor.js",
        });
    }

    if (pathname === "/health") {
        return new Response("status=ok", {
            status: 200,
            headers: { "content-type": "text/plain", "server": "nginx/1.25.3" },
        });
    }

    if (pathname === "/.env") {
        return new Response("DB_PASSWORD=sentinel-smoke\nAPP_KEY=test\n", {
            status: 200,
            headers: { "content-type": "text/plain" },
        });
    }

    if (pathname.startsWith("/api/") || pathname === "/graphql" || pathname === "/rest/v1/projects") {
        return Response.json({
            ok: true,
            endpoint: pathname,
            data: [{ id: 1, name: "smoke" }],
        }, {
            status: 200,
            headers: { "server": "nginx/1.25.3" },
        });
    }

    if (originHeader) {
        return new Response(buildHtml(url), {
            status: 200,
            headers: {
                "content-type": "text/html; charset=utf-8",
                "access-control-allow-origin": originHeader,
                "access-control-allow-credentials": "true",
                "server": "nginx/1.25.3",
            },
        });
    }

    if (bodyText.includes("evil.com") || requestUrl.includes("evil.com")) {
        return new Response("", {
            status: 302,
            headers: {
                "location": "https://evil.com",
                "server": "nginx/1.25.3",
            },
        });
    }

    if (probeValue) {
        if (String(probe?.technique || "").includes("xss")) {
            return new Response(`<html><body>${probeValue}</body></html>`, {
                status: 200,
                headers: { "content-type": "text/html; charset=utf-8", "server": "nginx/1.25.3" },
            });
        }
        if (String(probe?.technique || "") === "error-based") {
            return new Response("You have an error in your SQL syntax near ''", {
                status: 500,
                headers: { "content-type": "text/html; charset=utf-8", "server": "nginx/1.25.3" },
            });
        }
    }

    if (requestUrl.includes("169.254.169.254") || requestUrl.includes("localhost") || requestUrl.includes("127.0.0.1")) {
        return new Response("internal metadata service", {
            status: 200,
            headers: { "content-type": "text/plain" },
        });
    }

    if (pathname === "/") {
        return new Response(buildHtml(url), {
            status: 200,
            headers: {
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.25.3",
                "x-powered-by": "Next.js",
            },
        });
    }

    return new Response("not found", {
        status: 404,
        headers: { "content-type": "text/plain" },
    });
}

function installRuntimeStubs(): void {
    (globalThis as Record<string, unknown>).Sentinel = {
        log: () => undefined,
        emitFinding: () => true,
        Dictionary: {
            async getEntries(idOrName: string) {
                return dictionaryEntriesById[idOrName] || [];
            },
            async getDefaultId(dictType: string) {
                if (dictType === "fingerprint_rule") return "builtin_web_fingerprint_rules";
                if (dictType === "poc_rule") return "builtin_safe_poc_rules";
                if (dictType === "sensitive_file") return "builtin_sensitive_files_web";
                if (dictType === "service_fingerprint") return null;
                return null;
            },
            async getWords(_idOrName: string) {
                return [".env", "admin", "backup", "login"];
            },
        },
        Monitor: {
            async reportProgress() {
                return true;
            },
        },
        Network: {
            async scanPorts(request: { targets: Array<{ host: string; ports?: number[] }>; ports: number[] }) {
                return {
                    success: true,
                    results: request.targets.map((target) => ({
                        host: target.host,
                        open_ports: (target.ports && target.ports.length > 0 ? target.ports : request.ports).slice(0, 2),
                    })),
                };
            },
            async probeServices(request: { targets: Array<{ host: string; port: number; protocol: string }> }) {
                return {
                    success: true,
                    ruleCount: 0,
                    engineRequested: "native",
                    engineUsed: "native",
                    engineExperimental: false,
                    results: request.targets.map((target) => ({
                        target: `${target.host}:${target.port}/${target.protocol}`,
                        success: true,
                        available: true,
                        host: target.host,
                        port: target.port,
                        protocol: target.protocol,
                        serviceName: target.protocol === "https" ? "https" : "http",
                        productName: "nginx",
                        vendor: "NGINX",
                        version: "1.25.3",
                        banner: "HTTP/1.1 200 OK",
                        serverHeader: "nginx/1.25.3",
                        title: "Smoke App",
                        statusCode: 200,
                        confidence: 0.95,
                    })),
                };
            },
            async getServiceProbeCapabilities() {
                return {
                    default_engine: "native",
                    engines: [{ id: "native", experimental: false, available: true, implemented: true }],
                };
            },
        },
        TLS: {
            async getCertificate(domain: string) {
                return {
                    success: true,
                    cert: {
                        subject: `CN=${domain}`,
                        issuer: "CN=Smoke CA",
                        validFrom: nowIso,
                        validTo: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
                        fingerprint: "AA:BB:CC:DD",
                        serialNumber: "01AB",
                        altNames: [domain, `www.${domain}`],
                        protocol: "TLSv1.3",
                        cipher: "TLS_AES_128_GCM_SHA256",
                    },
                };
            },
        },
    };

    (globalThis as Record<string, unknown>).SecurityUtils = {
        randomString(length: number) {
            return "x".repeat(Math.max(1, length));
        },
    };

    globalThis.fetch = fetchStub;
    (Deno as unknown as { resolveDns?: (name: string, recordType: string) => Promise<unknown[]> }).resolveDns = async (
        name: string,
        recordType: string,
    ) => {
        if (recordType === "A") return ["203.0.113.10"];
        if (recordType === "AAAA") return ["2001:db8::10"];
        if (recordType === "CNAME") return [`edge.${name}`];
        if (recordType === "MX") return [{ preference: 10, exchange: `mail.${name}` }];
        if (recordType === "NS") return [`ns1.${name}`, `ns2.${name}`];
        if (recordType === "TXT") return [["v=spf1 include:_spf.example.com ~all"]];
        return [];
    };
}

function resolveLocalPluginPath(downloadUrl: string): URL {
    const marker = "/main/plugins/";
    const markerIndex = downloadUrl.indexOf(marker);
    if (markerIndex < 0) {
        throw new Error(`Unsupported download_url: ${downloadUrl}`);
    }
    const relativePath = downloadUrl.slice(markerIndex + marker.length);
    return new URL(`../plugins/${relativePath}`, import.meta.url);
}

function toArrayBody(text: string): number[] {
    return Array.from(bytes(text));
}

function sampleTrafficTransaction(): TrafficTransaction {
    const requestUrl = "https://example.com/search?q=test&next=%2Fdashboard&url=https%3A%2F%2Fexample.com";
    return {
        request: {
            id: "req-1",
            method: "GET",
            url: requestUrl,
            headers: {
                host: "example.com",
                accept: "text/html",
                authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
            },
            body: [],
            content_type: "text/plain",
            query_params: {
                q: "test",
                next: "/dashboard",
                url: "https://example.com",
            },
            is_https: true,
            timestamp: nowIso,
        },
        response: {
            request_id: "req-1",
            status: 200,
            headers: {
                "content-type": "text/html; charset=utf-8",
                server: "nginx/1.25.3",
            },
            body: toArrayBody(`<html><body>token=AKIAIOSFODNN7EXAMPLE Authorization: Bearer eyJhbGciOiJIUzI1NiJ9 next=/dashboard</body></html>`),
            content_type: "text/html; charset=utf-8",
            timestamp: nowIso,
        },
    };
}

function buildInputForPlugin(plugin: ManifestPlugin): Record<string, unknown> {
    switch (plugin.id) {
        case "intruder_dictionary_payload_generator":
            return { config: { preset: "custom", values: ["alpha", "beta"], limit: 10 } };
        case "intruder_hmac_request_signer":
            return {
                rawRequest: "GET /orders HTTP/1.1\r\nHost: example.com\r\nX-Test: 1\r\n\r\n",
                config: { secret: "sentinel-secret", algorithm: "SHA-256", headerName: "X-Signature" },
            };
        case "nextjs_rce_scanner":
            return { targets: ["https://example.com"], detectOnly: true };
        case "subdomain_enumerator":
            return { domain: "example.com", sources: ["crtsh"], removeDuplicates: true };
        case "dns_resolver":
            return { targets: ["example.com"], recordTypes: ["A", "CNAME", "TXT"], concurrency: 4 };
        case "cidr_mapper":
            return { targets: ["203.0.113.0/30"], maxHostsPerCidr: 8, includeNetworkAndBroadcast: false };
        case "http_prober":
            return { targets: ["https://example.com"], followRedirects: true, ports: [80, 443] };
        case "tech_fingerprinter":
            return {
                targets: ["https://example.com"],
                dictionaryEntries: dictionaryEntriesById.builtin_web_fingerprint_rules,
            };
        case "sensitive_file_scanner":
            return {
                targets: ["https://example.com"],
                dictionaryEntries: dictionaryEntriesById.builtin_sensitive_files_web,
            };
        case "risk_scanner":
            return {
                targets: ["https://example.com"],
                dictionaryEntries: dictionaryEntriesById.builtin_safe_poc_rules,
            };
        case "favicon_fingerprinter":
            return { targets: ["https://example.com/static/font/favicon.ico"] };
        case "service_monitor":
        case "service_probe":
            return {
                service_targets: [{ host: "example.com", port: 443, protocol: "https" }],
                serviceProbeEngine: "native",
            };
        case "fofa_asset_monitor":
            return {
                fofaKey: "smoke-fofa-key",
                domains: ["example.com"],
                pageSize: 10,
                maxPages: 1,
            };
        case "directory_bruteforcer":
            return { url: "https://example.com", wordlist: "common", concurrency: 4 };
        case "js_analyzer":
            return { urls: ["https://example.com"], analyzeImports: true, maxJsFiles: 4 };
        case "cert_monitor":
            return { targets: ["https://example.com"], checkExpiry: true };
        case "content_monitor":
            return { targets: ["https://example.com"], includeHeaders: true };
        case "api_monitor":
            return { targets: ["https://example.com"], crawlDepth: 1, maxJsFiles: 4, probeSpaManifests: false };
        case "port_monitor":
            return {
                service_targets: [{ host: "example.com", port: 443, protocol: "https" }],
                ports: [80, 443],
            };
        case "ssrf_detector":
            return {
                url: "https://example.com/fetch?url=https://example.com",
                method: "GET",
                params: { url: "https://example.com" },
            };
        case "subdomain_takeover":
            return {
                subdomains: ["orphan.example.com"],
                concurrency: 2,
                checkCname: true,
                checkHttp: true,
            };
        case "cors_misconfiguration":
            return { url: "https://example.com", method: "GET" };
        case "open_redirect_detector":
            return {
                url: "https://example.com/redirect?next=/dashboard",
                method: "GET",
                params: { next: "/dashboard" },
            };
        case "xss_scanner":
            return {
                url: "https://example.com/search?q=test",
                method: "GET",
                params: { q: "test" },
            };
        case "sql_injection_scanner":
            return {
                url: "https://example.com/search?id=1",
                method: "GET",
                params: { id: "1" },
                testErrorBased: true,
                testBlindBoolean: false,
                testTimeBased: false,
            };
        default:
            return { targets: ["https://example.com"] };
    }
}

async function runManifestPlugin(plugin: ManifestPlugin): Promise<SmokeResult> {
    let localUrl: URL;
    try {
        localUrl = resolveLocalPluginPath(plugin.download_url);
    } catch (error) {
        return {
            id: plugin.id,
            name: plugin.name,
            mainCategory: plugin.main_category,
            localPath: null,
            status: "failed",
            detail: error instanceof Error ? error.message : String(error),
        };
    }

    try {
        await Deno.stat(localUrl);
    } catch {
        return {
            id: plugin.id,
            name: plugin.name,
            mainCategory: plugin.main_category,
            localPath: localUrl.pathname,
            status: "failed",
            detail: "Local plugin file referenced by plugins.json does not exist",
        };
    }

    try {
        const module = await import(`${localUrl.href}?smoke=${Date.now()}-${plugin.id}`);
        if (plugin.main_category === "traffic") {
            if (typeof module.scan_transaction !== "function") {
                throw new Error("Missing exported scan_transaction function");
            }
            const findings = await module.scan_transaction(sampleTrafficTransaction());
            if (!Array.isArray(findings)) {
                throw new Error("scan_transaction did not return an array");
            }
            return {
                id: plugin.id,
                name: plugin.name,
                mainCategory: plugin.main_category,
                localPath: localUrl.pathname,
                status: "passed",
                detail: `scan_transaction ok (${findings.length} findings)`,
            };
        }

        if (typeof module.get_input_schema !== "function") {
            throw new Error("Missing exported get_input_schema function");
        }
        if (typeof module.get_output_schema !== "function") {
            throw new Error("Missing exported get_output_schema function");
        }
        if (typeof module.analyze !== "function") {
            throw new Error("Missing exported analyze function");
        }

        const inputSchema = module.get_input_schema();
        const outputSchema = module.get_output_schema();
        if (!inputSchema || typeof inputSchema !== "object") {
            throw new Error("get_input_schema returned an invalid value");
        }
        if (!outputSchema || typeof outputSchema !== "object") {
            throw new Error("get_output_schema returned an invalid value");
        }

        const output = await module.analyze(buildInputForPlugin(plugin));
        if (!output || typeof output !== "object") {
            throw new Error("analyze returned an invalid value");
        }
        if (output.success !== true) {
            throw new Error(String(output.error || "analyze returned success=false"));
        }

        return {
            id: plugin.id,
            name: plugin.name,
            mainCategory: plugin.main_category,
            localPath: localUrl.pathname,
            status: "passed",
            detail: "analyze ok",
        };
    } catch (error) {
        return {
            id: plugin.id,
            name: plugin.name,
            mainCategory: plugin.main_category,
            localPath: localUrl.pathname,
            status: "failed",
            detail: error instanceof Error ? error.message : String(error),
        };
    }
}

async function main(): Promise<void> {
    installRuntimeStubs();
    const manifest = JSON.parse(await Deno.readTextFile(manifestUrl)) as ManifestFile;
    const results: SmokeResult[] = [];
    for (const plugin of manifest.plugins) {
        results.push(await runManifestPlugin(plugin));
    }

    const passed = results.filter((item) => item.status === "passed");
    const failed = results.filter((item) => item.status === "failed");

    console.log(JSON.stringify({
        manifestVersion: manifest.version,
        updatedAt: manifest.updated_at,
        repoRoot: repoRootUrl.pathname,
        totalPlugins: results.length,
        passed: passed.length,
        failed: failed.length,
        failures: failed,
    }, null, 2));
}

await main();
