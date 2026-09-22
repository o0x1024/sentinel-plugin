/**
 * Comprehensive functional test for all bounty plugins.
 * Validates real output structure, data quality, and surface artifacts.
 *
 * Usage: deno run --allow-read --allow-net scripts/bounty_functional_test.ts
 */

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

function buildHtml(url: URL): string {
    return `<!doctype html>
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
  </body>
</html>`;
}

function buildJsBundle(): string {
    return `window.__APP_CONFIG__ = {
  apiBase: "/api",
  graphql: "/graphql",
  auth: "/api/auth/login",
  upload: "/api/upload",
  githubToken: "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
  stripeKey: "pk_live_abcdefghijklmnopqrstuvwxyz"
};
fetch("/api/health");
fetch("/api/users");
fetch("/rest/v1/projects");`;
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

async function fetchStub(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const requestUrl = typeof input === "string"
        ? input
        : input instanceof URL
            ? input.toString()
            : input.url;
    const url = new URL(requestUrl);
    const pathname = normalizePathname(url.pathname);

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
        AST: {
            parse(code: string, _filename?: string) {
                const literals: Array<{ type: string; value: string; line?: number }> = [];
                const fetchRegex = /fetch\(["']([^"']+)["']\)/g;
                let match;
                while ((match = fetchRegex.exec(code)) !== null) {
                    literals.push({ type: "string", value: match[1] });
                }
                const propRegex = /:\s*["']([^"']+)["']/g;
                while ((match = propRegex.exec(code)) !== null) {
                    literals.push({ type: "string", value: match[1] });
                }
                return {
                    success: true,
                    literals,
                    errors: [],
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

// --- Test definitions ---

interface TestCase {
    pluginId: string;
    file: string;
    input: Record<string, unknown>;
    validate: (output: any) => string[];
}

function assertField(obj: any, path: string, check?: (val: any) => boolean): string | null {
    const parts = path.split(".");
    let current = obj;
    for (const part of parts) {
        if (current == null || typeof current !== "object") {
            return `Missing field: ${path}`;
        }
        current = current[part];
    }
    if (current === undefined || current === null) {
        return `Missing field: ${path}`;
    }
    if (check && !check(current)) {
        return `Field ${path} failed validation (value: ${JSON.stringify(current).slice(0, 100)})`;
    }
    return null;
}

function assertArrayNotEmpty(obj: any, path: string): string | null {
    return assertField(obj, path, (val) => Array.isArray(val) && val.length > 0);
}

function assertNumber(obj: any, path: string, minVal?: number): string | null {
    return assertField(obj, path, (val) => typeof val === "number" && (minVal === undefined || val >= minVal));
}

const bountyTests: TestCase[] = [
    {
        pluginId: "subdomain_enumerator",
        file: "subdomain_enumerator.ts",
        input: { domain: "example.com", sources: ["crtsh"], removeDuplicates: true },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertField(output, "data.subdomains", (v) => Array.isArray(v)));
            e(assertArrayNotEmpty(output, "data.sourceResults"));
            e(assertField(output, "data.summary"));
            e(assertNumber(output, "data.summary.totalUnique", 0));
            if (output.data?.surface_artifacts) {
                e(assertArrayNotEmpty(output, "data.surface_artifacts.domains"));
            }
            return errors;
        },
    },
    {
        pluginId: "dns_resolver",
        file: "dns_resolver.ts",
        input: { targets: ["example.com"], recordTypes: ["A", "CNAME", "TXT"], concurrency: 4 },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertField(output, "data.summary"));
            e(assertNumber(output, "data.summary.totalRecords", 1));
            e(assertNumber(output, "data.summary.successfulTargets", 1));
            e(assertArrayNotEmpty(output, "data.surface_artifacts.domains"));
            e(assertArrayNotEmpty(output, "data.surface_artifacts.ips"));
            return errors;
        },
    },
    {
        pluginId: "cidr_mapper",
        file: "cidr_mapper.ts",
        input: { targets: ["203.0.113.0/30"], maxHosts: 8, includeNetworkBroadcast: false },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertNumber(output, "data.summary.generatedIps", 1));
            e(assertArrayNotEmpty(output, "data.surface_artifacts.ips"));
            const ips = output.data?.surface_artifacts?.ips;
            if (Array.isArray(ips)) {
                if (ips.length !== 2) {
                    errors.push(`Expected 2 IPs from /30 (no broadcast), got ${ips.length}`);
                }
                for (const ip of ips) {
                    if (!ip.ip_address) errors.push("IP artifact missing ip_address");
                }
            }
            return errors;
        },
    },
    {
        pluginId: "http_prober",
        file: "http_prober.ts",
        input: { targets: ["https://example.com"], followRedirects: true, ports: [80, 443] },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertField(output, "data.summary"));
            const results = output.data?.results;
            if (Array.isArray(results) && results.length > 0) {
                const r = results[0];
                if (!r.alive && !r.isAlive) errors.push("http_prober: first result is not alive");
                if (!r.title && !r.statusCode) errors.push("http_prober: missing title or statusCode");
            }
            if (output.data?.surface_artifacts) {
                e(assertArrayNotEmpty(output, "data.surface_artifacts.webs"));
            }
            return errors;
        },
    },
    {
        pluginId: "tech_fingerprinter",
        file: "tech_fingerprinter.ts",
        input: {
            targets: ["https://example.com"],
            dictionaryEntries: dictionaryEntriesById.builtin_web_fingerprint_rules,
        },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            const results = output.data?.results;
            if (Array.isArray(results) && results.length > 0) {
                const r = results[0];
                if (!r.technologies && !r.fingerprints && !r.matches) {
                    errors.push("tech_fingerprinter: no technology detection results");
                }
            }
            return errors;
        },
    },
    {
        pluginId: "favicon_fingerprinter",
        file: "favicon_fingerprinter.ts",
        input: { targets: ["https://example.com/static/font/favicon.ico"] },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            const results = output.data?.results;
            if (Array.isArray(results) && results.length > 0) {
                const r = results[0];
                if (r.faviconHash === undefined && r.faviconHash !== 0) {
                    errors.push(`favicon_fingerprinter: missing faviconHash (keys: ${Object.keys(r).join(",")})`);
                }
            }
            return errors;
        },
    },
    {
        pluginId: "service_probe",
        file: "service_probe.ts",
        input: {
            service_targets: [{ host: "example.com", port: 443, protocol: "https" }],
            serviceProbeEngine: "native",
        },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            const results = output.data?.results;
            if (Array.isArray(results) && results.length > 0) {
                const r = results[0];
                if (!r.serviceName && !r.service_name && !r.service) {
                    errors.push("service_probe: missing service name");
                }
            }
            return errors;
        },
    },
    {
        pluginId: "directory_bruteforcer",
        file: "directory_bruteforcer.ts",
        input: { url: "https://example.com", wordlist: "common", concurrency: 4 },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertField(output, "data.summary"));
            if (output.data?.results && Array.isArray(output.data.results)) {
                for (const r of output.data.results) {
                    if (!r.url && !r.path) errors.push("directory_bruteforcer: result missing url/path");
                }
            }
            return errors;
        },
    },
    {
        pluginId: "js_analyzer",
        file: "js_analyzer.ts",
        input: { urls: ["https://example.com"], followImports: true, maxJsFiles: 4 },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertField(output, "data.summary"));
            if (output.data?.endpoints && Array.isArray(output.data.endpoints)) {
                if (output.data.endpoints.length === 0) {
                    errors.push("js_analyzer: no endpoints extracted");
                }
            } else if (output.data?.results && Array.isArray(output.data.results)) {
                let hasEndpoints = false;
                for (const r of output.data.results) {
                    if (r.endpoints?.length > 0 || r.apiEndpoints?.length > 0) hasEndpoints = true;
                }
                if (!hasEndpoints) errors.push("js_analyzer: no endpoints extracted from results");
            }
            return errors;
        },
    },
    {
        pluginId: "sensitive_file_scanner",
        file: "sensitive_file_scanner.ts",
        input: {
            targets: ["https://example.com"],
            dictionaryEntries: dictionaryEntriesById.builtin_sensitive_files_web,
        },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertField(output, "data.summary"));
            if (output.data?.results && Array.isArray(output.data.results)) {
                const found = output.data.results.filter((r: any) =>
                    r.found || r.exposed || r.status === 200 || r.matched
                );
                if (found.length === 0) {
                    errors.push("sensitive_file_scanner: expected .env to be detected as exposed");
                }
            }
            return errors;
        },
    },
    {
        pluginId: "risk_scanner",
        file: "risk_scanner.ts",
        input: {
            targets: ["https://example.com"],
            dictionaryEntries: dictionaryEntriesById.builtin_safe_poc_rules,
        },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertField(output, "data.summary"));
            if (output.data?.results && Array.isArray(output.data.results)) {
                const verified = output.data.results.filter((r: any) => r.verified || r.matched || r.confirmed);
                if (verified.length === 0) {
                    errors.push("risk_scanner: expected health-check rule to match");
                }
            }
            return errors;
        },
    },
    {
        pluginId: "subdomain_takeover",
        file: "subdomain_takeover.ts",
        input: { subdomains: ["orphan.example.com"], concurrency: 2, checkCname: true, checkHttp: true },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertField(output, "data.summary"));
            return errors;
        },
    },
    {
        pluginId: "service_monitor",
        file: "service_monitor.ts",
        input: {
            service_targets: [{ host: "example.com", port: 443, protocol: "https" }],
            serviceProbeEngine: "native",
        },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertField(output, "data.snapshots"));
            return errors;
        },
    },
    {
        pluginId: "fofa_asset_monitor",
        file: "fofa_asset_monitor.ts",
        input: {
            fofaKey: "smoke-fofa-key",
            domains: ["example.com"],
            pageSize: 10,
            maxPages: 1,
        },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertField(output, "data.summary"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertArrayNotEmpty(output, "data.assets"));
            const results = output.data?.results;
            if (Array.isArray(results) && results.length > 0 && results[0].assets) {
                if (results[0].assets.length === 0) {
                    errors.push("fofa_asset_monitor: results[0].assets is empty");
                }
            }
            e(assertNumber(output, "data.summary.totalAssets", 1));
            return errors;
        },
    },
    {
        pluginId: "cert_monitor",
        file: "cert_monitor.ts",
        input: { targets: ["example.com"], checkExpiry: true },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertField(output, "data.snapshots"));
            const results = output.data?.results;
            if (Array.isArray(results) && results.length > 0) {
                const r = results[0];
                if (!r.certInfo?.subject) {
                    errors.push(`cert_monitor: missing certInfo.subject (keys: ${Object.keys(r).join(",")})`);
                }
                if (r.daysUntilExpiry === undefined) {
                    errors.push("cert_monitor: missing daysUntilExpiry");
                }
            }
            return errors;
        },
    },
    {
        pluginId: "content_monitor",
        file: "content_monitor.ts",
        input: { targets: ["https://example.com"], includeHeaders: true },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertField(output, "data.snapshots"));
            const results = output.data?.results;
            if (Array.isArray(results) && results.length > 0) {
                const r = results[0];
                if (!r.snapshot?.contentHash) {
                    errors.push(`content_monitor: missing snapshot.contentHash (keys: ${Object.keys(r).join(",")})`);
                }
            }
            return errors;
        },
    },
    {
        pluginId: "api_monitor",
        file: "api_monitor.ts",
        input: { targets: ["https://example.com"], crawlDepth: 1, maxJsFiles: 4, probeSpaManifests: false },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertField(output, "data.summary"));
            e(assertField(output, "data.snapshots"));
            return errors;
        },
    },
    {
        pluginId: "port_monitor",
        file: "port_monitor.ts",
        input: {
            service_targets: [{ host: "example.com", port: 443, protocol: "https" }],
            ports: [80, 443],
        },
        validate(output) {
            const errors: string[] = [];
            const e = (msg: string | null) => { if (msg) errors.push(msg); };
            e(assertField(output, "data"));
            e(assertArrayNotEmpty(output, "data.results"));
            e(assertField(output, "data.snapshots"));
            e(assertField(output, "data.summary"));
            return errors;
        },
    },
];

// --- Runner ---

interface TestResult {
    pluginId: string;
    status: "pass" | "fail" | "error";
    errors: string[];
    outputKeys?: string[];
    surfaceArtifactTypes?: string[];
    duration: number;
}

async function runTest(test: TestCase): Promise<TestResult> {
    const start = performance.now();
    try {
        const moduleUrl = new URL(`../plugins/bounty/${test.file}`, import.meta.url);
        const module = await import(`${moduleUrl.href}?test=${Date.now()}-${test.pluginId}`);

        if (typeof module.get_input_schema !== "function") {
            return { pluginId: test.pluginId, status: "error", errors: ["Missing get_input_schema"], duration: performance.now() - start };
        }
        if (typeof module.get_output_schema !== "function") {
            return { pluginId: test.pluginId, status: "error", errors: ["Missing get_output_schema"], duration: performance.now() - start };
        }
        if (typeof module.analyze !== "function") {
            return { pluginId: test.pluginId, status: "error", errors: ["Missing analyze function"], duration: performance.now() - start };
        }

        const inputSchema = module.get_input_schema();
        if (!inputSchema || typeof inputSchema !== "object") {
            return { pluginId: test.pluginId, status: "error", errors: ["Invalid input schema"], duration: performance.now() - start };
        }

        const output = await module.analyze(test.input);
        const duration = performance.now() - start;

        if (!output || typeof output !== "object") {
            return { pluginId: test.pluginId, status: "error", errors: ["analyze returned non-object"], duration };
        }

        const errors: string[] = [];
        if (output.success !== true) {
            errors.push(`analyze returned success=false: ${output.error || "unknown"}`);
        }

        const validationErrors = test.validate(output);
        errors.push(...validationErrors);

        const outputKeys = output.data ? Object.keys(output.data) : [];
        const surfaceArtifactTypes = output.data?.surface_artifacts
            ? Object.keys(output.data.surface_artifacts)
            : [];

        return {
            pluginId: test.pluginId,
            status: errors.length > 0 ? "fail" : "pass",
            errors,
            outputKeys,
            surfaceArtifactTypes,
            duration,
        };
    } catch (error) {
        return {
            pluginId: test.pluginId,
            status: "error",
            errors: [error instanceof Error ? `${error.message}\n${error.stack}` : String(error)],
            duration: performance.now() - start,
        };
    }
}

async function main(): Promise<void> {
    installRuntimeStubs();

    console.log("=== Bounty Plugin Functional Test ===\n");
    console.log(`Testing ${bountyTests.length} plugins...\n`);

    const results: TestResult[] = [];
    for (const test of bountyTests) {
        const result = await runTest(test);
        results.push(result);

        const icon = result.status === "pass" ? "PASS" : result.status === "fail" ? "FAIL" : "ERR ";
        const durStr = `${result.duration.toFixed(0)}ms`;
        console.log(`[${icon}] ${result.pluginId.padEnd(28)} ${durStr.padStart(6)}`);
        if (result.errors.length > 0) {
            for (const err of result.errors) {
                console.log(`       -> ${err}`);
            }
        }
        if (result.outputKeys && result.outputKeys.length > 0) {
            console.log(`       data keys: ${result.outputKeys.join(", ")}`);
        }
        if (result.surfaceArtifactTypes && result.surfaceArtifactTypes.length > 0) {
            console.log(`       surface artifacts: ${result.surfaceArtifactTypes.join(", ")}`);
        }
    }

    const passed = results.filter((r) => r.status === "pass");
    const failed = results.filter((r) => r.status !== "pass");

    console.log(`\n=== Summary ===`);
    console.log(`Total: ${results.length}  Passed: ${passed.length}  Failed: ${failed.length}`);

    if (failed.length > 0) {
        console.log(`\nFailed plugins:`);
        for (const f of failed) {
            console.log(`  - ${f.pluginId}: ${f.errors.join("; ").slice(0, 200)}`);
        }
        Deno.exit(1);
    } else {
        console.log(`\nAll bounty plugins passed functional testing!`);
    }
}

await main();
