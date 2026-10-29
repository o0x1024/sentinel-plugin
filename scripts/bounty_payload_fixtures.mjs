/** Deterministic, bounded fixtures for producer-envelope benchmarks. No I/O. */
import { monitorExecution } from './monitor_stream_fixture.ts';

const date = '2026-10-29T00:00:00Z';
const icon = Uint8Array.from([0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0, 104, 4, 0, 0, 22, 0, 0, 0]);
const featureRule = { id: 'fixture-php', word: 'php', category: 'programming_language', metadata: {
    name: 'PHP', product: 'PHP', asset_category: 'programming_language',
    matchers: [{ part: 'header', key: 'x-powered-by', type: 'contains', value: 'PHP' }],
} };
const serviceRule = { id: 'fixture-nginx', word: 'nginx', category: 'web_server', metadata: {
    name: 'nginx', product: 'nginx', asset_category: 'web_server',
    matchers: [{ part: 'header', type: 'contains', value: 'nginx' }],
} };
const riskRules = [0, 1].map(index => ({ id: `risk-${index}`, word: `risk-${index}`, category: 'verification', metadata: {
    name: `Owned rule ${index}`, severity: 'low', requests: [{ method: 'GET', path: '/health',
        matchers: [{ part: 'status', type: 'equals', value: 200 }, { part: 'body', type: 'contains', value: 'status=ok' }] }],
} }));
const sensitiveRules = [0, 1].map(index => ({ id: `file-${index}`, word: `fixture-config-${index}`, category: 'config', metadata: {
    path: `/fixture-config-${index}`, name: `Owned configuration ${index}`, severity: 'low',
    matchers: [{ part: 'status', type: 'equals', value: 200 }, { part: 'body', type: 'contains', value: 'OWNED_FIXTURE=yes' }],
} }));
const faviconRule = { id: 'fixture-favicon', word: '-361114133', category: 'website', metadata: {
    name: 'Owned favicon', product: 'Owned', asset_category: 'website',
    matchers: [{ part: 'hash', type: 'contains', value: '-' }],
} };

function html() {
    return '<html><head><title>Owned benchmark</title><link rel="icon" href="/favicon.ico"><script src="/app.js"></script></head><body>Owned benchmark</body></html>';
}

function javascript() {
    return 'fetch("/api/health"); const route="/owned-route";';
}

function originals(count) {
    const domains = Array.from({ length: count }, (_, index) => `t${String(index).padStart(6, '0')}.bench.test`);
    const urls = domains.map(domain => `https://${domain}/`);
    const ips = domains.map((_, index) => `198.18.${Math.floor(index / 254)}.${index % 254 + 1}`);
    const ranges = domains.map((_, index) => `10.${Math.floor(index / 256)}.${index % 256}.0/30`);
    const services = domains.map(domain => `${domain}:443/tcp`);
    return { domains, urls, ips, ranges, services };
}

function references(targets, type) {
    return targets.map((value, index) => ({ type, value, source: 'surface_asset',
        asset_id: `00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}` }));
}

export function createPayloadCase(id, count, metrics) {
    const values = originals(count);
    const { domains, urls, ips, ranges, services } = values;
    let targets = urls;
    let input;
    switch (id) {
        case 'http_prober': targets = domains; input = { targets, ports: [80, 443, 8080, 8443], extractTitle: true }; break;
        case 'tech_fingerprinter': input = { targets, target_objects: references(targets, 'web'), dictionaryEntries: [featureRule] }; break;
        case 'directory_bruteforcer': input = { targets, customWordlist: ['path-a', 'path-b'], concurrency: 32 }; break;
        case 'risk_scanner': input = { targets, dictionaryEntries: riskRules, maxRules: 2 }; break;
        case 'sensitive_file_scanner': input = { targets, dictionaryEntries: sensitiveRules }; break;
        case 'actuator_scanner': input = { targets, actuator_endpoints: ['info'], concurrency: 32 }; break;
        case 'js_analyzer': targets = urls.map(url => `${url}app.js`); input = { urls: targets, maxFiles: 1, followImports: false, concurrency: 32 }; break;
        case 'api_monitor': input = { targets, maxPages: 1, crawlDepth: 0, maxJsFiles: 1, followSourceMaps: false, probeSpaManifests: false }; break;
        case 'content_monitor': input = { targets }; break;
        case 'favicon_fingerprinter': input = { targets, target_objects: references(targets, 'web'), dictionaryEntries: [faviconRule] }; break;
        case 'subdomain_takeover': targets = domains; input = { domains: targets, checkCname: true, checkHttp: true, concurrency: 32 }; break;
        case 'dns_resolver': targets = domains; input = { targets, recordTypes: ['A', 'CNAME', 'TXT'], concurrency: 32 }; break;
        case 'cidr_mapper': targets = ranges; input = { targets, maxHosts: 2 }; break;
        case 'cert_monitor': targets = domains; input = { targets, concurrency: 32 }; break;
        case 'service_probe':
        case 'service_monitor': targets = services; input = { targets, dictionaryEntries: [serviceRule], serviceProbeEngine: 'native' }; break;
        case 'port_monitor': targets = ips; input = { targets, ports: [80, 443] }; break;
        case 'fofa_asset_monitor': targets = domains; input = { domains: targets, fofaKey: 'owned-fixture-key', pageSize: 1, maxPages: 3 }; break;
        case 'subdomain_enumerator': targets = domains; input = { domains: targets, sources: ['crtsh', 'hackertarget'] }; break;
        case 'subdomain_brute': targets = domains; input = { targets, dictionary: ['api', 'www'], transport: 'udp' }; break;
        default: throw new Error(`Missing controlled payload fixture for ${id}`);
    }
    input.__monitorExecution = monitorExecution(targets, { pluginId: id });
    const dictionaries = {
        fingerprint_rule: [featureRule], service_probe_rule: [serviceRule],
        poc_rule: riskRules, sensitive_file: sensitiveRules, favicon: [faviconRule],
    };

    function response(body, init) { return new Response(body, init); }
    async function fetchFixture(raw) {
        metrics.fetches++;
        const url = new URL(String(raw));
        if (url.hostname === 'fofa.info') {
            const query = Buffer.from(url.searchParams.get('qbase64'), 'base64').toString('utf8');
            const domain = query.match(/(?:domain|host)="([^"]+)"/)?.[1];
            if (!domain) throw new Error('FOFA fixture received an unexpected query');
            const page = Number(url.searchParams.get('page'));
            return Response.json({ error: false, size: 2, results: page <= 2 ? [{
                host: `https://page${page}.${domain}/`, ip: '198.18.0.1', port: 443, protocol: 'https',
                title: 'Owned fixture', domain, server: 'nginx', lastupdatetime: date,
            }] : [] });
        }
        if (url.hostname === 'crt.sh') {
            const domain = url.searchParams.get('q').replace(/^%\./, '');
            return Response.json([{ name_value: `api.${domain}\nwww.${domain}` }]);
        }
        if (url.hostname === 'api.hackertarget.com') {
            const domain = url.searchParams.get('q');
            return response(`api.${domain},198.18.0.1\nmail.${domain},198.18.0.2`);
        }
        if (url.hostname === 'dns.google' || url.hostname === 'cloudflare-dns.com') {
            return Response.json({ Status: 0, Answer: [{ name: url.searchParams.get('name'), type: 5, data: 'owned.example.invalid.' }] });
        }
        if (!url.hostname.endsWith('.bench.test')) throw new Error(`Unconfigured fixture hostname ${url.hostname}`);
        if (url.pathname.endsWith('.ico')) return response(icon, { headers: { 'content-type': 'image/x-icon' } });
        if (url.pathname.endsWith('.js')) return response(javascript(), { headers: { 'content-type': 'application/javascript' } });
        if (url.pathname === '/health') return response('status=ok');
        if (url.pathname === '/actuator/info') return Response.json({ app: { name: 'Owned' }, build: { version: '1.0' } });
        if (url.pathname.startsWith('/fixture-config-')) return response('OWNED_FIXTURE=yes', { headers: { 'content-type': 'text/plain' } });
        if (url.pathname.includes('baseline') || url.pathname.includes('sentinel-not-found')) return response('missing', { status: 404 });
        return response(html(), { headers: { 'content-type': 'text/html', 'server': 'nginx', 'x-powered-by': 'PHP/8.2' } });
    }

    async function bruteFixture(request) {
        metrics.native_calls++;
        const commit = globalThis.Sentinel.Monitor.commitResults;
        let sequence = 0;
        for (const domain of request.targets) {
            const found = `api.${domain}`;
            for (const [key, complete, data] of [
                ['dns-responses:2:1', false, { results: [{ root_domain: domain, domain: found, record_type: 'A', record_value: '198.18.0.1' }],
                    surface_artifacts: { domains: [{ fqdn: found, root_domain: domain, source: id }] } }],
                ['root-complete', true, { snapshots: { [domain]: { domain, subdomains: [found], last_checked: date } } }],
            ]) {
                const item = { sequence: ++sequence, work: [{ target: domain, key, status: 'ok', complete }], output: { success: true, data } };
                const ack = await commit(item);
                if (ack.ok !== true || ack.sequence !== sequence) throw new Error('Native fixture save was not acknowledged');
            }
        }
        return { success: true, data: { targets: request.targets, subdomains: [], results: [], change_events: [],
            snapshots: {}, summary: { total_targets: request.targets.length }, surface_artifacts: {}, stream_complete: true } };
    }

    function install(commitResults) {
        globalThis.Deno = { resolveDns: async (host, type) => {
            metrics.native_calls++;
            if (type === 'A') return ['198.18.0.1'];
            if (type === 'AAAA') return ['2001:db8::1'];
            if (type === 'CNAME') return [`edge.${host}`];
            if (type === 'TXT') return [['owned=fixture']];
            return [];
        } };
        globalThis.Sentinel = {
            log() {}, Monitor: { reportProgress(request) {
                metrics.progress_events++;
                metrics.progress_bytes += Buffer.byteLength(JSON.stringify(request), 'utf8');
                return true;
            }, commitResults },
            Dictionary: {
                getDefaultId: async type => type,
                getEntries: async id => dictionaries[id] || [faviconRule],
                getWords: async () => ['path-a', 'path-b'],
            },
            AST: { parse: () => ({ literals: [{ type: 'string', value: '/api/health', line: 1, column: 0 }], errors: [] }) },
            TLS: { getCertificate: async domain => {
                metrics.native_calls++;
                return { success: true, cert: { subject: `CN=${domain}`, issuer: 'Owned fixture CA',
                    validFrom: '2026-01-01T00:00:00Z', validTo: '2027-01-01T00:00:00Z',
                    fingerprintSha256: 'ab'.repeat(32), serialNumber: '01', subjectAltNames: [domain] } };
            } },
            Network: {
                bruteForceSubdomains: bruteFixture,
                getServiceProbeCapabilities: async () => ({ default_engine: 'native',
                    engines: [{ id: 'native', available: true, implemented: true, experimental: false }] }),
                probeServices: async request => {
                    metrics.native_calls++;
                    return { success: true, ruleCount: 1, engineRequested: 'native', engineUsed: 'native', results: request.targets.map(target => ({
                        ...target, target: `${target.host}:${target.port}`, success: true, available: true,
                        serviceName: 'https', productName: 'nginx', serverHeader: 'nginx', version: '1.0', statusCode: 200,
                    })) };
                },
                scanPorts: async request => {
                    metrics.native_calls++;
                    return { success: true, results: request.targets.map(target => ({ host: target.host,
                        resolved_ips: [target.host], open_ports: [request.ports[0]], closed_ports: request.ports.slice(1), unknown_ports: [] })) };
                },
            },
        };
    }
    return { input, targets, install, fetch: fetchFixture, scenario: id === 'subdomain_brute' ? 'native-emission-fixture' : 'bounded-success' };
}
