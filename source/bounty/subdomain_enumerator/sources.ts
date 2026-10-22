import { fetchWithRetry } from './request.ts';

/**
 * Extract subdomains from text using regex
 */
export function extractSubdomains(text: string, domain: string): string[] {
    const escapedDomain = domain.replace(/\./g, "\\.");
    const regex = new RegExp(`[a-zA-Z0-9][-a-zA-Z0-9]*(?:\\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\\.${escapedDomain}`, "gi");
    const matches = text.match(regex) || [];
    return [...new Set(matches.map(m => m.toLowerCase()))];
}

/**
 * Query crt.sh Certificate Transparency logs
 */
export async function queryCrtsh(domain: string ): Promise<string[]> {
    const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    const subdomains = new Set<string>();

    try {
        const data = JSON.parse(text.replace(/\n/g, " "));
        for (const entry of data) {
            const nameValue = entry.name_value || "";
            const names = nameValue.split(/\n/);
            for (const name of names) {
                const cleaned = name.trim().toLowerCase();
                if (cleaned && cleaned.endsWith(domain) && !cleaned.startsWith("*")) {
                    subdomains.add(cleaned);
                }
            }
        }
    } catch {
        // Fallback to regex extraction
        return extractSubdomains(text, domain);
    }

    return [...subdomains];
}

/**
 * Query HackerTarget API
 */
export async function queryHackerTarget(domain: string ): Promise<string[]> {
    const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    if (text.includes("error") || text.includes("API count exceeded")) {
        throw new Error("API rate limit exceeded");
    }

    return extractSubdomains(text, domain);
}

/**
 * Query RapidDNS
 */
export async function queryRapidDNS(domain: string ): Promise<string[]> {
    const url = `https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query AlienVault OTX
 */
export async function queryAlienVault(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    const errors: string[] = [];

    // Query passive DNS
    const dnsUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
    try {
        const dnsResponse = await fetchWithRetry(dnsUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        if (dnsResponse.ok) {
            const text = await dnsResponse.text();
            extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        }
    } catch (error: any) { errors.push(error?.message || String(error)); }

    // Query URL list
    const urlListUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list`;
    try {
        const urlResponse = await fetchWithRetry(urlListUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });
        if (urlResponse.ok) {
            const text = await urlResponse.text();
            extractSubdomains(text, domain).forEach(s => subdomains.add(s));
        }
    } catch (error: any) { errors.push(error?.message || String(error)); }

    if (errors.length === 2) throw new Error(errors.join("; "));
    return [...subdomains];
}

/**
 * Query VirusTotal (public API, no key required)
 */
export async function queryVirusTotal(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    let cursor = "";
    let iterations = 0;
    const maxIterations = 3; // Limit iterations to avoid too many requests

    while (iterations < maxIterations) {
        const url = `https://www.virustotal.com/ui/domains/${encodeURIComponent(domain)}/subdomains?limit=40&cursor=${cursor}`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://www.virustotal.com/"
            },
            // @ts-ignore
        });

        if (!response.ok) {
            break;
        }

        const text = await response.text();
        const found = extractSubdomains(text, domain);

        if (found.length === 0) {
            break;
        }

        found.forEach(s => subdomains.add(s));

        try {
            const data = JSON.parse(text);
            cursor = data?.meta?.cursor || "";
            if (!cursor) break;
        } catch {
            break;
        }

        iterations++;
    }

    return [...subdomains];
}

/**
 * Query URLScan.io
 */
export async function queryURLScan(domain: string ): Promise<string[]> {
    const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Anubis DB
 */
export async function queryAnubis(domain: string ): Promise<string[]> {
    const url = `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    try {
        const data = JSON.parse(text);
        if (Array.isArray(data)) {
            return data.filter(s => typeof s === "string" && s.endsWith(domain)).map(s => s.toLowerCase());
        }
    } catch { /* fallback to regex */ }

    return extractSubdomains(text, domain);
}

/**
 * Query DNSDumpster
 */
export async function queryDNSDumpster(domain: string ): Promise<string[]> {
    const baseUrl = "https://dnsdumpster.com/";

    // Get CSRF token
    const getResponse = await fetchWithRetry(baseUrl, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://dnsdumpster.com"
        },
        // @ts-ignore
    });

    if (!getResponse.ok) {
        throw new Error(`HTTP ${getResponse.status}`);
    }

    // Extract CSRF token from cookies
    const cookies = getResponse.headers.get("set-cookie") || "";
    const csrfMatch = cookies.match(/csrftoken=([^;]+)/);
    if (!csrfMatch) {
        throw new Error("Failed to get CSRF token");
    }
    const csrfToken = csrfMatch[1];

    // POST request
    const formData = new URLSearchParams();
    formData.append("csrfmiddlewaretoken", csrfToken);
    formData.append("targetip", domain);
    formData.append("user", "free");

    const postResponse = await fetchWithRetry(baseUrl, {
        method: "POST",
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://dnsdumpster.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": `csrftoken=${csrfToken}`
        },
        body: formData.toString(),
        // @ts-ignore
    });

    if (!postResponse.ok) {
        throw new Error(`HTTP ${postResponse.status}`);
    }

    const text = await postResponse.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Sublist3r API
 */
export async function querySublist3r(domain: string ): Promise<string[]> {
    const url = `https://api.sublist3r.com/search.php?domain=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    try {
        const data = JSON.parse(text);
        if (Array.isArray(data)) {
            return data.filter(s => typeof s === "string" && s.endsWith(domain)).map(s => s.toLowerCase());
        }
    } catch { /* fallback to regex */ }

    return extractSubdomains(text, domain);
}

/**
 * Query CertSpotter
 */
export async function queryCertSpotter(domain: string ): Promise<string[]> {
    const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    const subdomains = new Set<string>();

    try {
        const data = JSON.parse(text);
        if (Array.isArray(data)) {
            for (const entry of data) {
                const dnsNames = entry.dns_names || [];
                for (const name of dnsNames) {
                    const cleaned = name.trim().toLowerCase();
                    if (cleaned && cleaned.endsWith(domain) && !cleaned.startsWith("*")) {
                        subdomains.add(cleaned);
                    }
                }
            }
        }
    } catch {
        return extractSubdomains(text, domain);
    }

    return [...subdomains];
}

/**
 * Query ThreatMiner
 */
export async function queryThreatMiner(domain: string ): Promise<string[]> {
    const url = `https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=5`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Netcraft
 */
export async function queryNetcraft(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    const baseUrl = "https://searchdns.netcraft.com/";
    let pageNum = 1;
    let last = "";
    let previousLast = "";

    for (let i = 0; i < 25; i++) { // Limit to 25 pages (500 results)
        const url = `${baseUrl}?restriction=site+contains&position=limited&host=*.${encodeURIComponent(domain)}&from=${pageNum}${last}`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        const found = extractSubdomains(text, domain);

        if (found.length === 0) break;
        found.forEach(s => subdomains.add(s));

        if (!text.includes("Next Page")) break;

        const lastMatch = text.match(new RegExp(`&last=.*${domain.replace(/\./g, "\\.")}`));
        if (lastMatch) {
            last = lastMatch[0];
        }

        // Detect stuck pagination: if cursor didn't advance, stop
        if (last === previousLast) break;
        previousLast = last;

        pageNum += 20;
    }

    return [...subdomains];
}

/**
 * Query Riddler
 */
export async function queryRiddler(domain: string ): Promise<string[]> {
    const url = `https://riddler.io/search?q=pld:${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Robtex
 */
export async function queryRobtex(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    const baseUrl = "https://freeapi.robtex.com/pdns";

    // Get forward DNS records
    const forwardUrl = `${baseUrl}/forward/${encodeURIComponent(domain)}`;
    const forwardResponse = await fetchWithRetry(forwardUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!forwardResponse.ok) {
        throw new Error(`HTTP ${forwardResponse.status}`);
    }

    const forwardText = await forwardResponse.text();
    const lines = forwardText.split("\n");
    const ips = new Set<string>();

    for (const line of lines) {
        if (!line.trim()) continue;
        try {
            const record = JSON.parse(line);
            if (record.rrtype === "A" || record.rrtype === "AAAA") {
                ips.add(record.rrdata);
            }
        } catch { /* ignore */ }
    }

    // Query reverse DNS for each IP (limit to first 10 IPs)
    const ipArray = [...ips].slice(0, 10);
    for (const ip of ipArray) {
        try {
            const reverseUrl = `${baseUrl}/reverse/${encodeURIComponent(ip)}`;
            const reverseResponse = await fetchWithRetry(reverseUrl, {
                headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
                // @ts-ignore
            });

            if (reverseResponse.ok) {
                const reverseText = await reverseResponse.text();
                extractSubdomains(reverseText, domain).forEach(s => subdomains.add(s));
            }
        } catch { /* ignore */ }
    }

    return [...subdomains];
}

/**
 * Query SiteDossier
 */
export async function querySiteDossier(domain: string ): Promise<string[]> {
    const url = `http://www.sitedossier.com/parentdomain/${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query DNSGrep
 */
export async function queryDNSGrep(domain: string ): Promise<string[]> {
    const url = `https://dns.bufferover.run/dns?q=.${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    const subdomains = new Set<string>();

    try {
        const data = JSON.parse(text);
        const fdns = data.FDNS_A || [];
        const rdns = data.RDNS || [];

        for (const entry of fdns) {
            const parts = entry.split(",");
            if (parts.length > 1) {
                const subdomain = parts[1].toLowerCase();
                if (subdomain.endsWith(domain)) {
                    subdomains.add(subdomain);
                }
            }
        }

        for (const entry of rdns) {
            const parts = entry.split(",");
            if (parts.length > 1) {
                const subdomain = parts[1].toLowerCase();
                if (subdomain.endsWith(domain)) {
                    subdomains.add(subdomain);
                }
            }
        }
    } catch {
        return extractSubdomains(text, domain);
    }

    return [...subdomains];
}

/**
 * Query BeVigil API
 */
export async function queryBeVigil(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("BeVigil API token required");
    }

    const url = `https://osint.bevigil.com/api/${encodeURIComponent(domain)}/subdomains/`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-Access-Token": apiToken
        },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    try {
        const data = JSON.parse(text);
        if (data.subdomains && Array.isArray(data.subdomains)) {
            return data.subdomains
                .filter((s: any) => typeof s === "string" && s.endsWith(domain))
                .map((s: string) => s.toLowerCase());
        }
    } catch { /* fallback */ }

    return extractSubdomains(text, domain);
}

/**
 * Query Censys API
 */
export async function queryCensys(domain: string , apiId?: string, apiSecret?: string): Promise<string[]> {
    if (!apiId || !apiSecret) {
        throw new Error("Censys API credentials required");
    }

    const subdomains = new Set<string>();
    const url = "https://search.censys.io/api/v2/certificates/search";
    let cursor: string | undefined;

    for (let i = 0; i < 5; i++) { // Limit to 5 pages
        const params = new URLSearchParams({
            q: `names: ${domain}`,
            per_page: "100"
        });

        if (cursor) {
            params.append("cursor", cursor);
        }

        const auth = btoa(`${apiId}:${apiSecret}`);
        const response = await fetchWithRetry(`${url}?${params}`, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Authorization": `Basic ${auth}`
            },
            // @ts-ignore
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));

        try {
            const data = JSON.parse(text);
            cursor = data?.result?.links?.next;
            if (!cursor) break;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query VirusTotal API
 */
export async function queryVirusTotalAPI(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("VirusTotal API token required");
    }

    const subdomains = new Set<string>();
    let cursor = "";

    for (let i = 0; i < 5; i++) {
        const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/subdomains?limit=40${cursor ? `&cursor=${cursor}` : ""}`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "x-apikey": apiToken
            },
            // @ts-ignore
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const text = await response.text();

        try {
            const data = JSON.parse(text);
            const dataArray = data?.data || [];

            for (const entry of dataArray) {
                const id = entry?.id;
                if (id && typeof id === "string" && id.endsWith(domain)) {
                    subdomains.add(id.toLowerCase());
                }
            }

            cursor = data?.meta?.cursor || "";
            if (!cursor) break;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query SecurityTrails API
 */
export async function querySecurityTrails(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("SecurityTrails API token required");
    }

    const url = `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "APIKEY": apiToken
        },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    const subdomains: string[] = [];

    try {
        const data = JSON.parse(text);
        const subs = data?.subdomains || [];

        for (const sub of subs) {
            if (typeof sub === "string") {
                subdomains.push(`${sub}.${domain}`.toLowerCase());
            }
        }
    } catch {
        return extractSubdomains(text, domain);
    }

    return subdomains;
}

/**
 * Query Shodan API
 */
export async function queryShodan(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Shodan API token required");
    }

    const url = `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${encodeURIComponent(apiToken)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    try {
        const data = JSON.parse(text);
        const subs = data?.subdomains || [];
        return subs
            .filter((s: any) => typeof s === "string")
            .map((s: string) => `${s}.${domain}`.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query GitHub API
 */
export async function queryGitHub(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("GitHub API token required");
    }

    const subdomains = new Set<string>();

    for (let page = 1; page <= 3; page++) {
        const url = `https://api.github.com/search/code?q=${encodeURIComponent(domain)}&per_page=100&page=${page}&sort=indexed`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/vnd.github.v3.text-match+json",
                "Authorization": `token ${apiToken}`
            },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));

        try {
            const data = JSON.parse(text);
            if (!data.items || data.items.length === 0) break;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query BinaryEdge API
 */
export async function queryBinaryEdge(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("BinaryEdge API token required");
    }

    const subdomains = new Set<string>();
    let page = 1;

    for (let i = 0; i < 5; i++) {
        const url = `https://api.binaryedge.io/v2/query/domains/subdomain/${encodeURIComponent(domain)}?page=${page}`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "X-Key": apiToken
            },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();

        try {
            const data = JSON.parse(text);
            const events = data?.events || [];

            if (events.length === 0) break;

            for (const event of events) {
                if (typeof event === "string" && event.endsWith(domain)) {
                    subdomains.add(event.toLowerCase());
                }
            }

            page++;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query FullHunt API
 */
export async function queryFullHunt(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("FullHunt API token required");
    }

    const url = `https://fullhunt.io/api/v1/domain/${encodeURIComponent(domain)}/subdomains`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-API-KEY": apiToken
        },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    try {
        const data = JSON.parse(text);
        const hosts = data?.hosts || [];
        return hosts
            .filter((h: any) => typeof h === "string" && h.endsWith(domain))
            .map((h: string) => h.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query Google Certificate Transparency
 */
export async function queryGoogleCT(domain: string ): Promise<string[]> {
    const url = `https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query MySSL
 */
export async function queryMySSL(domain: string ): Promise<string[]> {
    const url = `https://myssl.com/api/v1/discover_sub_domain?domain=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query IP138
 */
export async function queryIP138(domain: string ): Promise<string[]> {
    const url = `https://site.ip138.com/${encodeURIComponent(domain)}/domain.htm`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query RiskIQ API
 */
export async function queryRiskIQ(domain: string , username?: string, apiKey?: string): Promise<string[]> {
    if (!username || !apiKey) {
        throw new Error("RiskIQ API credentials required");
    }

    const url = `https://api.riskiq.net/pt/v2/enrichment/subdomains?query=${encodeURIComponent(domain)}`;
    const auth = btoa(`${username}:${apiKey}`);

    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
            "Authorization": `Basic ${auth}`
        },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    try {
        const data = JSON.parse(text);
        const subs = data?.subdomains || [];
        return subs
            .filter((s: any) => typeof s === "string")
            .map((s: string) => `${s}.${domain}`.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query ThreatBook API
 */
export async function queryThreatBook(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("ThreatBook API key required");
    }

    const url = `https://api.threatbook.cn/v3/domain/sub_domains?apikey=${encodeURIComponent(apiKey)}&resource=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    try {
        const data = JSON.parse(text);
        const subs = data?.data?.sub_domains || [];
        return subs
            .filter((s: any) => typeof s === "string" && s.endsWith(domain))
            .map((s: string) => s.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query FOFA API
 */
export async function queryFOFA(domain: string , email?: string, apiKey?: string): Promise<string[]> {
    if (!email || !apiKey) {
        throw new Error("FOFA API credentials required");
    }

    const subdomains = new Set<string>();
    const query = `domain="${domain}"`;
    const qbase64 = btoa(query);

    for (let page = 1; page <= 5; page++) {
        const url = `https://fofa.info/api/v1/search/all?email=${encodeURIComponent(email)}&key=${encodeURIComponent(apiKey)}&qbase64=${qbase64}&page=${page}&size=100&full=true`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));

        try {
            const data = JSON.parse(text);
            if (!data.results || data.results.length === 0) break;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query Hunter API
 */
export async function queryHunter(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Hunter API key required");
    }

    const subdomains = new Set<string>();

    for (let page = 1; page <= 5; page++) {
        const url = `https://hunter.qianxin.com/openApi/search?api-key=${encodeURIComponent(apiKey)}&search=${encodeURIComponent(domain)}&page=${page}&page_size=100&is_web=1`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));

        try {
            const data = JSON.parse(text);
            if (!data.data?.arr || data.data.arr.length === 0) break;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query Quake API
 */
export async function queryQuake(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Quake API key required");
    }

    const subdomains = new Set<string>();

    for (let page = 0; page < 5; page++) {
        const url = "https://quake.360.cn/api/v3/search/quake_service";
        const body = JSON.stringify({
            query: `domain:"${domain}"`,
            start: page * 100,
            size: 100
        });

        const response = await fetchWithRetry(url, {
            method: "POST",
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json",
                "X-QuakeToken": apiKey
            },
            body,
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));

        try {
            const data = JSON.parse(text);
            if (!data.data || data.data.length === 0) break;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query ZoomEye API
 */
export async function queryZoomEye(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("ZoomEye API key required");
    }

    const subdomains = new Set<string>();

    for (let page = 1; page <= 5; page++) {
        const url = `https://api.zoomeye.org/domain/search?q=${encodeURIComponent(domain)}&page=${page}&type=1`;
        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "API-KEY": apiKey
            },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));

        try {
            const data = JSON.parse(text);
            if (!data.list || data.list.length === 0) break;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query Spyse API
 */
export async function querySpyse(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Spyse API token required");
    }

    const url = `https://api.spyse.com/v4/data/domain/subdomain?domain=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Authorization": `Bearer ${apiToken}`
        },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();

    try {
        const data = JSON.parse(text);
        const items = data?.data?.items || [];
        return items
            .map((item: any) => item?.name)
            .filter((s: any) => typeof s === "string" && s.endsWith(domain))
            .map((s: string) => s.toLowerCase());
    } catch {
        return extractSubdomains(text, domain);
    }
}

/**
 * Query Chinaz
 */
export async function queryChinaz(domain: string ): Promise<string[]> {
    const url = `https://alexa.chinaz.com/${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query CeBaidu
 */
export async function queryCeBaidu(domain: string ): Promise<string[]> {
    const url = `https://ce.baidu.com/index/getRelatedSites?site_address=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Qianxun
 */
export async function queryQianxun(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();

    for (let page = 1; page <= 10; page++) {
        const url = `https://www.dnsscan.cn/dns.html?keywords=${encodeURIComponent(domain)}&page=${page}`;
        const response = await fetchWithRetry(url, {
            method: "POST",
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
                ecmsfrom: "",
                show: "",
                num: "",
                classid: "0",
                keywords: domain
            }).toString(),
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        const found = extractSubdomains(text, domain);

        if (found.length === 0) break;
        found.forEach(s => subdomains.add(s));

        if (!text.includes('<div id="page" class="pagelist">')) break;
        if (text.includes('<li class="disabled"><span>&raquo;</span></li>')) break;
    }

    return [...subdomains];
}

/**
 * Query Windvane
 */
export async function queryWindvane(domain: string , apiKey?: string): Promise<string[]> {
    const subdomains = new Set<string>();
    const url = "https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService/ListSubDomain";

    let page = 1;
    let totalPages = 1;

    while (page <= totalPages && page <= 10) {
        const headers: Record<string, string> = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Referer": "https://windvane.lichoin.com"
        };

        if (apiKey) {
            headers["X-Api-Key"] = apiKey;
        }

        const body = JSON.stringify({
            domain: domain,
            page_request: {
                page: page,
                count: 1000
            }
        });

        const response = await fetchWithRetry(url, {
            method: "POST",
            headers,
            body,
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();

        try {
            const data = JSON.parse(text);

            if (data.code !== 0) break;

            extractSubdomains(text, domain).forEach(s => subdomains.add(s));

            const pageInfo = data?.data?.page_response || {};
            totalPages = parseInt(pageInfo.total_page || "1");

            page++;
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query Racent
 */
export async function queryRacent(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Racent API token required");
    }

    const url = `https://face.racent.com/tool/query_ctlog?token=${encodeURIComponent(apiToken)}&keyword=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Common Crawl Index
 */
export async function queryCDX(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();
    const url = `https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.${encodeURIComponent(domain)}&output=json`;

    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    const lines = text.split("\n");

    for (const line of lines) {
        if (!line.trim()) continue;
        try {
            const data = JSON.parse(line);
            const url = data?.url || "";
            extractSubdomains(url, domain).forEach(s => subdomains.add(s));
        } catch { /* ignore */ }
    }

    return [...subdomains];
}

/**
 * Query Archive.org Wayback Machine
 */
export async function queryArchive(domain: string ): Promise<string[]> {
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Chinaz API
 */
export async function queryChinazAPI(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Chinaz API key required");
    }

    const url = `https://apidata.chinaz.com/CallAPI/Alexa?key=${encodeURIComponent(apiKey)}&domainName=${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query CIRCL PassiveDNS API
 */
export async function queryCIRCL(domain: string , username?: string, password?: string): Promise<string[]> {
    if (!username || !password) {
        throw new Error("CIRCL API credentials required");
    }

    const url = `https://www.circl.lu/pdns/query/${encodeURIComponent(domain)}`;
    const auth = btoa(`${username}:${password}`);

    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Authorization": `Basic ${auth}`
        },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Cloudflare API
 */
export async function queryCloudflare(domain: string , apiToken?: string): Promise<string[]> {
    if (!apiToken) {
        throw new Error("Cloudflare API token required");
    }

    const subdomains = new Set<string>();
    const headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": `Bearer ${apiToken}`,
        "Content-Type": "application/json"
    };

    // Get account ID
    const accountResponse = await fetchWithRetry("https://api.cloudflare.com/client/v4/accounts", {
        headers,
        // @ts-ignore
    });

    if (!accountResponse.ok) {
        throw new Error(`HTTP ${accountResponse.status}`);
    }

    const accountData = await accountResponse.json();
    const accountId = accountData?.result?.[0]?.id;

    if (!accountId) {
        throw new Error("No Cloudflare account found");
    }

    // Get zones for domain
    const zonesResponse = await fetchWithRetry(`https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(domain)}`, {
        headers,
        // @ts-ignore
    });

    if (!zonesResponse.ok) {
        throw new Error(`HTTP ${zonesResponse.status}`);
    }

    const zonesData = await zonesResponse.json();
    const zoneId = zonesData?.result?.[0]?.id;

    if (!zoneId) {
        return []; // Domain not in Cloudflare
    }

    // Get DNS records
    let page = 1;
    while (page <= 10) {
        const dnsResponse = await fetchWithRetry(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?page=${page}&per_page=100`, {
            headers,
            // @ts-ignore
        });

        if (!dnsResponse.ok) break;

        const text = await dnsResponse.text();
        extractSubdomains(text, domain).forEach(s => subdomains.add(s));

        try {
            const dnsData = JSON.parse(text);
            const totalPages = dnsData?.result_info?.total_pages || 0;
            if (page >= totalPages) break;
        } catch {
            break;
        }

        page++;
    }

    return [...subdomains];
}

/**
 * Query DNSDB API
 */
export async function queryDNSDB(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("DNSDB API key required");
    }

    const url = `https://api.dnsdb.info/lookup/rrset/name/*.${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-API-Key": apiKey
        },
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query IPv4Info API
 */
export async function queryIPv4Info(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("IPv4Info API key required");
    }

    const subdomains = new Set<string>();

    for (let page = 0; page < 50; page++) {
        const url = `http://ipv4info.com/api_v1/?type=SUBDOMAINS&key=${encodeURIComponent(apiKey)}&value=${encodeURIComponent(domain)}&page=${page}`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();

        try {
            const data = JSON.parse(text);
            const subs = data?.Subdomains || [];

            if (subs.length === 0) break;

            extractSubdomains(JSON.stringify(data), domain).forEach(s => subdomains.add(s));

            if (subs.length < 300) break; // Less than 300 means last page
        } catch {
            break;
        }
    }

    return [...subdomains];
}

/**
 * Query PassiveDNS API
 */
export async function queryPassiveDNS(domain: string , apiToken?: string, apiAddr?: string): Promise<string[]> {
    const baseUrl = apiAddr || "http://api.passivedns.cn";

    const headers: Record<string, string> = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    };

    if (apiToken) {
        headers["X-AuthToken"] = apiToken;
    }

    const url = `${baseUrl}/flint/rrset/*.${encodeURIComponent(domain)}`;
    const response = await fetchWithRetry(url, {
        headers,
        // @ts-ignore
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    return extractSubdomains(text, domain);
}

/**
 * Query Bing API
 */
export async function queryBingAPI(domain: string , apiKey?: string): Promise<string[]> {
    if (!apiKey) {
        throw new Error("Bing API key required");
    }

    const subdomains = new Set<string>();
    let offset = 0;
    const perPage = 50;

    for (let i = 0; i < 20; i++) { // Limit to 1000 results (20 * 50)
        const query = `site:.${domain}`;
        const url = `https://api.bing.microsoft.com/v7.0/search?q=${encodeURIComponent(query)}&count=${perPage}&offset=${offset}&safesearch=Off`;

        const response = await fetchWithRetry(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Ocp-Apim-Subscription-Key": apiKey
            },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        const found = extractSubdomains(text, domain);

        if (found.length === 0) break;
        found.forEach(s => subdomains.add(s));

        offset += perPage;
    }

    return [...subdomains];
}

/**
 * Query Google Custom Search API
 */
export async function queryGoogleAPI(domain: string , apiKey?: string, searchEngineId?: string): Promise<string[]> {
    if (!apiKey || !searchEngineId) {
        throw new Error("Google API key and search engine ID required");
    }

    const subdomains = new Set<string>();

    for (let start = 1; start <= 91; start += 10) { // Max 100 results (10 pages)
        const query = `site:.${domain}`;
        const url = `https://www.googleapis.com/customsearch/v1?key=${encodeURIComponent(apiKey)}&cx=${encodeURIComponent(searchEngineId)}&q=${encodeURIComponent(query)}&fields=items/link&start=${start}&num=10`;

        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();
        const found = extractSubdomains(text, domain);

        if (found.length === 0) break;
        found.forEach(s => subdomains.add(s));
    }

    return [...subdomains];
}

/**
 * Query Gitee code search
 */
export async function queryGitee(domain: string ): Promise<string[]> {
    const subdomains = new Set<string>();

    for (let page = 1; page <= 100; page++) {
        const url = `https://search.gitee.com/?pageno=${page}&q=${encodeURIComponent(domain)}&type=code`;
        const response = await fetchWithRetry(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            // @ts-ignore
        });

        if (!response.ok) break;

        const text = await response.text();

        if (text.includes('class="empty-box"')) break;
        if (text.includes('<li class="disabled"><a href="###">')) break;

        const found = extractSubdomains(text, domain);
        if (found.length === 0) break;

        found.forEach(s => subdomains.add(s));
    }

    return [...subdomains];
}
