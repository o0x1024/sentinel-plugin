/** Deterministic native-bridge fixture; never resolves DNS or reads a wordlist. */
export async function nativeSubdomainBruteFixture(request: Record<string, unknown>, timestamp = "2026-10-28T00:00:00Z") {
    const targets = request.targets as string[];
    const subdomains = targets.map(domain => `api.${domain}`);
    const previous = request.previous_snapshots as Record<string, unknown> | undefined;
    const change_events = targets.map((domain, index) => ({
        id: `asset_discovered-${domain}-${timestamp}`.replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 120),
        asset_id: domain, event_type: "asset_discovered", severity: "low",
        title: `New subdomains discovered for ${domain}`, description: `Discovered 1 subdomain(s): ${subdomains[index]}`,
        old_value: null, new_value: subdomains[index], detection_method: "subdomain_brute",
        tags: ["subdomain", "discovered", "dns", "dictionary"], auto_trigger_enabled: true,
        risk_score: 45, metadata: { domain, subdomains: [subdomains[index]] },
    }));
    const changes = change_events.map(event => ({
        asset_key: event.asset_id, asset_type: "domain", change_type: event.event_type,
        severity: event.severity, title: event.title, description: event.description,
        old_value: event.old_value, new_value: event.new_value, risk_score: event.risk_score,
        source: "subdomain_brute", metadata: event.metadata,
    }));
    const output = {
        success: true,
        data: {
            targets, subdomains,
            results: targets.map((root_domain, index) => ({ root_domain, domain: subdomains[index], record_value: "203.0.113.10", record_type: "A", verified: null, dns_records: null })),
            change_events,
            snapshots: { ...previous, ...Object.fromEntries(targets.map((domain, index) => [domain, { domain, subdomains: [subdomains[index]], last_checked: timestamp }])) },
            summary: { total_targets: targets.length, dictionary_size: (request.dictionary as string[] | undefined)?.length || 2, estimated_queries: targets.length * 2, total_discovered: subdomains.length, domains_with_results: targets.length, alive_domains: 0, changes_detected: change_events.length, dictionary_source: request.dictionary_id || "inline" },
            surface_artifacts: {
                domains: subdomains.map((fqdn, index) => ({ fqdn, root_domain: targets[index], main_domain: targets[index], source: "subdomain_brute", confidence: 0.98 })),
                ips: [{ ip_address: "203.0.113.10", ip_version: "IPv4", source: "subdomain_brute", confidence: 0.98 }],
                relations: subdomains.flatMap((domain, index) => [
                    { from_type: "domain", from_key: targets[index], to_type: "domain", to_key: domain, relation_type: "contains_subdomain", source: "subdomain_brute", confidence: 0.98 },
                    { from_type: "domain", from_key: domain, to_type: "ip", to_key: "203.0.113.10", relation_type: "resolves_to", source: "subdomain_brute", confidence: 0.98 },
                ]),
                evidences: subdomains.map((domain, index) => ({ asset_type: "domain", asset_key: domain,
                    evidence_type: "subdomain_bruteforce", title: `Dictionary brute force discovery: ${domain}`,
                    content_json: { root_domain: targets[index], record_value: "203.0.113.10", record_type: "A", verified: null, dns_records: null }, source: "subdomain_brute" })),
                changes,
            },
        },
    };
    const context = request.__monitorExecution as { result_stream?: { protocol?: string; targets?: string[] } } | undefined;
    if (!context) return output;
    if (context.result_stream?.protocol !== "monitor-results-v1") throw new Error("Native monitor fixture requires monitor-results-v1");
    const commit = (globalThis as any).Sentinel?.Monitor?.commitResults;
    if (typeof commit !== "function") throw new Error("Native monitor fixture requires commitResults");
    let sequence = 0;
    const submit = async (target: string, key: string, complete: boolean, data: Record<string, unknown>) => {
        const request = { sequence: ++sequence, work: [{ target, key, status: "ok", complete }], output: { success: true, data } };
        const ack = await commit(request);
        if (ack?.ok !== true || ack.sequence !== sequence) throw new Error("Native monitor fixture commit was not acknowledged");
    };
    for (const [index, target] of targets.entries()) {
        if (!context.result_stream.targets?.includes(target)) throw new Error("Native monitor fixture target ownership mismatch");
        await submit(target, "dns-responses:2:0:1", false, {
            results: [output.data.results[index]],
            native_dns_completion: { answered_queries: 2, failed_queries: 0, completed_queries: 2 },
            surface_artifacts: {
                domains: [output.data.surface_artifacts.domains[index]],
                ips: output.data.surface_artifacts.ips,
                relations: output.data.surface_artifacts.relations.slice(index * 2, index * 2 + 2),
                evidences: [output.data.surface_artifacts.evidences[index]],
            },
        });
        await submit(target, "root-complete", true, {
            snapshots: { [target]: output.data.snapshots[target] },
            changeEvents: [change_events[index]], surface_artifacts: { changes: [changes[index]] },
        });
    }
    return { success: true, data: { ...output.data, stream_complete: true,
        subdomains: [], results: [], change_events: [], changeEvents: [], snapshots: {},
        surface_artifacts: { domains: [], ips: [], relations: [], evidences: [], changes: [] } } };
}
