/** Deterministic native-bridge fixture; never resolves DNS or reads a wordlist. */
export function nativeSubdomainBruteFixture(request: Record<string, unknown>, timestamp = "2026-10-28T00:00:00Z") {
    const targets = request.targets as string[];
    const subdomains = targets.map(domain => `api.${domain}`);
    const previous = request.previous_snapshots as Record<string, unknown> | undefined;
    const change_events = targets.map((domain, index) => ({
        id: `fixture-${index}`, asset_id: subdomains[index], event_type: "asset_discovered", severity: "info",
        title: `Discovered ${subdomains[index]}`, description: "Native bridge fixture", old_value: null, new_value: subdomains[index],
        detection_method: "subdomain_brute", tags: ["dns"], auto_trigger_enabled: false, risk_score: 0, metadata: { root_domain: domain },
    }));
    return {
        success: true,
        data: {
            targets, subdomains,
            results: targets.map((root_domain, index) => ({ root_domain, domain: subdomains[index], record_value: "203.0.113.10", record_type: "A", verified: null, dns_records: null })),
            change_events,
            snapshots: { ...previous, ...Object.fromEntries(targets.map((domain, index) => [domain, { domain, subdomains: [subdomains[index]], last_checked: timestamp }])) },
            summary: { total_targets: targets.length, dictionary_size: (request.dictionary as string[] | undefined)?.length || 2, estimated_queries: targets.length * 2, total_discovered: subdomains.length, domains_with_results: targets.length, alive_domains: 0, changes_detected: change_events.length, dictionary_source: request.dictionary_id || "inline" },
            surface_artifacts: {
                domains: subdomains.map((domain, index) => ({ domain, root_domain: targets[index], source: "subdomain_brute" })),
                ips: [{ ip_address: "203.0.113.10", source: "subdomain_brute" }],
                relations: subdomains.map(domain => ({ from_type: "domain", from_key: domain, to_type: "ip", to_key: "203.0.113.10", relation_type: "resolves_to", source: "subdomain_brute" })),
                evidences: [{ evidence_type: "dns_record", title: "Native batch fixture", content_text: "A 203.0.113.10", source: "subdomain_brute" }],
                changes: change_events,
            },
        },
    };
}
