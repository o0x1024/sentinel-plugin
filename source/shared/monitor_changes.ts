/** Project completed Web inventory changes into the existing surface contract. */
export function webMonitorChanges(events: Array<{
    assetId: string; eventType: string; severity: string; title: string; description: string;
    oldValue?: string; newValue?: string; riskScore: number; metadata: unknown;
}>, source: string) {
    return events.map(event => ({
        asset_key: event.assetId,
        asset_type: "web",
        change_type: event.eventType,
        severity: event.severity,
        title: event.title,
        description: event.description,
        old_value: event.oldValue,
        new_value: event.newValue,
        risk_score: event.riskScore,
        source,
        metadata: event.metadata,
    }));
}
