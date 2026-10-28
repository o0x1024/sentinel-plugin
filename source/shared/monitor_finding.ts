/** A finding is high confidence here only after the scanner's explicit matcher succeeds. */
export function confirmedMonitorFinding(
    finding: {
        title: string; description: string; severity: string; url: string;
        cwe?: string; remediation?: string; impact?: string; tags?: string[]; evidence?: unknown;
    },
    findingType: string,
    evidence: unknown = finding.evidence,
): Record<string, unknown> {
    const required = (value: string, field: string) => {
        if (typeof value !== "string" || !value.trim()) throw new Error(`Confirmed monitor finding requires ${field}`);
        return value.trim();
    };
    const output: Record<string, unknown> = {
        title: required(finding.title, "title"),
        description: required(finding.description, "description"),
        finding_type: required(findingType, "finding_type"),
        severity: required(finding.severity, "severity"),
        confidence: "high",
        affected_url: required(finding.url, "affected_url"),
    };
    if (finding.cwe?.trim()) output.cwe_id = finding.cwe.trim();
    if (finding.remediation?.trim()) output.remediation = finding.remediation.trim();
    if (finding.impact?.trim()) output.impact = finding.impact.trim();
    if (finding.tags?.length) output.tags = finding.tags;
    if (evidence !== undefined) output.evidence = evidence;
    return output;
}
