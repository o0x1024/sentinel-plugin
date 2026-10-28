import type { createMonitorResultStream } from './monitor_results.ts';

type Stream = ReturnType<typeof createMonitorResultStream>;
type Options = Parameters<Stream["record"]>[3];

/** Resolve only aliases produced by this plugin's own deterministic normalizer. */
export function createMonitorTargetWriter(
    input: unknown,
    stream: Stream,
    normalize: (target: string) => string | null = target => target,
) {
    const context = (input as any)?.__monitorExecution;
    const originals: unknown = context?.result_stream?.targets;
    const aliases = new Map<string, string[]>();
    if (stream.enabled) {
        if (!Array.isArray(originals)) throw new Error("Monitor stream is missing host target identities");
        for (const original of originals) {
            if (typeof original !== "string") throw new Error("Monitor target identity must be a string");
            const normalized = normalize(original);
            if (!normalized) continue;
            const values = aliases.get(normalized) || [];
            if (!values.includes(original)) values.push(original);
            aliases.set(normalized, values);
        }
    }
    return async (target: string, key: string, output: unknown, options?: Options): Promise<void> => {
        if (!stream.enabled) return;
        const owners = aliases.get(target);
        if (!owners?.length) throw new Error("Completed work does not belong to an injected monitor target");
        const data = output && typeof output === "object" ? (output as any).data : undefined;
        const artifacts = data?.surface_artifacts;
        for (let index = 0; index < owners.length; index++) {
            let delta = index === 0 ? output : { success: true, data: {} };
            if (artifacts && typeof artifacts === "object") {
                const bound: Record<string, unknown> = index === 0 ? { ...artifacts } : {};
                for (const kind of ["evidences", "fingerprints", "changes"]) {
                    if (!Array.isArray(artifacts[kind])) continue;
                    const refersToTarget = (artifact: any) => artifact?.asset_type === "web"
                        && typeof artifact.asset_key === "string" && normalize(artifact.asset_key) === target;
                    const entries = index === 0 ? artifacts[kind] : artifacts[kind].filter(refersToTarget);
                    if (index > 0 && entries.length === 0) continue;
                    bound[kind] = entries.map((artifact: any) => refersToTarget(artifact)
                        ? { ...artifact, asset_key: owners[index] } : artifact);
                }
                // Shared network work may enrich several exact stored identities.
                // Only reference artifacts repeat; discovery/results/findings remain once.
                if (index === 0 || Object.keys(bound).length > 0) {
                    delta = { success: true, data: { ...(index === 0 ? data : {}), surface_artifacts: bound } };
                }
            }
            await stream.record(owners[index], key, delta, options);
        }
    };
}
