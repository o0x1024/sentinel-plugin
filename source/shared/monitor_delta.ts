/** Exact UTF-8 sizing for immutable, bounded monitor deltas. */
export type JsonObject = Record<string, any>;

export const MONITOR_DELTA_INPUT_FIELDS = [
    "targets", "target_objects", "service_targets", "__monitorExecution",
    "previousSnapshots", "previous_snapshots", "dictionaryEntries", "dictionary",
] as const;

type Member = { node: DeltaNode; keyBytes: number };
export type DeltaNode = {
    kind: "scalar" | "array" | "object";
    value: any;
    bytes: number;
    members?: Map<string, Member>;
};

export function isJsonObject(value: unknown): value is JsonObject {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Count already-serialized JSON; lone surrogates have been escaped by stringify. */
function serializedBytes(text: string): number {
    let bytes = 0;
    for (let index = 0; index < text.length; index++) {
        const code = text.charCodeAt(index);
        if (code < 0x80) bytes++;
        else if (code < 0x800) bytes += 2;
        else if (code >= 0xd800 && code <= 0xdbff) { bytes += 4; index++; }
        else bytes += 3;
    }
    return bytes;
}

export function jsonBytes(value: unknown): number {
    return serializedBytes(JSON.stringify(value));
}

function objectNode(members: Map<string, Member>): DeltaNode {
    let bytes = 2 + Math.max(0, members.size - 1);
    const entries: Array<[string, any]> = [];
    for (const [key, entry] of members) {
        bytes += entry.keyBytes + 1 + entry.node.bytes;
        entries.push([key, entry.node.value]);
    }
    return { kind: "object", value: Object.fromEntries(entries), bytes, members };
}

function node(value: any): DeltaNode {
    if (Array.isArray(value)) {
        let bytes = 2 + Math.max(0, value.length - 1);
        for (const item of value) bytes += node(item).bytes;
        return { kind: "array", value, bytes };
    }
    if (isJsonObject(value)) {
        return objectNode(new Map(Object.entries(value).map(([key, value]) =>
            [key, { keyBytes: jsonBytes(key), node: node(value) }])));
    }
    return { kind: "scalar", value, bytes: jsonBytes(value) };
}

function validateDeltaData(data: unknown): asserts data is JsonObject {
    if (!isJsonObject(data)) {
        throw new Error("Monitor result delta must contain success:true and an object data");
    }
    for (const key of MONITOR_DELTA_INPUT_FIELDS) {
        if (Object.prototype.hasOwnProperty.call(data, key)) {
            throw new Error(`Monitor result delta must not repeat execution input field data.${key}`);
        }
    }
    if (data.snapshots !== undefined && !isJsonObject(data.snapshots)) {
        throw new Error("Monitor snapshot delta must be an object");
    }
}

/** Clone once at the ownership boundary; validate the actual JSON projection too. */
export function copyMonitorDelta(output: unknown): DeltaNode {
    if (!isJsonObject(output) || output.success !== true) {
        throw new Error("Monitor result delta must contain success:true and an object data");
    }
    validateDeltaData(output.data);
    const data: unknown = JSON.parse(JSON.stringify(output.data));
    validateDeltaData(data);
    return node(data);
}

type MergeMode = "data" | "object" | "summary" | "snapshots";

function merge(left: DeltaNode, right: DeltaNode, mode: MergeMode): DeltaNode {
    if (left.kind === "array" && right.kind === "array") {
        if (!left.value.length) return right;
        if (!right.value.length) return left;
        return { kind: "array", value: [...left.value, ...right.value], bytes: left.bytes + right.bytes - 1 };
    }
    if (mode === "summary" && typeof left.value === "number" && typeof right.value === "number") {
        return node(left.value + right.value);
    }
    if (left.kind !== "object" || right.kind !== "object") return right;
    const members = new Map(left.members!);
    for (const [key, entry] of right.members!) {
        const previous = members.get(key);
        if (!previous || mode === "snapshots") { members.set(key, entry); continue; }
        const childMode: MergeMode = mode === "data"
            ? key === "summary" ? "summary" : key === "snapshots" ? "snapshots" : "object"
            : mode;
        members.set(key, { keyBytes: previous.keyBytes, node: merge(previous.node, entry.node, childMode) });
    }
    return objectNode(members);
}

export function mergeMonitorDelta(left: DeltaNode | undefined, right: DeltaNode): DeltaNode {
    return left ? merge(left, right, "data") : right;
}

const EMPTY_REQUEST_BYTES = jsonBytes({ sequence: 0, work: [] });

/** Each work item's cached size already includes its independently owned output. */
export function monitorRequestBytes(sequence: number, workContentsBytes: number): number {
    return EMPTY_REQUEST_BYTES - 1 + jsonBytes(sequence) + workContentsBytes;
}
