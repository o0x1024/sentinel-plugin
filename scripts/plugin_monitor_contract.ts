/** Keep catalog validation aligned with sentinel-contracts/src/monitor_plugin.rs. */
export interface MonitorPluginMetadata {
    id: string;
    main_category: string;
    monitor_type?: string | null;
    input_mode?: string | null;
    target_asset_types?: string[];
    seed_bindings?: Array<{ seed_type: string; input_key: string }>;
}

const assetTypes = new Set([
    "web", "domain", "domain_root", "domain_level_1", "domain_level_2",
    "domain_level_3_plus", "host", "ip", "ip_range", "service", "api",
]);
const monitorTypes = new Set(["dns", "ip", "cert", "content", "api", "port", "service", "web", "risk"]);

export function validateMonitorMetadata(plugin: MonitorPluginMetadata): void {
    const fail = (message: string): never => {
        throw new Error(`Monitor plugin '${plugin.id}': ${message}`);
    };
    const targets = plugin.target_asset_types ?? [];
    const bindings = plugin.seed_bindings ?? [];
    if (plugin.monitor_type == null) {
        if (plugin.input_mode != null || targets.length || bindings.length) {
            fail("monitor inputs require monitor_type");
        }
        return;
    }
    if (!["agent", "bounty"].includes(plugin.main_category)) fail("requires agent or bounty main_category");
    if (!monitorTypes.has(plugin.monitor_type)) fail("requires a valid monitor_type");
    if (plugin.input_mode == null) fail("has no input_mode");
    if (!["asset", "seed", "hybrid"].includes(plugin.input_mode!)) fail("unsupported input_mode");
    if (targets.some((type) => !assetTypes.has(type)) || new Set(targets).size !== targets.length) {
        fail("target_asset_types contains an invalid or duplicate type");
    }
    const seen = new Set<string>();
    for (const { seed_type: type, input_key: key } of bindings) {
        if (!key || key.length > 128 || key.trim() !== key || key.startsWith("__monitor") ||
            ["target_objects", "service_targets", "domain", "url", "ip"].includes(key)) {
            fail(`invalid or reserved seed input: ${key}`);
        }
        const pair = JSON.stringify([type, key]);
        if (!type || type.length > 64 || type.trim() !== type || seen.has(pair)) {
            fail("seed_bindings contains an invalid or duplicate binding");
        }
        seen.add(pair);
    }
    if (plugin.input_mode === "asset" && (!targets.length || bindings.length)) {
        fail("asset mode requires target_asset_types and forbids seed_bindings");
    }
    if (plugin.input_mode === "seed" && (targets.length || !bindings.length)) {
        fail("seed mode requires seed_bindings and forbids target_asset_types");
    }
    if (plugin.input_mode === "hybrid" && (!targets.length || !bindings.length)) {
        fail("hybrid mode requires target_asset_types and seed_bindings");
    }
}

type Schema = {
    type?: string | string[];
    properties?: Record<string, Schema>;
    items?: Schema;
    anyOf?: Schema[];
    oneOf?: Schema[];
};

function acceptsString(schema: Schema): boolean {
    return schema.type === "string" || (Array.isArray(schema.type) && schema.type.includes("string")) ||
        [...(schema.anyOf ?? []), ...(schema.oneOf ?? [])].some(acceptsString);
}

export function validateMonitorSchema(plugin: MonitorPluginMetadata, schema: Schema): void {
    validateMonitorMetadata(plugin);
    if (plugin.monitor_type == null) return;
    if (!schema || schema.type !== "object" || !schema.properties) {
        throw new Error(`Plugin '${plugin.id}' input schema must declare object properties`);
    }
    for (const { input_key: key } of plugin.seed_bindings ?? []) {
        const field = schema.properties[key];
        if (field?.type !== "array" || !field.items || !acceptsString(field.items)) {
            throw new Error(`Plugin '${plugin.id}' seed input must accept an array of strings: ${key}`);
        }
    }
}
