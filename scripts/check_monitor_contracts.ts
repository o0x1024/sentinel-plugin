/** Read-only metadata/schema verification. No network or plugin execution. */
type SeedBinding = { seed_type: string; input_key: string };
type Contract = {
    id: string;
    version?: string;
    stream_tag?: string;
    monitor_type: string;
    input_mode: "asset" | "seed" | "hybrid";
    target_asset_types: string[];
    target_sources: string[];
    seed_bindings: SeedBinding[];
    capability_tags: string[];
};
type Schema = {
    type?: string | string[];
    properties?: Record<string, Schema>;
    items?: Schema;
    anyOf?: Schema[];
    oneOf?: Schema[];
};

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(await Deno.readTextFile(new URL("plugins.json", root)));
const catalog = JSON.parse(await Deno.readTextFile(new URL("scripts/monitor_plugin_contracts.json", root)));
const fields = ["id", "monitor_type", "input_mode", "target_asset_types", "target_sources", "seed_bindings"] as const;
const stages = new Set(["dns", "ip", "cert", "content", "api", "port", "service", "web", "risk"]);
const targetTypes = new Set(["domain", "domain_root", "domain_level_1", "domain_level_2", "domain_level_3_plus", "host", "ip", "ip_range", "service", "web", "api"]);
const forbiddenSeedKeys = new Set(["domain", "url", "ip", "target_objects", "service_targets"]);
const assetKeys = ["targets", "urls", "url", "domains", "domain", "ips", "ip", "target_objects", "service_targets"];
const capabilityTags = new Set(["fetch", "network-scan", "filesystem-read", "filesystem-write", "dictionary", "monitor-events", "ast-parse", "tls-inspect"].map(name => `capability:${name}`));

function declaredCapabilities(tags: string[]): string[] {
    return tags.filter(tag => tag.startsWith("capability:"));
}

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) throw new Error(message);
}

function acceptsString(schema: Schema): boolean {
    if (schema.type === "string" || Array.isArray(schema.type) && schema.type.includes("string")) return true;
    return [...(schema.anyOf ?? []), ...(schema.oneOf ?? [])].some(acceptsString);
}

function headerValue(source: string, field: string): string {
    const header = source.slice(0, source.indexOf("*/") + 2);
    const value = header.match(new RegExp(`^ \\* @${field} (.+)$`, "m"))?.[1];
    assert(value !== undefined, `Missing header declaration: ${field}`);
    return value;
}

const visited = new Set<string>();
for (const contract of catalog.plugins as Contract[]) {
    assert(!visited.has(contract.id), `Duplicate contract: ${contract.id}`);
    visited.add(contract.id);
    const entry = manifest.plugins.find((plugin: { id: string }) => plugin.id === contract.id);
    assert(entry, `Missing manifest entry: ${contract.id}`);
    assert(["bounty", "agent"].includes(entry.main_category), `${contract.id}: invalid category`);
    assert(stages.has(contract.monitor_type), `${contract.id}: invalid monitor stage`);
    for (const field of fields) {
        assert(JSON.stringify(entry[field]) === JSON.stringify(contract[field]), `${contract.id}: manifest drift at ${field}`);
    }
    if (entry.monitor_type) {
        assert(contract.version === entry.version, `${contract.id}: reviewed version drift`);
        assert(contract.stream_tag === "monitor:results-stream-v2", `${contract.id}: reviewed result-stream contract required`);
        assert(entry.tags.includes(contract.stream_tag), `${contract.id}: manifest result-stream declaration missing`);
        assert(!entry.tags.includes("monitor:technology-stream-v1"), `${contract.id}: obsolete technology-stream declaration`);
        assert(contract.capability_tags.includes("capability:monitor-events"), `${contract.id}: acknowledged results require monitor-events`);
    }
    assert(["asset", "seed", "hybrid"].includes(contract.input_mode), `${contract.id}: explicit input_mode required`);
    assert(Array.isArray(contract.target_sources), `${contract.id}: explicit target_sources required`);
    assert(new Set(contract.target_sources).size === contract.target_sources.length && contract.target_sources.every(value => ["surface_asset","bounty_asset","scope"].includes(value)), `${contract.id}: invalid target_sources`);
    assert(contract.input_mode === "seed" ? contract.target_sources.length === 0 : contract.target_sources.length > 0, `${contract.id}: target source/mode conflict`);
    const hasAssets = contract.target_asset_types.length > 0;
    const hasSeeds = contract.seed_bindings.length > 0;
    assert(hasAssets === (contract.input_mode !== "seed"), `${contract.id}: inconsistent asset contract`);
    assert(hasSeeds === (contract.input_mode !== "asset"), `${contract.id}: inconsistent seed contract`);
    assert(new Set(contract.target_asset_types).size === contract.target_asset_types.length, `${contract.id}: duplicate target types`);
    assert(contract.target_asset_types.every(type => targetTypes.has(type)), `${contract.id}: unsupported target type`);
    assert(Array.isArray(contract.capability_tags), `${contract.id}: explicit capability_tags required, including an empty array for pure computation`);
    assert(new Set(contract.capability_tags).size === contract.capability_tags.length, `${contract.id}: duplicate capabilities`);
    assert(contract.capability_tags.every(tag => capabilityTags.has(tag)), `${contract.id}: unknown capability`);
    assert(!contract.capability_tags.includes("capability:network-scan") || !contract.capability_tags.includes("capability:fetch"), `${contract.id}: redundant fetch grant; network-scan already permits fetch`);
    assert(JSON.stringify(declaredCapabilities(entry.tags)) === JSON.stringify(contract.capability_tags), `${contract.id}: manifest capability drift`);

    const sourceUrl = new URL(`plugins/${entry.main_category}/${entry.id}.ts`, root);
    const source = await Deno.readTextFile(sourceUrl);
    assert(source.split("\n").length <= 2001, `${contract.id}: source exceeds 2000 lines`);
    assert(headerValue(source, "plugin") === contract.id, `${contract.id}: header id drift`);
    assert(headerValue(source, "version") === entry.version, `${contract.id}: published version drift`);
    assert(JSON.stringify(declaredCapabilities(headerValue(source, "tags").split(",").map(tag => tag.trim()))) === JSON.stringify(contract.capability_tags), `${contract.id}: published capability drift`);
    if (entry.monitor_type) {
        const moduleSource = await Deno.readTextFile(new URL(`source/${entry.main_category}/${contract.id}/index.ts`, root));
        assert(headerValue(moduleSource, "version") === entry.version, `${contract.id}: authoritative module version drift`);
        assert(headerValue(moduleSource, "tags").split(",").map(tag => tag.trim()).includes(contract.stream_tag!), `${contract.id}: authoritative result-stream declaration missing`);
        assert(headerValue(source, "tags").split(",").map(tag => tag.trim()).includes(contract.stream_tag!), `${contract.id}: published result-stream declaration missing`);
        assert(JSON.stringify(declaredCapabilities(headerValue(moduleSource, "tags").split(",").map(tag => tag.trim()))) === JSON.stringify(contract.capability_tags), `${contract.id}: authoritative module capability drift`);
    }
    for (const field of ["monitor_type", "input_mode"] as const) {
        assert(headerValue(source, field) === contract[field], `${contract.id}: header drift at ${field}`);
    }
    for (const field of ["target_asset_types", "target_sources", "seed_bindings"] as const) {
        assert(JSON.stringify(JSON.parse(headerValue(source, field))) === JSON.stringify(contract[field]), `${contract.id}: header drift at ${field}`);
    }

    // Importing reads only the exported schema. Deno is invoked without network,
    // write, run, or environment permissions; analyze() is never called here.
    const plugin = await import(sourceUrl.href);
    assert(typeof plugin.get_input_schema === "function", `${contract.id}: input schema missing`);
    assert(typeof plugin.get_output_schema === "function", `${contract.id}: output schema missing`);
    const schema = plugin.get_input_schema() as Schema;
    assert(schema.type === "object" && schema.properties, `${contract.id}: input schema must define object properties`);
    if (hasAssets) {
        assert(assetKeys.some(key => key in schema.properties!), `${contract.id}: schema cannot consume monitor asset inputs`);
    }
    const seenBindings = new Set<string>();
    for (const binding of contract.seed_bindings) {
        const pair = `${binding.seed_type}:${binding.input_key}`;
        assert(!seenBindings.has(pair), `${contract.id}: duplicate binding ${pair}`);
        seenBindings.add(pair);
        assert(!binding.input_key.startsWith("__monitor") && !forbiddenSeedKeys.has(binding.input_key), `${contract.id}: reserved seed key ${binding.input_key}`);
        const field = schema.properties[binding.input_key];
        assert(field?.type === "array" && field.items && acceptsString(field.items), `${contract.id}: ${binding.input_key} must accept a string array`);
    }
    console.log(`${contract.id}: ${contract.input_mode}, ${contract.target_asset_types.length} target types, ${contract.seed_bindings.length} seed bindings, ${contract.capability_tags.length} capabilities`);
}
for (const plugin of manifest.plugins.filter((entry: { main_category: string }) => entry.main_category === "bounty")) {
    assert(visited.has(plugin.id), `${plugin.id}: bounty monitor missing its reviewed contract`);
}
console.log(`Validated ${visited.size} monitor contracts against manifest, published headers, and executable schemas; no plugins executed.`);
