// Run: deno test --allow-read scripts/plugin_manifest_test.ts
import { deepEqual, throws } from "node:assert/strict";
import { validateMonitorMetadata, validateMonitorSchema } from "./plugin_monitor_contract.ts";
import type { MonitorPluginMetadata } from "./plugin_monitor_contract.ts";

const manifest = JSON.parse(await Deno.readTextFile(new URL("../plugins.json", import.meta.url)));

for (const plugin of manifest.plugins) {
    Deno.test(`catalog contract: ${plugin.id}`, async () => {
        validateMonitorMetadata(plugin);
        const relativePath = new URL(plugin.download_url).pathname.split("/main/plugins/")[1];
        const url = new URL(`../plugins/${relativePath}`, import.meta.url);
        const source = await Deno.readTextFile(url);
        deepEqual(source.match(/@version\s+(\S+)/)?.[1], plugin.version);
        const module = await import(url.href);
        if (!plugin.monitor_type) return;
        validateMonitorSchema(plugin, module.get_input_schema());
        if (plugin.input_mode === "asset") {
            deepEqual(source.match(/@input_mode\s+(\S+)/)?.[1], "asset");
            deepEqual(source.match(/@monitor_type\s+(\S+)/)?.[1], plugin.monitor_type);
            deepEqual(source.match(/@target_asset_types ([^\n]+)/)?.[1].trim().split(/,\s*/), plugin.target_asset_types);
            // Targets must be supplied through fields the monitor actually injects.
            const properties = module.get_input_schema().properties;
            const keys = ["targets", "domains", "urls", "url", "ips", "ip", "target_objects", "service_targets", "api_paths"];
            deepEqual(keys.some((key) => key in properties), true);
        }
    });
}

const asset: MonitorPluginMetadata = {
    id: "test", main_category: "bounty", monitor_type: "ip",
    input_mode: "asset", target_asset_types: ["domain"],
};
const seed: MonitorPluginMetadata = {
    ...asset, input_mode: "seed", target_asset_types: [],
    seed_bindings: [{ seed_type: "domain", input_key: "domains" }],
};

Deno.test("reject incomplete, invalid, and contradictory monitor declarations", () => {
    const invalid = [
        { ...asset, input_mode: undefined },
        { ...asset, input_mode: "unknown" },
        { ...asset, target_asset_types: [] },
        { ...asset, target_asset_types: ["url"] },
        { ...asset, target_asset_types: ["domain", "domain"] },
        { ...asset, main_category: "traffic" },
        { ...asset, monitor_type: "unknown" },
        { ...asset, monitor_type: undefined },
        { ...asset, seed_bindings: seed.seed_bindings },
        { ...seed, target_asset_types: ["domain"] },
        { ...seed, seed_bindings: [] },
        { ...seed, seed_bindings: [...seed.seed_bindings!, ...seed.seed_bindings!] },
        { ...seed, seed_bindings: [{ seed_type: "domain", input_key: "url" }] },
        { ...asset, input_mode: "hybrid" },
        { ...seed, input_mode: "hybrid" },
    ];
    for (const plugin of invalid) throws(() => validateMonitorMetadata(plugin));
    validateMonitorMetadata(seed);
    validateMonitorMetadata({ ...asset, input_mode: "hybrid", seed_bindings: seed.seed_bindings });
    validateMonitorMetadata({ id: "plain", main_category: "agent" });
});

Deno.test("seed bindings must exist in the executable schema and accept string lists", () => {
    for (const field of [undefined, { type: "string" }, { type: "array", items: { type: "integer" } }]) {
        throws(() => validateMonitorSchema(seed, { type: "object", properties: field ? { domains: field } : {} }));
    }
    validateMonitorSchema(seed, { type: "object", properties: { domains: { type: "array", items: { type: "string" } } } });
});

Deno.test("takeover accepts monitor domains and preserves the legacy subdomains alias", async () => {
    const pluginUrl = new URL("../plugins/bounty/subdomain_takeover.ts", import.meta.url);
    const plugin = await import(pluginUrl.href);
    for (const input of [{ domains: ["test.example.com"] }, { subdomains: ["test.example.com"] }]) {
        const output = await plugin.analyze({ ...input, checkCname: false, checkHttp: false });
        deepEqual(output.success, true);
        deepEqual(output.data?.subdomains, ["test.example.com"]);
        deepEqual(output.data?.summary.total, 1);
    }
    const output = await plugin.analyze({ domains: [], subdomains: ["stale.example.com"], checkCname: false, checkHttp: false });
    deepEqual(output.success, false);
});
