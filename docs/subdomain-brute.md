# Native subdomain brute-force monitor

`subdomain_brute` 1.0.0 is a small, self-contained monitor plugin. It delegates
the complete target batch to `Sentinel.Network.bruteForceSubdomains(request)`.
The host uses the shared Rust DNS engine and reads platform dictionaries natively;
the plugin never loads a platform wordlist into JavaScript or sends one DNS
request per dictionary entry.

The catalog declares DNS monitoring with seed input ownership:

```json
{
  "monitor_type": "dns",
  "input_mode": "seed",
  "target_asset_types": [],
  "seed_bindings": [
    { "seed_type": "root_domain", "input_key": "targets" },
    { "seed_type": "domain", "input_key": "targets" }
  ]
}
```

## Install and run

Rebuild and restart a Sentinel host that provides the native
`Sentinel.Network.bruteForceSubdomains` bridge. Import the local file
`plugins/bounty/subdomain_brute.ts` through plugin management, or install the
catalog entry after this source and `plugins.json` have been published. The
plugin is registered through the existing monitor plugin registry; the host
does not automatically seed or replace the user's installed plugins.

This plugin is authored directly as one small file and needs no bundling.
`build:monitors` continues to build only the existing module-based monitors;
their generated bundles and unrelated working-tree edits remain independent.

Configure the platform subdomain dictionary and add a DNS monitor using
`subdomain_brute`. Root-domain and domain seeds are injected into `targets`.
Targets and monitor execution context belong to the monitor task, rather than
global plugin defaults. A direct invocation can use:

```json
{
  "targets": ["example.test", "other.test"],
  "dictionary_id": "your-subdomain-dictionary-id",
  "dictionary": ["api", "admin"],
  "resolvers": ["127.0.0.1:5353"],
  "transport": "udp",
  "skip_wildcard": true,
  "bandwidth_limit": "3M",
  "dns_timeout_seconds": 10,
  "max_wait_seconds": 30
}
```

`dictionary_id` and inline `dictionary` are forwarded unchanged. The native
engine validates dictionary contents and applies its normal selection
rules, including the configured default when no explicit source is supplied.
Timeouts, resolver errors, missing dictionaries and cancellation propagate as
failures. They are not converted to successful empty snapshots.

The ordinary monitor host currently keeps its existing 300-second execution
budget. `max_wait_seconds` is only the response wait window after the initial
batch has been sent; it does not extend that host budget. Callers choose a batch
size suitable for their dictionary, roots and bandwidth.

UDP is the plugin default for ordinary desktop permissions. Ethernet transport
is an explicit raw-packet choice and may require suitable device/OS permissions.
An unavailable transport is an explicit failure; the plugin never silently
switches transport or falls back to a JavaScript DNS implementation. Missing
native APIs produce an actionable host-update error.

## Host and result contracts

The bridge receives native snake_case arguments in one batch. Other supported
settings include `max_retries`, `verify_mode`, `verify_timeout_seconds`,
`verify_concurrency`, `resolve_records`, `query_types`, `raw_records` and `device`.
Their types, ranges and defaults are published by `get_input_schema()`.

The host-injected `__monitorExecution` object is forwarded unchanged. The host
checks its plugin-run identity and owns progress/cancellation context; callers
cannot substitute another monitor task. Compatibility capability declarations
are `network-scan` and `monitor-events`; they do not provide a missing host API.

Results retain native `targets`, `subdomains`, `results`, `change_events`,
`snapshots`, `summary` and `surface_artifacts`. The `changeEvents` compatibility
alias points at the same array as `change_events`. Standard surface persistence
uses `surface_artifacts`, including its `changes` array. Snapshot timestamps
remain `last_checked`. Old injected `previousSnapshots` and `lastChecked` values
are adapted to native names without changing the caller's objects.

## Offline validation

```sh
node --test scripts/subdomain_brute_test.mjs
deno test --allow-read scripts/plugin_manifest_test.ts
deno run --allow-read scripts/check_monitor_contracts.ts
deno run --allow-read scripts/plugin_catalog_smoke.ts
deno run --allow-read scripts/bounty_functional_test.ts
```

The new unit tests and catalog/functional scenarios use a deterministic mocked
native bridge. They cover schema/catalog agreement, one-call multi-target
execution, platform dictionary references, transport failures, legacy snapshots,
host-context pass-through, complete surface results and errors/cancellation.
These tests do not prove live DNS behavior or native OS packet permissions;
those require the host's separate native-engine acceptance.
