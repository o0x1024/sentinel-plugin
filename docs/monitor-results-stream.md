# Acknowledged bounty monitor results

All 27 declared monitors (20 bounty and 7 Agent plugins) declare `monitor:results-stream-v2`. Their monitor runs
publish durable deltas through the existing `Sentinel.Monitor.commitResults`
channel. They share one implementation in `source/shared/monitor_results.ts`;
the native subdomain brute-force engine publishes through the same host channel.

## Execution contract

The host injects `__monitorExecution.result_stream` with:

```json
{
  "protocol": "monitor-results-v2",
  "targets": ["host-owned original target"],
  "max_work_items": 32,
  "max_pending_commits": 2,
  "max_bytes": 2097152
}
```

A monitor context requires this exact protocol and an available
`Sentinel.Monitor.commitResults` API. Missing or unsupported declarations fail
explicitly. Ordinary tool execution has no monitor context and returns the
plugin's existing complete output.

Each request contains only a strictly increasing sequence and independent work
records. Every record owns its standard output delta:

```json
{
  "sequence": 1,
  "work": [{
    "target": "host-owned original target",
    "key": "independent-work-item",
    "status": "ok",
    "complete": false,
    "output": { "success": true, "data": { "results": [] } }
  }]
}
```

`target` must belong to the host-injected target list. `key` identifies unique
work within that target and contains at most 2048 characters. Work status is
`ok`, `failed`, or `skipped`; errors may add `error` and `failure_category`.
`complete:true` ends the original target; later work for that target is invalid.
An intermediate request must explicitly use `complete:false`.

The host owns duplicate detection and persistence receipts. Plugins verify
`ack.ok === true` and the matching sequence before considering a save confirmed.
Save failure is terminal and is never converted into a target network failure.

## Bounds and useful progress

- Submit up to 32 work items, or submit completed work when five seconds have
  elapsed since the previous submission.
- Count the complete JSON request in UTF-8 bytes. Split before the 2 MiB bound;
  a single result exceeding the bound fails explicitly.
- Keep at most two unacknowledged submissions, including the currently saving
  batch. Wait for capacity before producing more buffered work.
- Only a newly acknowledged save renews the host's useful-progress budget.
  Logs, progress events, empty work, and duplicate receipts do not renew it.
- Monitor execution can exceed 300 seconds while new results are being saved.
  The host allows 90 seconds without a new save receipt and bounds each save
  phase to 60 seconds.

`createMonitorResultStream(input)` returns `enabled`, `assertHealthy()`,
`record(target, key, output, options)`, and `finish(finalOutput)`.
`record` defaults to status `ok` and `complete:true`. Producers check
`assertHealthy()` before starting more network or native work and propagate
submission errors. `finish` flushes remaining deltas, waits for every receipt,
and requires all original targets to have ended.

The SDK retains independent work outputs. After individual validation the host aggregates
outputs for the existing importer: arrays concatenate; snapshot dictionaries merge by key;
surface artifact arrays merge by kind; numeric summary values are increments.
Do not repeatedly supply a growing cumulative array or cumulative numeric
summary. The helper copies each work delta so producers can release their
local arrays after `record` resolves. Previously acknowledged work keys are
not retained by the plugin helper; the host keeps durable duplicate authority.

Stream deltas must never echo monitor inputs. Both the shared helper and the
host reject top-level `data.targets`, `data.target_objects`,
`data.service_targets`, `data.__monitorExecution`, `data.previousSnapshots`,
`data.previous_snapshots`, `data.dictionaryEntries`, and `data.dictionary`
before persistence. This also applies to a one-element echo. Target ownership
already belongs to each work item; successful observations and authoritative
snapshot changes belong in their respective result fields. The protocol does
not silently remove invalid fields.

Each discovery page/source is submitted once. Its final work item contains
only completion information, authoritative snapshots, and final changes or
evidence; it does not resend assets already acknowledged from earlier pages.

Monitoring completion returns `stream_complete:true` and numeric diagnostics.
It does not replay the saved payload. An unsuccessful final plugin output is
reported as an execution failure after prior valid deltas have been flushed
and acknowledged. Earlier saved results remain available.

## Work and snapshot boundaries

| Plugin | Saved work |
| --- | --- |
| `http_prober` | Each real HTTP/HTTPS endpoint; original domain/service completion |
| `tech_fingerprinter` | Each eligible existing Web asset |
| `cert_monitor` | Each complete certificate inspection |
| `content_monitor` | Each complete URL/content observation |
| `dns_resolver` | A hostname's requested DNS record set |
| `favicon_fingerprinter` | Page/icon observations and the target's final fingerprint result |
| `subdomain_takeover` | Each domain's completed verification |
| `cidr_mapper` | Bounded IP expansion pages and input-range completion |
| `directory_bruteforcer` | Deduplicated path probes |
| `risk_scanner` | Target/rule verification; scan-wide stop-on-first-hit state is shared |
| `sensitive_file_scanner` | Target baseline and rule probes; target failure state is shared |
| `actuator_scanner` | Shared origin baselines and deduplicated endpoint probes |
| `js_analyzer` | Retrieved/analyzed JavaScript files |
| `api_monitor` | Page, script, manifest and source-map observations |
| `fofa_asset_monitor` | Query pages and query completion |
| `subdomain_enumerator` | Root-domain/source observations and root completion |
| `port_monitor` | Bounded native port batches and complete-host observations |
| `service_probe` | Native service endpoint results |
| `service_monitor` | Native endpoint results and complete endpoint snapshots |
| `subdomain_brute` | Native completed-DNS observations, enrichment results and root completion |

Partial pages, sources, paths, or port batches are useful observations but do
not establish a complete baseline. FOFA query snapshots, root-domain source
snapshots, site/API snapshots, and host port snapshots are replaced only at
their authoritative completion boundary. Failed work cannot erase an earlier
complete baseline or imply that previously known assets disappeared.

## Build and verify

Edit `source/<main_category>/<plugin>/index.ts` and its supporting modules. Published
`plugins/<main_category>/<plugin>.ts` files are generated and contain no runtime imports.
The build enumerates every catalog entry declaring monitor_type, requires source/catalog
version agreement and the stream tag, pins esbuild 0.21.5, and limits each
published file to 2000 lines.

```sh
rtk npm run build:monitors
rtk npm run check:monitors
rtk npm run test:monitor-results
rtk proxy node --disable-warning=ExperimentalWarning scripts/run_readonly_tests.mjs scripts/check_monitor_contracts.ts
rtk proxy node --disable-warning=ExperimentalWarning scripts/run_readonly_tests.mjs scripts/plugin_catalog_smoke.ts
rtk proxy node --disable-warning=ExperimentalWarning scripts/run_readonly_tests.mjs scripts/tech_fingerprinter_test.ts
rtk proxy node --disable-warning=ExperimentalWarning --test scripts/bounty_payload_test.mjs
rtk proxy node --disable-warning=ExperimentalWarning scripts/bounty_payload_benchmark.mjs --sizes 64,256,1024 --assert-linear --output /private/tmp/sentinel-bounty-payload-benchmark.json
```

The payload benchmark defaults to current v2 producers and measures scaling across input sizes.
It counts independently serialized UTF-8 request bytes, work records and peak packages;
all network and native APIs are deterministic fixtures. Seven Agent monitors additionally
compare ordinary outputs, HTTP requests and in-memory file writes against their pre-migration
business behavior. These are controlled producer measurements, not public-network throughput.

The Node 24 runner supplies read-only Deno file/test-registration APIs and
blocks real fetch before installing deterministic test fixtures. It does not
prove native runtime permissions, real-provider behavior, production database
acceptance, or desktop operation. `scripts/export_monitor_stream_fixtures.mjs --output /private/tmp/monitor-v2-fixtures.json`
exports all 27 published producers with fixed authorizations for host validation.

Enabling these plugins requires the new host and updated installed plugin
code/metadata. Updating this repository alone does not replace an installed
plugin or restart the desktop application.

## Explicit capabilities and state ownership

Declare target_sources from surface_asset, bounty_asset and scope for asset/hybrid modes.
Seed mode uses declared seed_bindings and has no asset source. The host collects and scopes
inputs from these declarations. Plugin IDs identify producers and state namespaces; they
never select business behavior. HTTP/TLS applicability is decided by the producer from typed
service transport and application facts.

work.key is independent from the stable key in data.snapshots. Nonempty snapshots and
api_inventory require that same work to be successful and snapshot_complete:true. This
attests complete resource observation/inventory, independently of parent target complete.
Failed or partial inventories cannot replace retained state or imply removals.

Complete API inventories use data.api_inventory: [{baseUrl,success:true,snapshot:{baseUrl,
lastChecked,apiEndpoints:[{path,source?}]},addedApiEndpoints?,removedApiEndpoints?}]. The host
validates ownership, snapshot completion, timestamps and same-origin endpoints before writing
existing api_snapshot observations. Lists and downstream collectors select this result type,
including results from newly named plugins.

The host journals original work[] and checkpoints only the durable ACK prefix. Settled v1
history remains readable; unresolved old checkpoints block cutover. v1 execution is rejected.
Authoring tests use the production collector and persistence path in isolated full-schema
SQLite, and distinguish actual materialization from unexercised output families.
