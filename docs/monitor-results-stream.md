# Acknowledged bounty monitor results

All 20 bounty plugins declare `monitor:results-stream-v1`. Their monitor runs
publish durable deltas through the existing `Sentinel.Monitor.commitResults`
channel. They share one implementation in `source/shared/monitor_results.ts`;
the native subdomain brute-force engine publishes through the same host channel.

## Execution contract

The host injects `__monitorExecution.result_stream` with:

```json
{
  "protocol": "monitor-results-v1",
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

Each request contains a strictly increasing sequence, completed work, and a
standard output delta:

```json
{
  "sequence": 1,
  "work": [{
    "target": "host-owned original target",
    "key": "independent-work-item",
    "status": "ok",
    "complete": false
  }],
  "output": { "success": true, "data": { "results": [] } }
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

Arrays in output deltas are concatenated; snapshot dictionaries merge by key;
surface artifact arrays merge by kind; numeric summary values are increments.
Do not repeatedly supply a growing cumulative array or cumulative numeric
summary. The helper copies buffered deltas so producers can release their
local arrays after `record` resolves. Previously acknowledged work keys are
not retained by the plugin helper; the host keeps durable duplicate authority.

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

Edit `source/bounty/<plugin>/index.ts` and its supporting modules. Published
`plugins/bounty/<plugin>.ts` files are generated and contain no runtime imports.
The build enumerates every bounty catalog entry, requires source/catalog
version agreement and the stream tag, pins esbuild 0.21.5, and limits each
published file to 2000 lines.

```sh
rtk npm run build:monitors
rtk npm run check:monitors
rtk npm run test:monitor-results
rtk proxy node --disable-warning=ExperimentalWarning scripts/run_readonly_tests.mjs scripts/check_monitor_contracts.ts
rtk proxy node --disable-warning=ExperimentalWarning scripts/run_readonly_tests.mjs scripts/plugin_catalog_smoke.ts
rtk proxy node --disable-warning=ExperimentalWarning scripts/run_readonly_tests.mjs scripts/tech_fingerprinter_test.ts
```

The Node 24 runner supplies read-only Deno file/test-registration APIs and
blocks real fetch before installing deterministic test fixtures. It does not
prove native runtime permissions, real-provider behavior, production database
acceptance, or desktop operation. An explicit `--stream-fixtures-out` argument
can export synthetic commit requests to `/private/tmp/` for host validator tests.

Enabling these plugins requires the new host and updated installed plugin
code/metadata. Updating this repository alone does not replace an installed
plugin or restart the desktop application.
