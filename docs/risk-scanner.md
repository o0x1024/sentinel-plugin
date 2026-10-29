# Risk Scanner: full rule coverage

Risk Scanner executes every applicable rule from the selected Risk Scanner Rules
dictionary or inline `dictionaryEntries`. Rules are deduplicated and filtered by
enabled state, safe mode and fingerprint scope. Rule preconditions and chained
request matchers still determine whether a rule sends its remaining requests.

There is no `maxRules` parameter or first-N truncation. The existing host
`Sentinel.Dictionary.getEntries(id, null)` API reads the complete dictionary using
its unbounded query. Explicit JSON null crosses the native bridge safely. An
explicit dictionary is authoritative: an empty or
failed read is an execution failure. No other dictionary is substituted.

`concurrency` defaults to 32 and accepts integers from 1 to 1000. It limits the
number of concurrent target/rule verifications across the execution. A rule's
requests remain sequential. HTTP requests also share the host's global direct
fetch limit.

Workers claim task indexes on demand. They do not allocate an array for the
target/rule Cartesian product, one closure per combination, or an unused result
array. Input storage is O(targets + rules); scheduler storage is O(concurrency).
After a failure, workers claim no additional tasks and drain started work before
returning the failure. `stopOnFirstHit` also stops future task claims.

Monitor mode commits evidence incrementally using the existing acknowledged
result stream and its bounded pending batches. UI progress updates are coalesced
at 250 ms intervals; final phase updates remain immediate. Completion diagnostics
report loaded rules, applicable rules, planned target/rule tasks and completed
target/rule tasks. A persistence failure or cancelled execution cannot report
successful stream completion.

Ordinary tool mode returns its complete findings and evidence. Its output storage
therefore grows with returned results even though its scheduler is bounded.

## Validation

Use Node 24:

```sh
rtk proxy node --test scripts/risk_scanner_concurrency_test.mjs scripts/risk_scanner_full_scan_test.mjs
rtk proxy node scripts/risk_scanner_scheduler_benchmark.mjs --assert-memory
rtk proxy node scripts/validate_risk_scanner_native.mjs
rtk npm run check:monitors
```

The benchmark runs the real published producers in separate processes. It gives
the previous version equal rule coverage, gates the first 32 HTTP calls, and
measures preparation memory for 100,000 and 1,000,000 planned target/rule tasks.
All I/O is mocked. These measurements do not establish real HTTP throughput or
native desktop performance.

Native acceptance requires the sibling `sentinel-ai-pro` checkout and permission
to open loopback sockets. Its fixture uses in-memory SQLite, the real
PluginManager/QuickJS bridge, and owned HTTP servers. It verifies 10,005 loaded
rules, global request concurrency and cancellation. The runner installs an
exclusive temporary Cargo test and removes it afterward; existing test files
are never overwritten. Add `--output report.json` to save its evidence.
Use `--bundle path/to/plugin.ts` to validate an exact release artifact.
