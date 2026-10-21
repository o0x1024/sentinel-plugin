# Module-based monitor sources

`bounty/api_monitor` separates input/output contracts, discovery helpers, and the
monitor workflow. `bounty/subdomain_enumerator` separates request handling, data
source adapters, and the enumeration workflow. All source files stay below 2000
lines.

The desktop plugin loader installs one source string. These modules therefore
publish self-contained generated files at the existing `plugins/bounty/*.ts`
paths. Do not edit those two generated files directly. No module downloads or
runtime compatibility path are introduced.

Build with the pinned local `esbuild` dependency:

```sh
npm run build:monitors
npm run check:monitors
```

An existing installation may be selected explicitly without fetching packages:

```sh
node scripts/build_monitor_plugins.mjs --esbuild-module /absolute/path/to/esbuild/lib/main.js
node scripts/build_monitor_plugins.mjs --check --esbuild-module /absolute/path/to/esbuild/lib/main.js
```

`scripts/monitor_plugin_contracts.json` is the reviewed metadata-only contract
for the 19 installed monitors. It contains no credentials or plugin code. Its
values must match `plugins.json` and each plugin's metadata header. Use the
contract checking script after any metadata or input-schema change.

```sh
deno run --allow-read scripts/check_monitor_contracts.ts
deno run --allow-read scripts/verify_monitor_bundles.ts
```

The second command compares exported schemas, full results, snapshots, events,
and request sequences against deterministic fixtures. Network access is not
granted. During refactoring, `--baseline-dir /absolute/path/to/originals` also
compares saved pre-refactor single-file sources with the modules and bundles.
