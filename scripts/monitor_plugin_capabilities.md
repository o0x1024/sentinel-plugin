# Monitor plugin host capabilities

These declarations are derived from the handlers and their imported modules,
not from monitor stages or category names. `capability_tags` in
`monitor_plugin_contracts.json` is the reviewed contract; manifest `tags` and
published/source `@tags` must contain exactly that capability subset.

`network-scan` permits both native network probing and HTTP fetch. It therefore
does not also need `fetch`. `filesystem-write` permits file reads and writes;
none of these plugins needs a separate `filesystem-read` declaration.
Logging, returning data, and returning change-event arrays are core functions.
Host progress and acknowledged result publication require `monitor-events`.

All bounty monitors now also use the shared acknowledged-result stream,
`Sentinel.Monitor.commitResults`, when executing a monitor task. This requires
`monitor-events` even for a pure-computation plugin such as `cidr_mapper`.
The published tag is `monitor:results-stream-v1`; every bounty entry is bundled
from `source/bounty/<id>/index.ts` with `source/shared/monitor_results.ts`.

| Plugin | Capabilities (without `capability:` prefix) | Actual host calls and purpose |
| --- | --- | --- |
| actuator_scanner | fetch, monitor-events | HTTP actuator checks; `Sentinel.Monitor.reportProgress` |
| api_monitor | fetch, monitor-events | Discovery module fetches pages, JavaScript, manifests and source maps; progress publication |
| cert_monitor | tls-inspect, monitor-events | `Sentinel.TLS.getCertificate` inspects certificate metadata; progress publication |
| cidr_mapper | monitor-events | Pure IPv4/CIDR expansion; acknowledged result publication requires no network grant |
| content_monitor | fetch, monitor-events | HTTP content retrieval; progress publication |
| directory_bruteforcer | fetch, dictionary, monitor-events | HTTP path checks; `Sentinel.Dictionary.getWords`; progress publication |
| dns_resolver | network-scan, monitor-events | Native DNS resolution (`Deno.resolveDns`); progress publication |
| favicon_fingerprinter | fetch, dictionary, monitor-events | HTTP favicon discovery/download; `Sentinel.Dictionary.getEntries`; progress publication |
| fofa_asset_monitor | fetch, monitor-events | FOFA API requests; progress publication via the global Sentinel object |
| http_prober | fetch, monitor-events | HTTP/HTTPS endpoint probes; progress publication |
| js_analyzer | fetch, ast-parse, monitor-events | JavaScript retrieval; `Sentinel.AST.parse`; progress publication |
| port_monitor | network-scan, monitor-events | `Sentinel.Network.scanPorts`; progress publication |
| risk_scanner | fetch, dictionary, monitor-events | HTTP verification; dictionary default ID and entries; progress publication |
| sensitive_file_scanner | fetch, dictionary, monitor-events | HTTP exposure checks; dictionary default ID and entries; progress publication |
| service_monitor | network-scan, dictionary, monitor-events | Native `Sentinel.Network.probeServices`; HTTP protocol checks and TCP banner operations; dictionary entries; progress publication |
| service_probe | network-scan, dictionary, monitor-events | Native `Sentinel.Network.probeServices`; HTTP protocol checks and TCP banner operations; dictionary entries; progress publication |
| subdomain_enumerator | fetch, monitor-events | Imported source modules make OSINT HTTP requests; acknowledged source results and progress publication |
| subdomain_takeover | fetch, monitor-events | CNAME/HTTP takeover checks; acknowledged per-domain results |
| subdomain_brute | network-scan, monitor-events | One `Sentinel.Network.bruteForceSubdomains` batch delegates dictionary loading, DNS, progress, snapshots and surface artifacts to the shared native Rust engine; no per-word JavaScript DNS or Dictionary calls |
| tech_fingerprinter | fetch, dictionary, monitor-events | HTTP fingerprinting; dictionary default ID and entries; progress publication |
| webpack_source_downloader | fetch, filesystem-write, monitor-events | HTTP source-map/source download; `Deno.mkdir` and `Deno.writeTextFile` export source files; progress publication |

The metadata checker performs no plugin execution and grants no network access.
The deterministic bundle comparison uses fixtures and does not establish native
host permissions. Native acceptance must load source metadata through
`PluginEngine::new_for_metadata`, verify a declared fetch reaches a loopback
server, and verify the same call without its grant fails explicitly.

The DNS declaration requires the native runtime to expose `Deno.resolveDns`
under `network-scan`. A declaration alone cannot supply a missing host API;
installation and acceptance must verify that binding rather than substitute
another resolver or grant unrestricted access.

## Installed-code audit and existing SDK gaps (2026-10-18)

A read-only check of all 19 installed `plugin_registry.plugin_code` values
(each was nonempty, so `code` was not selected) confirmed the same host API
requirements as this catalog. In particular, installed subdomain_enumerator
2.2.5 uses `_nativeFetch` and logging, without progress publication, AST, DNS,
TLS, or filesystem access. Installed FOFA 1.2.5 publishes progress through
the local `sentinel` alias; its `monitor-events` grant is required.

These findings do not establish that every SDK method exists in the current
native runtime. Separate existing gaps were identified by inspecting actual
registered bindings and bootstrap methods:

| Installed plugin | API gap | Effect and scope |
| --- | --- | --- |
| dns_resolver 1.1.2 | `Deno.resolveDns` has no registered implementation | Required resolution call cannot execute; its handler explicitly requires this API. Granting `network-scan` alone does not supply it. |
| webpack_source_downloader 1.0.6 | `Deno.mkdir` / `Deno.writeTextFile` are absent from the Deno object | The host has permission-gated `__sentinel_mkdir` / `__sentinel_write_text_file`, but this handler does not call those names. The optional local-file export path remains unsupported by that SDK surface. |
| service_probe 1.2.6 and service_monitor 1.0.6 | Their older TCP branch references absent `Deno.connect` | Their primary path calls the available native `Sentinel.Network.probeServices`. This declaration repair does not establish that the older branch works. |

The current bootstrap initializes `Deno` with `build` information only.
No compatibility aliases, alternate handlers, or unrestricted grants were
introduced to hide these gaps. The metadata repair's desktop acceptance is
the actual HTTP manual/scheduled loopback chain; these separate SDK paths
require their own explicit implementation and native acceptance.
