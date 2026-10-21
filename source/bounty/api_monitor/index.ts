/**
 * API Endpoint Change Monitor
 *
 * @plugin api_monitor
 * @name API Monitor
 * @version 1.4.3
 * @author Sentinel Team
 * @main_category bounty
 * @category monitor
 * @monitor_type api
 * @input_mode asset
 * @target_asset_types ["web"]
 * @seed_bindings []
 * @default_severity high
 * @tags api, endpoint, monitor, change-detection, rest, javascript, spa, capability:fetch, capability:monitor-events
 * @description Monitor API endpoints and HTML routes by discovering JavaScript assets from pages and bundles, extracting API-like and route-like path literals, and comparing snapshot changes over time
 */
import type { MonitorExecutionContext, ToolInput, JsLink, ScriptContentSource, SourceMapLike, FetchResult, JsDiscoveryResult, ApiEndpoint, HtmlRoute, ApiSnapshot, JsFetchFailure, ChangeEvent, ApiResult, ToolOutput } from './types.ts';
import { reportMonitorProgress, generateId, runWithConcurrency, DEFAULT_MAX_JS_FILES, DEFAULT_PAGE_CRAWL_LIMIT, DEFAULT_MAX_PAGES, PAGE_FETCH_CONCURRENCY_LIMIT, JS_FETCH_CONCURRENCY_LIMIT, MAX_JS_DISCOVERY_DEPTH, MAX_STRING_SCAN_MATCHES, MAX_PATH_CANDIDATE_LENGTH, EXCLUDED_STATIC_PREFIXES, EXCLUDED_EXACT_PATHS, EXCLUDED_STATIC_EXTENSIONS, EXCLUDED_HTML_TAG_PATHS, VENDOR_JS_FILENAME_PATTERNS, VENDOR_JS_PATH_SEGMENTS, normalizeCommonPathCandidate, extractPathCandidate, isStaticAssetPath, normalizeEndpointPath, normalizeHtmlRoutePath, pushApiEndpoint, pushHtmlRoute, maybePushStringCandidate, readEscapedJsChar, skipJsComment, skipQuotedJsValue, skipTemplateExpression, extractStringPathCandidates, extractPathsFromJs, simpleHash, resolveUrl, isSameOrigin, looksLikeJs, shouldSkipVendorJs, PAGE_FETCH_TIMEOUT_MS, fetchDocument, canAnalyzePageResponse, describeTargetFetchFailure, extractScriptTags, extractLinkTags, extractInlineScripts, extractWebpackRuntimeChunkLinks, pushDiscoveredJsLink, extractJsFromContent, resolveSourceMapSourceUrl, parseSourceMapScriptContents, parseManifest, getManifestUrls, extractSameOriginPageLinks, pushJsLink, discoverJavascriptAssets, calculateRiskScore } from './discovery.ts';

type PluginGlobals = typeof globalThis & {
    get_input_schema?: typeof get_input_schema;
    get_output_schema?: typeof get_output_schema;
    analyze?: typeof analyze;
};

const pluginGlobals = globalThis as PluginGlobals;

/**
 * Export input schema
 */
export function get_input_schema() {
    return {
        type: "object",
        required: ["targets"],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "List of base URLs to monitor for API changes"
            },
            userAgent: {
                type: "string",
                description: "Custom User-Agent header"
            },
            crawlDepth: {
                type: "integer",
                description: "Depth to crawl for JS discovery (0 = current page only, 1 = current page + JS bundles, 2+ = crawl same-origin pages)",
                default: 1,
                minimum: 0,
                maximum: 3
            },
            maxPages: {
                type: "integer",
                description: "Maximum same-origin pages to crawl per target when crawlDepth is greater than 1",
                default: 20,
                minimum: 1,
                maximum: 50
            },
            maxJsFiles: {
                type: "integer",
                description: "Maximum JavaScript files to analyze per target",
                default: 20,
                minimum: 10,
                maximum: 300
            },
            includeSameOriginOnly: {
                type: "boolean",
                description: "Only analyze JavaScript assets from the same origin",
                default: true
            },
            followSourceMaps: {
                type: "boolean",
                description: "Follow sourceMappingURL references during JS discovery",
                default: false
            },
            probeSpaManifests: {
                type: "boolean",
                description: "Probe common SPA manifest endpoints to discover bundled JS",
                default: false
            },
            previousSnapshots: {
                type: "object",
                description: "Previous API and HTML route snapshots for comparison"
            }
        }
    };
}

pluginGlobals.get_input_schema = get_input_schema;

/**
 * Export output schema
 */
export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean", description: "Whether the operation succeeded" },
            data: {
                type: "object",
                properties: {
                    results: {
                        type: "array",
                        items: {
                            type: "object",
                            properties: {
                                baseUrl: { type: "string" },
                                success: { type: "boolean" },
                                snapshot: {
                                    type: "object",
                                    properties: {
                                        baseUrl: { type: "string" },
                                        lastChecked: { type: "string" },
                                        htmlRoutes: {
                                            type: "array",
                                            items: {
                                                type: "object",
                                                properties: {
                                                    path: { type: "string" },
                                                    source: { type: "string" },
                                                }
                                            }
                                        },
                                        apiEndpoints: {
                                            type: "array",
                                            items: {
                                                type: "object",
                                                properties: {
                                                    path: { type: "string" },
                                                    source: { type: "string" },
                                                }
                                            }
                                        }
                                    }
                                },
                                timings: {
                                    type: "object",
                                    properties: {
                                        targetFetchMs: { type: "integer" },
                                        assetDiscoveryMs: { type: "integer" },
                                        pageCrawlMs: { type: "integer" },
                                        manifestProbeMs: { type: "integer" },
                                        jsFetchMs: { type: "integer" },
                                        sourceMapFetchMs: { type: "integer" },
                                        nestedJsDiscoveryMs: { type: "integer" },
                                        astExtractionMs: { type: "integer" },
                                        compareMs: { type: "integer" },
                                        totalMs: { type: "integer" },
                                    }
                                },
                                metrics: {
                                    type: "object",
                                    properties: {
                                        crawledPages: { type: "integer" },
                                        htmlRoutesDiscovered: { type: "integer" },
                                        scriptSources: { type: "integer" },
                                        jsFilesAnalyzed: { type: "integer" },
                                        pageFetchCount: { type: "integer" },
                                        manifestRequests: { type: "integer" },
                                        jsFetchCount: { type: "integer" },
                                        jsFetchFailureCount: { type: "integer" },
                                        sourceMapFetchCount: { type: "integer" },
                                        jsLinksDiscovered: { type: "integer" },
                                        inlineScriptCount: { type: "integer" },
                                    }
                                },
                                jsFetchFailures: {
                                    type: "array",
                                    items: {
                                        type: "object",
                                        properties: {
                                            url: { type: "string" },
                                            finalUrl: { type: "string" },
                                            linkType: { type: "string" },
                                            discoverySource: { type: "string" },
                                            status: { type: ["integer", "null"] },
                                            contentType: { type: "string" },
                                            size: { type: "integer" },
                                            error: { type: "string" },
                                        }
                                    }
                                },
                                addedHtmlRoutes: { type: "array" },
                                removedHtmlRoutes: { type: "array" },
                                addedApiEndpoints: { type: "array" },
                                removedApiEndpoints: { type: "array" }
                            }
                        },
                        description: "API and HTML route monitoring results"
                    },
                    changeEvents: { type: "array", description: "Change events detected" },
                    snapshots: { type: "object", description: "API and HTML route snapshots by URL" },
                    summary: {
                        type: "object",
                        properties: {
                            totalTargets: { type: "integer" },
                            totalHtmlRoutes: { type: "integer" },
                            totalApiEndpoints: { type: "integer" },
                            totalJsFiles: { type: "integer" },
                            addedHtmlRoutes: { type: "integer" },
                            removedHtmlRoutes: { type: "integer" },
                            addedApiEndpoints: { type: "integer" },
                            removedApiEndpoints: { type: "integer" },
                            routeChanges: { type: "integer" },
                            apiChanges: { type: "integer" }
                        }
                    }
                }
            },
            error: { type: "string", description: "Error message if failed" }
        }
    };
}

pluginGlobals.get_output_schema = get_output_schema;

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        if (!input.targets || !Array.isArray(input.targets)) {
            return {
                success: false,
                error: "Invalid input: targets array is required"
            };
        }

        const validTargets = input.targets.filter(t => typeof t === 'string' && t.trim().length > 0);
        if (validTargets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets array must contain at least one non-empty string"
            };
        }

        const userAgent = input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        const crawlDepth = input.crawlDepth ?? 1;
        const maxPages = Math.max(1, Math.min(input.maxPages || DEFAULT_MAX_PAGES, 200));
        const maxJsFiles = Math.max(10, Math.min(input.maxJsFiles || DEFAULT_MAX_JS_FILES, 500));
        const includeSameOriginOnly = input.includeSameOriginOnly === true;
        const followSourceMaps = input.followSourceMaps === true;
        const probeSpaManifests = input.probeSpaManifests === true;
        const previousSnapshots = input.previousSnapshots || {};
        const monitorExecution = input.__monitorExecution;
        const totalProgressUnits = validTargets.length + 2;

        await reportMonitorProgress(monitorExecution, {
            current: 0,
            total: totalProgressUnits,
            phase: "prepare",
            message: "Preparing API discovery",
        });

        const results: ApiResult[] = [];
        const changeEvents: ChangeEvent[] = [];
        const newSnapshots: Record<string, ApiSnapshot> = {};

        let successfulChecks = 0;
        let failedChecks = 0;
        let totalHtmlRoutes = 0;
        let totalApiEndpoints = 0;
        let totalJsFiles = 0;
        let addedHtmlRoutesCount = 0;
        let removedHtmlRoutesCount = 0;
        let addedApiEndpointsCount = 0;
        let removedApiEndpointsCount = 0;
        let routeChanges = 0;
        let apiChanges = 0;
        let completedTargets = 0;

        const targetTasks = validTargets.map((target) => async () => {
            let baseUrl = target;
            if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
                baseUrl = `https://${baseUrl}`;
            }

            const result: ApiResult = {
                baseUrl,
                success: false,
            };

            try {
                const targetStartedAt = Date.now();
                const allHtmlRoutes: HtmlRoute[] = [];
                const allApiEndpoints: ApiEndpoint[] = [];
                let jsFilesAnalyzed = 0;
                let crawledPages = 1;
                let htmlRoutesDiscovered = 0;
                let scriptSourceCount = 0;
                let targetFetchMs = 0;
                let assetDiscoveryMs = 0;
                let pageCrawlMs = 0;
                let manifestProbeMs = 0;
                let jsFetchMs = 0;
                let sourceMapFetchMs = 0;
                let nestedJsDiscoveryMs = 0;
                let astExtractionMs = 0;
                let compareMs = 0;
                let pageFetchCount = 0;
                let manifestRequests = 0;
                let jsFetchCount = 0;
                let jsFetchFailureCount = 0;
                let sourceMapFetchCount = 0;
                let jsLinksDiscovered = 0;
                let inlineScriptCount = 0;

                const targetFetchStartedAt = Date.now();
                const pageResult = await fetchDocument(
                    baseUrl,
                    userAgent,
                    "text/html,application/xhtml+xml,*/*",
                );
                targetFetchMs = Date.now() - targetFetchStartedAt;

                if (!pageResult || pageResult.status === null) {
                    result.error = describeTargetFetchFailure(pageResult);
                    failedChecks++;
                    results.push(result);
                    return;
                }

                successfulChecks++;

                const pageContent = canAnalyzePageResponse(pageResult) ? pageResult.text : "";
                const directJsTarget = Boolean(pageContent) && (looksLikeJs(baseUrl) || pageResult.contentType.includes("javascript"));
                let scriptSources: ScriptContentSource[] = [];

                if (pageContent) {
                    if (directJsTarget) {
                        scriptSources = [{ source: baseUrl, content: pageContent }];
                    } else {
                        const assetDiscoveryStartedAt = Date.now();
                        const discoveryResult = await discoverJavascriptAssets(
                            baseUrl,
                            pageContent,
                            userAgent,
                            crawlDepth,
                            maxPages,
                            maxJsFiles,
                            includeSameOriginOnly,
                            followSourceMaps,
                            probeSpaManifests,
                        );
                        assetDiscoveryMs = Date.now() - assetDiscoveryStartedAt;
                        scriptSources = discoveryResult.scriptContents;
                        allHtmlRoutes.push(...discoveryResult.htmlRoutes);
                        crawledPages = discoveryResult.crawledPages.length;
                        htmlRoutesDiscovered = discoveryResult.htmlRoutes.length;
                        pageCrawlMs = discoveryResult.timings.pageCrawlMs;
                        manifestProbeMs = discoveryResult.timings.manifestProbeMs;
                        jsFetchMs = discoveryResult.timings.jsFetchMs;
                        sourceMapFetchMs = discoveryResult.timings.sourceMapFetchMs;
                        nestedJsDiscoveryMs = discoveryResult.timings.nestedJsDiscoveryMs;
                        pageFetchCount = discoveryResult.metrics.pageFetchCount;
                        manifestRequests = discoveryResult.metrics.manifestRequests;
                        jsFetchCount = discoveryResult.metrics.jsFetchCount;
                        jsFetchFailureCount = discoveryResult.metrics.jsFetchFailureCount;
                        sourceMapFetchCount = discoveryResult.metrics.sourceMapFetchCount;
                        jsLinksDiscovered = discoveryResult.metrics.jsLinksDiscovered;
                        inlineScriptCount = discoveryResult.metrics.inlineScriptCount;
                        result.jsFetchFailures = discoveryResult.jsFetchFailures;
                    }
                }

                scriptSourceCount = scriptSources.length;

                jsFilesAnalyzed = directJsTarget
                    ? 1
                    : scriptSources.filter(source => !source.source.startsWith("inline://")).length;
                totalJsFiles += jsFilesAnalyzed;

                const astExtractionStartedAt = Date.now();
                for (const source of scriptSources) {
                    try {
                        const extracted = extractPathsFromJs(source.content, source.source);
                        allHtmlRoutes.push(...extracted.htmlRoutes);
                        allApiEndpoints.push(...extracted.apiEndpoints);
                    } catch {
                        continue;
                    }
                }
                astExtractionMs = Date.now() - astExtractionStartedAt;

                const uniqueHtmlRoutes: HtmlRoute[] = [];
                const seenHtmlRoutes = new Set<string>();
                for (const route of allHtmlRoutes) {
                    if (!seenHtmlRoutes.has(route.path)) {
                        seenHtmlRoutes.add(route.path);
                        uniqueHtmlRoutes.push(route);
                    }
                }
                const uniqueApiEndpoints: ApiEndpoint[] = [];
                const seenApiEndpoints = new Set<string>();
                for (const endpoint of allApiEndpoints) {
                    if (!seenApiEndpoints.has(endpoint.path)) {
                        seenApiEndpoints.add(endpoint.path);
                        uniqueApiEndpoints.push(endpoint);
                    }
                }
                totalHtmlRoutes += uniqueHtmlRoutes.length;
                totalApiEndpoints += uniqueApiEndpoints.length;
                htmlRoutesDiscovered = uniqueHtmlRoutes.length;

                const snapshot: ApiSnapshot = {
                    baseUrl,
                    htmlRoutes: uniqueHtmlRoutes,
                    apiEndpoints: uniqueApiEndpoints,
                    lastChecked: new Date().toISOString(),
                };

                result.success = true;
                result.snapshot = snapshot;
                newSnapshots[baseUrl] = snapshot;

                await reportMonitorProgress(monitorExecution, {
                    current: completedTargets + 1,
                    total: totalProgressUnits,
                    phase: "scan",
                    currentTarget: baseUrl,
                    message: `Analyzed ${jsFilesAnalyzed} JS files and discovered ${uniqueHtmlRoutes.length} HTML routes and ${uniqueApiEndpoints.length} API endpoints`,
                });

                const compareStartedAt = Date.now();
                const prevSnapshot = previousSnapshots[baseUrl];
                if (prevSnapshot) {
                    const prevHtmlRoutePaths = new Set(prevSnapshot.htmlRoutes.map(route => route.path));
                    const newHtmlRoutePaths = new Set(uniqueHtmlRoutes.map(route => route.path));
                    const addedHtmlRoutes = uniqueHtmlRoutes.filter(route => !prevHtmlRoutePaths.has(route.path));
                    const removedHtmlRoutes = prevSnapshot.htmlRoutes.filter(route => !newHtmlRoutePaths.has(route.path));
                    const prevApiPaths = new Set(prevSnapshot.apiEndpoints.map(endpoint => endpoint.path));
                    const newApiPaths = new Set(uniqueApiEndpoints.map(endpoint => endpoint.path));
                    const addedApiEndpoints = uniqueApiEndpoints.filter(endpoint => !prevApiPaths.has(endpoint.path));
                    const removedApiEndpoints = prevSnapshot.apiEndpoints.filter(endpoint => !newApiPaths.has(endpoint.path));

                    result.addedHtmlRoutes = addedHtmlRoutes;
                    result.removedHtmlRoutes = removedHtmlRoutes;
                    result.addedApiEndpoints = addedApiEndpoints;
                    result.removedApiEndpoints = removedApiEndpoints;

                    if (addedHtmlRoutes.length > 0) {
                        routeChanges++;
                        addedHtmlRoutesCount += addedHtmlRoutes.length;

                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "html_routes_added",
                            severity: "low",
                            title: `New HTML Routes Discovered: ${new URL(baseUrl).hostname}`,
                            description: `${addedHtmlRoutes.length} new HTML route(s) discovered: ${addedHtmlRoutes.map(route => route.path).join(", ")}`,
                            newValue: JSON.stringify(addedHtmlRoutes.map(route => route.path)),
                            detectionMethod: "api_monitor",
                            tags: ["html", "route", "new", "discovery"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                addedHtmlRoutes,
                                count: addedHtmlRoutes.length,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, addedHtmlRoutes.length);
                        changeEvents.push(event);
                    }

                    if (removedHtmlRoutes.length > 0) {
                        routeChanges++;
                        removedHtmlRoutesCount += removedHtmlRoutes.length;

                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "html_routes_removed",
                            severity: "low",
                            title: `HTML Routes Removed: ${new URL(baseUrl).hostname}`,
                            description: `${removedHtmlRoutes.length} HTML route(s) removed: ${removedHtmlRoutes.map(route => route.path).join(", ")}`,
                            oldValue: JSON.stringify(removedHtmlRoutes.map(route => route.path)),
                            detectionMethod: "api_monitor",
                            tags: ["html", "route", "removed"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                removedHtmlRoutes,
                                count: removedHtmlRoutes.length,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, removedHtmlRoutes.length);
                        changeEvents.push(event);
                    }

                    if (addedApiEndpoints.length > 0) {
                        apiChanges++;
                        addedApiEndpointsCount += addedApiEndpoints.length;

                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_added",
                            severity: "high",
                            title: `New API Endpoints Discovered: ${new URL(baseUrl).hostname}`,
                            description: `${addedApiEndpoints.length} new API endpoint(s) discovered: ${addedApiEndpoints.map(endpoint => endpoint.path).join(", ")}`,
                            newValue: JSON.stringify(addedApiEndpoints.map(endpoint => endpoint.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "new", "discovery"],
                            autoTriggerEnabled: true,
                            riskScore: 0,
                            metadata: {
                                addedApiEndpoints,
                                count: addedApiEndpoints.length,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, addedApiEndpoints.length);
                        changeEvents.push(event);
                    }

                    if (removedApiEndpoints.length > 0) {
                        apiChanges++;
                        removedApiEndpointsCount += removedApiEndpoints.length;

                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_removed",
                            severity: "low",
                            title: `API Endpoints Removed: ${new URL(baseUrl).hostname}`,
                            description: `${removedApiEndpoints.length} API endpoint(s) removed: ${removedApiEndpoints.map(endpoint => endpoint.path).join(", ")}`,
                            oldValue: JSON.stringify(removedApiEndpoints.map(endpoint => endpoint.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "removed"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                removedApiEndpoints,
                                count: removedApiEndpoints.length,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, removedApiEndpoints.length);
                        changeEvents.push(event);
                    }
                } else {
                    if (uniqueHtmlRoutes.length > 0) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "html_routes_discovered",
                            severity: "low",
                            title: `HTML Routes Discovered: ${new URL(baseUrl).hostname}`,
                            description: `Initial scan discovered ${uniqueHtmlRoutes.length} HTML route(s).`,
                            newValue: JSON.stringify(uniqueHtmlRoutes.map(route => route.path)),
                            detectionMethod: "api_monitor",
                            tags: ["html", "route", "initial-scan"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                htmlRoutes: uniqueHtmlRoutes,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, uniqueHtmlRoutes.length);
                        changeEvents.push(event);
                    }

                    if (uniqueApiEndpoints.length > 0) {
                        const event: ChangeEvent = {
                            id: generateId(),
                            assetId: baseUrl,
                            eventType: "api_endpoints_discovered",
                            severity: "medium",
                            title: `API Endpoints Discovered: ${new URL(baseUrl).hostname}`,
                            description: `Initial scan discovered ${uniqueApiEndpoints.length} API endpoint(s).`,
                            newValue: JSON.stringify(uniqueApiEndpoints.map(endpoint => endpoint.path)),
                            detectionMethod: "api_monitor",
                            tags: ["api", "endpoint", "initial-scan"],
                            autoTriggerEnabled: false,
                            riskScore: 0,
                            metadata: {
                                apiEndpoints: uniqueApiEndpoints,
                            },
                        };
                        event.riskScore = calculateRiskScore(event.severity, event.eventType, uniqueApiEndpoints.length);
                        changeEvents.push(event);
                    }
                }
                compareMs = Date.now() - compareStartedAt;

                result.timings = {
                    targetFetchMs,
                    assetDiscoveryMs,
                    pageCrawlMs,
                    manifestProbeMs,
                    jsFetchMs,
                    sourceMapFetchMs,
                    nestedJsDiscoveryMs,
                    astExtractionMs,
                    compareMs,
                    totalMs: Date.now() - targetStartedAt,
                };
                result.metrics = {
                    crawledPages,
                    htmlRoutesDiscovered,
                    scriptSources: scriptSourceCount,
                    jsFilesAnalyzed,
                    pageFetchCount,
                    manifestRequests,
                    jsFetchCount,
                    jsFetchFailureCount,
                    sourceMapFetchCount,
                    jsLinksDiscovered,
                    inlineScriptCount,
                };

            } catch (error: any) {
                result.error = error.message || String(error);
                failedChecks++;
            }

            results.push(result);
            completedTargets += 1;
            await reportMonitorProgress(monitorExecution, {
                current: completedTargets,
                total: totalProgressUnits,
                currentTarget: baseUrl,
                phase: "discover",
                message: `Completed API discovery for ${baseUrl}`,
            });
        });

        await runWithConcurrency(targetTasks, Math.min(50, validTargets.length || 1));

        await reportMonitorProgress(monitorExecution, {
            current: validTargets.length + 1,
            total: totalProgressUnits,
            phase: "compare",
            message: "Comparing API snapshots",
        });

        await reportMonitorProgress(monitorExecution, {
            current: totalProgressUnits,
            total: totalProgressUnits,
            phase: "build",
            message: "Building API results",
        });

        return {
            success: true,
            data: {
                results,
                changeEvents,
                snapshots: newSnapshots,
                summary: {
                    totalTargets: validTargets.length,
                    successfulChecks,
                    failedChecks,
                    totalHtmlRoutes,
                    totalApiEndpoints,
                    totalJsFiles,
                    addedHtmlRoutes: addedHtmlRoutesCount,
                    removedHtmlRoutes: removedHtmlRoutesCount,
                    addedApiEndpoints: addedApiEndpointsCount,
                    removedApiEndpoints: removedApiEndpointsCount,
                    routeChanges,
                    apiChanges,
                },
            },
        };

    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

pluginGlobals.analyze = analyze;
