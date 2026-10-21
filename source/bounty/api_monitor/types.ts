export interface MonitorExecutionContext {
    task_id: string;
    task_name: string;
    program_id: string;
    execution_mode: string;
    started_at: string;
    current_plugin: string;
    current_plugin_index: number;
    completed_steps: number;
    total_steps: number;
    imported_assets?: number;
}

export interface ToolInput {
    targets: string[];  // Base URLs or JS files to analyze
    userAgent?: string;
    crawlDepth?: number;
    maxPages?: number;
    maxJsFiles?: number;
    includeSameOriginOnly?: boolean;
    followSourceMaps?: boolean;
    probeSpaManifests?: boolean;
    previousSnapshots?: Record<string, ApiSnapshot>;
    __monitorExecution?: MonitorExecutionContext;
}

export interface JsLink {
    url: string;
    type: "external" | "inline" | "module" | "dynamic" | "sourcemap" | "webpack" | "manifest";
    source: string;
    size?: number;
    hash?: string;
}

export interface ScriptContentSource {
    source: string;
    content: string;
}

export interface SourceMapLike {
    version?: number;
    file?: string;
    sourceRoot?: string;
    sources?: string[];
    sourcesContent?: Array<string | null>;
    sections?: Array<{ map?: SourceMapLike }>;
}

export interface FetchResult {
    ok: boolean;
    status: number | null;
    text: string;
    size: number;
    contentType: string;
    finalUrl: string;
    error?: string;
}

export interface JsDiscoveryResult {
    jsLinks: JsLink[];
    scriptContents: ScriptContentSource[];
    crawledPages: string[];
    htmlRoutes: HtmlRoute[];
    jsFetchFailures: JsFetchFailure[];
    timings: {
        pageCrawlMs: number;
        manifestProbeMs: number;
        jsFetchMs: number;
        sourceMapFetchMs: number;
        nestedJsDiscoveryMs: number;
    };
    metrics: {
        pageFetchCount: number;
        manifestRequests: number;
        jsFetchCount: number;
        jsFetchFailureCount: number;
        sourceMapFetchCount: number;
        jsLinksDiscovered: number;
        inlineScriptCount: number;
    };
}

export interface ApiEndpoint {
    path: string;
    source: string;
}

export interface HtmlRoute {
    path: string;
    source: string;
}

export interface ApiSnapshot {
    baseUrl: string;
    htmlRoutes: HtmlRoute[];
    apiEndpoints: ApiEndpoint[];
    lastChecked: string;
}

export interface JsFetchFailure {
    url: string;
    finalUrl?: string;
    linkType: JsLink["type"];
    discoverySource: string;
    status: number | null;
    contentType?: string;
    size?: number;
    error?: string;
}

export interface ChangeEvent {
    id: string;
    assetId: string;
    eventType: string;
    severity: "low" | "medium" | "high" | "critical";
    title: string;
    description: string;
    oldValue?: string;
    newValue?: string;
    detectionMethod: string;
    tags: string[];
    autoTriggerEnabled: boolean;
    riskScore: number;
    metadata: Record<string, any>;
}

export interface ApiResult {
    baseUrl: string;
    success: boolean;
    snapshot?: ApiSnapshot;
    addedHtmlRoutes?: HtmlRoute[];
    removedHtmlRoutes?: HtmlRoute[];
    addedApiEndpoints?: ApiEndpoint[];
    removedApiEndpoints?: ApiEndpoint[];
    jsFetchFailures?: JsFetchFailure[];
    timings?: {
        targetFetchMs: number;
        assetDiscoveryMs: number;
        pageCrawlMs: number;
        manifestProbeMs: number;
        jsFetchMs: number;
        sourceMapFetchMs: number;
        nestedJsDiscoveryMs: number;
        astExtractionMs: number;
        compareMs: number;
        totalMs: number;
    };
    metrics?: {
        crawledPages: number;
        htmlRoutesDiscovered: number;
        scriptSources: number;
        jsFilesAnalyzed: number;
        pageFetchCount: number;
        manifestRequests: number;
        jsFetchCount: number;
        jsFetchFailureCount: number;
        sourceMapFetchCount: number;
        jsLinksDiscovered: number;
        inlineScriptCount: number;
    };
    error?: string;
}

export interface ToolOutput {
    success: boolean;
    data?: {
        results: ApiResult[];
        changeEvents: ChangeEvent[];
        snapshots: Record<string, ApiSnapshot>;
        summary: {
            totalTargets: number;
            successfulChecks: number;
            failedChecks: number;
            totalHtmlRoutes: number;
            totalApiEndpoints: number;
            totalJsFiles: number;
            addedHtmlRoutes: number;
            removedHtmlRoutes: number;
            addedApiEndpoints: number;
            removedApiEndpoints: number;
            routeChanges: number;
            apiChanges: number;
        };
    };
    error?: string;
}
