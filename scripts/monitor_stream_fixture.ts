/** Host input fixture shared by deterministic plugin tests. No network calls. */
export function monitorExecution(targets: string[], options: {
    pluginId?: string;
    maxWorkItems?: number;
    maxPendingCommits?: number;
    maxBytes?: number;
} = {}) {
    return {
        task_id: "owned-monitor-test", task_name: "Owned monitor test", program_id: "owned-test-program",
        execution_mode: "test", started_at: "2026-10-28T00:00:00Z",
        current_plugin: options.pluginId ?? "test_plugin", current_plugin_index: 1,
        completed_steps: 0, total_steps: 1,
        result_stream: {
            protocol: "monitor-results-v2" as const,
            targets: [...targets], max_work_items: options.maxWorkItems ?? 32,
            max_pending_commits: options.maxPendingCommits ?? 2,
            max_bytes: options.maxBytes ?? 2 * 1024 * 1024,
        },
    };
}
