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

export interface MonitorProgressUpdate {
    current?: number;
    total?: number;
    message?: string;
    currentTarget?: string;
    phase?: string;
    phaseLabel?: string;
    indeterminate?: boolean;
}

type SentinelGlobal = typeof globalThis & {
    Sentinel?: {
        Monitor?: {
            reportProgress?(request: {
                monitorProgress?: MonitorExecutionContext;
                current?: number;
                total?: number;
                message?: string;
                currentTarget?: string;
                phase?: string;
                phaseLabel?: string;
                indeterminate?: boolean;
            }): Promise<boolean> | boolean;
        };
    };
};

const sentinelGlobal = globalThis as SentinelGlobal;

export async function reportMonitorProgress(
    monitorExecution: MonitorExecutionContext | undefined,
    update: MonitorProgressUpdate,
): Promise<boolean> {
    if (!monitorExecution) {
        return false;
    }

    const reportProgress = sentinelGlobal.Sentinel?.Monitor?.reportProgress;
    if (typeof reportProgress !== "function") {
        return false;
    }

    try {
        return Boolean(await reportProgress({
            monitorProgress: monitorExecution,
            ...update,
        }));
    } catch {
        return false;
    }
}
