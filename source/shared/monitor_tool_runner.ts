/** One-target business functions can participate in the same acknowledged monitor stream. */
import { createMonitorResultStream } from './monitor_results.ts';

const aliases = ['targets', 'urls', 'url', 'domains', 'domain', 'ips', 'ip'] as const;
type Scope = { target: string; stream: ReturnType<typeof createMonitorResultStream>; sequence: number; pending: Set<Promise<any>> };
let activeScope: Scope | undefined;

/** Lexically imported by business helpers; the host's global fetch is never replaced. */
export function observedFetch(input: any, init?: any): Promise<any> {
    const scope = activeScope;
    if (!scope) return globalThis.fetch(input, init);
    const key = `http:${++scope.sequence}`;
    const operation = (async () => {
        scope.stream.assertHealthy();
        let response: any;
        try { response = await globalThis.fetch(input, init); }
        catch (error) {
            await scope.stream.record(scope.target, key, { success: true, data: { results: [{ kind: 'http_observation', success: false }] } },
                { status: 'failed', complete: false, error: String(error).slice(0, 2048), failure_category: 'network_other' });
            throw error;
        }
        await scope.stream.record(scope.target, key, { success: true, data: { results: [{ kind: 'http_observation', success: true,
            statusCode: response.status, method: String(init?.method || 'GET') }] } }, { complete: false });
        return response;
    })();
    scope.pending.add(operation);
    void operation.finally(() => scope.pending.delete(operation)).catch(() => {});
    return operation;
}

export async function runMonitorTool(input: any, schema: any, business: (input: any) => Promise<any>): Promise<any> {
    const stream = createMonitorResultStream(input);
    if (activeScope) throw new Error('A monitored business scope is already active');
    if (!stream.enabled) return await business(input);
    try {
        const properties = schema?.properties || {};
        const supported = aliases.filter(key => Object.prototype.hasOwnProperty.call(properties, key));
        if (!supported.length) throw new Error('Monitor business schema must declare a standard target input');
        const targets = input.__monitorExecution.result_stream.targets as string[];
        for (const target of targets) {
            stream.assertHealthy();
            const ordinary = { ...input };
            delete ordinary.__monitorExecution;
            for (const key of aliases) {
                if (!supported.includes(key)) delete ordinary[key];
                else ordinary[key] = ['url', 'domain', 'ip'].includes(key) ? target : [target];
            }
            let result: any;
            const scope: Scope = { target, stream, sequence: 0, pending: new Set() };
            activeScope = scope;
            try { result = await business(ordinary); }
            catch (error) { result = { success: false, error: error instanceof Error ? error.message : String(error) }; }
            finally {
                while (scope.pending.size) await Promise.allSettled([...scope.pending]);
                activeScope = undefined;
            }
            stream.assertHealthy();
            if (!result || typeof result.success !== 'boolean') throw new Error('Monitor business must return a ToolOutput');
            const success = result.success === true;
            const data: Record<string, any> = { results: [{ target, output: result }] };
            await stream.record(target, "complete", { success: true, data }, {
                status: success ? 'ok' : 'failed', complete: true, snapshot_complete: success,
                ...(success ? {} : { error: String(result.error || 'Business observation failed') }),
            });
        }
        return await stream.finish();
    } catch (error) {
        const failure = { success: false, error: error instanceof Error ? error.message : String(error) };
        try { return await stream.finish(failure); }
        catch (saveError) { return { success: false, error: saveError instanceof Error ? saveError.message : String(saveError) }; }
    }
}

export function monitorToolOutputSchema(business: any): any {
    const terminalData = { type: 'object', required: ['stream_complete', 'summary'],
        properties: { stream_complete: { const: true }, summary: { type: 'object' } } };
    const terminal = { type: 'object', required: ['success', 'data'],
        properties: { success: { const: true }, data: terminalData } };
    const failure = { type: 'object', required: ['success', 'error'],
        properties: { success: { const: false }, error: { type: 'string', minLength: 1 } } };
    return {
        type: 'object', required: ['success'],
        properties: { success: { type: 'boolean', description: 'Execution outcome' },
            data: { type: 'object', description: 'Business output or acknowledged monitor completion',
                properties: { stream_complete: { type: 'boolean' }, summary: { type: 'object' } } },
            error: { type: 'string', description: 'Execution failure' } },
        anyOf: [business, terminal, failure],
    };
}
