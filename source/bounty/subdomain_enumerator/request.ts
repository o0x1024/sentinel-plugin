// @ts-ignore — One Engine exposes globals via bare assignment, not globalThis
export const _nativeFetch: typeof fetch = fetch;

export type FetchWithTimeoutInit = RequestInit & {
    timeout?: number;
};

export const DEFAULT_FETCH_TIMEOUT_MS = 15000;

export const RETRYABLE_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

export function sleep(_ms: number): Promise<void> {
    // QuickJS has no timers; retries proceed immediately without backoff.
    return Promise.resolve();
}

export function parseRetryAfter(value: string | null): number | null {
    if (!value) return null;

    const seconds = Number(value);
    if (Number.isFinite(seconds) && seconds >= 0) {
        return seconds * 1000;
    }

    const retryAt = Date.parse(value);
    if (Number.isNaN(retryAt)) {
        return null;
    }

    return Math.max(0, retryAt - Date.now());
}

export function isRetryableMethod(method: string): boolean {
    return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

export function isRetryableError(error: any): boolean {
    const message = String(error?.message || error || "").toLowerCase();
    return message.includes("timeout")
        || message.includes("network")
        || message.includes("fetch")
        || message.includes("socket")
        || message.includes("connection");
}

export async function fetchWithRetry(input: RequestInfo | URL, init: FetchWithTimeoutInit = {}): Promise<Response> {
    const method = String(init.method || "GET").toUpperCase();
    const maxAttempts = isRetryableMethod(method) ? 2 : 1;
    const fetchInit: FetchWithTimeoutInit = {
        ...init,
        timeout: init.timeout ?? DEFAULT_FETCH_TIMEOUT_MS,
    };
    let lastError: any;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const response = await _nativeFetch(input, fetchInit);
            if (attempt < maxAttempts && RETRYABLE_STATUSES.has(response.status)) {
                const retryDelay = parseRetryAfter(response.headers.get("retry-after")) ?? (300 * attempt);
                try {
                    await response.arrayBuffer();
                } catch {
                    // Ignore body drain failures before retry.
                }
                await sleep(Math.min(retryDelay, 2000));
                continue;
            }

            return response;
        } catch (error: any) {
            lastError = error;
            if (attempt >= maxAttempts || !isRetryableError(error)) {
                throw error;
            }
            await sleep(300 * attempt);
        }
    }

    throw lastError ?? new Error("Request failed");
}
