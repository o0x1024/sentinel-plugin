/** Run existing Deno schema/fixture tests with Node 24; no network or writes. */
import { readFile, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const [relativeFile, ...args] = process.argv.slice(2);
if (!relativeFile) throw new Error('Usage: node scripts/run_readonly_tests.mjs scripts/<test>.ts [arguments]');
const root = new URL('../', import.meta.url);
const target = new URL(relativeFile, root);
if (!target.href.startsWith(new URL('scripts/', root).href)) throw new Error('Test entry must be inside scripts/');
const tests = [];
globalThis.fetch = async () => { throw new Error('External network is disabled in read-only tests'); };
globalThis.Deno = {
    args,
    readTextFile: path => readFile(path, 'utf8'),
    readFile: async path => new Uint8Array(await readFile(path)),
    stat,
    exit(code = 0) { if (code !== 0) throw new Error(`Test script exited with status ${code}`); },
    test(name, fn) {
        if (typeof name === 'object') { fn = name.fn; name = name.name; }
        if (typeof name !== 'string' || typeof fn !== 'function') throw new Error('Invalid test registration');
        tests.push({ name, fn });
    },
};
await import(target.href);
let failures = 0;
for (const { name, fn } of tests) {
    try { await fn(); console.log(`PASS ${name}`); }
    catch (error) { failures++; console.error(`FAIL ${name}:`, error); }
}
if (tests.length) console.log(`Passed ${tests.length - failures}/${tests.length} read-only fixture tests`);
const fixtureIndex = args.indexOf('--stream-fixtures-out');
if (fixtureIndex >= 0) {
    const destination = args[fixtureIndex + 1];
    if (!destination || !resolve(destination).startsWith('/private/tmp/')) {
        throw new Error('Synthetic stream fixtures may only be exported to an explicit /private/tmp/ path');
    }
    const fixtures = globalThis.__sentinelBountyStreamFixtures;
    if (!Array.isArray(fixtures) || !fixtures.length) throw new Error('No synthetic stream fixtures were collected');
    await writeFile(destination, JSON.stringify(fixtures, null, 2) + '\n');
    console.log(`Exported ${fixtures.length} synthetic stream fixtures to ${destination}`);
}
if (failures) process.exitCode = 1;
