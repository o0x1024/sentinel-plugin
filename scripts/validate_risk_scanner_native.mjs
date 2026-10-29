/** Run the owned acceptance fixture against the sibling host; no user database. */
import { readFile, writeFile, mkdtemp, mkdir, unlink, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const options = new Map();
for (let index = 0; index < args.length; index += 2) {
  const flag = args[index], value = args[index + 1];
  if (!['--output', '--bundle'].includes(flag) || !value || options.has(flag)) {
    throw new Error('Usage: node scripts/validate_risk_scanner_native.mjs [--output report.json] [--bundle plugin.ts]');
  }
  options.set(flag, resolve(value));
}
const bundlePath = options.get('--bundle') || fileURLToPath(new URL('../plugins/bounty/risk_scanner.ts', import.meta.url));
const host = fileURLToPath(new URL('../../sentinel-ai-pro/src-tauri/', import.meta.url));
const fixture = await readFile(new URL('./native/risk_scanner_full_scan.rs', import.meta.url));
const target = join(host, 'sentinel-plugins/tests/owned_risk_full_scan_validation.rs');
const temporary = await mkdtemp(join(tmpdir(), 'sentinel-risk-native-'));
const evidence = join(temporary, 'report.json');
let installed = false;
try {
  await writeFile(target, fixture, { flag: 'wx' });
  installed = true;
  const child = spawn('cargo', ['test', '--offline', '--locked', '-p', 'sentinel-plugins',
    '--test', 'owned_risk_full_scan_validation', '--', '--nocapture', '--test-threads=1'], {
    cwd: host, stdio: 'inherit', env: { ...process.env,
      SENTINEL_RISK_FULL_SCAN_EVIDENCE: evidence, SENTINEL_RISK_SCANNER_BUNDLE: bundlePath },
  });
  const [code, signal] = await once(child, 'exit');
  if (code !== 0) throw new Error(`Native acceptance failed: ${signal || code}`);
  const report = JSON.parse(await readFile(evidence, 'utf8'));
  const bundle = await readFile(bundlePath);
  report.plugin_version = bundle.toString('utf8').match(/@version\s+(\S+)/)?.[1];
  report.bundle_sha256 = createHash('sha256').update(bundle).digest('hex');
  const json = JSON.stringify(report, null, 2) + '\n';
  if (options.has('--output')) {
    const output = options.get('--output');
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, json);
  }
  console.log(json);
} finally {
  if (installed) {
    const current = await readFile(target);
    if (!current.equals(fixture)) throw new Error('Acceptance fixture changed during execution; preserving it');
    await unlink(target);
  }
  await rm(temporary, { recursive: true });
}
