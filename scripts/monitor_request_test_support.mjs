// Test-only view over independently owned v2 outputs. Never mutates the wire packet.
import assert from 'node:assert/strict';
import { copyMonitorDelta, mergeMonitorDelta } from '../source/shared/monitor_delta.ts';

export function requestData(request) {
  assert.ok(Array.isArray(request.work), 'expected a v2 work packet');
  assert.equal(Object.hasOwn(request, 'output'), false, 'v2 must retain per-work ownership');
  let data;
  for (const work of request.work) data = mergeMonitorDelta(data, copyMonitorDelta(work.output));
  return data?.value || {};
}
