import test from 'node:test';
import assert from 'node:assert/strict';
import { runMonitorTool, observedFetch, monitorToolOutputSchema } from '../source/shared/monitor_tool_runner.ts';

const nativeFetch=globalThis.fetch, originalSentinel=globalThis.Sentinel;
test.afterEach(()=>{globalThis.fetch=nativeFetch;globalThis.Sentinel=originalSentinel;});
const schema={type:'object',properties:{url:{type:'string'}}};
const input=targets=>({headers:{'x-owned':'sample'},__monitorExecution:{result_stream:{protocol:'monitor-results-v2',targets,max_work_items:2,max_pending_commits:1,max_bytes:2097152}}});
function fixture(commit){const requests=[];globalThis.Sentinel={Monitor:{commitResults:async packet=>{requests.push(structuredClone(packet));return commit?commit(packet):{ok:true,sequence:packet.sequence};}}};return requests;}

test('ordinary business execution retains its original input/output and needs no monitor host',async()=>{
 delete globalThis.Sentinel;
 const supplied={url:'https://owned.test/',custom:42},result={success:true,data:{vulnerabilities:[]}};
 assert.equal(await runMonitorTool(supplied,schema,async received=>{assert.equal(received,supplied);return result;}),result);
});

test('monitor targets are projected individually and actual HTTP work acknowledges before business completion',async()=>{
 const targets=['https://one.owned.test/','https://two.owned.test/'];const packets=fixture();let calls=0;
 const fake=globalThis.fetch=async()=>({status:200,text:async()=>'owned'});
 const output=await runMonitorTool(input(targets),schema,async received=>{
  assert.equal(received.__monitorExecution,undefined);assert.equal(received.headers['x-owned'],'sample');
  assert.equal(received.url,targets[calls++]);
  await observedFetch(received.url);await observedFetch(received.url);
  assert.ok(packets.length>0,'real work must renew progress before target completion');
  return {success:true,data:{vulnerabilities:[]}};
 });
 assert.equal(globalThis.fetch,fake);assert.equal(output.data.stream_complete,true);
 const work=packets.flatMap(packet=>packet.work);
 assert.equal(work.filter(item=>item.key.startsWith('http:')).length,4);
 assert.deepEqual(work.filter(item=>item.complete).map(item=>item.target),targets);
 assert.ok(work.every(item=>item.output.success===true));
});

test('save failure stops subsequent network calls and remains a save failure',async()=>{
 let calls=0;fixture(async()=>{throw new Error('owned save failure');});
 globalThis.fetch=async()=>{calls++;return {status:200};};
 const supplied=input(['https://owned.test/']);supplied.__monitorExecution.result_stream.max_work_items=1;
 const output=await runMonitorTool(supplied,schema,async()=>{
  for(let i=0;i<3;i++){try{await observedFetch('https://owned.test/');}catch{}}
  return {success:true,data:{}};
 });
 assert.equal(output.success,false);assert.match(output.error,/save failure/);assert.equal(calls,1);
});

test('failed targets retain evidence while later independent targets can finish',async()=>{
 const packets=fixture();let calls=0;
 const output=await runMonitorTool(input(['https://one.test/','https://two.test/']),schema,async()=>{
  if(calls++===0)throw new Error('owned business error');return {success:true,data:{}};
 });
 assert.equal(output.data.stream_complete,true);
 assert.deepEqual(packets.flatMap(packet=>packet.work).map(item=>item.status),['failed','ok']);
 const projected=monitorToolOutputSchema({type:'object',properties:{success:{type:'boolean'}}});
 assert.equal(projected.anyOf.length,3);
});
