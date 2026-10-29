// Deterministic payload-growth regressions. No network, production DB, or installed-plugin writes.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const originals = { Sentinel: globalThis.Sentinel, fetch: globalThis.fetch, Deno: globalThis.Deno };
let fetchHandler = async () => { throw new Error('No configured network fixture'); };
globalThis.fetch = (...args) => fetchHandler(...args);
const ids = ['dns_resolver','cidr_mapper','cert_monitor','service_probe','service_monitor','port_monitor','fofa_asset_monitor','subdomain_enumerator','subdomain_brute'];
const plugins = Object.fromEntries(await Promise.all(ids.map(async id => [id, await import(`../source/bounty/${id}/index.ts`)])));
const { nativeSubdomainBruteFixture } = await import('./subdomain_brute_fixture.ts');
after(() => Object.assign(globalThis, originals));
const forbidden = ['targets','target_objects','service_targets','__monitorExecution','previousSnapshots','previous_snapshots','dictionaryEntries','dictionary'];
const marker = `UNRELATED-HISTORY-AND-RULES-${'z'.repeat(32768)}`;
const sizes = [64,256,1024];
const root = index => `root${String(index).padStart(4,'0')}.test`;
const ip = index => `10.20.${Math.floor(index/256)}.${index%256}`;
const context = (id, targets, maxWork = 32) => ({ task_id:'payload-growth',task_name:'Payload fixture',program_id:'owned',execution_mode:'test',started_at:'2026-10-29T00:00:00Z',current_plugin:id,current_plugin_index:1,completed_steps:0,total_steps:1,
  result_stream:{protocol:'monitor-results-v1',targets,max_work_items:maxWork,max_pending_commits:2,max_bytes:2097152} });
const ok = body => new Response(JSON.stringify(body), { status:200 });
const rules = Array.from({length:64},(_,i) => ({word:`unmatched-rule-${i}`,metadata:{note:marker,matchers:[{part:'banner',type:'contains',value:'NEVER-MATCH-THIS'}]}}));

function capture(keep = false) {
  const stats = { bytes:0, maxBytes:0, progressBytes:0, commits:0, work:0, completed:0, domains:0, webs:0, ports:0, requests:[] };
  globalThis.Sentinel = { log() {}, Dictionary:{getDefaultId:()=> 'owned',getEntries:()=>rules},
    Monitor:{reportProgress:update=>{
      const encoded=JSON.stringify(update);
      assert.ok(!Object.hasOwn(update.monitorProgress || {},'result_stream'),'progress must not echo the complete stream target context');
      assert.ok(!encoded.includes(marker),'progress must not echo unrelated history/rules');
      assert.ok(Buffer.byteLength(encoded)<4096,'progress is scalar metadata for the current work');
      stats.progressBytes+=Buffer.byteLength(encoded);return true;
    },commitResults:async request => {
      const data = request.output.data;
      for (const key of forbidden) assert.ok(!Object.hasOwn(data,key),`delta must not echo ${key}`);
      const encoded = JSON.stringify(request);
      assert.ok(!encoded.includes(marker),'unrelated history/rules must stay outside saved deltas');
      const bytes = Buffer.byteLength(encoded);
      stats.bytes += bytes; stats.maxBytes = Math.max(stats.maxBytes,bytes);stats.commits++;
      stats.work += request.work.length;stats.completed += request.work.filter(item=>item.complete).length;
      for (const key of ['domains','webs','ports']) stats[key] += data.surface_artifacts?.[key]?.length || 0;
      if (keep) stats.requests.push(structuredClone(request));
      return {ok:true,sequence:request.sequence};
    }} };
  globalThis.Deno = {resolveDns:async (_,type)=>type==='A'?['192.0.2.1']:[]};
  return stats;
}
function input(id, n, maxWork = 32) {
  const roots=Array.from({length:n},(_,i)=>root(i));
  const urls=roots.map(value=>`https://${value}/`);
  const ips=Array.from({length:n},(_,i)=>ip(i));
  const services=roots.map(value=>`${value}:443/tcp`);
  let targets, params;
  if (id==='dns_resolver') {targets=roots;params={targets,recordTypes:['A'],previousSnapshots:{'history.test':{target:'history.test',records:[{recordType:'TXT',value:marker}],lastChecked:'old'}}};}
  else if (id==='cidr_mapper') {targets=ips;params={targets};}
  else if (id==='cert_monitor') {
    targets=urls;params={targets,previousSnapshots:{'history.test':{domain:'history.test',fingerprint:marker,issuer:'Old',validTo:'2099-01-01'}}};
    globalThis.Sentinel.TLS={getCertificate:async hostname=>({success:true,cert:{subject:`CN=${hostname}`,issuer:'Owned CA',serialNumber:'01',validFrom:'2020-01-01T00:00:00Z',validTo:'2099-01-01T00:00:00Z',fingerprintSha256:createHash('sha256').update(hostname).digest('hex'),subjectAltNames:[hostname]}})};
  } else if (id==='service_probe' || id==='service_monitor') {
    targets=services;params={targets,dictionaryEntries:rules,...(id==='service_monitor'?{previousSnapshots:{'history.test:443':{target:'history.test:443',host:'history.test',port:443,available:true,protocol:'https',banner:marker,lastChecked:'old'}}}:{})};
    globalThis.Sentinel.Network={probeServices:async ({targets})=>({success:true,results:targets.map(target=>({...target,target:`${target.host}:${target.port}`,success:true,available:true,serviceName:'https',banner:'owned bounded banner'})),ruleCount:rules.length})};
  } else if (id==='port_monitor') {
    targets=ips;params={targets,ports:[80,443],previousSnapshots:{'history.test':{host:'history.test',openPorts:[],lastChecked:marker}}};
    globalThis.Sentinel.Network={scanPorts:async request=>({success:true,results:request.targets.map(target=>({host:target.host,resolved_ips:[target.host],open_ports:[request.ports[0]]}))})};
  } else if (id==='fofa_asset_monitor') {
    targets=roots;params={domains:targets,fofaKey:'owned-fixture',pageSize:1,maxPages:1,previousSnapshots:{history:{id:'history',query:'old',assetKeys:[marker],totalReported:1,lastChecked:'old'}}};
    fetchHandler=async raw=>{const query=atob(new URL(raw).searchParams.get('qbase64'));const domain=query.match(/domain="([^"]+)"/)[1];return ok({error:false,size:1,results:[[`https://api.${domain}`,'192.0.2.1','443','https','owned',`api.${domain}`,'now']]});};
  } else if (id==='subdomain_enumerator') {
    targets=roots;params={domains:targets,sources:['crtsh'],previousSnapshots:{'history.test':{domain:'history.test',subdomains:[marker],lastChecked:'old'}}};
    fetchHandler=async raw=>{const domain=new URL(raw).searchParams.get('q').replace(/^%\./,'');return ok([{name_value:`api.${domain}`}]);};
  } else {
    targets=roots;params={targets,dictionary:['api'],previousSnapshots:{'history.test':{domain:'history.test',subdomains:[marker],lastChecked:'old'}}};
    globalThis.Sentinel.Network={bruteForceSubdomains:nativeSubdomainBruteFixture};
  }
  return {...params,__monitorExecution:context(id,targets,maxWork)};
}

for (const id of ids) test(`${id}: saved bytes grow with work, not full run inputs/history`,async()=>{
  const measured=[];
  for (const n of sizes) {
    const stats=capture();const output=await plugins[id].analyze(input(id,n));
    assert.equal(output.success,true,output.error);assert.equal(output.data.stream_complete,true);
    assert.equal(stats.completed,n);assert.ok(stats.bytes>0);
    measured.push({n,bytes:stats.bytes,work:stats.work,commits:stats.commits,maxBytes:stats.maxBytes,progressBytes:stats.progressBytes});
  }
  for (let i=1;i<measured.length;i++) {
    const ratio=measured[i].bytes/measured[i-1].bytes;
    assert.ok(ratio<4.6,`${id}: 4x work must not create quadratic saved bytes (${ratio.toFixed(2)}x)`);
    if (measured[i-1].progressBytes) assert.ok(measured[i].progressBytes/measured[i-1].progressBytes<4.6,`${id}: progress RPC must not echo the full input`);
  }
  assert.ok(measured.at(-1).bytes/measured.at(-1).work<12000,`${id}: saved work must remain bounded`);
  console.log(JSON.stringify({plugin:id,measured}));
});

test('DNS ordinary output still contains the complete target list and target results',async()=>{
  capture();const data=input('dns_resolver',3);delete data.__monitorExecution;
  const output=await plugins.dns_resolver.analyze(data);
  assert.equal(output.success,true);assert.deepEqual(output.data.targets,data.targets);assert.equal(output.data.results.length,3);
});

test('FOFA pages publish only current response assets; query-complete does not replay cumulative rows',async()=>{
  const stats=capture(true);const params=input('fofa_asset_monitor',1,1);params.maxPages=3;
  fetchHandler=async raw=>{const page=Number(new URL(raw).searchParams.get('page'));return ok({error:false,size:2,results:[[`https://page${page}.root0000.test`,'192.0.2.1','443','https','owned',`page${page}.root0000.test`,'now']]});};
  const output=await plugins.fofa_asset_monitor.analyze(params);assert.equal(output.success,true);
  assert.equal(stats.webs,2);const complete=stats.requests.find(request=>request.work[0].key.endsWith(':complete')).output.data;
  for (const key of ['queries','assets','subdomains','urls','ips']) assert.ok(!Object.hasOwn(complete,key));
  assert.ok(complete.results.every(row=>!Object.hasOwn(row,'assets')));
  assert.ok(!Object.hasOwn(complete.surface_artifacts,'webs'));assert.ok(!Object.hasOwn(complete.surface_artifacts,'domains'));
  assert.equal(Object.values(complete.snapshots)[0].assetKeys.length,2);
});

test('subdomain root-complete retains the full new baseline without replaying provider result/asset arrays',async()=>{
  const stats=capture(true);const params=input('subdomain_enumerator',1,1);params.sources=['crtsh','alienvault'];
  fetchHandler=async raw=>String(raw).includes('crt.sh')?ok([{name_value:'api.root0000.test'}]):ok({passive_dns:[{hostname:'www.root0000.test'}]});
  const output=await plugins.subdomain_enumerator.analyze(params);assert.equal(output.success,true);
  const complete=stats.requests.find(request=>request.work[0].key==='domain-complete').output.data;
  for (const key of ['subdomains','sourceResults','slowSources','skippedSources']) assert.ok(!Object.hasOwn(complete,key));
  for (const key of ['domains','relations']) assert.ok(!Object.hasOwn(complete.surface_artifacts,key));
  assert.deepEqual(complete.snapshots['root0000.test'].subdomains,['api.root0000.test','www.root0000.test']);
  assert.equal(complete.surface_artifacts.evidences.length,1);
});

test('port host-complete compares one complete baseline without replaying already saved port inventory',async()=>{
  const stats=capture(true);const params=input('port_monitor',1,1);params.ports=Array.from({length:512},(_,i)=>i+1);
  globalThis.Sentinel.Network.scanPorts=async request=>({success:true,results:request.targets.map(target=>({host:target.host,resolved_ips:[target.host],open_ports:request.ports}))});
  const output=await plugins.port_monitor.analyze(params);assert.equal(output.success,true);
  assert.equal(stats.ports,512);const complete=stats.requests.find(request=>request.work[0].key==='host-complete').output.data;
  for (const key of ['ports','domains','ips','relations']) assert.ok(!Object.hasOwn(complete.surface_artifacts,key));
  assert.ok(complete.results.every(result=>!Object.hasOwn(result,'knownOpenPorts')&&!Object.hasOwn(result,'snapshot')));
  assert.equal(complete.snapshots[ip(0)].openPorts.length,512);
  assert.equal(stats.requests.reduce((sum, request)=>sum+(request.output.data.summary?.totalTargets || 0),0),1);
  assert.equal(stats.requests.reduce((sum, request)=>sum+(request.output.data.summary?.totalOpenPorts || 0),0),512);
});

test('FOFA many-page saved byte volume stays linear including its one complete baseline',async()=>{
  const measured=[];
  for (const pages of [8,32]) {
    const stats=capture();const params=input('fofa_asset_monitor',1,1);params.maxPages=pages;
    fetchHandler=async raw=>{const page=Number(new URL(raw).searchParams.get('page'));const label=`page${String(page).padStart(3,'0')}.root0000.test`;return ok({error:false,size:pages,results:[[`https://${label}`,'192.0.2.1','443','https','owned',label,'now']]});};
    const output=await plugins.fofa_asset_monitor.analyze(params);assert.equal(output.success,true);assert.equal(stats.webs,pages);measured.push(stats.bytes);
  }
  assert.ok(measured[1]/measured[0]<4.6,`4x pages caused ${measured[1]/measured[0]}x saved bytes`);
});
