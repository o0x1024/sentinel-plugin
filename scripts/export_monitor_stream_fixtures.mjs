// Export real published producers under deterministic APIs for the Rust receiver contract suite.
import {readFile,writeFile} from 'node:fs/promises';
import {createPayloadCase} from './bounty_payload_fixtures.mjs';
import {agentFixture} from './agent_monitor_fixture.mjs';
const output=process.argv[process.argv.indexOf('--output')+1];if(!process.argv.includes('--output')||!output)throw new Error('--output is required');
const manifest=JSON.parse(await readFile(new URL('../plugins.json',import.meta.url),'utf8'));
const all=[];let activeFetch;
const originals={Sentinel:globalThis.Sentinel,Deno:globalThis.Deno,fetch:globalThis.fetch};
globalThis.fetch=(...args)=>activeFetch(...args);
try {
    for (const metadata of manifest.plugins.filter(plugin=>plugin.monitor_type)) {
        let requests,targets,input,result;
        if(metadata.main_category==='agent') {
            const fixture=await agentFixture(metadata.id);result=await fixture.monitor();({packets:requests,targets,input}=fixture);
        } else {
            const fixture=createPayloadCase(metadata.id,4,{fetches:0,native_calls:0,progress_events:0,progress_bytes:0});
            requests=[];activeFetch=fixture.fetch;fixture.install(async request=>{requests.push(structuredClone(request));return {ok:true,sequence:request.sequence};});
            ({targets,input}=fixture);
            const source=await readFile(new URL(`../plugins/bounty/${metadata.id}.ts`,import.meta.url),'utf8');
            const module=await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);result=await module.analyze(input);
        }
        if(!result.success||!result.data?.stream_complete) throw new Error(`${metadata.id}: ${result.error||'missing completion'}`);
        // These authorizations are fixed by the fixture, never inferred from output.
        const scopes=[['domain','bench.test'],['domain','owned.test'],['ip_range','198.18.0.0/15'],['ip_range','10.0.0.0/8']].map(([target_type,target],i)=>({
            id:`scope-${i}`,program_id:'p1',scope_type:'in_scope',target_type,target,requires_auth:false,asset_count:0,finding_count:0,priority:0,created_at:'2026-10-29T00:00:00Z',updated_at:'2026-10-29T00:00:00Z'}));
        all.push({id:metadata.id,metadata,input,targets,scopes,requests});
    }
    await writeFile(output,JSON.stringify(all));console.log(`Exported ${all.length} published monitor fixtures`);
} finally {Object.assign(globalThis,originals);}
