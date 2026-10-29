// Controlled VM fixture for the seven Agent-category monitors. No network or disk writes.
import { readFile } from 'node:fs/promises';
import { transform } from 'esbuild';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { monitorExecution } from './monitor_stream_fixture.ts';

export const agentMonitorIds = ['nextjs_rce_scanner','webpack_source_downloader','ssrf_detector',
    'cors_misconfiguration','open_redirect_detector','xss_scanner','sql_injection_scanner'];
const epoch=Date.parse('2026-10-29T00:00:00Z');
class FixtureDate extends Date {constructor(...args){super(...(args.length?args:[epoch]));} static now(){return epoch;}}

export function agentInput(id) {
    const url='https://agent.owned.test/?owned=sample';
    if (id==='nextjs_rce_scanner') return {targets:[url],detectOnly:true};
    if (id==='webpack_source_downloader') return {targets:[url],maxJsFiles:1,maxSourceMaps:1,maxSourceFiles:1,saveDirectory:'/owned-fixture'};
    return {url,params:{owned:'sample'},customPayloads:['OWNED_PAYLOAD'],testOrigins:['https://origin.owned.test'],
        testInternal:false,testCloud:false,testProtocols:false,testErrorBased:true,testBlind:false,testTimeBased:false,testUnion:false};
}

export async function agentFixture(id, source) {
    source ??= await readFile(new URL(`../plugins/agent/${id}.ts`,import.meta.url),'utf8');
    const code=(await transform(source,{loader:'ts',format:'cjs',target:'es2022'})).code;
    const packets=[],requests=[],writes=[];
    const exports={};const quiet={log(){},warn(){},error(){},info(){}};
    const context=vm.createContext({exports,module:{exports},URL,URLSearchParams,Response,Headers,Request,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,
        Date:FixtureDate,performance:{now:()=>0},btoa,atob,Math:Object.assign(Object.create(Math),{random:()=>0.5}),crypto:webcrypto,console:quiet,
        setTimeout:(fn)=>{fn();return 1;},clearTimeout(){},
        Deno:{mkdir:async()=>{},writeTextFile:async(path,text)=>{writes.push({path,text});}},
        fetch:async(raw,init)=>{
            const url=String(raw);requests.push(JSON.parse(JSON.stringify({url,init})));
            if(new URL(url).pathname.endsWith('.map')) return Response.json({version:3,sources:['webpack:///src/owned.js'],sourcesContent:['export const owned=true;']});
            if(new URL(url).pathname.endsWith('.js')) return new Response('fetch("/api/owned");\n//# sourceMappingURL=app.js.map',{headers:{'content-type':'application/javascript'}});
            return new Response('<title>Owned</title><script src="/app.js"></script>',{headers:{'content-type':'text/html','x-powered-by':'Next.js'}});
        },
        Sentinel:{log(){},Monitor:{reportProgress(){return true;},commitResults:async request=>{packets.push(JSON.parse(JSON.stringify(request)));return {ok:true,sequence:request.sequence};}}},
    });
    new vm.Script(code,{filename:`${id}.fixture.js`}).runInContext(context);
    const input=agentInput(id),targets=input.targets||[input.url];
    return {packets,requests,writes,targets,input,
        ordinary:()=>context.module.exports.analyze(structuredClone(input)),
        monitor:()=>context.module.exports.analyze({...structuredClone(input),__monitorExecution:monitorExecution(targets,{pluginId:id})})};
}
