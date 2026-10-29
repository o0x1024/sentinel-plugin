import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { agentFixture,agentMonitorIds } from './agent_monitor_fixture.mjs';
const root=new URL('../',import.meta.url);
for(const id of agentMonitorIds) {
    test(`${id}: ordinary behavior matches the pre-migration business and monitor work completes`,async()=>{
        const source=execFileSync('rtk',['proxy','git','show',`23853f6:plugins/agent/${id}.ts`],{cwd:root,encoding:'utf8'});
        const before=await agentFixture(id,source),after=await agentFixture(id);
        const expected=await before.ordinary(),actual=await after.ordinary();
        assert.equal(actual.success,true,actual.error);
        assert.deepEqual(JSON.parse(JSON.stringify(actual)),JSON.parse(JSON.stringify(expected)));
        assert.deepEqual(after.requests,before.requests);assert.deepEqual(after.writes,before.writes);
        const monitored=await agentFixture(id);const output=await monitored.monitor();
        assert.equal(output.success,true,output.error);assert.equal(output.data.stream_complete,true);
        const work=monitored.packets.flatMap(packet=>packet.work);
        assert.deepEqual(work.filter(item=>item.complete).map(item=>item.target),monitored.targets);
        assert.equal(work.filter(item=>item.key.startsWith('http:')).length,monitored.requests.length);
        assert(monitored.packets.every(packet=>!Object.hasOwn(packet,'output')));
    });
}
