// DOM/HTTP simulation only: no browser, installation or device commands.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const {runInNewContext}=require('node:vm');
const source=readFileSync(join(__dirname,'../app/static/admin.js'),'utf8');
const html=readFileSync(join(__dirname,'../app/static/admin.html'),'utf8');
function harness(){
 const nodes=new Map(),calls=[],timers=[];
 const node=id=>{if(!nodes.has(id))nodes.set(id,{value:'',textContent:'',innerHTML:'',disabled:false,style:{},classList:{add(){},remove(){}},setAttribute(k,v){this[k]=v}});return nodes.get(id)};
 const context={document:{querySelector:node},URLSearchParams,AbortController,Intl,Date,
  fetch:(url,opt)=>new Promise((resolve,reject)=>calls.push({url,opt,resolve,reject})),
  setTimeout:(fn,delay)=>{const timer={fn,delay};timers.push(timer);return timer},clearTimeout:timer=>{if(timer)timer.cleared=true}};
 runInNewContext(source.replace('init().catch(e=>toast(e.message,true));','globalThis.auditTest={S,audit,renderAudit,auditOrigin};'),context);
 const reply=(index,data,status=200)=>calls[index].resolve({ok:status===200,status,json:async()=>data});
 return {api:context.auditTest,node,calls,timers,reply};
}
const event=seq=>({seq,occurred_at:'2026-01-01T00:00:00Z',actor_type:'guest',action:'login',outcome:'allowed',metadata:{label:'Ospite sintetico'}});
const page=(number,events=Array.from({length:number===3?1:100},(_,i)=>event(202-number*100-i)))=>({page:number,pages:3,total:201,page_size:100,snapshot_seq:201,events,valid:true,stats:{events:201}});

test('new columns follow details, controls are accessible, and assets are cache-busted',()=>{
 assert.ok(html.indexOf('>Dettagli<')<html.indexOf('>IP provenienza<'));
 assert.ok(html.indexOf('>IP provenienza<')<html.indexOf('>Paese<'));
 assert.ok(html.indexOf('>Paese<')<html.indexOf('>Città indicativa<'));
 assert.ok(html.indexOf('>Città indicativa<')<html.indexOf('>Esito<'));
 for(const id of ['first','previous','next','last'])assert.ok(html.includes('id="audit-'+id+'"'));
 assert.match(html,/aria-label="Pagine del registro"/);assert.match(html,/id="audit-error" role="alert"/);
 assert.match(html,/admin.js\?v=20261112-origin067/);assert.doesNotMatch(source,/audit\?limit=1000/);
});

test('renders at most100 rows, legacy data is not invented and all origin data is escaped',()=>{
 const h=harness();h.api.S.auditEvents=Array.from({length:101},(_,i)=>event(i));
 h.api.S.auditEvents[0].metadata.origin={client_ip:'<img onerror=bad>',country_code:'IT',ip_source:'cloudflare'};
 h.api.S.auditTotal=101;h.api.S.auditPages=2;h.api.renderAudit();const body=h.node('#audit').innerHTML;
 assert.equal((body.match(/<tr>/g)||[]).length,100);assert.match(body,/Italia \(IT\)/);
 assert.match(body,/&lt;img onerror=bad&gt;/);assert.doesNotMatch(body,/<img/);
 assert.match(body,/Non registrato/);assert.match(body,/Non disponibile/);
 assert.equal(h.api.auditOrigin({metadata:{origin:{country_code:'T1'}}}).country,'Rete Tor');
 assert.equal(h.api.auditOrigin({metadata:{origin:{network_kind:'local'}}}).country,'Non rilevabile (IP interno)');
});

test('internal peer is visibly distinguished from verified visitor IP without changing audit data',()=>{
 const h=harness(),e=event(1);e.metadata.origin={client_ip:'172.30.32.1',network_kind:'local',ip_source:'peer'};
 const before=JSON.stringify(e);h.api.S.auditEvents=[e];h.api.renderAudit();const body=h.node('#audit').innerHTML;
 assert.match(body,/172\.30\.32\.1/);assert.match(body,/<small class="audit-origin-source">IP interno del collegamento/);
 assert.match(body,/IP pubblico ospite non rilevato/);assert.match(body,/Non rilevabile \(IP interno\)/);
 assert.equal(JSON.stringify(e),before);
 assert.match(h.api.auditOrigin({metadata:{origin:{ip_source:'cloudflare'}}}).source,/IP visitatore/);
 assert.match(h.api.auditOrigin({metadata:{origin:{ip_source:'proxy_unresolved'}}}).source,/IP del proxy/);
 const origin={ip_source:'cloudflare',city_source:'cloudflare',city:'Città sintetica'};
 assert.equal(h.api.auditOrigin({metadata:{origin}}).city,'Città sintetica');
 assert.equal(h.api.auditOrigin({metadata:{origin:{...origin,ip_source:'peer'}}}).city,'Non disponibile');
});

test('unverified forwarded observation is visible but never presented as trusted',()=>{
 const h=harness(),e=event(2);e.metadata.origin={client_ip:'172.30.32.1',network_kind:'local',ip_source:'proxy_unresolved',
  observed_client_ip:'1.1.1.1',observed_country_code:'IT',observed_city:'Milano',observation_source:'cloudflare_headers_unverified'};
 const before=JSON.stringify(e);h.api.S.auditEvents=[e];h.api.renderAudit();const body=h.node('#audit').innerHTML;
 assert.match(body,/1\.1\.1\.1/);assert.match(body,/collegamento 172\.30\.32\.1/);
 assert.match(body,/non verificato/);assert.match(body,/Italia \(IT\)/);assert.match(body,/Milano/);
 assert.doesNotMatch(body,/connector Cloudflare fidato/);assert.equal(JSON.stringify(e),before);
});

test('navigation fetches only one page and keeps snapshot; refresh resets it',async()=>{
 const h=harness();let work=h.api.audit();assert.equal(h.node('#audit-next').disabled,true);
 h.reply(0,page(1));await work;assert.equal(h.node('#audit-previous').disabled,true);assert.equal(h.node('#audit-next').disabled,false);
 work=h.node('#audit-next').onclick();assert.match(h.calls[1].url,/page=2/);assert.match(h.calls[1].url,/snapshot_seq=201/);
 h.reply(1,page(2));await work;assert.equal((h.node('#audit').innerHTML.match(/<tr>/g)||[]).length,100);
 work=h.node('#audit-last').onclick();h.reply(2,page(3));await work;
 assert.equal(h.node('#audit-next').disabled,true);assert.match(h.node('#audit-page-info').textContent,/Pagina 3 di 3/);
 assert.match(h.node('#audit-page-info').textContent,/201–201 di 201/);
 work=h.node('#refresh-audit').onclick();assert.doesNotMatch(h.calls[3].url,/snapshot_seq/);
 h.reply(3,page(1));await work;
 assert.ok(h.calls.every(call=>!call.opt.method&&!call.opt.body));
});

test('search is debounced and server-side across history, not a filter on the visible page',async()=>{
 const h=harness();h.api.S.auditSnapshot=201;h.node('#audit-filter').value='Ospite nuovo';
 h.node('#audit-filter').oninput();assert.equal(h.calls.length,0);assert.equal(h.node('#audit-next').disabled,true);
 const work=h.timers.find(timer=>timer.delay===300).fn();assert.match(h.calls[0].url,/q=Ospite\+nuovo/);
 assert.doesNotMatch(h.calls[0].url,/snapshot_seq/);h.reply(0,{...page(1,[event(150)]),total:1,pages:1});await work;
 assert.match(h.node('#audit-page-info').textContent,/di 1/);
});

test('late old responses never replace new search and never unlock its pending controls',async()=>{
 const h=harness();const old=h.api.audit();h.node('#audit-filter').value='latest';const latest=h.api.audit();
 h.reply(0,page(1,[{...event(99),metadata:{label:'OLD'}}]));await old;
 assert.equal(h.api.S.auditBusy,true);assert.doesNotMatch(h.node('#audit').innerHTML,/OLD/);
 h.reply(1,{...page(1,[{...event(100),metadata:{label:'LATEST'}}]),pages:1,total:1});await latest;
 assert.match(h.node('#audit').innerHTML,/LATEST/);assert.equal(h.api.S.auditBusy,false);
});

test('failure and malformed payload clear previous rows and integrity success; retry recovers',async()=>{
 const h=harness();let work=h.api.audit();h.reply(0,page(1));await work;
 work=h.api.audit(2,false);h.reply(1,{detail:'unavailable'},502);await work;
 assert.equal(h.api.S.auditEvents.length,0);assert.match(h.node('#audit-error').textContent,/Registro non caricato/);
 assert.equal(h.node('#audit-state').textContent,'Verifica non disponibile');assert.equal(h.node('#refresh-audit').disabled,false);
 work=h.api.audit();h.reply(2,{...page(1),events:Array.from({length:101},(_,i)=>event(i))});await work;
 assert.match(h.node('#audit-error').textContent,/Risposta del registro non valida/);
 work=h.api.audit();h.reply(3,page(1));await work;assert.equal(h.node('#audit-error').textContent,'');
});
