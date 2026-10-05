/** Browser integration: resident passkey enrollment, logout, discoverable login,
 * actual EventSource and WebSocket through Bouncer, and persistence on restart.
 * Run with make test-browser. Uses temporary config only; no external services.
 */
import { chromium } from 'playwright';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const dir = await mkdtemp(join(tmpdir(), 'bouncer-browser-'));
const backend = Bun.serve({hostname:'127.0.0.1',port:0,fetch(req,server){
 const path = new URL(req.url).pathname;
 if(path==='/ws' && server.upgrade(req)) return;
 if(path==='/events') return new Response(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('data: browser-event\n\n'));},cancel(){}}),{headers:{'Content-Type':'text/event-stream'}});
 return new Response('<!doctype html><title>Protected backend</title><h1 id="backend">Authenticated</h1>',{headers:{'Content-Type':'text/html'}});
},websocket:{message(ws,data){ws.send(data);}}});
// Reserve an ephemeral listening port before starting the binary.
const reservation = Bun.serve({hostname:'127.0.0.1',port:0,fetch(){return new Response('reserved')}});
const port=reservation.port; reservation.stop(true);
const tls = Bun.env.BOUNCER_TEST_TLS === '1';
const bootstrap=Bun.serve({hostname:'127.0.0.1',port:0,fetch(){return new Response('reserved')}});
const bootstrapPort=bootstrap.port;bootstrap.stop(true);
const origin=`${tls ? "https" : "http"}://localhost:${port}`;
const cfgPath=join(dir,'bouncer.json');
await Bun.write(cfgPath,JSON.stringify({server:{listen:`127.0.0.1:${port}`,cloudflare:!tls,httpListen:`127.0.0.1:${bootstrapPort}`,publicOrigin:origin,rpID:'localhost',hostnames:['localhost'],backend:`http://127.0.0.1:${backend.port}`},onboarding:{enabled:true,localBypass:false,oneTimeToken:true,token:'123456',geoip:{enabled:false}}}));
let process: ReturnType<typeof Bun.spawn>|undefined;
let logs = '';
let logReaders: Promise<void>[] = [];
async function capture(stream: ReadableStream<Uint8Array>) {
 const reader = stream.getReader();
 const decoder = new TextDecoder();
 for (;;) { const {done,value}=await reader.read(); if(done)return; logs=(logs+decoder.decode(value,{stream:true})).slice(-32_768); }
}
const start=async()=>{
 logs='';
 process=Bun.spawn([Bun.env.BOUNCER_TEST_BINARY || './bouncer','--config',cfgPath],{stdout:'pipe',stderr:'pipe'});
 logReaders=[capture(process.stdout),capture(process.stderr)];
 const deadline=Date.now()+15_000;
 while(Date.now()<deadline){
  if(process.exitCode!==null)break;
  try{if((await fetch(origin+'/login',{tls:{rejectUnauthorized:false},signal:AbortSignal.timeout(500)})).ok)return;}catch{}
  await Bun.sleep(50);
 }
 throw new Error('Bouncer failed readiness deadline: '+logs);
};
const stop=async()=>{
 if(!process)return;
 const child=process;process=undefined;
 if(child.exitCode===null)child.kill('SIGTERM');
 const code=await Promise.race([child.exited,Bun.sleep(10_000).then(()=>null)]);
 if(code===null){child.kill('SIGKILL');await child.exited;await Promise.all(logReaders);throw new Error('Bouncer shutdown timed out; allocation profile may be incomplete: '+logs);}
 await Promise.all(logReaders);
 assert.equal(code,0,'Bouncer exited unsuccessfully: '+logs);
};
let browser: Awaited<ReturnType<typeof chromium.launch>>|undefined;
try {
 await start();
 browser=await chromium.launch({headless:true});
 const context=await browser.newContext({ignoreHTTPSErrors:true}); const page=await context.newPage();
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true,defaultBackupEligibility:true,defaultBackupState:true}});
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 if(tls){await page.goto('http://localhost:'+bootstrapPort+'/onboarding');assert.equal(await page.locator('#continue').getAttribute('href'),origin+'/onboarding');await page.locator('#continue').click();}else{await page.goto(origin+'/onboarding');}
 assert(await page.locator('#token-group').isVisible(),'enrollment code UI hidden');
 for(let i=0;i<6;i++) await page.locator('.otp-input').nth(i).fill('123456'[i]);
 await page.locator('#name-input').fill('Browser smoke');
 await page.locator('#register-btn').click();
 await page.waitForURL(origin+'/',{timeout:15000});
 assert.equal(await page.locator('#backend').textContent(),'Authenticated');
 const login=async()=>{await page.goto(origin+'/login');await page.locator('#login-btn').click();await page.waitForURL(origin+'/',{timeout:15000});assert.equal(await page.locator('#backend').textContent(),'Authenticated');};
 assert.equal(await page.evaluate(async()=> (await fetch('/logout',{method:'POST'})).status),200);
 await login();
 const streams=await page.evaluate(async()=>{
  const event=await new Promise<string>((resolve,reject)=>{const s=new EventSource('/events');const timeout=setTimeout(()=>{s.close();reject(new Error('SSE timeout'));},3000);s.onmessage=e=>{clearTimeout(timeout);s.close();resolve(e.data)};});
  const echo=await new Promise<string>((resolve,reject)=>{const ws=new WebSocket(location.origin.replace('http','ws')+'/ws');const timeout=setTimeout(()=>{ws.close();reject(new Error('WS timeout'));},3000);ws.onopen=()=>ws.send('browser-websocket');ws.onmessage=e=>{clearTimeout(timeout);ws.close();resolve(e.data)};ws.onerror=()=>reject(new Error('WS failure'));});
  return {event,echo};
 });
 assert.deepEqual(streams,{event:'browser-event',echo:'browser-websocket'});
 await stop();await start();await page.reload();assert.equal(await page.locator('#backend').textContent(),'Authenticated');
 assert.equal(await page.evaluate(async()=> (await fetch('/logout',{method:'POST'})).status),200);
 await login();assert.deepEqual(errors,[]);
 console.log('PASS: resident passkey enrollment → logout → discoverable login; browser SSE/WS; session and credential persistence across restart.');
} finally {
 try { await browser?.close(); } finally {
  try { await stop(); } finally { backend.stop(true);await rm(dir,{recursive:true,force:true}); }
 }
}
