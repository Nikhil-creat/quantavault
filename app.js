const $=i=>document.getElementById(i),E=new TextEncoder(),D=new TextDecoder(),$$=s=>document.querySelector(s);
const b64=u=>{let s="";for(let i=0;i<u.length;i+=8192)s+=String.fromCharCode.apply(null,u.subarray(i,i+8192));return btoa(s)};
const unb=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const fmt=n=>n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(1)+" MB";
const msg=(id,t,c)=>{const e=$(id);e.textContent=t;e.className="status "+(c||"")};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let KEY=null,timer,fails=0,STATS={files:0,bytes:0};
function gen(n=20){const A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",r=crypto.getRandomValues(new Uint8Array(n));return[...r].map(x=>A[x&63]).join("")}
function save(bytes,name,type){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([bytes],{type:type||"application/octet-stream"}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2e3)}
/* storage (IndexedDB) */
const db=new Promise((res,rej)=>{if(!window.indexedDB)return rej(new Error("Storage unavailable"));const r=indexedDB.open("qv",1);r.onupgradeneeded=()=>{r.result.createObjectStore("files",{keyPath:"id"});r.result.createObjectStore("meta",{keyPath:"k"})};r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)});
const tx=async(s,m,f)=>{const d=await db;return new Promise((res,rej)=>{const t=d.transaction(s,m),q=f(t.objectStore(s));t.oncomplete=()=>res(q&&q.result);t.onerror=()=>rej(t.error)})};
const dbGet=(s,k)=>tx(s,"readonly",o=>o.get(k)),dbAll=s=>tx(s,"readonly",o=>o.getAll()),dbPut=(s,v)=>tx(s,"readwrite",o=>o.put(v)),dbDel=(s,k)=>tx(s,"readwrite",o=>o.delete(k)),dbClr=s=>tx(s,"readwrite",o=>o.clear());
/* crypto */
const enc=async(k,b)=>{const iv=crypto.getRandomValues(new Uint8Array(12));return{iv,ct:new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},k,b))}};
const dcr=(k,iv,ct)=>crypto.subtle.decrypt({name:"AES-GCM",iv},k,ct);
async function derive(pw,salt){const m=await crypto.subtle.importKey("raw",E.encode(pw),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:250000,hash:"SHA-256"},m,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
/* audit log (hash chain, persisted) */
let LOG=[];try{LOG=JSON.parse(localStorage.getItem("qvlog")||"[]")}catch(e){}
const hx=async s=>[...new Uint8Array(await crypto.subtle.digest("SHA-256",E.encode(s)))].map(x=>x.toString(16).padStart(2,"0")).join("");
async function audit(ev){const prev=LOG.length?LOG[LOG.length-1].h:"0".repeat(64),t=new Date().toISOString();LOG.push({ev,t,prev,h:await hx(prev+ev+t)});LOG=LOG.slice(-60);try{localStorage.setItem("qvlog",JSON.stringify(LOG))}catch(e){}draw()}
const draw=()=>{$("log").textContent=LOG.slice(-8).map((e,i)=>`${e.t.slice(11,19)} ${e.ev} ${e.h.slice(0,10)}`).join("\n")||"No events yet."};
$("lv").onclick=async()=>{let p=LOG.length?LOG[0].prev:"";for(let i=0;i<LOG.length;i++){const e=LOG[i];if(e.prev!==p||await hx(p+e.ev+e.t)!==e.h)return msg("lst","Chain broken at entry "+(i+1)+". Tampering detected.","bad");p=e.h}msg("lst","Chain intact ("+LOG.length+" entries).","ok")};
$("lt").onclick=()=>{if(LOG.length<2)return msg("lst","Need 2+ events first.");LOG[LOG.length-2].ev="edited";draw();msg("lst","An entry was edited in memory. Press Verify chain.")};
/* lock / unlock */
function show(){const o=!!KEY;$("locked").hidden=o;$("open").hidden=!o;$("qlock").textContent=o?"Lock":"Unlock";$("pks").textContent=localStorage.getItem("pk")?"on":"off"}
async function unlock(){const pw=$("mp").value;if(pw.length<8)return msg("ust","Use at least 8 characters.","bad");msg("ust","Working...");
try{const m=await dbGet("meta","vault");if(fails)await sleep(Math.min(fails,5)*1000);
if(!m){const salt=crypto.getRandomValues(new Uint8Array(16)),k=await derive(pw,salt);await dbPut("meta",{k:"vault",salt,v:await enc(k,E.encode("QV-OK"))});KEY=k;audit("vault created")}
else{const k=await derive(pw,m.salt);try{await dcr(k,m.v.iv,m.v.ct)}catch(e){fails++;audit("failed unlock");return msg("ust","Wrong passphrase.","bad")}
const pk=localStorage.getItem("pk");if(pk){msg("ust","Confirm with your passkey...");try{await navigator.credentials.get({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),allowCredentials:[{type:"public-key",id:unb(pk)}],userVerification:"preferred",timeout:6e4}})}catch(e){return msg("ust","Passkey check failed ("+e.name+"). Try again, or use Disable passkey.","bad")}}
KEY=k;audit("unlocked")}
fails=0;$("mp").value="";msg("ust","");show();await render();arm();showTasks();try{navigator.storage&&navigator.storage.persist&&navigator.storage.persist()}catch(e){}}catch(e){msg("ust","Error: "+e.message,"bad")}}
function lock(){KEY=null;clearTimeout(timer);$("lib").replaceChildren();$("vwb").hidden=true;$("vw").textContent="";show();showTasks();audit("locked")}
function arm(){clearTimeout(timer);const m=+$("al").value;if(KEY&&m)timer=setTimeout(lock,m*6e4)}
$("ub").onclick=unlock;$("mp").onkeydown=e=>{if(e.key==="Enter")unlock()};$("lk").onclick=lock;
$("pkx").onclick=async()=>{try{const m=await dbGet("meta","vault");if(!m)return msg("ust","No vault yet.");await dcr(await derive($("mp").value,m.salt),m.v.iv,m.v.ct);localStorage.removeItem("pk");show();audit("passkey removed");msg("ust","Passkey requirement removed.","ok")}catch(e){msg("ust","Enter your correct passphrase first.","bad")}};
$("pkr").onclick=async()=>{try{if(!window.PublicKeyCredential)return msg("ast","Passkeys are not supported here.","bad");const c=await navigator.credentials.create({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),rp:{name:"QuantaVault"},user:{id:crypto.getRandomValues(new Uint8Array(16)),name:"vault-user",displayName:"Vault user"},pubKeyCredParams:[{type:"public-key",alg:-7},{type:"public-key",alg:-257}],authenticatorSelection:{userVerification:"preferred",residentKey:"preferred"},timeout:6e4}});localStorage.setItem("pk",b64(new Uint8Array(c.rawId)));show();audit("passkey registered");msg("ast","Passkey registered. It is now required to unlock.","ok")}catch(e){msg("ast","Passkey cancelled: "+e.name,"bad")}};
/* files */
async function put(name,type,bytes){const a=await enc(KEY,bytes),m=await enc(KEY,E.encode(JSON.stringify({name,type})));await dbPut("files",{id:crypto.randomUUID(),t:Date.now(),size:bytes.length,iv:a.iv,ct:a.ct,niv:m.iv,nct:m.ct})}
let adding=false;
async function addFiles(fl){if(!KEY)return msg("ast","Unlock the vault first.","bad");if(adding)return;fl=[...fl];if(!fl.length)return msg("ast","Choose files first.","bad");adding=true;$("addb").disabled=true;let n=0,bad=0;
for(let i=0;i<fl.length;i++){const f=fl[i];msg("ast","Encrypting "+(i+1)+" of "+fl.length+": "+f.name);
try{if(f.size>50*1048576)throw new Error("over 50 MB");if(!f.size)throw new Error("empty or unreadable (download it to your phone first)");await put(f.name||"file",f.type||"application/octet-stream",new Uint8Array(await f.arrayBuffer()));n++}
catch(e){bad++;msg("ast",f.name+": "+(e.name==="QuotaExceededError"?"device storage is full":e.message),"bad");await sleep(1500)}}
adding=false;$("addb").disabled=false;$("af").value="";$("cam").value="";
msg("ast",n?n+" file(s) encrypted and stored."+(bad?" "+bad+" failed.":""):"Nothing was stored.",n&&!bad?"ok":"bad");if(n)audit("added "+n+" file(s)");await render();arm()}
$("af").onchange=()=>addFiles($("af").files);$("cam").onchange=()=>addFiles($("cam").files);$("addb").onclick=()=>addFiles($("af").files);$("cb").onclick=()=>$("cam").click();
["dragover","drop"].forEach(v=>$("drop").addEventListener(v,e=>{e.preventDefault();if(v==="drop")addFiles(e.dataTransfer.files)}));
$("nsave").onclick=async()=>{if(!KEY)return msg("ast","Unlock first.","bad");const c=$("nc").value;if(!c.trim())return msg("ast","Write some text first.","bad");const t=($("nt").value.trim()||"note").replace(/[\\/:*?"<>|]/g,"_").slice(0,80);try{await put(t+".txt","text/plain",E.encode(c));$("nc").value="";$("nt").value="";msg("ast","Note encrypted and stored.","ok");audit("note added");await render()}catch(e){msg("ast","Could not save note: "+e.message,"bad")}};
async function render(){if(!KEY)return;const rows=await dbAll("files"),out=[];let bytes=0;
for(const r of rows){let m={name:"(unreadable)",type:""};try{m=JSON.parse(D.decode(await dcr(KEY,r.niv,r.nct)))}catch(e){}out.push({...r,m});bytes+=r.size}
out.sort((a,b)=>b.t-a.t);STATS={files:out.length,bytes};$("s1").textContent=out.length;$("s2").textContent=fmt(bytes);$("s3").textContent=out[0]?new Date(out[0].t).toLocaleDateString():"-";
const q=$("fq").value.toLowerCase(),L=$("lib"),sh=out.filter(o=>o.m.name.toLowerCase().includes(q));L.replaceChildren();
if(!sh.length){const p=document.createElement("p");p.className="status";p.textContent=out.length?"No match.":"No files yet. Add one above.";L.append(p)}
for(const o of sh){const d=document.createElement("div"),n=document.createElement("span"),s=document.createElement("span"),b=document.createElement("span");d.className="item";n.className="nm";n.textContent=o.m.name;s.className="status";s.textContent=fmt(o.size)+" · "+new Date(o.t).toLocaleString();b.className="btns";
for(const[a,l]of[["view","Open"],["dl","Download"],["rm","Delete"]]){const x=document.createElement("button");x.textContent=l;x.dataset.act=a;x.dataset.id=o.id;if(a!=="view")x.className="alt";b.append(x)}d.append(n,s,b);L.append(d)}}
$("fq").oninput=render;
$("lib").onclick=async e=>{const a=e.target.dataset.act;if(!a||!KEY)return;try{const r=await dbGet("files",e.target.dataset.id);
if(a==="rm"){if(confirm("Delete this file permanently?")){await dbDel("files",r.id);audit("file deleted");render()}return}
const m=JSON.parse(D.decode(await dcr(KEY,r.niv,r.nct))),pt=new Uint8Array(await dcr(KEY,r.iv,r.ct));
if(a==="view"&&(m.type.startsWith("text/")||m.type.startsWith("image/"))){const img=m.type.startsWith("image/");$("vwt").textContent=m.name;$("vw").hidden=img;$("vi").hidden=!img;if(img){if($("vi").src)URL.revokeObjectURL($("vi").src);$("vi").src=URL.createObjectURL(new Blob([pt],{type:m.type}))}else $("vw").textContent=D.decode(pt);$("vwb").hidden=false;$("vwb").scrollIntoView()}
else save(pt,m.name,m.type);audit("opened file");arm()}catch(x){msg("ast","Could not decrypt: "+x.message,"bad")}};
$("vx").onclick=()=>{$("vwb").hidden=true;$("vw").textContent="";if($("vi").src){URL.revokeObjectURL($("vi").src);$("vi").removeAttribute("src")}};
$("bx").onclick=async()=>{const m=await dbGet("meta","vault"),rows=await dbAll("files");save(E.encode(JSON.stringify({v:1,meta:{salt:b64(m.salt),iv:b64(m.v.iv),ct:b64(m.v.ct)},files:rows.map(r=>({id:r.id,t:r.t,size:r.size,iv:b64(r.iv),ct:b64(r.ct),niv:b64(r.niv),nct:b64(r.nct)}))})),"quantavault-backup.json","application/json");audit("backup exported");msg("ast","Encrypted backup downloaded.","ok")};
$("bi").onchange=async e=>{const f=e.target.files[0];if(!f)return;try{const j=JSON.parse(await f.text()),m=await dbGet("meta","vault");
if(m&&b64(m.salt)!==j.meta.salt)return msg("ust","Backup is from a different vault.","bad");
if(!m)await dbPut("meta",{k:"vault",salt:unb(j.meta.salt),v:{iv:unb(j.meta.iv),ct:unb(j.meta.ct)}});
for(const r of j.files)await dbPut("files",{id:r.id,t:r.t,size:r.size,iv:unb(r.iv),ct:unb(r.ct),niv:unb(r.niv),nct:unb(r.nct)});
msg("ust","Imported "+j.files.length+" files. Now unlock with the original passphrase.","ok")}catch(x){msg("ust","Invalid backup file.","bad")}};
$("wipe").onclick=async()=>{if(confirm("Erase ALL vault data on this device? This cannot be undone.")){await dbClr("files");await dbClr("meta");localStorage.removeItem("pk");localStorage.removeItem("qvlog");location.reload()}};
/* tools */
$("gb").onclick=()=>{const p=gen(+$("gl").value);$("go").textContent=p;msg("gs",Math.round(+$("gl").value*6)+" bits of entropy. Store it in a password manager or on paper.","ok")};
$("gc").onclick=async()=>{try{await navigator.clipboard.writeText($("go").textContent);msg("gs","Copied.","ok")}catch(e){msg("gs","Copy failed. Select the text manually.","bad")}};
/* shortcuts */
$("quick").onclick=e=>{const g=e.target.dataset.go;if(g){const t=$$(g);if(t.offsetParent===null){$$("#vault").scrollIntoView();msg("ust","Unlock your vault first.","bad")}else t.scrollIntoView()}if(e.target.id==="qlock"){KEY?lock():$$("#vault").scrollIntoView()}};
addEventListener("keydown",e=>{if(/INPUT|TEXTAREA|SELECT/.test(e.target.tagName)||e.ctrlKey||e.metaKey||e.altKey)return;if(e.key==="/"){e.preventDefault();$("q").focus()}if((e.key==="l"||e.key==="L")&&KEY)lock()});
["pointerdown","keydown"].forEach(v=>addEventListener(v,arm,{passive:true}));
const net=()=>{$("net").textContent=navigator.onLine?"":"Offline mode"};addEventListener("online",net);addEventListener("offline",net);net();
/* ---- RAG: knowledge base + TF-IDF-style ranking ---- */
const KB=[
["Encryption","Files and notes are encrypted on your device with AES-256-GCM. The key comes from your passphrase via PBKDF2 with 250,000 rounds and a random salt. The server only stores ciphertext."],
["Zero knowledge","The service never receives your passphrase or keys, so it cannot read, scan or hand over your data. Losing the passphrase means data cannot be recovered."],
["Post-quantum","Key exchange is designed to move to ML-KEM (Kyber, NIST FIPS 203) in hybrid mode with X25519, protecting stored data against harvest-now-decrypt-later attacks."],
["Authentication","Sign-in uses WebAuthn passkeys (fingerprint, face, hardware key). They resist phishing and there is no password to leak."],
["Audit log","Every login, share and delete is written to a hash-chained audit log. Editing any entry breaks the chain and is detected."],
["CNN inspection","A convolutional neural network views file bytes as an image and flags encrypted, packed or anomalous content before upload."],
["Agentic AI","VaultMind plans steps, calls tools such as knowledge search and a passphrase generator, then answers from retrieved facts."],
["Docker","docker compose up starts the FastAPI backend and web server. Containers run as non-root with healthchecks and read-only filesystems."],
["Passphrase advice","Use 5 or more random words or 16+ characters. Never reuse it. Store a paper backup in a safe place."]];
const tok=s=>s.toLowerCase().match(/[a-z0-9]+/g)||[];
function search(q,n=3){const qs=new Set(tok(q));return KB.map(([t,x])=>{const w=tok(t+" "+x);let sc=0;w.forEach(a=>{if(qs.has(a))sc+=a.length>3?2:1});return[sc,t,x]}).filter(r=>r[0]>0).sort((a,b)=>b[0]-a[0]).slice(0,n).map(r=>r[1]+": "+r[2])}
const WORDS="amber anvil birch cobalt delta ember falcon glacier harbor iris jade kernel lunar maple nova orbit prism quartz raven solar tundra umbra vertex willow xenon yonder zephyr".split(" ");
const TOOLS={
search_kb:({query})=>JSON.stringify(search(query)),
generate_passphrase:({length=20})=>gen(Math.min(Math.max(length|0||20,12),64)),vault_stats:()=>JSON.stringify(STATS),
check_password:({password})=>{let p=0;if(/[a-z]/.test(password))p+=26;if(/[A-Z]/.test(password))p+=26;if(/\d/.test(password))p+=10;if(/\W/.test(password))p+=32;const bits=Math.round(password.length*Math.log2(p||1));return JSON.stringify({entropy_bits:bits,rating:bits>80?"strong":bits>55?"fair":"weak"})}};
const SPEC=[["search_kb","Search the QuantaVault security knowledge base",{query:{type:"string"}},["query"]],["generate_passphrase","Generate a random passphrase",{length:{type:"integer"}},[]],["vault_stats","Count and total bytes of encrypted files in the vault (no names)",{},[]],["check_password","Estimate password strength",{password:{type:"string"}},["password"]]].map(([name,description,properties,required])=>({type:"function",function:{name,description,parameters:{type:"object",properties,required}}}));

const KEYRE=/^gsk_[A-Za-z0-9]{20,}$/,GURL="https://api.groq.com/openai/v1/";
$("key").value=localStorage.getItem("gk")||"";
$("savekey").onclick=async()=>{const k=$("key").value.replace(/[\s"'`]/g,"");$("key").value=k;if(!KEYRE.test(k))return msg("kst","This does not look like a Groq key. It must start with gsk_ and contain no spaces.","bad");msg("kst","Testing key...");
try{const r=await fetch(GURL+"models",{headers:{Authorization:"Bearer "+k}});if(r.ok){localStorage.setItem("gk",k);const l=await models(k);msg("kst","Key works. Auto-selected model: "+(l[0]||"none found")+". Saved in this browser only.","ok")}else msg("kst",r.status==401?"Groq rejected this key (401). Make a new key at console.groq.com/keys and paste the whole key.":"Groq error "+r.status,"bad")}catch(e){msg("kst","Network problem: "+e.message,"bad")}};
const SYS={sec:"You are VaultMind, the security assistant for QuantaVault, built by Nikhil Chary Sriramoju. Use search_kb before answering product questions. Be concise. Never ask for real passwords or passphrases.",pa:"You are Quanta, a friendly personal assistant inside QuantaVault, built by Nikhil Chary Sriramoju. Reply briefly in the language the user writes in (English, Telugu or Tenglish). Use tools: get_datetime for date or time, calculate for maths, set_timer for reminders, add_task/list_tasks/complete_task for to-dos, save_note to store an encrypted note, search_kb for security questions. If a tool says the vault is locked, tell the user to unlock it. Never ask for passwords or secrets."};
const H={sec:[{role:"system",content:SYS.sec}],pa:[{role:"system",content:SYS.pa}]},LOGS={};let MODE="sec",hist=H.sec;
function speak(t){try{speechSynthesis.cancel();const u=new SpeechSynthesisUtterance(t);u.lang=$("vl").value;speechSynthesis.speak(u)}catch(e){}}
function add(c,t,nolog){const d=document.createElement("div");d.className="m "+c;d.textContent=t;$("chat").append(d);$("chat").scrollTop=1e9;if(!nolog)(LOGS[MODE]=LOGS[MODE]||[]).push([c,t]);if(c==="a"&&!nolog&&$("spk").checked)speak(t)}
async function groq(body,k){for(let a=0;a<3;a++){const c=new AbortController(),t=setTimeout(()=>c.abort(),3e4);
try{const r=await fetch(GURL+"chat/completions",{method:"POST",signal:c.signal,headers:{"Content-Type":"application/json",Authorization:"Bearer "+k},body:JSON.stringify(body)});clearTimeout(t);
if(r.ok)return r.json();if((r.status==429||r.status>=500)&&a<2){await sleep(1500*(a+1));continue}
let m="";try{m=(await r.json()).error.message}catch(e){}{const x=new Error(r.status==401?"Invalid Groq key (401). Save a fresh key above.":"Groq "+r.status+": "+m);x.status=r.status;throw x}}
catch(e){clearTimeout(t);if(e.name==="AbortError"){if(a<2)continue;throw new Error("Groq timed out. Try again.")}throw e}}}
const BAD=/whisper|guard|tts|playai|orpheus|embed|safeguard/i,PREF=["llama-3.3-70b-versatile","openai/gpt-oss-120b","openai/gpt-oss-20b","meta-llama/llama-4-scout-17b-16e-instruct","qwen/qwen3-32b","llama-3.1-8b-instant","moonshotai/kimi-k2-instruct"];
async function models(k){const r=await fetch(GURL+"models",{headers:{Authorization:"Bearer "+k}});if(!r.ok){const x=new Error("Could not list models ("+r.status+")");x.status=r.status;throw x}
const ids=(await r.json()).data.map(m=>m.id).filter(i=>!BAD.test(i)),l=[...PREF.filter(p=>ids.includes(p)),...ids.filter(i=>!PREF.includes(i))];localStorage.setItem("gml",JSON.stringify(l));return l}
async function chatCall(k){let l=[];try{l=JSON.parse(localStorage.getItem("gml")||"[]")}catch(e){}if(!l.length)l=await models(k);
while(l.length){try{const j=await groq({model:l[0],messages:hist,tools:specFor(),tool_choice:"auto",temperature:.3},k);if(localStorage.getItem("gm")!==l[0]){localStorage.setItem("gm",l[0]);add("t","model: "+l[0])}return j}
catch(e){if(e.status===404||e.status===403||(e.status===400&&/model|tool/i.test(e.message))){add("t","Skipping "+l[0]+" ("+e.status+")");l.shift();localStorage.setItem("gml",JSON.stringify(l));continue}throw e}}
throw new Error("No usable Groq model found for this key. Check console.groq.com/settings/limits.")}
let busy=false;
async function ask(){const q=$("q").value.trim(),k=localStorage.getItem("gk");if(!q||busy)return;if(!k)return add("t","Save a working Groq key first.");
busy=true;$("send").disabled=true;$("q").value="";add("u",q);hist.push({role:"user",content:q});
while(hist.length>14){const i=hist.findIndex((m,j)=>j>1&&m.role==="user");if(i<0)break;hist.splice(1,i-1)}
try{for(let i=0;i<5;i++){const m=(await chatCall(k)).choices[0].message;hist.push(m);
if(!m.tool_calls){add("a",m.content||"(no answer)");return}
for(const c of m.tool_calls){let a={};try{a=JSON.parse(c.function.arguments||"{}")}catch(e){}let out;try{out=TOOLS[c.function.name]?await TOOLS[c.function.name](a):"unknown tool"}catch(e){out="tool error: "+e.message}add("t","tool: "+c.function.name);hist.push({role:"tool",tool_call_id:c.id,content:String(out)})}}
add("t","Stopped after 5 steps.")}catch(e){add("t",e.message)}finally{busy=false;$("send").disabled=false}}
$("send").onclick=ask;$("q").onkeydown=e=>{if(e.key==="Enter")ask()};
const LK="Vault is locked. Ask the user to unlock the vault first.";
function calc(x){const s=x.replace(/\s+/g,"").replace(/\^/g,"**");if(!/^[0-9+\-*/().%]+$/.test(s))throw 0;let i=0;
const P=()=>{if(s[i]==="-"){i++;return -P()}if(s[i]==="("){i++;const v=A();if(s[i]!==")")throw 0;i++;return v}const m=/^\d*\.?\d+/.exec(s.slice(i));if(!m)throw 0;i+=m[0].length;return +m[0]};
const W=()=>{const b=P();if(s[i]==="*"&&s[i+1]==="*"){i+=2;return b**W()}return b};
const M=()=>{let v=W();for(;i<s.length;){const c=s[i];if(c==="*"&&s[i+1]!=="*"){i++;v*=W()}else if(c==="/"){i++;v/=W()}else if(c==="%"){i++;v%=W()}else break}return v};
const A=()=>{let v=M();while(s[i]==="+"||s[i]==="-"){const c=s[i++],r=M();v=c==="+"?v+r:v-r}return v};
const r=A();if(i!==s.length||!isFinite(r))throw 0;return r}
async function tasks(){const m=await dbGet("meta","tasks");return m?JSON.parse(D.decode(await dcr(KEY,m.iv,m.ct))):[]}
async function saveTasks(l){const e=await enc(KEY,E.encode(JSON.stringify(l)));await dbPut("meta",{k:"tasks",iv:e.iv,ct:e.ct})}
async function showTasks(){const p=$("tasks");if(!KEY||MODE!=="pa"){p.hidden=true;return}p.hidden=false;const L=$("tl");L.replaceChildren();let l=[];try{l=await tasks()}catch(e){}
if(!l.length){const x=document.createElement("p");x.className="status";x.textContent="No tasks. Ask Quanta to add one.";L.append(x)}
for(const t of l){const d=document.createElement("div"),n=document.createElement("span"),b=document.createElement("span");d.className="item";n.className="nm";n.textContent=(t.done?"Done: ":"")+t.title+(t.due?" ("+t.due+")":"");b.className="btns";
for(const[a,lb]of[["done",t.done?"Undo":"Done"],["del","Delete"]]){const x=document.createElement("button");x.textContent=lb;x.className="alt";x.dataset.a=a;x.dataset.id=t.id;b.append(x)}d.append(n,b);L.append(d)}}
$("tl").onclick=async e=>{const a=e.target.dataset.a;if(!a||!KEY)return;let l=await tasks();const id=+e.target.dataset.id;l=a==="del"?l.filter(t=>t.id!==id):l.map(t=>t.id===id?{...t,done:!t.done}:t);await saveTasks(l);showTasks()};
const T2={get_datetime:()=>{const d=new Date();return JSON.stringify({iso:d.toISOString(),local:d.toLocaleString(),weekday:d.toLocaleDateString("en",{weekday:"long"}),timezone:Intl.DateTimeFormat().resolvedOptions().timeZone})},
calculate:({expression})=>{try{return String(calc(String(expression)))}catch(e){return "Could not evaluate. Use numbers and + - * / % ^ ( ) only."}},
set_timer:({minutes,label})=>{const m=Math.min(Math.max(+minutes||1,.1),180);setTimeout(()=>{add("a","Reminder: "+(label||"Timer finished"));try{navigator.vibrate&&navigator.vibrate([300,150,300]);if(window.Notification&&Notification.permission==="granted")new Notification("QuantaVault",{body:label||"Timer finished"})}catch(e){}},m*6e4);try{window.Notification&&Notification.permission==="default"&&Notification.requestPermission()}catch(e){}return "Timer set for "+m+" minutes. It only works while this page stays open."},
add_task:async({title,due})=>{if(!KEY)return LK;const l=await tasks(),id=l.reduce((m,t)=>Math.max(m,t.id),0)+1;l.push({id,title:String(title).slice(0,200),due:String(due||""),done:false});await saveTasks(l);audit("task added");return JSON.stringify({ok:true,id})},
list_tasks:async()=>KEY?JSON.stringify(await tasks()):LK,
complete_task:async({id})=>{if(!KEY)return LK;const l=await tasks();await saveTasks(l.map(t=>t.id===+id?{...t,done:true}:t));return "ok"},
save_note:async({title,text})=>{if(!KEY)return LK;await put(String(title||"note").replace(/[\\/:*?"<>|]/g,"_").slice(0,80)+".txt","text/plain",E.encode(String(text)));render();audit("assistant saved note");return "Saved as an encrypted note."}};
const mk=(name,description,properties,required)=>({type:"function",function:{name,description,parameters:{type:"object",properties,required}}});
SPEC.push(mk("get_datetime","Current date, time and timezone of the user",{},[]),mk("calculate","Evaluate arithmetic with numbers and + - * / % ^ ( ). For percentages use multiplication, e.g. 18% of 2450 is 0.18*2450",{expression:{type:"string"}},["expression"]),mk("set_timer","Set a reminder timer in minutes",{minutes:{type:"number"},label:{type:"string"}},["minutes"]),mk("add_task","Add a to-do task",{title:{type:"string"},due:{type:"string"}},["title"]),mk("list_tasks","List the user's tasks with ids",{},[]),mk("complete_task","Mark a task done by id",{id:{type:"integer"}},["id"]),mk("save_note","Save an encrypted note to the vault",{title:{type:"string"},text:{type:"string"}},["title","text"]));
Object.assign(TOOLS,T2);
const SEC=["search_kb","generate_passphrase","vault_stats","check_password"],specFor=()=>MODE==="pa"?SPEC:SPEC.filter(x=>SEC.includes(x.function.name));
const GREET={sec:"Hi, I'm VaultMind. Ask how your data is protected, or ask me for a strong passphrase.",pa:"Hi! I'm Quanta, your personal assistant. I can tell the date and time, do maths, set timers, keep your to-do list and save encrypted notes (unlock the vault first). Talk to me in English or Telugu."};
const DESC={sec:"Security expert. Searches the knowledge base and generates passphrases.",pa:"General assistant with tools: date and time, calculator, timers, encrypted to-do list and notes. Messages go to Groq, so do not paste secrets."};
const HINT={sec:["How is my data protected?","Give me a strong passphrase","What is zero knowledge?"],pa:["What is today's date?","Add task: buy milk","Remind me in 10 minutes to drink water","Show my tasks","Calculate 18% of 2450"]};
function setMode(m){MODE=m;hist=H[m];$("m1").classList.toggle("on",m==="sec");$("m2").classList.toggle("on",m==="pa");$("mdesc").textContent=DESC[m];$("chat").replaceChildren();if(!LOGS[m])LOGS[m]=[["a",GREET[m]]];LOGS[m].forEach(([c,t])=>add(c,t,true));
$("qc").replaceChildren(...HINT[m].map(t=>{const b=document.createElement("button");b.className="alt";b.textContent=t;b.dataset.q=t;return b}));showTasks()}
$("m1").onclick=()=>setMode("sec");$("m2").onclick=()=>setMode("pa");$("qc").onclick=e=>{if(e.target.dataset.q){$("q").value=e.target.dataset.q;ask()}};
const SR=window.SpeechRecognition||window.webkitSpeechRecognition;
$("mic").onclick=()=>{if(!SR)return add("t","Voice input is not supported in this browser.");const r=new SR();r.lang=$("vl").value;r.interimResults=false;$("mic").textContent="Listening...";r.onresult=e=>{$("q").value=e.results[0][0].transcript;ask()};r.onerror=e=>add("t","Mic: "+e.error);r.onend=()=>{$("mic").textContent="Speak"};try{r.start()}catch(e){$("mic").textContent="Speak"}};
setMode("sec");
/* ---- CNN-style inspector ---- */
$("file").onchange=async e=>{const f=e.target.files[0];if(!f)return;const b=new Uint8Array(await f.slice(0,16384).arrayBuffer());
const cnt=new Array(256).fill(0);b.forEach(v=>cnt[v]++);let H=0;cnt.forEach(c=>{if(c){const p=c/b.length;H-=p*Math.log2(p)}});
const N=128,g=new Float32Array(N*N);for(let i=0;i<N*N;i++)g[i]=(b[i%b.length]||0)/255;
const x=$("c1").getContext("2d"),im=x.createImageData(N,N);for(let i=0;i<N*N;i++){const v=g[i]*255;im.data.set([v,v,v,255],i*4)}x.putImageData(im,0,0);
const kx=[-1,0,1,-2,0,2,-1,0,1],ky=[-1,-2,-1,0,0,0,1,2,1],M=N/2,out=new Float32Array(M*M);let mean=0;
for(let y=0;y<M;y++)for(let z=0;z<M;z++){let mx=0;for(let dy=0;dy<2;dy++)for(let dx=0;dx<2;dx++){const cy=y*2+dy,cx=z*2+dx;let sx=0,sy=0;for(let j=0;j<3;j++)for(let i=0;i<3;i++){const yy=Math.min(N-1,Math.max(0,cy+j-1)),xx=Math.min(N-1,Math.max(0,cx+i-1)),v=g[yy*N+xx];sx+=v*kx[j*3+i];sy+=v*ky[j*3+i]}mx=Math.max(mx,Math.max(0,Math.hypot(sx,sy)))}out[y*M+z]=mx;mean+=mx}
mean/=M*M;const y2=$("c2").getContext("2d"),i2=y2.createImageData(M,M);for(let i=0;i<M*M;i++){const v=Math.min(255,out[i]*120);i2.data.set([v*.4,v,v*.9,255],i*4)}y2.putImageData(i2,0,0);
const v=H>7.6?"Uniform noise: looks encrypted or compressed.":H>6?"Mixed content: likely a binary or media file.":"Structured: likely readable text or simple data.";
$("verdict").textContent=`${f.name}: entropy ${H.toFixed(2)} / 8 bits, mean edge response ${mean.toFixed(2)}. ${v}`};


draw();show();
dbGet("meta","vault").then(m=>{$("ub").textContent=m?"Unlock":"Create vault"}).catch(e=>msg("ust",e.message+". Private browsing may block storage.","bad"));
if("serviceWorker" in navigator&&location.protocol.startsWith("http"))navigator.serviceWorker.register("sw.js").catch(()=>{});
