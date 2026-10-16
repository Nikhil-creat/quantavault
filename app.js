const $=i=>document.getElementById(i),E=new TextEncoder(),D=new TextDecoder();
const b64=u=>btoa(String.fromCharCode(...u)),unb=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const say=(t,c)=>{$("st").textContent=t};let blob;
async function K(pw,salt){const m=await crypto.subtle.importKey("raw",E.encode(pw),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:250000,hash:"SHA-256"},m,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
$("enc").onclick=async()=>{try{const s=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
const ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},await K($("pw").value,s),E.encode($("pt").value)));
blob={s:b64(s),iv:b64(iv),ct:b64(ct)};$("out").textContent=blob.s+"."+blob.iv+"."+blob.ct;say("Encrypted locally.")}catch(e){say("Needs a secure (https) page.")}};
$("dec").onclick=async()=>{if(!blob)return say("Encrypt first.");try{say("Decrypted: "+D.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb(blob.iv)},await K($("pw").value,unb(blob.s)),unb(blob.ct))))}catch(e){say("Wrong passphrase. Nothing revealed.")}};

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
generate_passphrase:({words=5})=>{const r=crypto.getRandomValues(new Uint32Array(Math.min(words,10)));return[...r].map(x=>WORDS[x%WORDS.length]).join("-")},
check_password:({password})=>{let p=0;if(/[a-z]/.test(password))p+=26;if(/[A-Z]/.test(password))p+=26;if(/\d/.test(password))p+=10;if(/\W/.test(password))p+=32;const bits=Math.round(password.length*Math.log2(p||1));return JSON.stringify({entropy_bits:bits,rating:bits>80?"strong":bits>55?"fair":"weak"})}};
const SPEC=[["search_kb","Search the QuantaVault security knowledge base",{query:{type:"string"}},["query"]],["generate_passphrase","Generate a random passphrase",{words:{type:"integer"}},[]],["check_password","Estimate password strength",{password:{type:"string"}},["password"]]].map(([name,description,properties,required])=>({type:"function",function:{name,description,parameters:{type:"object",properties,required}}}));
$("key").value=localStorage.getItem("gk")||"";$("savekey").onclick=()=>{localStorage.setItem("gk",$("key").value.trim());add("t","Key saved in this browser only.")};
const hist=[{role:"system",content:"You are VaultMind, the security assistant for QuantaVault, built by Nikhil Chary Sriramoju. Use search_kb before answering product questions. Be concise and never ask users to reveal real passwords."}];
function add(c,t){const d=document.createElement("div");d.className="m "+c;d.textContent=t;$("chat").append(d);$("chat").scrollTop=1e9}
async function ask(){const q=$("q").value.trim(),k=localStorage.getItem("gk");if(!q)return;if(!k)return add("t","Add your free Groq key first.");
$("q").value="";add("u",q);hist.push({role:"user",content:q});
try{for(let i=0;i<5;i++){const r=await fetch("https://api.groq.com/openai/v1/chat/completions",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+k},body:JSON.stringify({model:"llama-3.3-70b-versatile",messages:hist,tools:SPEC,tool_choice:"auto",temperature:.3})});
if(!r.ok)throw new Error("Groq error "+r.status);const m=(await r.json()).choices[0].message;hist.push(m);
if(!m.tool_calls){add("a",m.content);return}
for(const c of m.tool_calls){let a={};try{a=JSON.parse(c.function.arguments||"{}")}catch(e){}const out=TOOLS[c.function.name]?TOOLS[c.function.name](a):"unknown tool";add("t","tool: "+c.function.name+" "+JSON.stringify(a));hist.push({role:"tool",tool_call_id:c.id,content:String(out)})}}
add("t","Stopped after 5 steps.")}catch(e){add("t",e.message)}}
$("send").onclick=ask;$("q").onkeydown=e=>{if(e.key==="Enter")ask()};
add("a","Hi, I'm VaultMind. Ask how your data is protected, or ask me for a strong passphrase.");

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

/* ---- File vault: .qvault = "QV1" + salt(16) + iv(12) + ciphertext ---- */
const fs=m=>$("fst").textContent=m;
function save(bytes,name){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([bytes]));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1e3)}
$("efb").onclick=async()=>{const f=$("ef").files[0];if(!f)return fs("Choose a file first.");try{
const s=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
const ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},await K($("pw").value,s),await f.arrayBuffer()));
const o=new Uint8Array(3+28+ct.length);o.set(E.encode("QV1"));o.set(s,3);o.set(iv,19);o.set(ct,31);save(o,f.name+".qvault");fs("Encrypted "+f.name+" ("+f.size+" bytes).");audit("encrypt "+f.name)}catch(e){fs("Encryption failed.")}};
$("dfb").onclick=async()=>{const f=$("df").files[0];if(!f)return fs("Choose a .qvault file first.");try{
const b=new Uint8Array(await f.arrayBuffer());if(D.decode(b.slice(0,3))!=="QV1")return fs("Not a QuantaVault file.");
const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:b.slice(19,31)},await K($("pw").value,b.slice(3,19)),b.slice(31));
save(pt,f.name.replace(/\.qvault$/,"")||"decrypted");fs("Decrypted.");audit("decrypt "+f.name)}catch(e){fs("Wrong passphrase or damaged file. Nothing revealed.")}};

/* ---- Passkey (WebAuthn) ---- */
const ps=m=>$("pst").textContent=m;
$("pkr").onclick=async()=>{try{if(!window.PublicKeyCredential)return ps("Passkeys are not supported in this browser.");
const c=await navigator.credentials.create({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),rp:{name:"QuantaVault"},user:{id:crypto.getRandomValues(new Uint8Array(16)),name:"vault-user",displayName:"Vault user"},pubKeyCredParams:[{type:"public-key",alg:-7},{type:"public-key",alg:-257}],authenticatorSelection:{userVerification:"preferred",residentKey:"preferred"},timeout:60000}});
localStorage.setItem("pk",b64(new Uint8Array(c.rawId)));ps("Passkey registered.");audit("passkey registered")}catch(e){ps("Cancelled or blocked: "+e.name)}};
$("pka").onclick=async()=>{const id=localStorage.getItem("pk");if(!id)return ps("Register a passkey first.");try{
await navigator.credentials.get({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),allowCredentials:[{type:"public-key",id:unb(id)}],userVerification:"preferred",timeout:60000}});ps("Signed in with passkey.");audit("passkey sign-in")}catch(e){ps("Sign-in failed: "+e.name)}};

/* ---- Hash-chained audit log ---- */
const LOG=[];const hx=async s=>[...new Uint8Array(await crypto.subtle.digest("SHA-256",E.encode(s)))].map(x=>x.toString(16).padStart(2,"0")).join("");
async function audit(ev){const prev=LOG.length?LOG[LOG.length-1].h:"0".repeat(64),t=new Date().toISOString();LOG.push({ev,t,prev,h:await hx(prev+ev+t)});draw()}
function draw(){$("log").textContent=LOG.map((e,i)=>`#${i+1} ${e.ev} ${e.h.slice(0,12)}...`).join("\n")||"No events yet."}
$("lv").onclick=async()=>{let p="0".repeat(64);for(let i=0;i<LOG.length;i++){const e=LOG[i];if(e.prev!==p||await hx(p+e.ev+e.t)!==e.h){$("lst").textContent="Chain broken at entry "+(i+1)+". Tampering detected.";return}p=e.h}$("lst").textContent="Chain intact ("+LOG.length+" entries)."};
$("lt").onclick=()=>{if(LOG[1]){LOG[1].ev="edited";draw();$("lst").textContent="Entry 2 edited. Press Verify."}else $("lst").textContent="Create at least 2 events first (encrypt, decrypt or passkey)."};
audit("session started");audit("vault unlocked (demo)");
if("serviceWorker" in navigator&&location.protocol.startsWith("http"))navigator.serviceWorker.register("sw.js").catch(()=>{});
