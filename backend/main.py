import os, json, time, collections, httpx
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import rag, cnn
GROQ_KEY = os.getenv("GROQ_API_KEY", ""); MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
app = FastAPI(title="QuantaVault API")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","), allow_methods=["*"], allow_headers=["*"])
rag.load(os.getenv("DOCS_DIR", "docs")); hits = collections.defaultdict(list)
@app.middleware("http")
async def limiter(req: Request, nxt):  # 30 requests/minute/IP
    ip = req.client.host; now = time.time(); hits[ip] = [t for t in hits[ip] if now-t < 60]
    if len(hits[ip]) >= 30: raise HTTPException(429, "Rate limit")
    hits[ip].append(now); return await nxt(req)
class Chat(BaseModel): message: str
TOOLS = [{"type":"function","function":{"name":"search_docs","description":"Search security docs","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}}]
@app.get("/health")
def health(): return {"ok": True, "docs": len(rag.DOCS)}
@app.get("/rag")
def rag_q(q: str): return rag.search(q)
@app.post("/scan")
async def scan(file: UploadFile = File(...)): return cnn.scan(await file.read(1_000_000))
@app.post("/chat")  # agent loop: plan -> tool call -> answer
async def chat(c: Chat):
    if not GROQ_KEY: raise HTTPException(500, "Set GROQ_API_KEY")
    msgs = [{"role":"system","content":"You are VaultMind for QuantaVault. Use search_docs for product facts."},{"role":"user","content":c.message}]
    async with httpx.AsyncClient(timeout=30) as h:
        for _ in range(4):
            r = await h.post("https://api.groq.com/openai/v1/chat/completions", headers={"Authorization": f"Bearer {GROQ_KEY}"}, json={"model": MODEL, "messages": msgs, "tools": TOOLS})
            r.raise_for_status(); m = r.json()["choices"][0]["message"]; msgs.append(m)
            if not m.get("tool_calls"): return {"answer": m["content"]}
            for t in m["tool_calls"]:
                q = json.loads(t["function"]["arguments"]).get("query", "")
                msgs.append({"role":"tool","tool_call_id":t["id"],"content":json.dumps(rag.search(q))})
    return {"answer": "Could not finish in 4 steps."}
