# QuantaVault
Post-quantum-ready private data vault with an agentic AI assistant (Groq), RAG, a CNN file inspector and Docker.
**Designed & developed by NIKHIL CHARY SRIRAMOJU** · [GitHub](https://github.com/Nikhil-creat) · [LinkedIn](https://in.linkedin.com/in/nikhil-chary-sriramoju-95041b38a)

## Run locally
- Frontend only: open `index.html` (use a local server such as `python -m http.server` for WebCrypto).
- Full stack: `cp .env.example .env`, add your free Groq key from console.groq.com, then `docker compose up --build`. Site: http://localhost:8080, API docs: http://localhost:8000/docs

## Deploy to GitHub Pages
1. Create a new public repo named `quantavault` on github.com.
2. In this folder run: `git init && git add . && git commit -m "QuantaVault" && git branch -M main && git remote add origin https://github.com/Nikhil-creat/quantavault.git && git push -u origin main`
3. Repo Settings > Pages > Source: **GitHub Actions**. The included workflow deploys on every push.
4. Your site goes live at https://nikhil-creat.github.io/quantavault/ in about a minute.

## Features
Client-side AES-256-GCM text and file encryption (.qvault), passkey demo, hash-chained audit log, VaultMind agent (Groq tool-calling), RAG, CNN file inspector, installable PWA with offline cache, strict Content-Security-Policy, Docker backend. See SECURITY.md for honest limits.

## Notes
- Pages hosts only the static site. The chatbot calls Groq straight from the browser with the key each visitor pastes (kept in their localStorage). Never commit your own key.
- The FastAPI backend (RAG, CNN, server-side agent) needs a host that runs Docker, such as Render or Fly.io free tiers.
- The PyTorch CNN ships untrained; the entropy heuristic works out of the box. Train on labelled files and load the weights in `backend/cnn.py`.
