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

## v3 additions
Unlockable encrypted library (files and notes stored encrypted in IndexedDB, names encrypted too), passkey second factor, auto-lock, encrypted backup/restore, quick-action bar, keyboard shortcuts (/ and L), passphrase generator, Groq key test with clear errors, retries and timeouts, offline indicator, FAQ.

## v5 additions
Files are now encrypted the moment you pick them (progress and clear errors), camera capture, drag and drop, persistent-storage request, shortcut buttons explain when the vault is locked. New "Quanta" personal assistant (date/time, calculator, timers, encrypted to-do list and notes, voice in/out) beside VaultMind.

## v6
Encrypted backup now includes your to-do list (tasks) as well as files. Restoring keeps tasks already on the device if any exist.

## v7
Change passphrase (atomic re-encryption of files, names and tasks), persistent unlock lockout, strength meter, lock-when-backgrounded, storage usage, clipboard auto-clear, CI workflow and backend unit tests.

## v8: AI + privacy
Sensitive-data masking before any text goes to the AI (cards via Luhn, ID numbers, phones, emails, PAN, passwords, API keys), a visible "last request" ledger, assistant tools search_vault (local RAG over your own notes, off by default) and security_report, consent-gated AI summaries, a security score, Groq key stored encrypted inside the vault, AI chat wiped on lock, privacy blur when the app is backgrounded, stricter CSP and no-referrer.

## Roadmap (not built yet)
Hybrid ML-KEM + X25519 key exchange, server-side passkey verification, multi-device encrypted sync, a trained CNN model.

## Notes
- Pages hosts only the static site. The chatbot calls Groq straight from the browser with the key each visitor pastes (kept in their localStorage). Never commit your own key.
- The FastAPI backend (RAG, CNN, server-side agent) needs a host that runs Docker, such as Render or Fly.io free tiers.
- The PyTorch CNN ships untrained; the entropy heuristic works out of the box. Train on labelled files and load the weights in `backend/cnn.py`.
