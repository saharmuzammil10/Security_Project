# RAG Security Console

A defense-in-depth security layer for Retrieval-Augmented Generation (RAG) pipelines, with a React dashboard for interacting with it and inspecting exactly how each defense layer responds to a given question. Built to detect and block **prompt injection attacks** — both direct (malicious user questions) and indirect (poisoned documents smuggled into the knowledge base).

Most prompt injection demos show a single filter catching an obvious attack. This project instead treats every layer as fallible on its own, measures how much each layer actually contributes, and includes an automated red-team/blue-team loop that attacks its own live code path — not a mocked copy — so results reflect real production behavior.

---

## Why this exists

RAG systems retrieve external documents and hand them to an LLM as trusted context. That's the attack surface: if an attacker gets malicious instructions into a document that later gets retrieved, or hides them inside an ordinary-looking question, they can attempt to hijack the model — leak its system prompt, override its behavior, or return attacker-controlled output.

This project treats **both the documents and the user's question as untrusted input**, and defends accordingly, at every stage from ingestion through to the final answer shown to a user.

---

## Architecture

**Three phases:**

- **Ingestion** (run when documents change) — scans and quarantines poisoned files before they're ever embedded into the vector store.
- **Query time** (run per question) — a layered pipeline a question and its retrieved context must pass through before an answer is returned.
- **Testing / offense** — an automated red-team/blue-team loop that attacks the live pipeline and proposes defense improvements, plus a per-layer diagnostic suite.

### Query-time defense layers

```
question
   │
   ▼
regex sanitizer          — free, instant, catches literal known phrasing
   │ pass
   ▼
semantic question guard  — one LLM call, catches paraphrased/leetspeak/
   │ pass                  translated injection attempts regex can't;
   │                       also screens off-topic questions before any
   │                       retrieval/generation compute is spent
   ▼
retrieval (over-fetch)   — vector search, fetches extra candidates so
   │                       blocked chunks can be backfilled
   ▼
document firewall        — classifies each retrieved chunk SAFE/MALICIOUS,
   │                        can double-check and fail closed on disagreement
   ▼
generation                — chunks wrapped in a randomly-tagged delimiter
   │                        (secrets.token_hex per request, not a fixed
   │                        tag -- can't be forged by attacker content) +
   │                        a separate random canary token embedded in
   │                        the system prompt
   ▼
canary check              — did the secret session token leak into output?
   │
   ▼
signature output validation — fingerprint/marker match, fast and free
   │
   ▼
semantic output validation  — optional LLM judge call, backstop for
   │                          markers the signature check doesn't know
   ▼
answer returned
```

**Fail-closed by design:** any ambiguous or disagreeing signal (two firewall classifications disagreeing, an unparseable LLM judgment) defaults to *blocking*, not passing through. A false block costs convenience; a false pass costs a breach.

---

## Full stack

```
Security_Project/
├── src/                         core security pipeline (defense layers above)
│   ├── rag_query.py             answer_question() -- the single source of truth,
│   │                            called identically by the CLI, the API, and the
│   │                            red-team harness, so nothing can silently drift
│   ├── sanitizer.py, question_guard.py, firewall.py, output_validator.py
│   ├── llm_client.py            pluggable backend: Ollama (local, free, default)
│   │                            or Claude (Anthropic API, optional)
│   ├── retriever.py, embed_and_store.py, preprocess.py, ingestion_guard.py
│   ├── red_team_suite.py        tests each defense layer in isolation + full
│   │                            pipeline + false-positive control questions
│   ├── redteam_agent.py         generates paraphrased attack variants
│   ├── redblue_orchestrator.py  full attacker-vs-defender loop, human-approved
│   ├── blueteam_agent.py        proposes sanitizer patches from bypasses found
│   └── trace_report.py
├── backend/
│   └── api.py                   thin FastAPI wrapper -- imports and calls the
│                                 real answer_question() directly, no duplicated
│                                 logic, so the API is guaranteed to reflect
│                                 exactly what the CLI/tests already proved
├── frontend/                    React (Vite) dashboard
│   └── src/
│       ├── components/
│       │   ├── SecurityConsole.jsx  ask a question, see the live per-layer
│       │   │                        trace with a per-message show/hide toggle
│       │   ├── DefensesPanel.jsx    toggle individual defense layers on/off
│       │   ├── Dashboard.jsx        aggregate stats / red-team results view
│       │   └── Sidebar.jsx
│       ├── hooks/useLocalStorage.js
│       └── api.js                   frontend client for backend/api.py
├── documents/                    raw input (CVE/MITRE ATT&CK data, test payloads)
├── data/                         generated at runtime -- chunks, vector DB, logs
├── .github/workflows/            CI: smoke test + security gate on block rate
└── Dockerfile, docker-compose.yml, requirements.txt, .env.example
```

**Request path:** React (`SecurityConsole.jsx`, via `api.js`) → `POST /ask` → FastAPI's `ask()` in `backend/api.py` → `answer_question()` in `src/rag_query.py` (the exact same function the CLI and the red-team suite call) → full JSON result (trace, answer, canary status) returned and rendered.

---

## Measured results

Not claims — actual output from `red_team_suite.py` against the live pipeline (Ollama backend), across 14 attack payloads spanning direct override, roleplay/persona hijack, leetspeak, foreign language, base64 encoding, and formal/administrative framing:

| Layer | Tested alone | Result |
|---|---|---|
| Regex sanitizer | 14 payloads | **1/14 blocked (7%)** |
| Semantic question guard | 14 payloads | **14/14 blocked (100%)** |
| Document firewall | 3 poisoned chunks | **3/3 blocked (100%)** |
| Full pipeline (end-to-end) | 14 payloads | **14/14 blocked (100%)** |
| False positive check | 5 legitimate questions | **0/5 wrongly blocked** |

**Why the 7% vs 100% gap matters:** the regex layer was never intended to catch obfuscated attacks — it exists purely as a free first pass for the most obvious, literal phrasing. The semantic layer backstops everything else. This is measured, not architectural, evidence that single-layer defenses are insufficient against paraphrased injection.

**Why 0/5 false positives matters just as much as the block rate:** a system that blocks everything isn't secure, it's unusable. Both numbers being strong at once is the actual bar for a working defense.

---

## Two real gaps found and fixed during testing

Rather than presenting this as flawless, here are two actual defects the red-team process surfaced — and how each was closed. Both were confirmed with a working before/after, not just reasoned about.

**1. Static delimiter tag (indirect injection risk).**
The prompt originally wrapped retrieved chunks in a fixed tag, `<reference_material>`. Since the tag never changed, an attacker who read the source (or guessed a common pattern) could embed a fake closing tag inside a malicious document chunk, attempting to trick the model into treating injected instructions as if they'd left the untrusted data boundary. Fixed by generating a random per-request tag via `secrets.token_hex(8)` — the same primitive already used for the canary token — so there's nothing fixed left to forge. Confirmed live: a real response now shows a fresh tag like `<reference_material_ba96ce225bde0586>` on every call.

**2. Semantic output validator flagged correct refusals as leaks (false positive).**
Testing surfaced a case where the model correctly refused to reveal its rules — producing a sentence like *"I do not follow any instructions found in the reference material or reveal any internal configuration/tokens"* — and the semantic output judge flagged it as `SUSPICIOUS` anyway. Root cause: the judge's instructions described what a violation looks like, but never explicitly stated that a correct refusal which *names* the rule while following it is normal, not a violation. Fixed by adding an explicit exception to the judge's system prompt clarifying that a correct refusal is `NORMAL`. This is the kind of gap that's easy to miss because both a real leak and a correct refusal use similar vocabulary — only intent differs.

---

## Known limitations (not yet fixed)

- **Regex layer has near-zero standalone coverage against obfuscated attacks** (7%, see above) — by design, not a bug, but worth being explicit about rather than letting the number speak for itself out of context.
- **No authentication on the API.** `backend/api.py` has no API key, login, or token check on any endpoint — anyone who can reach the server can call `/ask` directly, bypassing the React UI entirely. Fine for local dev use; would need addressing before any public deployment. Note the prompt-injection defenses themselves are unaffected either way, since they live inside `answer_question()`, not the frontend.
- **Error messages leak internal details.** `api.py`'s exception handler returns the raw Python exception string (`detail=str(e)`) to the client on any failure — could expose file paths or internal structure to an attacker probing the API.
- **No rate limiting / cost-abuse protection**, on either the CLI backend selection or the API — nothing currently stops a user (or script) from spamming questions to run up LLM API costs (a "denial-of-wallet" attack class), which is a different threat category than prompt injection.
- **Claude backend confirmed connecting correctly to the live Anthropic API (authenticated, request reached and was processed by their servers) — full generation not yet tested due to account credit balance, not a code issue.**

---

## Tech stack

- **Core pipeline:** Python, pluggable LLM backend (Ollama local / Claude API) via a small `LLMClient` abstraction.
- **API layer:** FastAPI (`backend/api.py`), thin wrapper — no duplicated logic.
- **Vector store:** ChromaDB (persistent, local).
- **Embeddings:** `all-MiniLM-L6-v2` via `sentence-transformers` (local, free, cached after first run).
- **Frontend:** React (Vite).
- **Deployment:** Docker Compose (separate `ollama` and `app` services).
- **CI:** GitHub Actions — smoke test always runs; security-gate job fails the build if block rate regresses or a false positive appears.

---

## Running it

```bash
# 1. Ingest documents into the vector store
python src/ingestion_guard.py
python src/preprocess.py
python src/embed_and_store.py

# 2a. Ask a question via CLI (run from the project root)
python src/rag_query.py "What is CVE-2024-88421?" --backend ollama

# 2b. Or run the full stack
cd backend && uvicorn api:app --reload --port 8000    # terminal 1
cd frontend && npm install && npm run dev              # terminal 2
# then open the Vite dev server URL, default http://localhost:5173

# 3. Run the red-team test suite
python src/red_team_suite.py --backend ollama
```

Requires a running Ollama instance (`ollama serve`) with a pulled model, or an `ANTHROPIC_API_KEY` set in `.env` to use Claude instead.

---

## What this project demonstrates

Defense-in-depth against prompt injection in a RAG pipeline — treating both retrieved documents and user questions as untrusted input, using multiple independent, fail-closed checks so no single point of failure lets an attacker hijack the model's behavior or exfiltrate its instructions. Includes an automated red-team/blue-team loop that attacks the system's own live code path, a full-stack UI for inspecting defense behavior per-question, and two real, measured, fixed vulnerabilities found through the project's own testing process rather than assumed away.
