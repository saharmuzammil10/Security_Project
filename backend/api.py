"""
api.py
------
Thin REST wrapper around the existing pipeline (rag_query.py etc).
None of the actual security logic changes, this just exposes
answer_question() and the trace/red-team logs over HTTP so a separate
React frontend can call them, instead of importing Python functions
directly the way streamlit_app.py did.

Run:
    cd backend
    uvicorn api:app --reload --port 8000

CORS is open to the Vite dev server's default port (5173). Tighten this
before deploying anywhere real.
"""

import json
import sys
from pathlib import Path
import os

# Forcing Python to look at the 'src' directory for imports
SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.rag_query import answer_question
from src.trace_report import TRACE_LOG_PATH  
from src.red_team_suite import REPORT_PATH as RED_TEAM_REPORT_PATH 

app = FastAPI(title="RAG Security Console API")

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AskRequest(BaseModel):
    question: str
    backend: str = "ollama"
    model: str | None = None
    k: int = 5
    question_sanitize: bool = True
    question_semantic_check: bool = True
    firewall: bool = True
    validate: bool = True
    validate_semantic: bool = False


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ask")
def ask(req: AskRequest):
    try:
        result = answer_question(
            req.question,
            backend=req.backend,
            k=req.k,
            model=req.model,
            question_sanitize=req.question_sanitize,
            question_semantic_check=req.question_semantic_check,
            firewall=req.firewall,
            validate=req.validate,
            validate_semantic=req.validate_semantic,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard/trace-summary")
def trace_summary():
    if not TRACE_LOG_PATH.exists():
        return {"total": 0, "blocked_by_stage": {}}

    total = 0
    blocked_by_stage = {}
    with open(TRACE_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            entry = json.loads(line)
            total += 1
            for step in entry["trace"]:
                if step["result"] == "block":
                    blocked_by_stage[step["stage"]] = blocked_by_stage.get(step["stage"], 0) + 1

    return {"total": total, "blocked_by_stage": blocked_by_stage}


@app.get("/dashboard/red-team-summary")
def red_team_summary():
    if not RED_TEAM_REPORT_PATH.exists():
        return {"runs": 0, "latest": None}

    with open(RED_TEAM_REPORT_PATH, "r", encoding="utf-8") as f:
        runs = [json.loads(line) for line in f]

    latest = runs[-1] if runs else None
    layer_summaries = {}
    if latest:
        for layer_name, results in latest["results"].items():
            if results and "blocked" in results[0]:
                total = len(results)
                blocked = sum(1 for r in results if r.get("blocked"))
                layer_summaries[layer_name] = {"total": total, "blocked": blocked}

    return {
        "runs": len(runs),
        "latest_timestamp": latest["timestamp"] if latest else None,
        "layer_summaries": layer_summaries,
    }