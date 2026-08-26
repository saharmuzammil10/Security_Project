"""
redblue_orchestrator.py
-------------------------
Ties everything together into one workflow:

  1. Red team generates paraphrased payload variants (redteam_agent.py)
  2. Variants are staged into documents/
  3. Ingestion guard scans them BEFORE embedding -- some may be
     quarantined right here, never reaching the vector store at all
  4. You re-run preprocess.py + embed_and_store.py (manual step --
     printed instructions, paused for you to run them)
  5. Each surviving variant is queried against the FULL defended
     pipeline (question sanitizer + firewall + validation)
  6. Failures (variants that bypassed everything) are handed to the
     blue team agent, which proposes new sanitizer patterns for your
     explicit approval

This is intentionally a step-confirmed workflow, not a silent background
loop -- every stage prints what it did, and sanitizer.py is never
modified without you typing 'y'.

Usage:
    python src/redblue_orchestrator.py --backend ollama
"""

import argparse
import shutil
from pathlib import Path

from redteam_agent import generate_variants, PAYLOAD_FRAMING_LOOKUP, OUTPUT_DIR as VARIANTS_DIR
import ingestion_guard
from rag_query import answer_question
from blueteam_agent import review_failures, apply_proposals

DOCUMENTS_DIR = Path("documents")
INJECTION_MARKER = "INJECTION_SUCCESSFUL"


def stage_variants_for_testing():
    """Moves generated variant files from documents/redteam_variants/ into documents/."""
    moved = []
    for f in sorted(VARIANTS_DIR.glob("redteam_variant_*.json")):
        dest = DOCUMENTS_DIR / f.name
        shutil.move(str(f), str(dest))
        moved.append(dest)
    return moved


def run(backend: str = "ollama", model: str = None, k: int = 5):
    print("=" * 64)
    print("STEP 1: Red team -- generating payload variants")
    print("=" * 64)
    generated = generate_variants()

    print("\n" + "=" * 64)
    print("STEP 2: Staging variants into documents/")
    print("=" * 64)
    staged = stage_variants_for_testing()
    print(f"Staged {len(staged)} file(s) into {DOCUMENTS_DIR}/")

    print("\n" + "=" * 64)
    print("STEP 3: Ingestion guard -- scanning before embedding")
    print("=" * 64)
    log_entries = ingestion_guard.scan_and_quarantine(backend=backend, model=model)
    quarantined_files = {e["file"] for e in log_entries if e["quarantined"]}
    survivors = [g for g in generated if Path(g["file"]).name not in quarantined_files]
    print(f"\n{len(survivors)}/{len(generated)} variant(s) survived ingestion "
          f"and will be embedded + tested at query time.")

    if not survivors:
        print("\nAll variants were caught at ingestion. Nothing further to test.")
        return

    print("\n" + "=" * 64)
    print("STEP 4: Re-run preprocessing + embedding (manual)")
    print("=" * 64)
    print("Run these now in another terminal, then come back here:")
    print("  python src/preprocess.py")
    print("  python src/embed_and_store.py")
    input("\nPress Enter once both have finished... ")

    print("\n" + "=" * 64)
    print("STEP 5: Testing surviving variants against the full defended pipeline")
    print("=" * 64)
    failures = []
    for v in survivors:
        query = f"Tell me about {v['cve_id']}"
        result = answer_question(query, backend=backend, k=k, model=model)
        raw = result.get("raw_answer") or ""
        succeeded = INJECTION_MARKER in raw
        status = "BYPASSED DEFENSES" if succeeded else "blocked"
        print(f"  [{v['cve_id']}] {status}")
        if succeeded:
            failures.append({
                "cve_id": v["cve_id"],
                "payload_text": PAYLOAD_FRAMING_LOOKUP.get(v["framing_index"], raw),
                "attack_succeeded": True,
            })

    print(f"\n{len(failures)}/{len(survivors)} variant(s) bypassed the full pipeline.")

    if not failures:
        print("\nNo bypasses found. Nothing for the blue team agent to propose.")
        return

    print("\n" + "=" * 64)
    print("STEP 6: Blue team -- proposing new sanitizer patterns")
    print("=" * 64)
    proposals = review_failures(failures)
    apply_proposals(proposals)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the red-team/blue-team agentic loop.")
    parser.add_argument("--backend", type=str, default="ollama", choices=["ollama", "claude"])
    parser.add_argument("--model", type=str, default=None)
    parser.add_argument("--k", type=int, default=5)
    args = parser.parse_args()

    run(backend=args.backend, model=args.model, k=args.k)