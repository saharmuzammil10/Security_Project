"""
trace_report.py
-----------------
Builds a structured, step-by-step trace of what happened to a single
question as it moved through the pipeline: which checkpoint ran, what
it decided, and why. Instead of only seeing the final answer, you get
a full paper trail -- exactly what you'd want to show someone asking
"how do I know your defenses actually did anything?"

Also appends every trace to data/trace_log.jsonl, so you have a
persistent record across many questions over time -- useful for a
demo/writeup showing how many requests each defense actually touched.
"""

import json
from pathlib import Path
from datetime import datetime, timezone

TRACE_LOG_PATH = Path("data/trace_log.jsonl")

RESULT_MARKERS = {"pass": "  ->", "block": "  X ", "info": "  . ", "skip": "  o "}


def print_trace(trace: list):
    print("\n" + "=" * 64)
    print("DEFENSE TRACE")
    print("=" * 64)
    for step in trace:
        marker = RESULT_MARKERS.get(step["result"], "  ->")
        print(f"{marker}[{step['stage']}] {step['detail']}")
    print("=" * 64)


def save_trace(question: str, trace: list):
    TRACE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "trace": trace,
    }
    with open(TRACE_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def summarize_trace_log():
    """
    Reads the full trace_log.jsonl and prints aggregate stats: how many
    requests were blocked at each stage, over all logged questions.
    Handy once you've run a bunch of test queries and want the overall
    picture, not just one question's trace.
    """
    if not TRACE_LOG_PATH.exists():
        print("No trace log found yet -- run some queries first.")
        return

    total = 0
    blocked_by_stage = {}
    with open(TRACE_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            entry = json.loads(line)
            total += 1
            for step in entry["trace"]:
                if step["result"] == "block":
                    blocked_by_stage[step["stage"]] = blocked_by_stage.get(step["stage"], 0) + 1

    print(f"\n=== Trace log summary ({total} questions logged) ===")
    if not blocked_by_stage:
        print("No blocks recorded at any stage.")
    for stage, count in blocked_by_stage.items():
        print(f"  {stage}: blocked {count}/{total} question(s)")


if __name__ == "__main__":
    summarize_trace_log()