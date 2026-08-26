"""
ingestion_guard.py
-------------------
Agentic idea B: a guard that runs at INGESTION time, not query time.

Every existing defense so far (firewall, sanitizer) runs when a document
is RETRIEVED for a question. That leaves a gap: a poisoned document can
sit safely in your vector store from the moment it's embedded until some
query happens to retrieve it -- unnoticed the whole time.

This script closes that gap: it scans every file in documents/ BEFORE
preprocess.py/embed_and_store.py ever touch it, runs each one through
the firewall's classifier, and moves anything flagged malicious into
documents/quarantine/ -- so it never gets chunked or embedded at all.

Granularity note: this checks at the FILE level. If a single JSON file
contains multiple records (e.g. a KEV catalog with many CVEs) and only
one record is malicious, the whole file is quarantined. For this
project's data (mostly one-record-per-file test payloads) that's fine;
a production version would quarantine individual records instead.

"""

import argparse
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone
try:
    from loader import LOADERS
    from firewall import DocumentFirewall
except ImportError:
    from src.loader import LOADERS
    from src.firewall import DocumentFirewall

DOCUMENTS_DIR = Path("documents")
QUARANTINE_DIR = DOCUMENTS_DIR / "quarantine"
LOG_PATH = Path("data/ingestion_log.jsonl")

# Files that expand into MORE than this many individual records are
# treated as bulk reference datasets (e.g. the full MITRE ATT&CK catalog
# -> 858 separate technique records) rather than individually-planted
# documents. Scanning every record in a file like that means hundreds of
# sequential LLM calls -- for a trusted, unmodified download straight
# from MITRE's official repo, that's not a useful use of the firewall.
# Use --force-full-scan to override this and scan everything anyway.
BULK_FILE_RECORD_THRESHOLD = 20


def scan_and_quarantine(backend: str = "ollama", model: str = None, force_full_scan: bool = False):
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    fw = DocumentFirewall(backend=backend, model=model)
    log_entries = []

    files = [f for f in sorted(DOCUMENTS_DIR.glob("*")) if f.is_file()]
    print(f"Scanning {len(files)} file(s) in {DOCUMENTS_DIR}/ before ingestion...\n")

    for file_path in files:
        loader_fn = LOADERS.get(file_path.suffix.lower())
        if loader_fn is None:
            continue  # unsupported type, preprocess.py will skip it too

        try:
            docs = loader_fn(file_path)
        except Exception as e:
            print(f"[ingestion_guard] Failed to load {file_path.name}: {e}")
            continue

        if len(docs) > BULK_FILE_RECORD_THRESHOLD and not force_full_scan:
            print(f"[skipped] {file_path.name} -- {len(docs)} records, treated as a "
                  f"bulk reference dataset (use --force-full-scan to scan every record)")
            log_entries.append({
                "file": file_path.name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "quarantined": False,
                "skipped_bulk": True,
                "record_count": len(docs),
                "reasons": [],
            })
            continue

        file_flagged = False
        reasons = []
        for i, doc in enumerate(docs):
            print(f"  scanning {file_path.name}: record {i + 1}/{len(docs)}...", end="\r")
            result = fw.inspect_chunk(doc["text"])
            if result["verdict"] == "MALICIOUS":
                file_flagged = True
                reasons.append({"source": doc["source"], "reason": result["reason"]})
        print(" " * 80, end="\r")  # clear the progress line

        entry = {
            "file": file_path.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "quarantined": file_flagged,
            "skipped_bulk": False,
            "record_count": len(docs),
            "reasons": reasons,
        }
        log_entries.append(entry)

        if file_flagged:
            dest = QUARANTINE_DIR / file_path.name
            shutil.move(str(file_path), str(dest))
            print(f"[QUARANTINED] {file_path.name}")
            for r in reasons:
                print(f"    {r['source']}: {r['reason']}")
        else:
            print(f"[ok] {file_path.name} ({len(docs)} record(s) scanned)")

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        for entry in log_entries:
            f.write(json.dumps(entry) + "\n")

    quarantined_count = sum(1 for e in log_entries if e["quarantined"])
    skipped_count = sum(1 for e in log_entries if e.get("skipped_bulk"))
    print(f"\nDone. {quarantined_count}/{len(log_entries)} file(s) quarantined, "
          f"{skipped_count} bulk file(s) skipped.")
    print(f"Log appended to {LOG_PATH.resolve()}")
    return log_entries


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan documents/ and quarantine malicious files before ingestion.")
    parser.add_argument("--backend", type=str, default="ollama", choices=["ollama", "claude"])
    parser.add_argument("--model", type=str, default=None)
    parser.add_argument("--force-full-scan", action="store_true",
                         help="Scan every record in bulk files too (e.g. all 858 MITRE ATT&CK techniques). Slow.")
    args = parser.parse_args()

    scan_and_quarantine(backend=args.backend, model=args.model, force_full_scan=args.force_full_scan)