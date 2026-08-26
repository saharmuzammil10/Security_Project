"""
loader.py
---------
Reads raw documents from the `documents/` folder and turns them into a
uniform list of {"source": str, "text": str, "doc_type": str} dicts,
ready to be handed to the chunker.

Supports:
  - .txt / .md          -> read as plain text
  - .pdf                -> extract text with pypdf
  - MITRE ATT&CK STIX json (enterprise-attack.json) -> pulls out each
    technique's name + description as its own "document"
  - CISA KEV / generic CVE json -> pulls out each CVE's id + description
    as its own "document"
  - any other .json      -> falls back to dumping key/value text
"""

import json
import os
from pathlib import Path
from typing import List, Dict


def load_txt(path: Path) -> List[Dict]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [{"source": path.name, "text": text, "doc_type": "text"}]


def load_pdf(path: Path) -> List[Dict]:
    from pypdf import PdfReader  # pip install pypdf

    reader = PdfReader(str(path))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    return [{"source": path.name, "text": text, "doc_type": "pdf"}]


def load_mitre_attack_json(path: Path) -> List[Dict]:
    """
    Parses MITRE ATT&CK STIX bundle (enterprise-attack.json).
    Each 'attack-pattern' object is one technique. We turn each technique
    into its own mini-document: name + description + associated tactics.
    """
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    docs = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        name = obj.get("name", "Unnamed technique")
        description = obj.get("description", "")

        # external_references usually contains the technique ID (e.g. T1059)
        technique_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break

        # kill_chain_phases give us the tactic names (e.g. "execution")
        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
        ]

        text = (
            f"Technique ID: {technique_id}\n"
            f"Name: {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"Description: {description}"
        )

        docs.append({
            "source": f"mitre_attack::{technique_id or name}",
            "text": text,
            "doc_type": "mitre_attack_technique",
        })

    return docs


def load_cve_json(path: Path) -> List[Dict]:
    """
    Handles two common shapes:
      1. CISA KEV catalog: {"vulnerabilities": [ {...}, {...} ]}
      2. A single CVE record (CVE Program v5 schema) with
         containers.cna.descriptions[].value
    Falls back gracefully if the shape doesn't match either.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = []

    # Case 1: CISA KEV catalog (a list of vulnerabilities in one file)
    if isinstance(data, dict) and "vulnerabilities" in data:
        for vuln in data["vulnerabilities"]:
            cve_id = vuln.get("cveID", "UNKNOWN-CVE")
            text = (
                f"CVE ID: {cve_id}\n"
                f"Vendor/Project: {vuln.get('vendorProject', '')}\n"
                f"Product: {vuln.get('product', '')}\n"
                f"Vulnerability Name: {vuln.get('vulnerabilityName', '')}\n"
                f"Description: {vuln.get('shortDescription', '')}\n"
                f"Required Action: {vuln.get('requiredAction', '')}"
            )
            docs.append({
                "source": f"cve::{cve_id}",
                "text": text,
                "doc_type": "cve",
            })
        return docs

    # Case 2: single CVE record (CVE Program v5 format)
    cve_id = data.get("cveMetadata", {}).get("cveId", path.stem)
    try:
        descriptions = data["containers"]["cna"]["descriptions"]
        description_text = " ".join(d.get("value", "") for d in descriptions)
    except (KeyError, TypeError):
        description_text = json.dumps(data)[:2000]  # fallback, truncated

    docs.append({
        "source": f"cve::{cve_id}",
        "text": f"CVE ID: {cve_id}\nDescription: {description_text}",
        "doc_type": "cve",
    })
    return docs


def load_json(path: Path) -> List[Dict]:
    """
    Dispatches to the right JSON parser based on the file's actual
    CONTENT/structure, not its filename. This matters for security:
    an attacker planting a poisoned document has no reason to name it
    helpfully (e.g. including "cve" in the filename) -- if anything
    they'd avoid it specifically to dodge naive filename-based routing.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Shape 1: CISA KEV-style catalog -- {"vulnerabilities": [...]}
    if isinstance(data, dict) and "vulnerabilities" in data:
        try:
            return load_cve_json(path)
        except Exception:
            pass

    # Shape 2: single CVE record (CVE Program v5 schema) -- has cveMetadata
    if isinstance(data, dict) and "cveMetadata" in data:
        try:
            return load_cve_json(path)
        except Exception:
            pass

    # Shape 3: MITRE ATT&CK STIX bundle -- has a top-level "objects" list
    # containing "type": "attack-pattern" entries
    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        try:
            return load_mitre_attack_json(path)
        except Exception:
            pass

    # Generic fallback: just stringify the JSON
    return [{
        "source": path.name,
        "text": json.dumps(data, indent=2)[:5000],
        "doc_type": "json_generic",
    }]


LOADERS = {
    ".txt": load_txt,
    ".md": load_txt,
    ".pdf": load_pdf,
    ".json": load_json,
}


def load_documents(folder: str = "documents") -> List[Dict]:
    """
    Walks the given folder and loads every supported file into a flat
    list of document dicts.
    """
    folder_path = Path(folder)
    if not folder_path.exists():
        raise FileNotFoundError(f"Folder not found: {folder_path.resolve()}")

    all_docs = []
    for file_path in sorted(folder_path.rglob("*")):
        if not file_path.is_file():
            continue
        loader_fn = LOADERS.get(file_path.suffix.lower())
        if loader_fn is None:
            continue  # skip unsupported file types silently
        try:
            docs = loader_fn(file_path)
            all_docs.extend(docs)
        except Exception as e:
            print(f"[loader] Failed to load {file_path.name}: {e}")

    return all_docs


if __name__ == "__main__":
    docs = load_documents("documents")
    print(f"Loaded {len(docs)} documents.")
    for d in docs[:3]:
        print("-" * 40)
        print(d["source"], "|", d["doc_type"])
        print(d["text"][:300])