"""
preprocess.py
-------------
Ties loader.py + chunker.py together:
  1. Load every document from documents/
  2. Clean + chunk them
  3. Save the chunks to data/chunks.jsonl (one JSON object per line)

Run it with:
    python src/preprocess.py

Next step after this (not included yet) will be embedding these chunks
into a vector store like Chroma.
"""

import json
from pathlib import Path

from loader import load_documents
from chunker import chunk_documents


def run(
    documents_folder: str = "documents",
    output_path: str = "data/chunks.jsonl",
    max_chunk_chars: int = 1000,
    overlap_chars: int = 150,
):
    print(f"Loading documents from '{documents_folder}'...")
    docs = load_documents(documents_folder)
    print(f"  Loaded {len(docs)} raw documents.")

    if not docs:
        print("No documents found. Add files to the documents/ folder first.")
        return

    print("Cleaning + chunking...")
    chunks = chunk_documents(docs, max_chunk_chars, overlap_chars)
    print(f"  Produced {len(chunks)} chunks.")

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(chunk) + "\n")

    print(f"Saved chunks to {out_path.resolve()}")

    # quick sanity check preview
    print("\nSample chunk:")
    print(json.dumps(chunks[0], indent=2)[:500])


if __name__ == "__main__":
    run()