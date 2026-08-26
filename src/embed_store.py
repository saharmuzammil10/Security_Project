"""
embed_and_store.py
-------------------
Reads data/chunks.jsonl, generates embeddings locally (no API calls,
no data leaves your machine), and stores them in a local Chroma vector
database at data/chroma_db/.

Run once after preprocess.py, and again any time your documents/chunks
change:
    python src/embed_and_store.py

Model used: all-MiniLM-L6-v2 (sentence-transformers) -- small (~80MB),
fast on CPU, a standard baseline for RAG projects. Swap EMBED_MODEL_NAME
below if you want a different tradeoff of speed vs. quality later.
"""

import json
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
CHUNKS_PATH = "data/chunks.jsonl"
CHROMA_DB_PATH = "data/chroma_db"
COLLECTION_NAME = "security_docs"
BATCH_SIZE = 64  # how many chunks to embed at once


def load_chunks(path: str):
    chunks = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                chunks.append(json.loads(line))
    return chunks


def run():
    chunks = load_chunks(CHUNKS_PATH)
    print(f"Loaded {len(chunks)} chunks from {CHUNKS_PATH}")
    if not chunks:
        print("No chunks found -- run preprocess.py first.")
        return

    print(f"Loading local embedding model '{EMBED_MODEL_NAME}' "
          f"(first run downloads it, ~80MB)...")
    model = SentenceTransformer(EMBED_MODEL_NAME)

    print(f"Connecting to local Chroma DB at '{CHROMA_DB_PATH}'...")
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)

    # Fresh start each run -- delete + recreate collection so re-running
    # this script doesn't create duplicate entries.
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass  # collection didn't exist yet, that's fine
    collection = client.create_collection(COLLECTION_NAME)

    print(f"Embedding {len(chunks)} chunks in batches of {BATCH_SIZE}...")
    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i:i + BATCH_SIZE]
        texts = [c["text"] for c in batch]
        ids = [c["chunk_id"] for c in batch]
        metadatas = [
            {"source": c["source"], "doc_type": c.get("doc_type", "unknown")}
            for c in batch
        ]

        embeddings = model.encode(texts, show_progress_bar=False).tolist()

        collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=texts,
            metadatas=metadatas,
        )
        print(f"  Embedded {min(i + BATCH_SIZE, len(chunks))}/{len(chunks)}")

    print(f"\nDone. {collection.count()} chunks stored in Chroma "
          f"collection '{COLLECTION_NAME}' at {Path(CHROMA_DB_PATH).resolve()}")


if __name__ == "__main__":
    run()