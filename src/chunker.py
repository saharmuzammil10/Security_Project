"""
chunker.py
----------
Cleans document text and splits it into overlapping chunks suitable for
embedding + retrieval. No external NLP dependencies -- deliberately simple
so it's easy to see exactly what's happening to the text (important for
a security project where you want full visibility into your pipeline).
"""

import re
from typing import List, Dict


def clean_text(text: str) -> str:
    """
    Basic normalization:
      - collapse excess whitespace/newlines
      - strip control characters
      - trim leading/trailing whitespace
    Note: this is NOT a security defense by itself. Prompt-injection
    sanitization (stripping instruction-like phrases) happens later,
    as a separate explicit step -- keeping "cleaning" and "security
    filtering" separate makes each easier to reason about and test.
    """
    # Remove non-printable/control characters (keep newlines and tabs)
    text = re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", "", text)
    # Collapse 3+ newlines down to 2 (paragraph break)
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Collapse repeated spaces/tabs
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def split_into_sentences(text: str) -> List[str]:
    """
    Very lightweight sentence splitter (splits on '.', '?', '!' followed
    by whitespace). Good enough for chunking purposes -- doesn't need to
    be perfect, just needs to avoid cutting words in half.
    """
    sentences = re.split(r"(?<=[.?!])\s+", text)
    return [s.strip() for s in sentences if s.strip()]


def chunk_text(
    text: str,
    max_chunk_chars: int = 1000,
    overlap_chars: int = 150,
) -> List[str]:
    """
    Splits text into chunks up to `max_chunk_chars` long, using sentence
    boundaries so we don't cut sentences in half. Adds `overlap_chars`
    of overlap between consecutive chunks so context isn't lost at the
    boundary (important for retrieval quality).
    """
    sentences = split_into_sentences(text)
    chunks = []
    current = ""

    for sentence in sentences:
        # If adding this sentence would blow past the limit, close the
        # current chunk out and start a new one (carrying over overlap).
        if current and len(current) + len(sentence) + 1 > max_chunk_chars:
            chunks.append(current.strip())
            # carry the tail of the previous chunk forward as overlap
            overlap = current[-overlap_chars:] if overlap_chars else ""
            current = overlap + " " + sentence
        else:
            current = (current + " " + sentence).strip()

    if current.strip():
        chunks.append(current.strip())

    return chunks


def chunk_documents(
    documents: List[Dict],
    max_chunk_chars: int = 1000,
    overlap_chars: int = 150,
) -> List[Dict]:
    """
    Takes the list of {"source", "text", "doc_type"} dicts from loader.py
    and returns a flat list of chunk dicts:
        {
          "chunk_id": "source::0",
          "source": "...",
          "doc_type": "...",
          "text": "...",
        }
    """
    all_chunks = []
    for doc in documents:
        cleaned = clean_text(doc["text"])
        if not cleaned:
            continue

        pieces = chunk_text(cleaned, max_chunk_chars, overlap_chars)
        for i, piece in enumerate(pieces):
            all_chunks.append({
                "chunk_id": f"{doc['source']}::{i}",
                "source": doc["source"],
                "doc_type": doc.get("doc_type", "unknown"),
                "text": piece,
            })

    return all_chunks


if __name__ == "__main__":
    sample = (
        "Technique ID: T1059\nName: Command and Scripting Interpreter\n"
        "Description: " + ("Adversaries may abuse command and script interpreters. " * 40)
    )
    chunks = chunk_text(sample, max_chunk_chars=500, overlap_chars=80)
    for i, c in enumerate(chunks):
        print(f"--- chunk {i} ({len(c)} chars) ---")
        print(c[:150], "...\n")