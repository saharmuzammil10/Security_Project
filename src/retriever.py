"""
retriever.py
------------
Given a user query, embeds it with the same local model used for the
documents, and returns the top-k most similar chunks from Chroma.
This is the "R" in RAG -- and it's also the exact surface an attacker
targets with corpus-poisoning / indirect prompt injection, since
whatever this function returns gets treated as trusted context later.
"""

import chromadb
from sentence_transformers import SentenceTransformer

EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
CHROMA_DB_PATH = "data/chroma_db"
COLLECTION_NAME = "security_docs"


class Retriever:
    def __init__(self):
        self.model = SentenceTransformer(EMBED_MODEL_NAME)
        client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        self.collection = client.get_collection(COLLECTION_NAME)

    def retrieve(self, query: str, k: int = 5):
        """
        Returns a list of dicts: [{"text", "source", "doc_type", "distance"}, ...]
        sorted by relevance (lowest distance = most similar).
        """
        query_embedding = self.model.encode([query]).tolist()

        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=k,
        )

        hits = []
        for i in range(len(results["ids"][0])):
            hits.append({
                "chunk_id": results["ids"][0][i],
                "text": results["documents"][0][i],
                "source": results["metadatas"][0][i].get("source"),
                "doc_type": results["metadatas"][0][i].get("doc_type"),
                "distance": results["distances"][0][i],
            })
        return hits


if __name__ == "__main__":
    retriever = Retriever()
    query = "How do attackers perform process injection on Windows?"
    hits = retriever.retrieve(query, k=3)
    print(f"Query: {query}\n")
    for h in hits:
        print(f"[{h['distance']:.3f}] {h['source']}")
        print(f"  {h['text'][:150]}...\n")