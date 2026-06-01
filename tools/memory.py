"""
BypassEvo RAG Memory System — ChromaDB-backed persistent vector store.

Stores every attack attempt with:
  - Payload, reflection, response snippet, fitness score
  - Vulnerability type, endpoint, mutation strategy

Supports:
  - Cross-session persistence (ChromaDB on disk)
  - Similarity search (RAG retrieval) during Recon/Generate phases
  - Success/failure pattern analysis
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import chromadb
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False


# ── Data model ─────────────────────────────────────────────────────────


@dataclass
class MemoryEntry:
    id: str
    payload: str
    vuln_type: str       # sqli | xss | cmdi
    result: str          # success | failure | bypass | blocked | bypass_success
    endpoint: str = ""
    evidence: str = ""
    reflection: str = ""
    response_snippet: str = ""
    fitness: float = 0.0
    mutations_applied: list = field(default_factory=list)
    iteration: int = 0
    confidence: float = 0.0
    session_id: str = ""
    timestamp: float = 0.0
    metadata: dict = field(default_factory=dict)


# ── ChromaDB Memory ────────────────────────────────────────────────────


class _NoOpMemory:
    """No-op stub when memory is disabled — avoids AttributeError on .add()/.persist()."""

    def __init__(self):
        self._cache = []
        self._stats = {"total": 0, "successes": 0, "failures": 0}
        self._use_chroma = False
        self.session_id = ""

    def add(self, entry):
        self._cache.append(entry)
        self._stats["total"] += 1
        if entry.result == "success":
            self._stats["successes"] += 1
        else:
            self._stats["failures"] += 1

    def persist(self):
        pass

    def retrieve_similar(self, *args, **kwargs):
        return []

    def query_similar(self, *args, **kwargs):
        return []

    def query_successful(self, *args, **kwargs):
        return []

    def get_stats(self):
        return {**self._stats, "success_rate": 0, "session_id": self.session_id, "chromadb": False}

    def add_knowledge(self, *args, **kwargs):
        pass

    def query_knowledge(self, *args, **kwargs):
        return []

    def get_knowledge_stats(self):
        return {"total": 0, "avg_confidence": 0, "top_techniques": []}

    def add_inferred_rule(self, *args, **kwargs):
        pass

    def query_inferred_rules(self, *args, **kwargs):
        return []

    def add_hypothesis_result(self, *args, **kwargs):
        pass

    def query_hypothesis_results(self, *args, **kwargs):
        return []

    def cleanup_stale(self, *args, **kwargs):
        return {"cleaned": 0, "remaining": 0}


class AttackMemory:
    """Persistent RAG memory backed by ChromaDB (with in-memory fallback)."""

    def __init__(self, persist_dir: str = "./bypassevo_chroma_db", session_id: str = ""):
        self.persist_dir = persist_dir
        self.session_id = session_id or f"session_{int(time.time())}"
        self._use_chroma = HAS_CHROMADB
        self._cache: list[MemoryEntry] = []
        self._stats = {"total": 0, "successes": 0, "failures": 0}

        if HAS_CHROMADB:
            self._client = chromadb.PersistentClient(path=persist_dir)
            self._collection = self._client.get_or_create_collection(
                name="attack_memory", metadata={"hnsw:space": "cosine"},
            )
            self._success_collection = self._client.get_or_create_collection(
                name="successful_exploits", metadata={"hnsw:space": "cosine"},
            )
            self._bypass_collection = self._client.get_or_create_collection(
                name="bypass_techniques", metadata={"hnsw:space": "cosine"},
            )
            self._kb_collection = self._client.get_or_create_collection(
                name="knowledge_base", metadata={"hnsw:space": "cosine"},
            )
            # Auto-cleanup on session start to prevent unbounded growth
            self.cleanup_stale()
        else:
            self._client = None
            self._collection = None
            self._success_collection = None
            self._bypass_collection = None
            self._kb_collection = None

    def add(self, entry: MemoryEntry):
        """Store an attack attempt in ChromaDB.

        Quality filter: only stores entries that provide useful signal for future RAG retrieval.
        Low-fitness failures (< 0.3) are noise and are NOT persisted to ChromaDB
        (they still count in session stats).
        """
        entry.session_id = self.session_id
        entry.timestamp = time.time()

        self._cache.append(entry)
        self._stats["total"] += 1
        if entry.result == "success":
            self._stats["successes"] += 1
        else:
            self._stats["failures"] += 1

        if not self._use_chroma:
            return

        # Quality gate: only persist high-value entries to ChromaDB
        # This prevents unbounded growth of low-quality data that degrades RAG retrieval
        _high_value_results = ("success", "bypass", "bypass_success")
        if entry.result not in _high_value_results and entry.fitness < 0.3:
            return  # Skip low-fitness failures — they add noise without signal

        doc_text = self._build_document_text(entry)
        metadata = {
            "vuln_type": entry.vuln_type,
            "result": entry.result,
            "endpoint": entry.endpoint,
            "fitness": entry.fitness,
            "confidence": entry.confidence,
            "iteration": entry.iteration,
            "session_id": entry.session_id,
            "timestamp": entry.timestamp,
            "mutations": json.dumps(entry.mutations_applied[:5]),
        }

        try:
            self._collection.add(ids=[entry.id], documents=[doc_text], metadatas=[metadata])
            if entry.result == "success":
                self._success_collection.add(ids=[entry.id], documents=[doc_text], metadatas=[metadata])
            if entry.result == "bypass_success":
                bypass_doc = self._build_bypass_document(entry)
                bypass_meta = {
                    "waf_name": entry.metadata.get("waf_name", ""),
                    "technique": entry.metadata.get("technique", ""),
                    "vuln_type": entry.vuln_type,
                    "fitness": entry.fitness,
                    "timestamp": entry.timestamp,
                }
                self._bypass_collection.add(ids=[entry.id], documents=[bypass_doc], metadatas=[bypass_meta])
        except Exception:
            try:
                self._collection.update(ids=[entry.id], documents=[doc_text], metadatas=[metadata])
            except Exception:
                pass

    def query_similar(
        self,
        payload: str,
        vuln_type: str = "",
        n_results: int = 5,
        filter_result: Optional[str] = None,
    ) -> list[dict]:
        """RAG retrieval: find similar past attempts."""
        if not self._use_chroma or not self._collection:
            # Fallback: in-memory search
            candidates = [e for e in self._cache if not vuln_type or e.vuln_type == vuln_type]
            if filter_result:
                candidates = [e for e in candidates if e.result == filter_result]
            return [
                {"id": e.id, "payload": e.payload, "vuln_type": e.vuln_type,
                 "result": e.result, "evidence": e.evidence, "fitness": e.fitness,
                 "mutations": e.mutations_applied, "similarity": 0.5, "session_id": e.session_id}
                for e in candidates[-n_results:]
            ]

        where_filter = {}
        if vuln_type:
            where_filter["vuln_type"] = vuln_type
        if filter_result:
            where_filter["result"] = filter_result

        try:
            results = self._collection.query(
                query_texts=[payload], n_results=n_results,
                where=where_filter if where_filter else None,
            )
        except Exception:
            return []

        entries = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                doc = results["documents"][0][i] if results["documents"] else ""
                dist = results["distances"][0][i] if results["distances"] else 1.0
                entries.append({
                    "id": doc_id, "payload": self._extract_payload(doc),
                    "vuln_type": meta.get("vuln_type", ""), "result": meta.get("result", ""),
                    "evidence": self._extract_evidence(doc), "fitness": meta.get("fitness", 0),
                    "mutations": json.loads(meta.get("mutations", "[]")),
                    "similarity": 1 - dist, "session_id": meta.get("session_id", ""),
                })
        return entries

    def query_successful(self, vuln_type: str = "", n_results: int = 3) -> list[dict]:
        """Retrieve successful exploits."""
        if not self._use_chroma or not self._success_collection:
            successes = [e for e in self._cache if e.result == "success"]
            if vuln_type:
                successes = [e for e in successes if e.vuln_type == vuln_type]
            successes.sort(key=lambda x: x.fitness, reverse=True)
            return [
                {"id": e.id, "payload": e.payload, "vuln_type": e.vuln_type,
                 "fitness": e.fitness, "session_id": e.session_id}
                for e in successes[:n_results]
            ]

        where_filter = {}
        if vuln_type:
            where_filter["vuln_type"] = vuln_type
        try:
            results = self._success_collection.query(
                query_texts=["successful exploit"], n_results=n_results,
                where=where_filter if where_filter else None,
            )
        except Exception:
            return []

        entries = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                entries.append({
                    "id": doc_id, "payload": self._extract_payload(results["documents"][0][i]),
                    "vuln_type": meta.get("vuln_type", ""),
                    "fitness": meta.get("fitness", 0), "session_id": meta.get("session_id", ""),
                })
        return entries

    def query_bypasses(self, waf_name: str = "", vuln_type: str = "", n_results: int = 5) -> list[dict]:
        """Retrieve discovered bypass techniques."""
        if not self._use_chroma or not self._bypass_collection:
            bypasses = [e for e in self._cache if e.result == "bypass_success"]
            if waf_name:
                bypasses = [e for e in bypasses if e.metadata.get("waf_name") == waf_name]
            if vuln_type:
                bypasses = [e for e in bypasses if e.vuln_type == vuln_type]
            bypasses.sort(key=lambda x: x.fitness, reverse=True)
            return [
                {"id": e.id, "payload": e.payload, "technique": e.metadata.get("technique", ""),
                 "waf_name": e.metadata.get("waf_name", ""), "vuln_type": e.vuln_type,
                 "fitness": e.fitness, "session_id": e.session_id}
                for e in bypasses[:n_results]
            ]

        conditions = []
        if waf_name:
            conditions.append({"waf_name": waf_name})
        if vuln_type:
            conditions.append({"vuln_type": vuln_type})
        where_filter = {"$and": conditions} if len(conditions) > 1 else (conditions[0] if conditions else None)
        try:
            results = self._bypass_collection.query(
                query_texts=["waf bypass technique"], n_results=n_results,
                where=where_filter,
            )
        except Exception:
            return []

        entries = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                doc = results["documents"][0][i] if results["documents"] else ""
                entries.append({
                    "id": doc_id, "payload": self._extract_payload(doc),
                    "technique": meta.get("technique", ""),
                    "waf_name": meta.get("waf_name", ""),
                    "vuln_type": meta.get("vuln_type", ""),
                    "fitness": meta.get("fitness", 0),
                    "session_id": meta.get("session_id", ""),
                })
        return entries

    def get_failed_strategies(self, vuln_type: str, top_k: int = 10) -> list[str]:
        """Get mutation strategies that consistently failed (to avoid)."""
        try:
            results = self._collection.query(
                query_texts=["failed mutation strategy"],
                n_results=top_k,
                where={"vuln_type": vuln_type, "result": "failure"} if vuln_type else None,
            )
        except Exception:
            return []

        strategies = []
        if results and results["metadatas"] and results["metadatas"][0]:
            for meta in results["metadatas"][0]:
                mutations = json.loads(meta.get("mutations", "[]"))
                strategies.extend(mutations)
        return list(set(strategies))

    def get_stats(self) -> dict:
        """Get memory statistics."""
        total = self._stats["total"]
        success = self._stats["successes"]
        return {
            "total_entries": total, "successes": success,
            "failures": total - success,
            "success_rate": success / max(total, 1),
            "session_id": self.session_id, "cache_size": len(self._cache),
            "chromadb": self._use_chroma,
        }

    def persist(self):
        """Force persist to disk (PersistentClient auto-persists, this is a no-op)."""
        pass

    # ── Knowledge Base (permanent cross-session store) ───────────────────

    def add_knowledge(
        self,
        waf_name: str,
        technique: str,
        vuln_type: str,
        payload: str,
        success: bool = True,
        confidence: float = 0.0,
        source: str = "实战验证",
        evidence: str = "",
    ):
        """Store a verified bypass technique in the permanent knowledge base.

        Uses upsert semantics: if the same (waf_name, technique, vuln_type) exists,
        increments success/fail counters. Otherwise creates a new entry.
        """
        if not self._use_chroma or not self._kb_collection:
            return

        import hashlib
        # Deterministic ID for upsert: hash of (waf_name, technique, vuln_type)
        key_str = f"{waf_name.lower()}:{technique.lower()}:{vuln_type.lower()}"
        kb_id = hashlib.md5(key_str.encode()).hexdigest()[:12]

        doc_text = (
            f"Payload: {payload[:200]} | "
            f"Technique: {technique} | "
            f"WAF: {waf_name} | "
            f"VulnType: {vuln_type} | "
            f"Evidence: {evidence[:200]}"
        )

        # Try to get existing entry to increment counters
        try:
            existing = self._kb_collection.get(ids=[kb_id])
            if existing and existing["ids"]:
                old_meta = existing["metadatas"][0] if existing["metadatas"] else {}
                sc = old_meta.get("success_count", 0) + (1 if success else 0)
                fc = old_meta.get("fail_count", 0) + (0 if success else 1)
                total = sc + fc
                new_confidence = sc / max(total, 1)
                # Keep best payload example
                best_payload = old_meta.get("payload_example", payload[:200])
                if success and confidence > old_meta.get("confidence", 0):
                    best_payload = payload[:200]
                metadata = {
                    "waf_name": waf_name.lower(),
                    "technique": technique.lower(),
                    "vuln_type": vuln_type,
                    "success_count": sc,
                    "fail_count": fc,
                    "confidence": new_confidence,
                    "source": source,
                    "payload_example": best_payload,
                    "last_seen": time.time(),
                }
                self._kb_collection.update(ids=[kb_id], documents=[doc_text], metadatas=[metadata])
                return
        except Exception:
            pass

        # New entry
        metadata = {
            "waf_name": waf_name.lower(),
            "technique": technique.lower(),
            "vuln_type": vuln_type,
            "success_count": 1 if success else 0,
            "fail_count": 0 if success else 1,
            "confidence": confidence if success else 0.0,
            "source": source,
            "payload_example": payload[:200],
            "last_seen": time.time(),
        }
        try:
            self._kb_collection.add(ids=[kb_id], documents=[doc_text], metadatas=[metadata])
        except Exception:
            pass

    def query_knowledge(
        self,
        waf_name: str = "",
        vuln_type: str = "",
        top_k: int = 5,
    ) -> list[dict]:
        """Query the knowledge base for proven bypass techniques.

        Returns techniques sorted by confidence (success rate), filtered by
        WAF name and/or vulnerability type.
        """
        if not self._use_chroma or not self._kb_collection:
            return []

        conditions = []
        if waf_name:
            conditions.append({"waf_name": waf_name.lower()})
        if vuln_type:
            conditions.append({"vuln_type": vuln_type})
        where_filter = {"$and": conditions} if len(conditions) > 1 else (conditions[0] if conditions else None)

        try:
            results = self._kb_collection.query(
                query_texts=[f"waf bypass {waf_name} {vuln_type}"],
                n_results=top_k,
                where=where_filter,
            )
        except Exception:
            return []

        entries = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                entries.append({
                    "id": doc_id,
                    "technique": meta.get("technique", ""),
                    "waf_name": meta.get("waf_name", ""),
                    "vuln_type": meta.get("vuln_type", ""),
                    "success_count": meta.get("success_count", 0),
                    "fail_count": meta.get("fail_count", 0),
                    "confidence": meta.get("confidence", 0),
                    "source": meta.get("source", ""),
                    "payload_example": meta.get("payload_example", ""),
                })
        # Sort by confidence descending
        entries.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return entries

    def get_knowledge_stats(self) -> dict:
        """Get knowledge base statistics."""
        if not self._use_chroma or not self._kb_collection:
            return {"total": 0, "avg_confidence": 0, "top_techniques": []}
        try:
            count = self._kb_collection.count()
            if count == 0:
                return {"total": 0, "avg_confidence": 0, "top_techniques": []}
            # Get top 5 by confidence
            results = self._kb_collection.query(
                query_texts=["bypass technique"],
                n_results=min(count, 5),
            )
            top = []
            if results and results["metadatas"] and results["metadatas"][0]:
                for meta in results["metadatas"][0]:
                    top.append({
                        "technique": meta.get("technique", ""),
                        "waf_name": meta.get("waf_name", ""),
                        "confidence": meta.get("confidence", 0),
                        "success_count": meta.get("success_count", 0),
                    })
            avg_conf = sum(t["confidence"] for t in top) / max(len(top), 1)
            return {"total": count, "avg_confidence": avg_conf, "top_techniques": top}
        except Exception:
            return {"total": 0, "avg_confidence": 0, "top_techniques": []}

    # ── Inferred WAF Rules (from 403 response analysis) ──────────────

    def add_inferred_rule(
        self,
        waf_name: str,
        rule_type: str,
        trigger_keywords: list[str],
        confidence: float = 0.0,
        evidence: str = "",
        suggested_bypasses: list[dict] = None,
    ):
        """Store an inferred WAF rule from block analysis.

        Uses upsert: if the same (waf_name, rule_type) exists with lower confidence,
        updates it. Otherwise creates a new entry.
        """
        if not self._use_chroma or not self._kb_collection:
            return

        import hashlib
        key_str = f"inferred_rule:{waf_name.lower()}:{rule_type.lower()}"
        rule_id = hashlib.md5(key_str.encode()).hexdigest()[:12]

        doc_text = (
            f"WAF Rule: {waf_name} | "
            f"Type: {rule_type} | "
            f"Triggers: {', '.join(trigger_keywords[:5])} | "
            f"Evidence: {evidence[:200]}"
        )

        metadata = {
            "waf_name": waf_name.lower(),
            "rule_type": rule_type,
            "trigger_keywords": json.dumps(trigger_keywords[:10]),
            "confidence": confidence,
            "evidence": evidence[:300],
            "suggested_bypasses": json.dumps(suggested_bypasses or []),
            "last_seen": time.time(),
            "doc_type": "inferred_rule",
        }

        try:
            existing = self._kb_collection.get(ids=[rule_id])
            if existing and existing["ids"]:
                old_conf = existing["metadatas"][0].get("confidence", 0) if existing["metadatas"] else 0
                if confidence >= old_conf:
                    self._kb_collection.update(ids=[rule_id], documents=[doc_text], metadatas=[metadata])
            else:
                self._kb_collection.add(ids=[rule_id], documents=[doc_text], metadatas=[metadata])
        except Exception:
            pass

    def query_inferred_rules(self, waf_name: str = "", top_k: int = 5) -> list[dict]:
        """Query inferred WAF rules from knowledge base."""
        if not self._use_chroma or not self._kb_collection:
            return []

        conditions = [{"doc_type": "inferred_rule"}]
        if waf_name:
            conditions.append({"waf_name": waf_name.lower()})
        where_filter = {"$and": conditions} if len(conditions) > 1 else conditions[0]

        try:
            results = self._kb_collection.query(
                query_texts=[f"waf rule {waf_name}"],
                n_results=top_k,
                where=where_filter,
            )
        except Exception:
            return []

        entries = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                entries.append({
                    "id": doc_id,
                    "waf_name": meta.get("waf_name", ""),
                    "rule_type": meta.get("rule_type", ""),
                    "trigger_keywords": json.loads(meta.get("trigger_keywords", "[]")),
                    "confidence": meta.get("confidence", 0),
                    "evidence": meta.get("evidence", ""),
                    "suggested_bypasses": json.loads(meta.get("suggested_bypasses", "[]")),
                })
        entries.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return entries

    # ── Hypothesis Results (for learning across iterations) ──────────

    def add_hypothesis_result(
        self,
        waf_name: str,
        mechanism: str,
        action: str,
        best_fitness: float = 0.0,
        test_count: int = 0,
        bypass_count: int = 0,
        reasoning: str = "",
    ):
        """Store hypothesis validation result for cross-iteration learning.

        Args:
            waf_name: Target WAF
            mechanism: Hypothesis mechanism name
            action: "keep" | "refine" | "discard"
            best_fitness: Best fitness achieved by this hypothesis
            test_count: Number of payloads tested
            bypass_count: Number that passed WAF
            reasoning: Why this action was taken
        """
        if not self._use_chroma or not self._kb_collection:
            return

        import hashlib
        key_str = f"hypothesis:{waf_name.lower()}:{mechanism.lower()}"
        hyp_id = hashlib.md5(key_str.encode()).hexdigest()[:12]

        doc_text = (
            f"Hypothesis: {mechanism} | "
            f"WAF: {waf_name} | "
            f"Action: {action} | "
            f"Fitness: {best_fitness:.3f} | "
            f"Reasoning: {reasoning[:200]}"
        )

        metadata = {
            "waf_name": waf_name.lower(),
            "mechanism": mechanism,
            "action": action,
            "best_fitness": best_fitness,
            "test_count": test_count,
            "bypass_count": bypass_count,
            "reasoning": reasoning[:300],
            "last_seen": time.time(),
            "doc_type": "hypothesis_result",
        }

        try:
            existing = self._kb_collection.get(ids=[hyp_id])
            if existing and existing["ids"]:
                self._kb_collection.update(ids=[hyp_id], documents=[doc_text], metadatas=[metadata])
            else:
                self._kb_collection.add(ids=[hyp_id], documents=[doc_text], metadatas=[metadata])
        except Exception:
            pass

    def query_hypothesis_results(self, waf_name: str = "", top_k: int = 10) -> list[dict]:
        """Query past hypothesis results for a WAF."""
        if not self._use_chroma or not self._kb_collection:
            return []

        conditions = [{"doc_type": "hypothesis_result"}]
        if waf_name:
            conditions.append({"waf_name": waf_name.lower()})
        where_filter = {"$and": conditions} if len(conditions) > 1 else conditions[0]

        try:
            results = self._kb_collection.query(
                query_texts=[f"hypothesis {waf_name}"],
                n_results=top_k,
                where=where_filter,
            )
        except Exception:
            return []

        entries = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                entries.append({
                    "id": doc_id,
                    "waf_name": meta.get("waf_name", ""),
                    "mechanism": meta.get("mechanism", ""),
                    "action": meta.get("action", ""),
                    "best_fitness": meta.get("best_fitness", 0),
                    "test_count": meta.get("test_count", 0),
                    "bypass_count": meta.get("bypass_count", 0),
                    "reasoning": meta.get("reasoning", ""),
                })
        return entries

    # ── Memory maintenance ──────────────────────────────────────────────

    def cleanup_stale(self, keep_last_n_sessions: int = 10, max_entries: int = 5000):
        """Remove old low-value entries to maintain RAG retrieval quality.

        Strategy:
        - NEVER delete from knowledge_base, successful_exploits, or bypass_techniques
        - Only clean attack_memory (the high-volume collection)
        - Keep all entries from the last N sessions
        - If still over max_entries, evict lowest-fitness entries from oldest sessions

        Returns dict with cleanup stats.
        """
        if not self._use_chroma or not self._collection:
            return {"cleaned": 0, "remaining": 0, "skipped": "chromadb not available"}

        try:
            total = self._collection.count()
            if total <= max_entries:
                return {"cleaned": 0, "remaining": total, "skipped": "under limit"}

            # Get all entries sorted by timestamp (oldest first)
            all_data = self._collection.get(
                limit=total,
                include=["metadatas"],
            )
            if not all_data or not all_data["ids"]:
                return {"cleaned": 0, "remaining": total}

            # Identify unique sessions and their timestamps
            session_timestamps = {}
            entries_by_id = {}
            for i, doc_id in enumerate(all_data["ids"]):
                meta = all_data["metadatas"][i] if all_data["metadatas"] else {}
                sid = meta.get("session_id", "")
                ts = meta.get("timestamp", 0)
                fitness = meta.get("fitness", 0)
                result = meta.get("result", "failure")
                session_timestamps[sid] = max(session_timestamps.get(sid, 0), ts)
                entries_by_id[doc_id] = {"session_id": sid, "timestamp": ts, "fitness": fitness, "result": result}

            # Sort sessions by recency, keep last N
            sorted_sessions = sorted(session_timestamps.items(), key=lambda x: x[1], reverse=True)
            protected_sessions = set(sid for sid, _ in sorted_sessions[:keep_last_n_sessions])

            # Identify candidates for deletion (old sessions, low fitness, not success)
            delete_candidates = []
            for doc_id, info in entries_by_id.items():
                if info["session_id"] in protected_sessions:
                    continue  # Protected session
                if info["result"] in ("success", "bypass", "bypass_success"):
                    continue  # Always keep successes
                if info["fitness"] >= 0.6:
                    continue  # Keep high-fitness entries
                delete_candidates.append((doc_id, info["fitness"]))

            # Sort by fitness ascending (delete lowest first)
            delete_candidates.sort(key=lambda x: x[1])

            # Delete enough to get under max_entries
            to_delete = total - max_entries
            if to_delete <= 0:
                return {"cleaned": 0, "remaining": total}

            ids_to_delete = [doc_id for doc_id, _ in delete_candidates[:to_delete]]
            if ids_to_delete:
                # ChromaDB delete in batches of 100
                for i in range(0, len(ids_to_delete), 100):
                    batch = ids_to_delete[i:i + 100]
                    self._collection.delete(ids=batch)

            return {
                "cleaned": len(ids_to_delete),
                "remaining": total - len(ids_to_delete),
                "protected_sessions": len(protected_sessions),
                "candidates_found": len(delete_candidates),
            }
        except Exception as e:
            return {"cleaned": 0, "error": str(e)}

    # ── Document construction (for ChromaDB embedding) ─────────────────

    def _build_document_text(self, entry: MemoryEntry) -> str:
        """Build a text document that ChromaDB will embed for similarity search."""
        parts = [
            f"Payload: {entry.payload}",
            f"VulnType: {entry.vuln_type}",
            f"Result: {entry.result}",
            f"Endpoint: {entry.endpoint}",
            f"Evidence: {entry.evidence[:200]}",
            f"Reflection: {entry.reflection[:200]}",
            f"Mutations: {', '.join(entry.mutations_applied[:3])}",
        ]
        return " | ".join(parts)

    def _build_bypass_document(self, entry: MemoryEntry) -> str:
        """Build document text for bypass technique storage."""
        parts = [
            f"Payload: {entry.payload}",
            f"Technique: {entry.metadata.get('technique', 'unknown')}",
            f"WAF: {entry.metadata.get('waf_name', 'unknown')}",
            f"VulnType: {entry.vuln_type}",
            f"Fitness: {entry.fitness:.3f}",
        ]
        return " | ".join(parts)

    def _extract_payload(self, doc: str) -> str:
        """Extract payload from document text."""
        match = __import__("re").search(r"Payload: (.+?)(?:\s*\||$)", doc)
        return match.group(1).strip() if match else doc[:100]

    def _extract_evidence(self, doc: str) -> str:
        """Extract evidence from document text."""
        match = __import__("re").search(r"Evidence: (.+?)(?:\s*\||$)", doc)
        return match.group(1).strip() if match else ""
