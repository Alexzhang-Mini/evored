"""Executor Agent: sends payloads and analyzes responses."""

from tools.scanner import Scanner, ScanResult


class ExecutorAgent:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner

    def execute(
        self,
        payload: str,
        endpoint: str = "/search",
        param: str = "q",
        method: str = "GET",
        data: dict = None,
    ) -> dict:
        """Execute a payload against the target and return structured results."""
        result = self.scanner.inject(
            path=endpoint,
            payload=payload,
            param=param,
            method=method,
            data=data,
        )

        return {
            "success": result.success,
            "evidence": result.evidence,
            "response_code": result.status_code,
            "response_snippet": result.response_text[:5000],
            "response_time": result.response_time,
            "indicators": result.indicators,
            "dbms_hint": result.dbms_hint,
            "confidence": result.confidence,
            "payload": payload,
        }
