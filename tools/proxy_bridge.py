"""
BypassEvo Proxy Bridge — Burp Suite & OWASP ZAP Integration

Imports historical request/response data from Burp or ZAP to accelerate Recon.
Optionally exports successful payloads back to Burp for manual verification.
"""

import base64
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import requests


@dataclass
class ProxyRequest:
    """A request/response pair imported from Burp or ZAP."""
    method: str
    url: str
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    response_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    cookies: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    source: str = ""  # burp | zap


class BurpBridge:
    """Import/export data via Burp Suite REST API (Burp Extender)."""

    def __init__(self, api_url: str = "http://127.0.0.1:1337"):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()

    def is_available(self) -> bool:
        """Check if Burp API is reachable."""
        try:
            resp = self.session.get(f"{self.api_url}/health", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    def import_history(self, limit: int = 100) -> list[ProxyRequest]:
        """Import request history from Burp.

        Note: Requires Burp Suite Professional with REST API enabled
        or the 'CO2' / 'Logger++' extension with API endpoint.
        Falls back to parsing Burp XML export if API is unavailable.
        """
        try:
            resp = self.session.get(
                f"{self.api_url}/burp/api/v1/http-request-response",
                params={"limit": limit},
                timeout=10,
            )
            if resp.status_code == 200:
                return self._parse_burp_api_response(resp.json())
        except Exception:
            pass

        return []

    def import_from_xml(self, xml_path: str) -> list[ProxyRequest]:
        """Parse a Burp Suite XML export file.

        Burp → Project → Items → Save items → XML file.
        """
        requests_list = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for item in root.iter("item"):
                req = self._parse_burp_xml_item(item)
                if req:
                    requests_list.append(req)
        except Exception as e:
            pass

        return requests_list

    def export_payload(self, url: str, method: str, payload: str, headers: dict = None):
        """Send a payload to Burp Repeater for manual verification.

        Note: This requires a Burp extension that exposes a REST endpoint
        for creating Repeater tabs (e.g., 'Hackvertor' or custom extension).
        """
        try:
            self.session.post(
                f"{self.api_url}/burp/api/v1/repeater/send",
                json={
                    "url": url,
                    "method": method,
                    "headers": headers or {},
                    "body": payload,
                },
                timeout=5,
            )
        except Exception:
            pass

    def _parse_burp_api_response(self, data: dict) -> list[ProxyRequest]:
        """Parse Burp REST API response."""
        results = []
        for item in data.get("items", []):
            try:
                req_bytes = base64.b64decode(item.get("request", ""))
                resp_bytes = base64.b64decode(item.get("response", ""))
                req = self._parse_raw_http(req_bytes.decode("utf-8", errors="replace"), is_request=True)
                resp = self._parse_raw_http(resp_bytes.decode("utf-8", errors="replace"), is_request=False)
                req.response_code = resp.response_code
                req.response_headers = resp.response_headers
                req.response_body = resp.response_body
                req.source = "burp"
                results.append(req)
            except Exception:
                continue
        return results

    def _parse_burp_xml_item(self, item) -> Optional[ProxyRequest]:
        """Parse a single Burp XML <item> element."""
        try:
            req_el = item.find("request")
            resp_el = item.find("response")
            url_el = item.find("url")
            method_el = item.find("method")

            req_text = ""
            if req_el is not None:
                req_text = base64.b64decode(req_el.text or "").decode("utf-8", errors="replace")

            resp_text = ""
            resp_code = 0
            if resp_el is not None:
                resp_text = base64.b64decode(resp_el.text or "").decode("utf-8", errors="replace")
                # Extract status code
                import re
                match = re.search(r"HTTP/\d\.\d\s+(\d+)", resp_text)
                if match:
                    resp_code = int(match.group(1))

            req = ProxyRequest(
                method=method_el.text if method_el is not None else "GET",
                url=url_el.text if url_el is not None else "",
                request_body=self._extract_body(req_text),
                response_code=resp_code,
                response_body=self._extract_body(resp_text),
                source="burp",
            )
            req.params = self._extract_params(req.url, req.request_body)
            req.cookies = self._extract_cookies(req_text)
            return req
        except Exception:
            return None

    def _parse_raw_http(self, raw: str, is_request: bool = True) -> ProxyRequest:
        """Parse raw HTTP request or response."""
        lines = raw.split("\r\n")
        req = ProxyRequest(method="GET", url="")

        if lines:
            first_line = lines[0]
            if is_request:
                parts = first_line.split()
                if len(parts) >= 2:
                    req.method = parts[0]
                    req.url = parts[1]
            else:
                import re
                match = re.search(r"HTTP/\d\.\d\s+(\d+)", first_line)
                if match:
                    req.response_code = int(match.group(1))

        # Extract headers
        headers = {}
        body_start = len(lines)
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        body = "\r\n".join(lines[body_start:]) if body_start < len(lines) else ""

        if is_request:
            req.request_headers = headers
            req.request_body = body
        else:
            req.response_headers = headers
            req.response_body = body

        return req

    def _extract_body(self, raw_http: str) -> str:
        """Extract body from raw HTTP message."""
        idx = raw_http.find("\r\n\r\n")
        if idx >= 0:
            return raw_http[idx + 4:]
        idx = raw_http.find("\n\n")
        if idx >= 0:
            return raw_http[idx + 2:]
        return ""

    def _extract_params(self, url: str, body: str) -> dict:
        """Extract parameters from URL query string and POST body."""
        params = {}
        # URL params
        if "?" in url:
            query = url.split("?", 1)[1]
            for pair in query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        # POST params
        if body and "=" in body and "&" in body:
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        return params

    def _extract_cookies(self, raw_http: str) -> dict:
        """Extract cookies from Cookie header."""
        import re
        match = re.search(r"Cookie:\s*(.+)", raw_http, re.IGNORECASE)
        if not match:
            return {}
        cookies = {}
        for pair in match.group(1).split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies


class ZapBridge:
    """Import data via OWASP ZAP API."""

    def __init__(self, api_url: str = "http://127.0.0.1:8080", api_key: str = ""):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()

    def is_available(self) -> bool:
        try:
            resp = self.session.get(
                f"{self.api_url}/JSON/core/view/version/",
                params={"apikey": self.api_key},
                timeout=3,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def import_history(self, base_url: str = "", limit: int = 100) -> list[ProxyRequest]:
        """Import messages from ZAP's history."""
        params = {"apikey": self.api_key, "start": 0, "count": limit}
        if base_url:
            params["baseurl"] = base_url

        try:
            resp = self.session.get(
                f"{self.api_url}/JSON/core/view/messages/",
                params=params,
                timeout=10,
            )
            data = resp.json()
            return self._parse_zap_messages(data.get("messages", []))
        except Exception:
            return []

    def _parse_zap_messages(self, messages: list) -> list[ProxyRequest]:
        results = []
        for msg in messages:
            try:
                req = ProxyRequest(
                    method=msg.get("method", "GET"),
                    url=msg.get("url", ""),
                    request_body=msg.get("requestBody", ""),
                    response_code=int(msg.get("responseHeader", "").split(" ")[1]) if msg.get("responseHeader") else 0,
                    response_body=msg.get("responseBody", "")[:2000],
                    source="zap",
                )
                req.params = self._extract_params(req.url, req.request_body)
                results.append(req)
            except Exception:
                continue
        return results

    def _extract_params(self, url: str, body: str) -> dict:
        params = {}
        if "?" in url:
            query = url.split("?", 1)[1]
            for pair in query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        return params


# ── Unified Proxy Importer ─────────────────────────────────────────────


def import_from_proxy(
    source: str = "auto",
    burp_url: str = "http://127.0.0.1:1337",
    zap_url: str = "http://127.0.0.1:8080",
    zap_key: str = "",
    burp_xml: str = "",
    limit: int = 100,
) -> list[ProxyRequest]:
    """Unified import from Burp or ZAP.

    Args:
        source: "burp", "zap", "burp_xml", or "auto" (try all)
        burp_url: Burp REST API URL
        zap_url: ZAP API URL
        zap_key: ZAP API key
        burp_xml: Path to Burp XML export file
        limit: Max requests to import

    Returns:
        List of parsed request/response pairs
    """
    results = []

    if source in ("burp", "auto"):
        bridge = BurpBridge(burp_url)
        if bridge.is_available():
            results.extend(bridge.import_history(limit))
        if burp_xml:
            results.extend(bridge.import_from_xml(burp_xml))

    if source in ("zap", "auto") and not results:
        bridge = ZapBridge(zap_url, zap_key)
        if bridge.is_available():
            results.extend(bridge.import_history(limit=limit))

    return results[:limit]
