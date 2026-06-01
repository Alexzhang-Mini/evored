"""SQL Error Knowledge Base — centralized pattern matching for injection detection.

Pre-loaded with 60+ classic error patterns from MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
Supports user-enriched patterns (persisted to JSON).

Features:
  - Regex + keyword + fuzzy matching for high fault tolerance
  - smart_extract(): auto-detect error patterns from responses and suggest adding to KB
  - Highlight matching keywords in response text

Used by:
  - scanner._analyze() for success detection
  - scanner.analyze_response_content() for deep analysis
  - FitnessEvaluator for GA fitness scoring
"""

import json
import re
import os
from dataclasses import dataclass, field
from typing import Optional

KB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sql_error_patterns.json")


@dataclass
class ErrorPattern:
    """A single error pattern entry."""
    pattern: str              # Regex pattern (case-insensitive)
    dbms: str                 # mysql, postgresql, mssql, oracle, sqlite, generic
    category: str             # syntax, function, extraction, overflow, connection
    confidence: float         # 0.0-1.0, how strongly this indicates successful injection
    description: str          # Human-readable description
    source: str = "builtin"   # builtin | user_enriched


# ═══════════════════════════════════════════════════════════════════════════
# Pre-loaded patterns — 60+ SQL injection error signatures
# ═══════════════════════════════════════════════════════════════════════════

BUILTIN_PATTERNS: list[ErrorPattern] = [
    # ── MySQL Syntax Errors ──────────────────────────────────────────────
    ErrorPattern(
        pattern=r"you have an error in your sql syntax",
        dbms="mysql", category="syntax", confidence=0.95,
        description="MySQL classic syntax error — direct SQLi confirmation",
    ),
    ErrorPattern(
        pattern=r"warning.*mysql",
        dbms="mysql", category="syntax", confidence=0.85,
        description="MySQL warning message",
    ),
    ErrorPattern(
        pattern=r"unclosed quotation mark",
        dbms="mysql", category="syntax", confidence=0.90,
        description="Unclosed quote — string injection point",
    ),
    ErrorPattern(
        pattern=r"supplied argument is not a valid",
        dbms="mysql", category="syntax", confidence=0.85,
        description="Invalid argument to MySQL function",
    ),
    ErrorPattern(
        pattern=r"mysql_fetch_array",
        dbms="mysql", category="function", confidence=0.92,
        description="mysql_fetch_array() error — confirms PHP+MySQL stack",
    ),
    ErrorPattern(
        pattern=r"mysql_fetch_assoc",
        dbms="mysql", category="function", confidence=0.92,
        description="mysql_fetch_assoc() error",
    ),
    ErrorPattern(
        pattern=r"mysql_fetch_object",
        dbms="mysql", category="function", confidence=0.92,
        description="mysql_fetch_object() error",
    ),
    ErrorPattern(
        pattern=r"mysql_fetch_row",
        dbms="mysql", category="function", confidence=0.92,
        description="mysql_fetch_row() error",
    ),
    ErrorPattern(
        pattern=r"mysql_num_rows",
        dbms="mysql", category="function", confidence=0.90,
        description="mysql_num_rows() error",
    ),
    ErrorPattern(
        pattern=r"mysql_query",
        dbms="mysql", category="function", confidence=0.90,
        description="mysql_query() error",
    ),
    ErrorPattern(
        pattern=r"mysql_result",
        dbms="mysql", category="function", confidence=0.88,
        description="mysql_result() error",
    ),
    ErrorPattern(
        pattern=r"mysql_connect",
        dbms="mysql", category="connection", confidence=0.85,
        description="mysql_connect() error",
    ),
    ErrorPattern(
        pattern=r"mysql_select_db",
        dbms="mysql", category="function", confidence=0.85,
        description="mysql_select_db() error",
    ),

    # ── XPATH Errors (classic ~xxx~ format) ──────────────────────────────
    ErrorPattern(
        pattern=r"xpath\s+syntax\s+error",
        dbms="mysql", category="extraction", confidence=0.98,
        description="XPATH syntax error — EXTRACTVALUE/UPDATEXML confirmed",
    ),
    ErrorPattern(
        pattern=r"~[a-zA-Z0-9_.]+~",
        dbms="mysql", category="extraction", confidence=0.95,
        description="XPATH error payload reflection (~xxx~ format) — data extracted",
    ),
    ErrorPattern(
        pattern=r"~[a-zA-Z0-9_./\\\-]+~",
        dbms="mysql", category="extraction", confidence=0.93,
        description="XPATH error with path/special characters (~/xxx/~, ~a-b~)",
    ),
    ErrorPattern(
        pattern=r"~[a-f0-9]{8,}~",
        dbms="mysql", category="extraction", confidence=0.96,
        description="XPATH error with hex data (~abcdef~)",
    ),
    ErrorPattern(
        pattern=r"~\d+~",
        dbms="mysql", category="extraction", confidence=0.94,
        description="XPATH error with numeric data (~5~) — SELECT result reflected",
    ),
    ErrorPattern(
        pattern=r"~[a-zA-Z0-9+/=]{8,}~",
        dbms="mysql", category="extraction", confidence=0.90,
        description="XPATH error with base64-like data",
    ),
    ErrorPattern(
        pattern=r"0x7e[0-9a-f]+0x7e",
        dbms="mysql", category="extraction", confidence=0.97,
        description="XPATH error with 0x7e delimiters (CONCAT+0x7e trick)",
    ),
    ErrorPattern(
        pattern=r"0x7e.*0x7e",
        dbms="mysql", category="extraction", confidence=0.93,
        description="0x7e (tilde) delimiters in response — error-based extraction",
    ),

    # ── EXTRACTVALUE / UPDATEXML ─────────────────────────────────────────
    ErrorPattern(
        pattern=r"extractvalue\s*\(",
        dbms="mysql", category="function", confidence=0.95,
        description="EXTRACTVALUE() function error — error-based injection",
    ),
    ErrorPattern(
        pattern=r"updatexml\s*\(",
        dbms="mysql", category="function", confidence=0.95,
        description="UPDATEXML() function error — error-based injection",
    ),
    ErrorPattern(
        pattern=r"extractvalue",
        dbms="mysql", category="function", confidence=0.93,
        description="EXTRACTVALUE reference in response",
    ),
    ErrorPattern(
        pattern=r"updatexml",
        dbms="mysql", category="function", confidence=0.93,
        description="UPDATEXML reference in response",
    ),

    # ── EXP() Overflow ──────────────────────────────────────────────────
    ErrorPattern(
        pattern=r"double\s+overflow",
        dbms="mysql", category="overflow", confidence=0.95,
        description="EXP() double overflow — classic error-based via EXP(~(SELECT…))",
    ),
    ErrorPattern(
        pattern=r"overflow.*exp",
        dbms="mysql", category="overflow", confidence=0.90,
        description="EXP overflow variant",
    ),

    # ── FLOOR(RAND()) Duplicate Entry ────────────────────────────────────
    ErrorPattern(
        pattern=r"duplicate\s+entry.*for\s+key",
        dbms="mysql", category="overflow", confidence=0.95,
        description="FLOOR(RAND(0)*2) duplicate entry — GROUP BY injection",
    ),
    ErrorPattern(
        pattern=r"key\s+\d+",
        dbms="mysql", category="overflow", confidence=0.70,
        description="Key index reference in error (GROUP BY injection artifact)",
    ),
    ErrorPattern(
        pattern=r"duplicate\s+entry",
        dbms="mysql", category="overflow", confidence=0.85,
        description="Duplicate entry error (FLOOR+RAND variant)",
    ),

    # ── MySQL General ────────────────────────────────────────────────────
    ErrorPattern(
        pattern=r"syntax error.*mysql",
        dbms="mysql", category="syntax", confidence=0.90,
        description="Generic MySQL syntax error",
    ),
    ErrorPattern(
        pattern=r"valid\s+mysql\s+result",
        dbms="mysql", category="function", confidence=0.90,
        description="Invalid MySQL result resource",
    ),
    ErrorPattern(
        pattern=r"mysql.*error",
        dbms="mysql", category="syntax", confidence=0.80,
        description="Generic MySQL error",
    ),
    ErrorPattern(
        pattern=r"mysqli?_",
        dbms="mysql", category="function", confidence=0.88,
        description="MySQL/mysqli function error",
    ),
    ErrorPattern(
        pattern=r"myodbc",
        dbms="mysql", category="connection", confidence=0.80,
        description="MySQL ODBC driver error",
    ),
    ErrorPattern(
        pattern=r"unknown column",
        dbms="mysql", category="syntax", confidence=0.85,
        description="MySQL unknown column — table structure probe",
    ),
    ErrorPattern(
        pattern=r"table.*doesn't exist",
        dbms="mysql", category="syntax", confidence=0.85,
        description="MySQL table not found — useful for enumeration",
    ),
    ErrorPattern(
        pattern=r"operand should contain.*column",
        dbms="mysql", category="syntax", confidence=0.80,
        description="MySQL operand error — subquery context",
    ),
    ErrorPattern(
        pattern=r"subquery returns more than 1 row",
        dbms="mysql", category="syntax", confidence=0.85,
        description="MySQL subquery multi-row — injectable subquery context",
    ),
    ErrorPattern(
        pattern=r"incorrect.*parameter.*count.*to.*function",
        dbms="mysql", category="syntax", confidence=0.82,
        description="MySQL function parameter count error",
    ),

    # ── MariaDB ──────────────────────────────────────────────────────────
    ErrorPattern(
        pattern=r"mariadb.*error",
        dbms="mysql", category="syntax", confidence=0.85,
        description="MariaDB error",
    ),
    ErrorPattern(
        pattern=r"mariadb.*syntax",
        dbms="mysql", category="syntax", confidence=0.90,
        description="MariaDB syntax error",
    ),

    # ── PostgreSQL ───────────────────────────────────────────────────────
    ErrorPattern(
        pattern=r"pg_query",
        dbms="postgresql", category="function", confidence=0.95,
        description="pg_query() error — PostgreSQL confirmed",
    ),
    ErrorPattern(
        pattern=r"pg_exec",
        dbms="postgresql", category="function", confidence=0.95,
        description="pg_exec() error",
    ),
    ErrorPattern(
        pattern=r"pg_connect",
        dbms="postgresql", category="connection", confidence=0.85,
        description="pg_connect() error",
    ),
    ErrorPattern(
        pattern=r"pg_last_error",
        dbms="postgresql", category="function", confidence=0.85,
        description="pg_last_error() output",
    ),
    ErrorPattern(
        pattern=r"postgresql.*error",
        dbms="postgresql", category="syntax", confidence=0.85,
        description="PostgreSQL error",
    ),
    ErrorPattern(
        pattern=r"unterminated quoted string",
        dbms="postgresql", category="syntax", confidence=0.90,
        description="PostgreSQL unterminated string",
    ),
    ErrorPattern(
        pattern=r"current transaction is aborted",
        dbms="postgresql", category="syntax", confidence=0.85,
        description="PostgreSQL transaction aborted — stacked queries work",
    ),
    ErrorPattern(
        pattern=r"pg_regexp",
        dbms="postgresql", category="function", confidence=0.85,
        description="PostgreSQL regex error",
    ),
    ErrorPattern(
        pattern=r"syntax error at or near",
        dbms="postgresql", category="syntax", confidence=0.92,
        description="PostgreSQL syntax error near token",
    ),
    ErrorPattern(
        pattern=r"invalid input syntax for",
        dbms="postgresql", category="syntax", confidence=0.88,
        description="PostgreSQL invalid input syntax",
    ),
    ErrorPattern(
        pattern=r"relation.*does not exist",
        dbms="postgresql", category="syntax", confidence=0.85,
        description="PostgreSQL relation (table) not found",
    ),
    ErrorPattern(
        pattern=r"column.*does not exist",
        dbms="postgresql", category="syntax", confidence=0.85,
        description="PostgreSQL column not found",
    ),
    ErrorPattern(
        pattern=r"psycopg2",
        dbms="postgresql", category="function", confidence=0.90,
        description="psycopg2 (Python PostgreSQL driver) error",
    ),

    # ── MSSQL ────────────────────────────────────────────────────────────
    ErrorPattern(
        pattern=r"microsoft ole db provider",
        dbms="mssql", category="syntax", confidence=0.95,
        description="MSSQL OLE DB provider error — SQL Server confirmed",
    ),
    ErrorPattern(
        pattern=r"unclosed quotation mark after the character string",
        dbms="mssql", category="syntax", confidence=0.95,
        description="MSSQL unclosed quote — classic MSSQL injection",
    ),
    ErrorPattern(
        pattern=r"microsoft sql native client error",
        dbms="mssql", category="syntax", confidence=0.95,
        description="MSSQL Native Client error",
    ),
    ErrorPattern(
        pattern=r"\[microsoft\]\[odbc",
        dbms="mssql", category="syntax", confidence=0.90,
        description="MSSQL ODBC driver error",
    ),
    ErrorPattern(
        pattern=r"mssql_query",
        dbms="mssql", category="function", confidence=0.90,
        description="mssql_query() error",
    ),
    ErrorPattern(
        pattern=r"sqlserver.*error",
        dbms="mssql", category="syntax", confidence=0.85,
        description="SQL Server error",
    ),
    ErrorPattern(
        pattern=r"incorrect syntax near",
        dbms="mssql", category="syntax", confidence=0.90,
        description="MSSQL incorrect syntax near token",
    ),
    ErrorPattern(
        pattern=r"invalid column name",
        dbms="mssql", category="syntax", confidence=0.85,
        description="MSSQL invalid column name",
    ),
    ErrorPattern(
        pattern=r"conversion failed.*when converting",
        dbms="mssql", category="syntax", confidence=0.85,
        description="MSSQL type conversion error",
    ),
    ErrorPattern(
        pattern=r"must declare the scalar variable",
        dbms="mssql", category="syntax", confidence=0.88,
        description="MSSQL undeclared variable",
    ),
    ErrorPattern(
        pattern=r"procedure.*does not exist",
        dbms="mssql", category="syntax", confidence=0.85,
        description="MSSQL stored procedure not found",
    ),

    # ── Oracle ───────────────────────────────────────────────────────────
    ErrorPattern(
        pattern=r"ora-\d{5}",
        dbms="oracle", category="syntax", confidence=0.95,
        description="Oracle ORA-XXXXX error — Oracle confirmed",
    ),
    ErrorPattern(
        pattern=r"quoted string not properly terminated",
        dbms="oracle", category="syntax", confidence=0.90,
        description="Oracle unterminated string",
    ),
    ErrorPattern(
        pattern=r"oracle.*error",
        dbms="oracle", category="syntax", confidence=0.80,
        description="Generic Oracle error",
    ),
    ErrorPattern(
        pattern=r"oracle.*driver",
        dbms="oracle", category="syntax", confidence=0.85,
        description="Oracle driver error",
    ),
    ErrorPattern(
        pattern=r"ora-01756",
        dbms="oracle", category="syntax", confidence=0.92,
        description="Oracle quoted string not properly terminated",
    ),
    ErrorPattern(
        pattern=r"ora-00933",
        dbms="oracle", category="syntax", confidence=0.90,
        description="Oracle SQL command not properly ended",
    ),
    ErrorPattern(
        pattern=r"ora-00942",
        dbms="oracle", category="syntax", confidence=0.85,
        description="Oracle table or view does not exist",
    ),
    ErrorPattern(
        pattern=r"ora-01789",
        dbms="oracle", category="syntax", confidence=0.85,
        description="Oracle query block has incorrect number of result columns",
    ),

    # ── SQLite ───────────────────────────────────────────────────────────
    ErrorPattern(
        pattern=r"sqlite3?\.operationalerror",
        dbms="sqlite", category="syntax", confidence=0.95,
        description="SQLite OperationalError — SQLite confirmed",
    ),
    ErrorPattern(
        pattern=r"sqlite.*error",
        dbms="sqlite", category="syntax", confidence=0.85,
        description="Generic SQLite error",
    ),
    ErrorPattern(
        pattern=r"unrecognized token",
        dbms="sqlite", category="syntax", confidence=0.85,
        description="SQLite unrecognized token",
    ),
    ErrorPattern(
        pattern=r"sqlite3\.ProgrammingError",
        dbms="sqlite", category="syntax", confidence=0.90,
        description="SQLite ProgrammingError",
    ),
    ErrorPattern(
        pattern=r"no such table",
        dbms="sqlite", category="syntax", confidence=0.80,
        description="SQLite table not found",
    ),
    ErrorPattern(
        pattern=r"near.*syntax error",
        dbms="sqlite", category="syntax", confidence=0.85,
        description="SQLite syntax error near token",
    ),

    # ── Generic SQL Errors ───────────────────────────────────────────────
    ErrorPattern(
        pattern=r"syntax error",
        dbms="generic", category="syntax", confidence=0.75,
        description="Generic SQL syntax error",
    ),
    ErrorPattern(
        pattern=r"division by zero",
        dbms="generic", category="overflow", confidence=0.80,
        description="Division by zero — injectable arithmetic context",
    ),
    ErrorPattern(
        pattern=r"invalid query",
        dbms="generic", category="syntax", confidence=0.75,
        description="Invalid query error",
    ),
    ErrorPattern(
        pattern=r"quoted string not properly terminated",
        dbms="generic", category="syntax", confidence=0.85,
        description="Unterminated quoted string (generic)",
    ),
    ErrorPattern(
        pattern=r"sql.*syntax.*error",
        dbms="generic", category="syntax", confidence=0.80,
        description="SQL syntax error (generic)",
    ),
    ErrorPattern(
        pattern=r"internal server error",
        dbms="generic", category="syntax", confidence=0.50,
        description="Internal server error (possible SQL crash)",
    ),
    ErrorPattern(
        pattern=r"unhandled.*exception",
        dbms="generic", category="syntax", confidence=0.60,
        description="Unhandled exception (possible SQL injection trigger)",
    ),
    ErrorPattern(
        pattern=r"database.*error",
        dbms="generic", category="syntax", confidence=0.70,
        description="Database error (generic)",
    ),
    ErrorPattern(
        pattern=r"query.*failed",
        dbms="generic", category="syntax", confidence=0.65,
        description="Query failed (generic)",
    ),
    ErrorPattern(
        pattern=r"sql.*exception",
        dbms="generic", category="syntax", confidence=0.75,
        description="SQL exception (generic)",
    ),
    ErrorPattern(
        pattern=r"prepared statement.*error",
        dbms="generic", category="syntax", confidence=0.80,
        description="Prepared statement error",
    ),

    # ── DVWA Blind SQLi Success/Failure Signals ───────────────────────
    ErrorPattern(
        pattern=r"user id exists in the database",
        dbms="mysql", category="extraction", confidence=0.96,
        description="DVWA Blind SQLi — User ID exists (TRUE response)",
    ),
    ErrorPattern(
        pattern=r"user id is missing from the database",
        dbms="mysql", category="extraction", confidence=0.96,
        description="DVWA Blind SQLi — User ID missing (FALSE response)",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# Known SQL error keyword fragments (for fuzzy/keyword matching fallback)
# ═══════════════════════════════════════════════════════════════════════════

_SQL_ERROR_KEYWORDS = [
    "sql syntax", "you have an error", "mysql_fetch", "mysql_num_rows",
    "mariadb", "microsoft ole db", "unclosed quotation mark",
    "unterminated quoted string", "pg_query", "pg_exec",
    "ora-", "sqlite3.operationalerror", "unrecognized token",
    "syntax error", "quoted string not properly terminated",
    "microsoft sql native client", "xpathsyntax", "xpath",
    "supplied argument is not a valid", "division by zero",
    "convert(", "cast(", "invalid column name", "duplicate entry",
    "for key", "double overflow", "extractvalue", "updatexml",
    "floor(", "rand(", "database error", "query failed",
    "sql exception", "prepared statement", "no such table",
    "unknown column", "doesn't exist", "subquery returns",
    "operand should contain", "incorrect.*parameter",
    "0x7e", "concat(", "group by", "order by",
    "user id exists in the database", "user id is missing from the database",
]


# ═══════════════════════════════════════════════════════════════════════════
# Knowledge Base Class
# ═══════════════════════════════════════════════════════════════════════════

class SQLErrorKB:
    """Centralized SQL error pattern knowledge base.

    Usage:
        kb = SQLErrorKB()
        matches = kb.match("XPATH syntax error: '~dvwa~'")
        # matches = [("xpath_error", 0.98, "mysql"), ("xpath_reflection", 0.95, "mysql")]

        score = kb.score("response text containing mysql_fetch_array error")
        # score = 0.92

        suggestions = kb.smart_extract(response_text)
        # [{"pattern": "...", "description": "...", "confidence": 0.8}]
    """

    def __init__(self, load_user_patterns: bool = True):
        self._patterns: list[ErrorPattern] = list(BUILTIN_PATTERNS)
        self._compiled: list[tuple[re.Pattern, ErrorPattern]] = []
        if load_user_patterns:
            self._load_user_patterns()
        self._compile_all()

    def _compile_all(self):
        """Pre-compile all regex patterns for performance."""
        self._compiled = []
        for p in self._patterns:
            try:
                compiled = re.compile(p.pattern, re.IGNORECASE)
                self._compiled.append((compiled, p))
            except re.error:
                continue

    def _load_user_patterns(self):
        """Load user-enriched patterns from JSON file."""
        if not os.path.exists(KB_PATH):
            return
        try:
            with open(KB_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("patterns", []):
                self._patterns.append(ErrorPattern(
                    pattern=entry["pattern"],
                    dbms=entry.get("dbms", "generic"),
                    category=entry.get("category", "syntax"),
                    confidence=entry.get("confidence", 0.80),
                    description=entry.get("description", "User-enriched pattern"),
                    source="user_enriched",
                ))
        except Exception:
            pass

    def match(self, text: str) -> list[tuple[str, float, str]]:
        """Find all matching patterns in text.

        Returns list of (description, confidence, dbms) tuples.
        Uses regex matching as primary, keyword matching as fallback.
        """
        if not text:
            return []
        results = []
        seen_descs = set()

        # Primary: regex matching
        for compiled, pat in self._compiled:
            if compiled.search(text):
                if pat.description not in seen_descs:
                    results.append((pat.description, pat.confidence, pat.dbms))
                    seen_descs.add(pat.description)

        # Fallback: keyword matching (for patterns that regex might miss)
        if not results:
            text_lower = text.lower()
            for keyword in _SQL_ERROR_KEYWORDS:
                if keyword in text_lower:
                    # Find the best matching builtin pattern for this keyword
                    for pat in BUILTIN_PATTERNS:
                        if keyword in pat.pattern.lower() and pat.description not in seen_descs:
                            results.append((pat.description, pat.confidence * 0.85, pat.dbms))
                            seen_descs.add(pat.description)
                            break

        return results

    def score(self, text: str) -> float:
        """Return the highest confidence score from any matching pattern.

        Returns 0.0 if no match.
        """
        if not text:
            return 0.0
        best = 0.0
        for compiled, pat in self._compiled:
            if compiled.search(text):
                best = max(best, pat.confidence)
        # Keyword fallback
        if best == 0.0:
            text_lower = text.lower()
            for keyword in _SQL_ERROR_KEYWORDS:
                if keyword in text_lower:
                    best = max(best, 0.70)
                    break
        return best

    def get_best_match(self, text: str) -> Optional[ErrorPattern]:
        """Return the highest-confidence matching pattern, or None."""
        if not text:
            return None
        best: Optional[ErrorPattern] = None
        best_score = 0.0
        for compiled, pat in self._compiled:
            if compiled.search(text) and pat.confidence > best_score:
                best = pat
                best_score = pat.confidence
        return best

    def get_dbms_hint(self, text: str) -> str:
        """Guess DBMS from error patterns in text."""
        if not text:
            return "unknown"
        # Priority: most specific match wins
        scores: dict[str, float] = {}
        for compiled, pat in self._compiled:
            if compiled.search(text):
                if pat.confidence > scores.get(pat.dbms, 0):
                    scores[pat.dbms] = pat.confidence
        if not scores:
            return "unknown"
        return max(scores, key=scores.get)

    def get_sql_error_keywords(self, text: str) -> list[str]:
        """Return list of matched error keywords/patterns found in text."""
        if not text:
            return []
        keywords = []
        for compiled, pat in self._compiled:
            if compiled.search(text):
                keywords.append(pat.description)
        return keywords

    def highlight_matches(self, text: str, max_preview: int = 1800) -> tuple[str, list[str]]:
        """Return (highlighted_preview, matched_keywords).

        Highlights matched patterns in the response text using << >> markers.
        Truncates to max_preview chars, centered around the first match.
        """
        if not text:
            return "", []

        matched_keywords = []
        match_positions = []

        # Find all match positions
        for compiled, pat in self._compiled:
            m = compiled.search(text)
            if m:
                matched_keywords.append(pat.description)
                match_positions.append((m.start(), m.end(), pat.description))

        if not match_positions:
            # No matches — return truncated text
            return text[:max_preview], []

        # Sort by position
        match_positions.sort(key=lambda x: x[0])

        # Center preview around first match
        first_match = match_positions[0][0]
        start = max(0, first_match - max_preview // 3)
        end = min(len(text), start + max_preview)
        if end - start < max_preview:
            start = max(0, end - max_preview)

        preview = text[start:end]

        # Apply highlighting (mark matched regions)
        # Work backwards to avoid offset shifts
        adjusted_positions = []
        for m_start, m_end, desc in match_positions:
            if m_start >= start and m_end <= end:
                adjusted_positions.append((m_start - start, m_end - start))

        # Insert markers in reverse order
        for m_start, m_end in sorted(adjusted_positions, reverse=True):
            preview = preview[:m_start] + "<<" + preview[m_start:m_end] + ">>" + preview[m_end:]

        if start > 0:
            preview = "..." + preview
        if end < len(text):
            preview = preview + "..."

        return preview, list(set(matched_keywords))

    # ── Smart Extract ────────────────────────────────────────────────────

    def smart_extract(self, text: str) -> list[dict]:
        """Auto-detect likely error patterns from response text and suggest adding to KB.

        Returns a list of suggested patterns:
        [{"pattern": "regex", "dbms": "mysql", "category": "syntax",
          "confidence": 0.8, "description": "...", "matched_text": "..."}]
        """
        if not text or len(text) < 20:
            return []

        suggestions = []
        seen = set()

        # 1. Look for SQL error-like sentences
        error_sentences = re.findall(
            r'[^<>\n]{10,150}(?:sql|syntax|query|mysql|postgresql|oracle|sqlite|'
            r'mssql|database|ora-\d{5}|pg_|mariadb)[^<>\n]{0,150}',
            text, re.IGNORECASE
        )
        for sentence in error_sentences:
            sentence = sentence.strip()
            if len(sentence) < 15 or sentence in seen:
                continue
            seen.add(sentence)

            # Check if it's already covered by KB
            if self.score(sentence) > 0.7:
                continue

            # Guess DBMS from content
            s_lower = sentence.lower()
            if any(k in s_lower for k in ["mysql", "mariadb", "mysqli"]):
                dbms = "mysql"
            elif any(k in s_lower for k in ["pg_", "postgresql", "psycopg"]):
                dbms = "postgresql"
            elif any(k in s_lower for k in ["ora-", "oracle"]):
                dbms = "oracle"
            elif any(k in s_lower for k in ["mssql", "microsoft", "sql server", "sqlserver"]):
                dbms = "mssql"
            elif "sqlite" in s_lower:
                dbms = "sqlite"
            else:
                dbms = "generic"

            # Extract a regex-safe fragment
            # Use the most distinctive part of the sentence
            fragment = re.escape(sentence[:80])
            # Simplify: keep only alphanumeric and spaces pattern
            simple = re.sub(r'[^a-zA-Z0-9\s]', '.', sentence[:60]).strip()

            suggestions.append({
                "pattern": simple,
                "dbms": dbms,
                "category": "syntax",
                "confidence": 0.75,
                "description": f"Extracted: {sentence[:80]}",
                "matched_text": sentence[:200],
            })

        # 2. Look for stack trace patterns
        stack_traces = re.findall(
            r'(?:at\s+\w+\.\w+\.\w+|File\s+"[^"]+",\s+line\s+\d+|'
            r'Traceback\s+\(most recent|Fatal error|Parse error|Warning:)',
            text, re.IGNORECASE
        )
        for trace in stack_traces:
            if trace not in seen:
                seen.add(trace)
                suggestions.append({
                    "pattern": re.escape(trace[:50]),
                    "dbms": "generic",
                    "category": "syntax",
                    "confidence": 0.60,
                    "description": f"Stack trace: {trace[:80]}",
                    "matched_text": trace[:200],
                })

        # 3. Look for ORA-XXXXX not already in KB
        ora_errors = re.findall(r'ORA-\d{5}[^<>\n]{0,100}', text, re.IGNORECASE)
        for ora in ora_errors:
            ora_clean = ora.strip()
            if ora_clean not in seen and self.score(ora_clean) < 0.5:
                seen.add(ora_clean)
                suggestions.append({
                    "pattern": re.escape(ora_clean[:50]),
                    "dbms": "oracle",
                    "category": "syntax",
                    "confidence": 0.85,
                    "description": f"Oracle error: {ora_clean[:80]}",
                    "matched_text": ora_clean,
                })

        return suggestions[:10]  # Limit to 10 suggestions

    # ── User Enrichment ──────────────────────────────────────────────────

    def add_pattern(
        self,
        pattern: str,
        dbms: str = "generic",
        category: str = "syntax",
        confidence: float = 0.80,
        description: str = "",
    ) -> bool:
        """Add a user-enriched pattern and persist to JSON.

        Returns True on success.
        """
        # Validate regex
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error:
            return False

        new_entry = ErrorPattern(
            pattern=pattern,
            dbms=dbms,
            category=category,
            confidence=confidence,
            description=description or f"User pattern: {pattern[:50]}",
            source="user_enriched",
        )
        self._patterns.append(new_entry)
        # Re-compile
        compiled = re.compile(pattern, re.IGNORECASE)
        self._compiled.append((compiled, new_entry))

        # Persist to JSON
        self._save_user_patterns()
        return True

    def _save_user_patterns(self):
        """Persist user-enriched patterns to JSON file."""
        user_patterns = [p for p in self._patterns if p.source == "user_enriched"]
        os.makedirs(os.path.dirname(KB_PATH), exist_ok=True)
        data = {
            "version": 1,
            "patterns": [
                {
                    "pattern": p.pattern,
                    "dbms": p.dbms,
                    "category": p.category,
                    "confidence": p.confidence,
                    "description": p.description,
                }
                for p in user_patterns
            ],
        }
        try:
            with open(KB_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def get_stats(self) -> dict:
        """Return KB statistics."""
        return {
            "total_patterns": len(self._patterns),
            "builtin": sum(1 for p in self._patterns if p.source == "builtin"),
            "user_enriched": sum(1 for p in self._patterns if p.source == "user_enriched"),
            "by_dbms": {dbms: sum(1 for p in self._patterns if p.dbms == dbms)
                       for dbms in set(p.dbms for p in self._patterns)},
        }


# Singleton for shared use
_kb_instance: Optional[SQLErrorKB] = None


def get_kb() -> SQLErrorKB:
    """Get or create the singleton KB instance."""
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = SQLErrorKB()
    return _kb_instance
