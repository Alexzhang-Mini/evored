# BypassEvo 使用指南

## 目录

- [快速启动](#快速启动)
- [LLM 配置](#llm-配置)
- [DVWA 靶场配置](#dvwa-靶场配置)
- [发起攻击](#发起攻击)
- [攻击流程](#攻击流程)
- [面板说明](#面板说明)
- [攻击场景](#攻击场景)
- [GA 引擎配置](#ga-引擎配置)
- [Rate Limit 配置](#rate-limit-配置)
- [代理集成](#代理集成)
- [故障排查](#故障排查)

---

## 快速启动

### Docker 一键启动（推荐）

```bash
cd evored
docker-compose up -d
```

| 服务 | 地址 | 用途 |
|---|---|---|
| Frontend | `http://localhost:3000` | 攻击面板 |
| Backend API | `http://localhost:8000` | 后端引擎 |
| DVWA | `http://localhost:8080` | 靶场 |
| Coraza PL1 | `http://localhost:9081` | WAF（低防护） |
| Coraza PL3 | `http://localhost:9083` | WAF（中防护） |
| Coraza PL5 | `http://localhost:9085` | WAF（高防护） |

```bash
docker-compose logs -f backend   # 查看后端日志
docker-compose down              # 停止所有服务
```

### 手动启动

**终端 1 — 后端：**

```bash
cd evored
pip install -r requirements.txt
python -m uvicorn backend.app:app --reload
```

**终端 2 — 前端：**

```bash
cd evored/frontend
npm install
npm run dev
```

**终端 3 — 靶场：**

```bash
# Docker 启动 DVWA + WAF
docker-compose up -d dvwa coraza-pl1

# 或仅启动 DVWA
docker run --rm -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

---

## LLM 配置

| 提供方 | API Base | Model | API Key |
|---|---|---|---|
| Ollama（本地推荐） | `http://localhost:11434/v1` | `qwen2.5:7b` | 留空 |
| DeepSeek | `https://api.deepseek.com` | `deepseek-chat` | 你的 key |
| LM Studio | `http://localhost:1234/v1` | 自选 | 留空 |
| vLLM | `http://localhost:8000/v1` | 自选 | 留空 |

```bash
# Ollama 安装模型
ollama pull qwen2.5:7b
```

---

## DVWA 靶场配置

1. 浏览器打开 `http://localhost:8080`
2. 登录：`admin` / `password`
3. 点击 **Create / Reset Database**
4. 左侧 **Security** → 设置为 **Low** → Submit
5. 获取 PHPSESSID：`F12` → Application → Cookies → 复制 `PHPSESSID`

---

## 发起攻击

打开 `http://localhost:3000`，在 Sidebar 配置：

### 1. LLM Config

| 字段 | 示例 | 说明 |
|---|---|---|
| API Base URL | `http://localhost:11434/v1` | Ollama 地址 |
| Model | `qwen2.5:7b` | 模型名 |
| Temperature | `0.7` | 越高越随机 |

### 2. Target Config

| 字段 | 示例 | 说明 |
|---|---|---|
| Target URL | `http://localhost:8080` | 目标地址 |
| Preset | `DVWA_SQLi_GET` | 预设自动填充 |
| Endpoint | `/vulnerabilities/sqli` | 攻击路径 |
| Parameter | `id` | 注入参数名 |
| Method | `GET` | HTTP 方法 |
| Vuln Type | `SQL Injection` | 漏洞类型 |

### 3. Authentication

| 字段 | 示例 | 说明 |
|---|---|---|
| Session ID | `abc123def...` | DVWA 的 PHPSESSID |
| Security Level | `Low` | DVWA 安全等级 |

### 4. 开始攻击

点击 **Start Attack**。

---

## 攻击流程

### 两阶段状态机 + 假设驱动

```
┌──────────────────────────────────────────────────────────────┐
│                    Stage 1: WAF Bypass                       │
│                                                              │
│  recon → waf_detect → bypass_generate → bypass_execute ──┐   │
│                              ▲                  │         │   │
│                              │                  ▼         │   │
│                              │            block_analyze   │   │
│                              │                  │         │   │
│                              │                  ▼         │   │
│  ┌───────────────────────────┘        hypothesis_refine   │   │
│  │                                          │             │   │
│  │                                          ▼             │   │
│  └──────────────────────── ga_bypass_evolve ◄┘             │   │
│                                                    │       │   │
│                                          bypass_success?   │   │
└────────────────────────────────────────────────────┼───────┘
                                                     │
┌────────────────────────────────────────────────────▼───────┐
│                    Stage 2: Exploit                        │
│                                                              │
│  exploit_generate → exploit_execute ──┐                     │
│       ▲                  │           │                     │
│       │                  ▼           │                     │
│  ga_exploit_evolve ◄─────┘           │                     │
│       │                              │                     │
│       └── exploit_success? ──→ DONE ─┘                     │
└──────────────────────────────────────────────────────────────┘
```

### 核心机制

**1. WAF 分析（block_analyze）**
- Binary Search 定位触发片段（最大 6 层递归）
- 边界探测 15+ 编码变体（大小写、注释、URL 编码、Unicode、全角、base64 等）
- LLM 推断 WAF 规则类型和盲区

**2. 假设驱动绕过（hypothesis_refine）**
- 首次获得 block 分析后，LLM 生成 3-5 个绕过假设
- 每个假设包含：机制名称、检测分析、盲区推理、种子 payload、变异策略
- GA 在每个假设空间内定向探索
- 测试后 LLM 评估：保留 / 精炼 / 淘汰
- 精炼时可提出新假设

**3. 失败分析 + 知识闭环**
- `infer_rules_from_blocked()`：从多个 403 响应推断 WAF 规则（触发关键词、编码感知、规则类型）
- 推断结果存入 ChromaDB 知识库
- 假设验证结果存入知识库（成功/失败 + 原因）
- 下一轮假设生成时，LLM 接收：推断规则 + 历史假设结果 + 已验证技术

**4. 策略感知 GA**
- 种群按 bypass family 分组初始化（comment_injection、encoding、whitespace 等）
- 变异策略与 family 匹配（如 comment family 做 `/**/` 变异，encoding family 做 URL 编码变异）
- 被 block 的响应差异化评分（0.05-0.35）：部分成功检测、响应长度差异、状态码区分

**5. 绕过验证**
- 绕过后重测 N 次防误报（默认 3 次，全部通过才算成功）
- Exploit 阶段再次验证：确认绕过技术对实际 exploit payload 也有效

---

## 面板说明

### Attack Console

| 区域 | 说明 |
|---|---|
| 状态徽标 | `idle` / `running` / `success` / `done` |
| 阶段指示器 | `Stage 1: WAF Bypass` 或 `Stage 2: Exploit` |
| 迭代计数 | 当前迭代 / 最大迭代 + GA 统计 |
| Rate Limit 卡片 | 当前延迟、退避等级、连续 block 次数 |
| Agent Thought Chain | 实时日志流（自动滚动） |
| Latest Response | 最新一次请求的结果 |
| WAF Bypassed | 绕过成功时显示技术名和 payload |
| Successful Payload | 漏洞确认时显示最终 payload |

### Evolution Lab

| 区域 | 说明 |
|---|---|
| GA Metrics | 当前代数、最佳/平均适应度、变异率、种群大小 |
| Fitness Evolution | 适应度随代数变化的折线图 |
| Population Distribution | 适应度分布直方图 |
| Payload Evolution Tree | 父子变异关系 |
| Top Payloads | 适应度最高的 5 个 payload |

### Intel Center

| 区域 | 说明 |
|---|---|
| WAF Detection | 检测到的 WAF 名称、置信度、已知绕过策略 |
| Memory Status | RAG 记忆条目数、成功率、后端类型 |
| Discovered Bypass Techniques | 已发现的绕过技术列表 |
| Block Analysis | 触发片段、规则类型、建议绕过 |
| Attack History | 完整攻击历史（按时间倒序） |
| Attack Report | 最终 Markdown 报告（可折叠） |

---

## 攻击场景

### DVWA 预设

| Preset | Endpoint | Param | Method | Vuln |
|---|---|---|---|---|
| `DVWA_SQLi_GET` | `/vulnerabilities/sqli` | `id` | GET | SQLi |
| `DVWA_SQLi_POST` | `/vulnerabilities/sqli` | `id` | POST | SQLi |
| `DVWA_XSS_R` | `/vulnerabilities/xss_r` | `name` | GET | XSS |
| `DVWA_XSS_S` | `/vulnerabilities/xss_s` | `txtName` | POST | XSS |
| `DVWA_CMDi` | `/vulnerabilities/exec` | `ip` | POST | CMDi |
| `JuiceShop_Search` | `/rest/products/search` | `q` | GET | SQLi |

### POST 多参数场景

登录接口等多参数场景，用 Extra POST Params 配置：

```
Target URL:      http://target.com:9020
Endpoint:        /goLogin
Parameter:       name          ← 注入点（被 payload 替换）
Method:          POST
Extra POST Params: {"_token": "xxx", "password": "123"}
```

实际发送的 body：`_token=xxx&name=payload&password=123`

### 自定义目标

```
Target URL:  http://your-target.com
Endpoint:    /api/search
Parameter:   q
Method:      GET
Vuln Type:   SQL Injection
```

---

## GA 引擎配置

| 参数 | 默认值 | 说明 |
|---|---|---|
| Population Size | `12` | 每代种群数量。越大搜索越广，请求越多 |
| Max Generations | `10` | 最大进化代数 |
| Crossover Rate | `0.7` | 交叉概率 |
| Mutation Rate | `0.15` | 变异概率 |

### 适应度评分

**SQLi：** SQL 错误(35%) + 时间异常(20%) + 内容偏移(20%) + 指标命中(15%) + 状态码(10%)

**XSS：** 反射指标(40%) + 内容偏移(35%) + SQL 错误(10%) + 状态码(10%) + 时间(5%)

**被 block 的响应：** 差异化评分 0.05-0.35（部分成功检测、响应长度差异、状态码区分）

### 调试建议

| 场景 | 调整 |
|---|---|
| 迭代太慢 | 减小 Population Size 或 Max Generations |
| 搜索不够 | 增大 Population Size 和 Max Generations |
| 多样性差 | 增大 Mutation Rate |
| 陷入局部最优 | 增大 Mutation Rate + 减小 Crossover Rate |

---

## Rate Limit 配置

| 参数 | 默认值 | 说明 |
|---|---|---|
| Request Delay | `1.0s` | 请求间隔 |
| Delay Jitter | `0.5s` | 随机抖动 |
| Jitter Distribution | `uniform` | `uniform` 或 `normal` |
| Backoff on 429 | `30.0s` | 429 基础等待 |
| Backoff Multiplier | `2.0` | 指数退避倍数 |
| Max Backoff | `120.0s` | 退避上限 |
| Block Pause | `60.0s` | 连续 block 超限暂停 |
| Max Consecutive Blocks | `10` | 连续 block 暂停阈值 |
| Verify Bypass Attempts | `3` | 绕过后重测次数 |

### 指数退避

```
第 1 次: 30s
第 2 次: 60s
第 3 次: 120s（上限）
```

成功响应后自动重置。

### 推荐配置

**本地靶场（无 WAF）：**
```
Request Delay: 0.1s | Jitter: 0s | Max Consecutive Blocks: 50
```

**有 WAF（Coraza PL1）：**
```
Request Delay: 1.0s | Jitter: normal | Backoff on 429: 30s
```

**生产级 WAF（Coraza PL5）：**
```
Request Delay: 3.0s | Jitter: normal | Backoff on 429: 60s | Max Blocks: 5
```

**Per-Stage 分离：** 勾选 `Custom Bypass Stage` / `Custom Exploit Stage` 可分别配置。

---

## 代理集成

| 选项 | 说明 |
|---|---|
| `None` | 不使用（默认） |
| `Auto-detect` | 自动检测 Burp/ZAP |
| `Burp Suite` | 连接 Burp REST API |
| `OWASP ZAP` | 连接 ZAP API |
| `Burp XML Export` | 导入 Burp 导出的 XML |

### Burp Suite

1. Burp → Project Options → Misc → REST API → Enable
2. BypassEvo 中选择 `Burp Suite`，URL 填 `http://127.0.0.1:1337`

### OWASP ZAP

1. ZAP → Tools → Options → API → 启用
2. BypassEvo 中选择 `OWASP ZAP`，填入 API Key

导入内容：历史请求/响应（最近 100 条）、自动提取参数、Cookie、注入点。

---

## 故障排查

### 连接失败

```
[ERROR] Connection refused
```

检查后端：`curl http://localhost:8000/api/health`

### LLM 无响应

```
[ERROR] LLM API error
```

1. `ollama list` 确认模型已下载
2. `curl http://localhost:11434/v1/models` 测试 API

### DVWA 登录失效

```
[SYSTEM] Baseline capture failed
```

重新获取 PHPSESSID，确认 Security Level = Low，数据库已初始化。

### 全部被 Block

```
[BYPASS-EXEC] BLOCKED (403) x N
```

1. 增大 Request Delay
2. 查看 Intel Center 的 Block Analysis 了解触发原因
3. 系统会自动分析 403 响应推断 WAF 规则，LLM 会基于推断结果生成新假设

### 前端无法连接后端

```
WebSocket connection failed
```

1. 确认后端在 `localhost:8000`
2. 检查浏览器控制台 CORS 错误
3. Docker 下确认服务在同一网络

### 目标不可达

```
[SYSTEM] TARGET UNREACHABLE — 4 consecutive connection failures
```

确认目标地址可达，端口开放，Docker 容器正在运行。

### 服务器错误

```
[SYSTEM] TARGET ERROR — 4 consecutive 502 responses
```

502 通常意味着目标容器未启动。检查 `docker-compose ps` 确认所有服务状态。
