# AI Burp Copilot

AI Burp Copilot 是一个面向 Burp Suite 的 AI 辅助安全分析插件。它基于 Burp 中的真实 HTTP 流量，结合 LLM、规则化 Probe、JS AST 分析和本地历史数据库，辅助完成接口识别、攻击面分析、漏洞验证、静态资源分析、证据留存与报告整理。

项目定位不是“让大模型自由发包的自动扫描器”，而是一个更适合技术人员在 Burp 工作流中使用的分析与验证平台：

- LLM 负责理解接口语义、参数价值、攻击面和差异解释。
- 规则引擎负责按 YAML probe 执行可控、可复现的验证。
- JS AST 引擎负责恢复前端隐藏接口、脚本资源和敏感信息。
- 本地数据库负责保存历史流量、分析结果、验证证据和静态扫描详情。

---

## 功能概览

### 接口分析

- 从 Burp Proxy / Repeater / 右键 Send To 中接收 HTTP 请求响应。
- 识别接口类型、请求方法、参数位置、响应状态和内容类型。
- 调用 LLM 生成接口摘要、攻击面、推荐测试方向和高价值参数。
- 对接口进行去重、过滤、分类和历史保存。

### 漏洞验证

- 基于 LLM 分析结果和规则能力目录选择候选漏洞类型。
- 支持参数影响性判断、最小化变异、请求重放和响应差异分析。
- 通过 YAML probe 执行规则化验证，避免把发包逻辑硬编码在代码里。
- 对需要语义判断的结果支持 LLM 二次复核。
- 将验证过程中的请求、响应、证据、finding 和有效漏洞结果分开展示。

当前规则覆盖方向包括：

- SQL 注入
- XSS
- IDOR / 越权访问
- 认证 / JWT 问题
- 命令注入
- SSRF
- 路径遍历
- 开放重定向
- LDAP 注入
- GraphQL 暴露面
- 文件上传
- CORS
- SSTI
- XXE

### JS 静态分析

插件只对 JavaScript 资源做静态文件分析。JS 内容会发送到外部 JS AST 分析引擎：

- [zxcvbn001/js_analysis_engine](https://github.com/zxcvbn001/js_analysis_engine)

插件侧会提交：

- `url`：当前 JS URL
- `content`：当前 JS 文件内容
- `base_url`：用于降低相对路径解析误报的基础 URL
- `mode / fast_mode / async`：分析模式与异步任务配置

JS AST 返回结果会分成三类使用：

1. **API / Endpoint**
   - 展示到 Endpoints 表格。
   - 可按配置自动发包验证接口是否存在。
   - 验证存在后可写入历史流量，并进入接口分析链路。

2. **Sensitive / Exposure**
   - 展示到 Sensitive 表格。
   - 分析引擎侧已经做过增强判断，插件侧默认不再做 LLM 二次复核。

3. **Webpack / Script**
   - 展示到 Scripts 表格。
   - 可按配置探测脚本是否存在。
   - 可递归抓取并继续送入 JS AST 分析。

额外能力：

- 默认探测同名 `.js.map`，只展示确认存在的 source map。
- 支持异步任务提交、轮询、完成、失败、超时状态展示。
- 支持根据 JS AST 返回的 `method / url / params / headers / auth` 拼出候选请求包。

### 本地历史数据库

- 默认使用 SQLite 保存历史记录。
- 保存内容包括原始请求响应、接口分析、静态扫描、验证结果和 finding。
- 支持按站点、时间、风险、状态等条件检索。
- 支持清理和导出历史数据。

### Burp 右键菜单

在 Proxy / Repeater 的 message editor 中可右键发送到插件：

- 一键分析：执行完整流程。
- Endpoint 分析：只做接口分析链路。
- 静态文件分析：只做 JS 静态分析链路。

---

## 工作流

```text
Burp HTTP 流量
   |
   v
历史记录 / Send To / Proxy Handler
   |
   +--> Endpoint 识别
   |       |
   |       v
   |   LLM 接口分析
   |       |
   |       v
   |   参数影响性判断
   |       |
   |       v
   |   YAML Probe 验证
   |       |
   |       v
   |   Finding / 有效漏洞 / 报告
   |
   +--> JS 静态分析
           |
           +--> API / Endpoint 恢复、验证、入库、接口分析
           +--> Sensitive / Exposure 展示与留痕
           +--> Webpack / Script 探测与递归分析
```

---

## 环境要求

- Burp Suite，支持 Montoya API 的版本
- JDK 21
- Maven 3.9+
- 可选：JS AST 分析引擎服务

---

## 构建

```bash
mvn test
mvn -DskipTests package
```

构建产物：

```text
target/ai-burp-copilot-v2-jar-with-dependencies.jar
```

如果在 Windows 上使用本地 Maven / JDK，可以显式指定：

```powershell
& "D:\jdk\apache-maven-3.9.15-bin\apache-maven-3.9.15\bin\mvn.cmd" test
```

---

## 安装到 Burp

1. 打开 Burp Suite。
2. 进入 `Extensions -> Installed -> Add`。
3. Extension type 选择 `Java`。
4. 选择 `target/ai-burp-copilot-v2-jar-with-dependencies.jar`。
5. 插件加载后进入 `AI Burp Copilot` Tab。
6. 在设置页确认或加载配置目录。

---

## 配置目录

插件使用外置配置目录，目录结构如下：

```text
ai-burp-copilot/
├─ application.yml
├─ prompts/
├─ rules/
│  ├─ static-resource-rules.yaml
│  └─ payloads/
└─ data/
```

公开仓库提供脱敏模板：

```text
ai-burp-copilot-templates/
├─ application.yml
├─ prompts/
└─ rules/
```

### 默认加载顺序

插件会按下面顺序寻找配置目录：

1. UI 手动选择的配置目录。
2. JVM 参数 `-Daiburpcopilot.home=/path/to/ai-burp-copilot`。
3. 环境变量 `AI_BURP_COPILOT_HOME`。
4. 上一次保存的正式配置目录。
5. 插件 JAR 所在目录下的 `ai-burp-copilot`。
6. Burp 常见用户目录下的 `ai-burp-copilot`。
7. 当前工作目录下的 `ai-burp-copilot`。
8. 当前工作目录下的 `ai-burp-copilot-templates` 兜底。

配置目录必须包含：

- `application.yml`
- `prompts/`
- `rules/`

---

## 关键配置

### LLM

```yaml
llm:
  provider: openai
  model: gpt-4o-mini
  apiKey: YOUR_API_KEY_HERE
  apiUrl: https://api.openai.com/v1/chat/completions
  temperature: 0.3
  authorizationEnabled: true
  authHeaderName: Authorization
  authHeaderPrefix: Bearer
```

说明：

- `provider` 当前常用值包括 `openai`、`deepseek`、`qwen`。
- `apiUrl` 使用 OpenAI-compatible chat completions 格式。
- `extraHeaders` 可用于自定义网关 Header。

### 扫描

```yaml
scan:
  skipExtensions:
    - png
    - jpg
    - css
  skipKeywords:
    - logout
    - heartbeat
  skipStatusCodes:
    - 204
    - 304
  responseBodyScan:
    enabled: true
    maxSize: 204800
  staticScanMaxSize: 200
```

说明：

- `responseBodyScan.maxSize` 单位是字节。
- `staticScanMaxSize` 单位是 KB。
- 静态扫描当前只分析 JavaScript 资源。

### JS AST 分析

```yaml
jsAnalysis:
  enabled: true
  baseUrl: http://127.0.0.1:3000
  apiKey: YOUR_JS_ANALYSIS_API_KEY_HERE
  apiKeyHeader: x-api-key
  healthPath: /health
  analyzePath: /analyze/js
  mode: fast
  submitAsync: true
  taskPollIntervalMs: 1000
  taskTimeoutMs: 60000
  maxReferencedScripts: 6
  maxRecursiveDepth: 1
  maxVerifiedEndpointsPerScript: 12
  autoVerifyRecoveredApis: true
  autoAnalyzeVerifiedApis: true
  autoFetchReferencedScripts: true
```

说明：

- `mode` 支持 `fast` / `full`。
- `submitAsync` 建议保持 `true`，大文件更稳定。
- `autoVerifyRecoveredApis` 控制恢复出的接口是否自动发包验证。
- `autoAnalyzeVerifiedApis` 控制验证存在的接口是否进入 Endpoint 分析。
- `autoFetchReferencedScripts` 控制恢复出的 JS 脚本是否继续抓取和递归分析。

### JS 恢复接口请求构造

```yaml
jsAnalysis:
  requestBuilder:
    enabled: true
    appendParamsToQuery: true
    buildBodyForUnsafeMethods: false
    defaultBodyFormat: json
    placeholderValue: ""
    copyJsHeaders: true
    copyAuthSignalHeaders: false
    maxParams: 20
    maxHeaders: 12
```

说明：

- `appendParamsToQuery` 会把 JS AST 返回的参数补到 GET/DELETE/HEAD/OPTIONS 请求 query。
- `buildBodyForUnsafeMethods` 控制 POST/PUT/PATCH 是否自动构造 body，默认关闭，避免误操作。
- `copyJsHeaders` 会复制 JS AST 识别出的普通 Header。
- `copyAuthSignalHeaders` 默认关闭，不自动构造认证 Header。
- Cookie、Authorization、Proxy-Authorization 等敏感 Header 不会从 JS 结果直接复制。

### 存储

```yaml
storage:
  maxHistory: 2000
  cacheTtlSeconds: 3600
  maxCacheEntries: 5000
  historyDbPath: ""
```

说明：

- `historyDbPath` 为空时，默认使用配置目录下的 `data/history.db`。
- 不建议提交真实运行产生的数据库文件。

### 验证策略

```yaml
verification:
  enabled: true
  maxRequestsPerEndpoint: 5
  requestTimeoutSeconds: 10
  whitelist: []
  maxPayloadLength: 128
  allowedInfluenceActions:
    - READ
  allowedVerificationActions:
    - READ
```

说明：

- 生产或敏感环境建议只允许 `READ`。
- `CREATE / UPDATE / DELETE / AUTH / UNKNOWN / ALL` 需要明确授权后再开启。

---

## UI 模块

### Endpoint 分析

查看接口识别和 LLM 分析结果：

- 请求方法、URL、状态码
- Endpoint 类型
- 参数列表
- LLM 摘要
- 攻击面
- 高价值参数
- 推荐测试方向

### 静态扫描

查看 JS AST 分析结果：

- `Endpoints`：恢复出的 API / endpoint，以及访问验证状态。
- `Sensitive`：敏感信息、暴露项和风险信号。
- `Scripts`：webpack / script 资源、递归分析脚本和 source map。
- `Raw Findings`：JS 分析引擎返回的原始 finding 规整结果。
- `Params`：恢复出的参数。
- `Auth`：认证相关信号。
- `Tasks`：异步 JS AST 任务状态。

### 验证结果

查看 probe 验证过程：

- 候选漏洞类型
- 影响性判断
- 规则命中
- 请求/响应证据
- 本地 oracle 结果
- LLM 复核结果

### 有效漏洞

查看最终聚合出的有效漏洞。这里和 finding 是两层概念：

- Finding 表示某条规则或证据命中。
- 有效漏洞表示经过聚合、过滤和复核后认为可作为结果输出的漏洞。

如果 finding 中有结果但有效漏洞为空，通常需要查看：

- 置信度是否不足
- 是否被策略阻断
- 是否缺少必要请求/响应证据
- 是否被 LLM 复核降级
- 是否不满足最终聚合条件

### 设置

可在 UI 中修改：

- LLM 配置
- AI 通用参数
- JS AST 分析配置
- 静态扫描大小
- 自动验证恢复接口
- 自动分析已验证接口
- 自动抓取引用脚本
- JS 恢复接口请求构造
- SQLite 数据库路径
- 验证安全策略

---

## 规则编写

规则位于：

```text
ai-burp-copilot/rules/payloads/
```

一个漏洞类型通常对应一个 YAML 文件，例如：

```text
sqli.yaml
xss.yaml
auth.yaml
idor.yaml
```

典型结构：

```yaml
attackType: SQLI
aliases:
  - sql injection
  - sqli
workflow:
  skipInfluenceCheck: false
probes:
  - id: generic_boolean_pair_integer
    technique: BOOLEAN_BASED
    strategy: PAIR_DIFF
    strength: MEDIUM
    priority: 20
    stopOnMatch: true
    maxRequests: 2
    applicableParamTypes:
      - QUERY
      - BODY
    valueTypes:
      - NUMERIC
    requiresLlmReview: true
    payloadPairs:
      - trueValue: "..."
        falseValue: "..."
    oracle:
      type: PAIR_DIFF
      minConfidence: 0.7
```

常用字段：

- `attackType`：漏洞类型。
- `aliases`：别名，用于能力匹配。
- `workflow`：执行流程控制。
- `probes`：实际验证规则列表。
- `applicableParamTypes`：适用参数位置，如 `QUERY / BODY / PATH / HEADER / COOKIE`。
- `valueTypes`：适用值类型，如 `STRING / NUMERIC / URL / UUID / JWT / UNKNOWN`。
- `payloads`：单请求 payload。
- `payloadPairs`：true / false 成对 payload。
- `oracle`：命中判断方式。

规则 payload、`markers`、`oracle.keywords`、`oracle.requireMarkers` 和 `oracle.errorKeywords` 支持运行时随机变量。变量在每次 probe 执行时生成，同一个命名变量会在 payload 和 oracle 中保持一致：

```yaml
payloads:
  - value: ";echo {{randAlpha:cmdMarker:12}};"
    role: TRIGGER
    mutation: APPEND
oracle:
  type: KEYWORD
  keywords:
    - "{{randAlpha:cmdMarker:12}}"
```

可用变量：

- `{{rand:name:8}}` / `{{random:name:8}}`：随机字母数字。
- `{{randLower:name:8}}`：随机小写字母，适合标签名、文件名、域名前缀。
- `{{randAlpha:name:8}}`：随机字母。
- `{{randNum:name:6}}`：随机数字。
- `{{randHex:name:8}}`：随机十六进制。
- `{{uuid:name}}`：随机 UUID。
- `{{timestamp:name}}`：当前毫秒时间戳。
- `{{arithLeft:name}}` / `{{arithRight:name}}` / `{{arithResult:name}}`：同一组随机乘法表达式及结果，适合 SSTI 这类表达式验证。

常见 oracle：

- `PAIR_DIFF`
- `BASELINE_DIFF`
- `BASELINE_SIMILAR`
- `KEYWORD`
- `HTML_REFLECTION`
- `ERROR_KEYWORD_OR_RECOVERY`
- `TIME_DELAY`
- `REDIRECT_LOCATION`
- `EXPRESSION_EVALUATION`

扩展建议：

- 优先在现有 YAML 中新增 probe。
- 优先复用已有 oracle。
- 只新增 payload 或阈值时通常不需要改代码。
- 需要新的判断机制、请求改写方式或聚合逻辑时才需要改代码。

---

## 开发与调试

常用命令：

```bash
mvn test
mvn -DskipTests package
```

常见问题：

- 配置加载失败：检查实际加载目录是否包含 `application.yml / prompts / rules`。
- YAML 字段报错：检查 `application.yml` 是否包含旧字段或拼写错误。
- 规则未加载：检查 `rules/payloads` 是否存在 YAML 文件。
- JS 分析无结果：检查 `jsAnalysis.baseUrl / apiKey / healthPath / analyzePath`。
- SQLite 不可用：确认构建产物包含依赖，且数据库路径可写。
- UI 与实际 DB 不一致：以设置页展示的“当前存储路径”为准。

---

## 安全边界

请只在授权环境中使用本项目。

建议默认策略：

- JS 恢复接口自动验证可以开启，但写操作 body 构造默认关闭。
- 漏洞验证默认限制请求数和 payload 长度。
- 生产环境优先只允许 `READ` 类动作。
- 高风险规则、写操作验证和破坏性测试应手工确认后再执行。

本项目不承诺替代人工判断，尤其不适合单独完成：

- 深度业务逻辑漏洞审计
- 多步骤状态机漏洞
- 需要登录态切换的复杂越权链路
- 带外回连依赖较强的验证
- 高风险破坏性利用链

---

## 许可证与责任

本项目仅用于授权安全测试、安全研究和防御性验证。使用者需要自行确保测试目标、测试方式和测试范围均已获得授权。
