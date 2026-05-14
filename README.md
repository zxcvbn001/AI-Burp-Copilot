# AI Burp Copilot v2

AI Burp Copilot v2 是一个基于 Burp Suite Montoya API 的 AI 辅助渗透测试插件。它的目标不是替代被动扫描器，也不是让大模型自由发挥去“猜漏洞”，而是把 Burp 中真实经过的 HTTP 流量转化为可审计、可复放、可验证的安全分析工作流。

项目当前重点围绕三件事：

- 对 HTTP 请求/响应进行 Endpoint 与攻击面分析。
- 基于规则和最小化 PoC 对参数进行影响性判断与漏洞验证。
- 使用 LLM 作为建议层和二次研判层，辅助解释差异、降低误报，而不是直接控制发包或判定漏洞。

> 当前版本仍处于快速演进阶段，验证效果依赖规则质量、目标站点行为、LLM 配置以及人工确认。自动验证是否发包由 `verification.enabled` 和策略配置控制。
>
> 本项目仅用于授权范围内的内部安全测试、安全研究和验证引擎评估；不得用于未授权攻击、破坏或绕过真实系统防护。

## 设计定位

AI Burp Copilot v2 的核心设计原则是：验证能力围绕 HTTP，而不是围绕单个漏洞类型。

- Replay 是通用 HTTP 能力，不属于 SQLI、XSS、IDOR 等某个漏洞模块。
- Diff 是通用响应差异能力，不写 `SqliDiff`、`XssDiff` 这类强绑定实现。
- AI 只做候选建议、差异解释、二次研判，不直接发包、不直接控制 Workflow。
- Verification Engine 脱离 AI 仍可运行；AI 不可用时仍能基于规则执行最小化验证。
- 新增漏洞类型优先新增 YAML 规则；`attackType`、`technique`、`strategy` 已经是动态字符串能力键，通常不需要修改 Java 枚举。
- 所有主动请求统一走 Execution Engine，禁止各模块自行发包。

## 当前能力

### 被动流量分析

- 挂载 Burp Proxy 流量，生成统一的 `HTTPContext`。
- 根据 URL、方法、参数、响应类型进行 Endpoint 分类。
- 支持状态码、扩展名、关键字等过滤。
- 静态资源可单独分析，例如 JS 中的接口、敏感信息、路径等。
- 历史记录只保存原始数据包与分析/验证结论，避免把内部验证请求污染到历史流量中。

### AI 分析

- 支持 OpenAI Compatible、DeepSeek、Qwen 风格接口。
- Prompt 文件外置，可按环境调整。
- Endpoint 分析的漏洞类型来自当前已加载并启用的规则能力，不再使用写死列表；关闭 XSS 规则后，prompt 不会再暴露 XSS。
- Endpoint 分析只输出泛化攻击类型，例如 SQL 注入、XSS、水平越权，不要求模型细分盲注、反射型 XSS 等具体子类型。
- Diff 与漏洞复核可以将规则证据、请求响应差异、关键片段交给 LLM 二次分析。

### 参数影响性分析

- 参数影响性与漏洞验证分离。
- 参数影响性用于回答：“这个参数是否参与服务端业务语义，是否值得继续验证？”
- 影响性结论分为 `INFLUENTIAL`、`UNCERTAIN`、`NOT_INFLUENTIAL`。对象 ID、用户 ID、订单 ID 等高价值参数即使响应摘要变化很小，也会被标记为 `UNCERTAIN` 并继续验证，避免过早剪枝。
- 支持人工修改影响性结论。
- 手动标记为有影响后，可触发后续漏洞验证。
- 同一参数即使被 AI 建议多个漏洞类型，也会尽量复用一次影响性结果，避免重复发包。

### 漏洞验证

- 支持基于规则的最小化 PoC 验证。
- 支持 SQLI、XSS、IDOR、SSRF、Path Traversal、Auth、Open Redirect、SSTI、XXE、JWT、GraphQL、CORS、File Upload、Command Injection、LDAP Injection 等规则文件。
- 支持 PoC 优先级、命中即停、请求数上限、证据权重。
- 支持请求/响应证据合并展示，例如 `Request 1`、`Response 1`。
- 支持有效漏洞聚合记录，并自动进入漏洞级 LLM/本地二次研判队列。

### Burp UI

插件主 Tab 当前包含：

1. 历史
2. Endpoint分析
3. 参数分析
4. 漏洞验证过程
5. 静态文件分析
6. 有效漏洞
7. 日志
8. 设置

请求和响应展示尽量复用 Burp 内置 message editor，方便搜索、复制、发送到 Repeater 等 Burp 原生操作。

## 工作流总览

典型被动分析链路：

```text
Burp Proxy HTTP 流量
  -> ProxyTrafficHandler
  -> HTTPContext
  -> AnalysisPipeline
  -> StatusCodeFilterStage
  -> EndpointClassificationStage
  -> StaticScanStage
  -> AIAnalysisStage
  -> WorkflowVerificationStage
  -> HistoryStage
  -> UI Panels
```

典型验证链路：

```text
候选参数
  -> 参数画像 / 参数类型识别
  -> Influence Gate
  -> Rule Capability 匹配
  -> Payload Rule 加载
  -> WorkflowStep 执行
  -> Parameter Mutation
  -> RequestExecutionEngine
  -> ReplayEngine
  -> Response Diff / Oracle
  -> Evidence Merge
  -> Finding Aggregation
  -> LLM Review / Human Confirmation
```

## 目录结构

```text
src/main/java/com/aiburpcopilot
├─ burp
│  ├─ extender              # Burp 扩展入口
│  ├─ proxy                 # Proxy 流量 Hook
│  └─ ui                    # Swing UI 与 Burp message editor 封装
├─ core
│  ├─ ai                    # LLM Provider 抽象与实现
│  ├─ cache                 # 内存缓存
│  ├─ config                # 配置加载与外置资源目录管理
│  ├─ context               # HTTPContext、参数、风险、攻击类型等核心模型
│  ├─ history               # 历史记录服务
│  ├─ pipeline              # 被动分析 Pipeline 与 Stage
│  └─ verification          # 验证引擎核心
├─ prompts                  # Prompt 服务
├─ rules                    # 规则加载服务
├─ scanner
│  ├─ endpoint              # Endpoint 分类与分析
│  └─ staticresource        # 静态资源扫描
├─ storage                  # 存储相关扩展点
└─ utils                    # 日志、JSON、HTTP、安全等工具
```

外置配置目录：

```text
ai-burp-copilot
├─ application.yml
├─ prompts
│  ├─ diff-judge-v1.txt
│  ├─ endpoint-analysis-v1.txt
│  ├─ endpoint-classifier-v1.txt
│  └─ static-review-v1.txt
└─ rules
   ├─ static-resource-rules.yaml
   └─ payloads
      ├─ auth.yaml
      ├─ command_injection.yaml
      ├─ cors.yaml
      ├─ file_upload.yaml
      ├─ graphql.yaml
      ├─ idor.yaml
      ├─ jwt.yaml
      ├─ ldap_injection.yaml
      ├─ open_redirect.yaml
      ├─ path_traversal.yaml
      ├─ sqli.yaml
      ├─ ssrf.yaml
      ├─ ssti.yaml
      ├─ xxe.yaml
      └─ xss.yaml
```

## 核心模块说明

### Burp 集成

- `AIBurpCopilotExtension`：Montoya 扩展入口，负责注册插件、初始化配置、UI、Pipeline。
- `ProxyTrafficHandler`：接收 Burp Proxy HTTP 流量，构造分析上下文。
- `BurpMessageViewer`：封装 Burp 内置请求/响应编辑器。
- `MainTab`：组装全部功能页面。

### Pipeline

- `AnalysisPipeline`：串联多个分析阶段。
- `StatusCodeFilterStage`：按状态码过滤，例如默认跳过 `204`、`304`。
- `EndpointClassificationStage`：识别普通接口、静态资源等。
- `StaticScanStage`：处理 JS、静态资源、敏感内容规则扫描。
- `AIAnalysisStage`：调用 LLM 做 Endpoint 建议分析。
- `WorkflowVerificationStage`：根据候选参数和规则触发影响性判断与漏洞验证。
- `HistoryStage`：落入历史记录并通知 UI。

### AI Provider

- `IAIProvider`：统一大模型调用接口。
- `OpenAICompatibleProvider`：兼容 `/v1/chat/completions` 风格接口。
- `DeepSeekProvider`：DeepSeek 配置适配。
- `QwenProvider`：Qwen/内部 AIHub 风格接口适配。
- `AIProviderFactory`：根据 `application.yml` 中的 `llm.provider` 创建 Provider。

### Verification Engine

验证引擎按能力分层：

- `candidate`：从请求和 AI 建议中提取候选参数。
- `influence`：参数影响性判断、最小化变异、LLM 影响分析。
- `mutation`：参数变异，包含 URL、Body、JSON 等参数处理。
- `execution`：统一请求执行入口。
- `diff`：响应差异计算和摘要。
- `probe`：规则化 PoC、Oracle、证据判断。
- `workflow`：按 Step 执行验证流程，Workflow 由 YAML 规则自动生成。
- `capability`：把已加载规则转成 AI 能力边界，过滤模型越界输出。
- `finding`：漏洞结论聚合。
- `policy`、`safety`、`rate_limit`：请求限流、安全策略和防失控保护。

### 静态文件分析

- `StaticResourceScanner`：静态资源扫描入口。
- `RegexRuleEngine`：基于 YAML 规则匹配敏感内容。
- 黑名单命中会跳过扫描，并在结果中备注跳过原因。
- JS 静态分析结果只应出现在静态文件分析页，不混入 Endpoint 分析页。

## 配置说明

默认配置文件位于：

```text
ai-burp-copilot/application.yml
```

插件只从用户指定的外部配置目录加载 `application.yml`、`prompts/` 和 `rules/`。JAR 中不再内置默认配置、Prompt 或规则；首次使用时需要在设置页选择包含这些文件的配置目录。

### 配置路径优先级

1. JVM 参数：`-Daiburpcopilot.home=...`
2. 环境变量：`AI_BURP_COPILOT_HOME`
3. Burp 当前工作目录下的 `ai-burp-copilot`
4. 插件 JAR 同级目录下的 `ai-burp-copilot`
5. 设置页手动加载的配置路径

推荐移动到其他电脑时，把以下两个东西放在一起：

```text
ai-burp-copilot-v2-jar-with-dependencies.jar
ai-burp-copilot/
```

如果配置加载异常，请在“设置 -> Config Directory”中选择实际配置目录。

### `llm`

```yaml
llm:
  provider: "deepseek"
  model: "deepseek-chat"
  apiKey: ""
  apiUrl: "https://api.deepseek.com/v1/chat/completions"
  temperature: 0.3
  connectTimeoutMs: 30000
  readTimeoutMs: 120000
  writeTimeoutMs: 120000
  maxRetries: 2
  sendModel: true
  sendTemperature: true
  sendMaxTokens: true
  authorizationEnabled: true
  authHeaderName: "Authorization"
  authHeaderPrefix: "Bearer"
  extraHeaders: {}
```

常见 Provider：

- `deepseek`
- `qwen`
- `openai`
- 其他 OpenAI Compatible 接口

如果你的接口类似：

```bash
curl -X POST http://host/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"hello"}]}'
```

通常应配置：

```yaml
llm:
  provider: "qwen"
  apiUrl: "http://host/v1/chat/completions"
  apiKey: "你的 key"
  sendModel: false
  sendTemperature: false
  sendMaxTokens: false
```

### `scan`

```yaml
scan:
  skipExtensions:
    - "css"
    - "png"
  skipKeywords:
    - "logout"
    - "heartbeat"
  skipStatusCodes:
    - 204
    - 304
  responseBodyScan:
    enabled: true
    maxSize: 204800
  staticScanMaxSize: 204800
```

- `skipExtensions`：按路径后缀跳过，支持带 query 的静态资源，例如 `.css?v=2021`。
- `skipKeywords`：URL 包含指定关键字时跳过。
- `skipStatusCodes`：跳过指定状态码。
- `responseBodyScan.maxSize`：响应体过大时不做正文分析。
- `staticScanMaxSize`：静态文件扫描最大体积。

### `ai`

```yaml
ai:
  maxTokens: 2048
  timeoutMs: 60000
  maxPromptLength: 8000
  rateLimitPerSecond: 5
```

控制 AI 调用的 token、超时、Prompt 长度和调用速率。

### `request`

```yaml
request:
  concurrency: 5
  maxQueueSize: 1000
```

控制内部异步请求处理能力，避免 UI 阻塞和请求队列失控。

### `storage`

```yaml
storage:
  maxHistory: 10000
  cacheTtlSeconds: 3600
  maxCacheEntries: 5000
```

控制历史记录和缓存大小。

### `verification`

```yaml
verification:
  enabled: false
  maxRequestsPerEndpoint: 5
  requestTimeoutSeconds: 10
  whitelist: []
  maxPayloadLength: 128
```

- `enabled`：是否开启自动漏洞验证。默认关闭，避免误发主动请求。
- `maxRequestsPerEndpoint`：单个 Endpoint 最大验证请求数。
- `requestTimeoutSeconds`：验证请求超时。
- `whitelist`：验证白名单。空数组 `[]` 表示默认全放行。
- `maxPayloadLength`：限制 PoC 长度，降低危险 Payload 风险。

## 规则说明

规则系统已经拆成独立文档，建议从这里开始阅读：[`docs/rule-authoring.md`](docs/rule-authoring.md)。

当前默认规则遵循三个原则：

- **最小化**：优先使用低风险、短 payload、少请求数的 PoC。
- **强约束**：通过 `applicableParamTypes` 和 `valueTypes` 限制探针适用范围，避免数字字段跑字符串 PoC、URL 字段跑无关探针。
- **可复核**：对 IDOR、SSRF、SQLI 布尔差异等容易误报的场景使用 `requiresLlmReview: true`，让 LLM 基于请求/响应差异和规则证据二次研判。
- **动态能力**：prompt、workflow 和 probe step 会基于当前已加载规则生成；新增漏洞大类通常只需要新增 YAML。

规则文件位置：

```text
ai-burp-copilot/rules/payloads/*.yaml
```

修改规则后建议先使用“参数分析”手动标记目标参数并触发后续验证，或在受控测试环境中开启自动验证。运行时规则只从已选择配置目录下的 `rules/payloads/` 加载。

### Prompt

Prompt 文件位于：

```text
ai-burp-copilot/prompts
```

- `endpoint-classifier-v1.txt`：Endpoint 分类。
- `endpoint-analysis-v1.txt`：Endpoint 攻击面建议。
- `static-review-v1.txt`：静态文件安全审查。
- `diff-judge-v1.txt`：响应差异与证据研判。

Prompt 应强调：

- 只输出已有规则支持的泛化漏洞类型。
- 不编造请求、不建议危险攻击流量。
- 区分业务差异、参数类型错误、框架校验错误和真实漏洞证据。
- 输出可解析、稳定、低温度的结构化结果。

## 使用方法

### 1. 构建

项目要求：

- JDK 21
- Maven 3.9+
- Burp Suite 支持 Montoya API

通用构建：

```bash
mvn -DskipTests package
```

Windows 本项目开发环境示例：

```powershell
$env:JAVA_HOME='D:\jdk\jdk21'
$env:Path='D:\jdk\jdk21\bin;D:\jdk\apache-maven-3.9.15-bin\apache-maven-3.9.15\bin;' + $env:Path
& 'D:\jdk\apache-maven-3.9.15-bin\apache-maven-3.9.15\bin\mvn.cmd' -DskipTests package
```

也可以直接运行：

```bat
build.bat
```

构建产物：

```text
target/ai-burp-copilot-v2-jar-with-dependencies.jar
```

在 Burp 中加载时建议选择 `jar-with-dependencies` 版本。

### 2. 安装到 Burp

1. 打开 Burp Suite。
2. 进入 `Extensions -> Installed -> Add`。
3. Extension type 选择 `Java`。
4. 选择 `target/ai-burp-copilot-v2-jar-with-dependencies.jar`。
5. 加载成功后会出现 `AI Burp Copilot` 主 Tab。

### 3. 准备外置配置

首次启动会自动生成：

```text
ai-burp-copilot/application.yml
ai-burp-copilot/prompts/
ai-burp-copilot/rules/
```

如果要移动到其他机器：

1. 复制插件 JAR。
2. 复制 `ai-burp-copilot` 目录。
3. 尽量让二者位于同一目录。
4. 如果设置页显示为空或加载到了 Burp 临时目录，在设置页手动指定 `application.yml` 路径。

### 4. 配置 LLM

在 `application.yml` 或设置页中配置：

- Provider
- Model
- API URL
- API Key
- 超时时间
- 重试次数

配置完成后点击 `Save & Apply`，或在设置页重新加载配置路径。

### 5. 被动分析

1. 确保 Burp Proxy 正常代理浏览器流量。
2. 正常访问目标系统。
3. 插件会对经过的请求进行过滤、Endpoint 分析、静态资源分析。
4. 在“历史”“Endpoint分析”“静态文件分析”查看结果。

### 6. 自动验证

默认 `verification.enabled` 为 `false`。如果要开启自动验证：

```yaml
verification:
  enabled: true
```

建议同时配置：

- 白名单或确认 `whitelist: []` 是否符合你的测试范围。
- `maxRequestsPerEndpoint`。
- `requestTimeoutSeconds`。
- 低风险、最小化 Payload 规则。

### 7. 参数分析

“参数分析”页用于查看和修正参数影响性结果。

- 如果自动影响性判断不准，可以手动标记。
- 标记为“有影响”后，可触发后续漏洞验证。
- 影响性分析和漏洞验证是两个阶段，不应混为一个结论。
- 同一参数被多个攻击类型命中时，影响性结果会尽量复用，避免重复发起相同影响性请求。

### 8. 有效漏洞

“有效漏洞”页保存聚合后的有效漏洞记录，并执行统一的漏洞级二次研判。

包含：

- 漏洞类型
- 参数名
- 置信度
- 证据数量
- 证据来源
- 请求/响应过程
- 二次研判状态：待研判、研判中、证据支持、证据不足、研判失败、本地研判
- LLM 或本地二次研判结果

二次研判的定位是“复核证据是否充分”，不是让 LLM 直接决定漏洞成立。步骤级 LLM Diff 解释会作为证据进入推理过程；最终有效漏洞页只展示漏洞级 Review 状态，避免把单个 Step 的解释误当成最终结论。

## 扩展新漏洞类型

推荐扩展顺序：

1. 在 `rules/payloads/` 新增 YAML 规则，填写 `attackType`、`aliases`、`workflow`、`probes`。
2. 优先复用现有 mutation 与 oracle：`KEYWORD`、`PAIR_DIFF`、`BASELINE_DIFF`、`BASELINE_SIMILAR`、`HTML_REFLECTION`、`REDIRECT_LOCATION`、`EXPRESSION_EVALUATION`、`TIME_DELAY`。
3. 如现有 oracle 不够，再新增通用 oracle；不要新增 `SqliDiff`、`XssDiff` 这类漏洞绑定实现。
4. 如确实需要新的 HTTP 行为，再新增通用 `VerificationStep` 或 mutation 能力。
5. 在参数分析页手动标记目标参数，或在受控环境中开启自动验证来验证规则效果。

原则：新增漏洞不应修改 Replay、Diff、Execution Engine 等核心 HTTP 能力。

## 安全边界

使用前请注意：

- 插件可能发起主动验证请求，请仅在授权测试范围内使用。
- 默认关闭自动验证，避免误扫生产系统。
- 不建议把危险 Payload 写进规则文件。
- 不建议把敏感 Cookie、Token、Authorization 明文暴露给不可信 LLM。
- 如果使用外部 LLM 服务，请确认数据合规要求。
- LLM 结果只作为建议和辅助研判，最终漏洞确认应由规则证据和人工复核共同决定。
- 对状态改变接口，例如更新、删除、支付、发信，应优先人工验证，谨慎自动发包。

## 常见问题

### 设置页为空或配置不生效

检查日志中的配置加载路径。如果显示加载到了 Burp 临时目录，例如：

```text
Loaded application.yml from: ...\Temp\burp...\ai-burp-copilot\application.yml
```

请在设置页手动选择真实配置目录，或设置环境变量：

```powershell
$env:AI_BURP_COPILOT_HOME='D:\tools\ai-burp-copilot'
```

### Qwen 返回 403

常见原因：

- `apiUrl` 路径不正确。
- 网关不接受 `model`、`temperature`、`max_tokens` 字段。
- API Key 没有该路由权限。

可尝试：

```yaml
llm:
  provider: "qwen"
  sendModel: false
  sendTemperature: false
  sendMaxTokens: false
```

### AI 超时

这通常不是插件崩溃，而是 LLM 响应超出超时时间。可以提高：

```yaml
llm:
  connectTimeoutMs: 30000
  readTimeoutMs: 120000
  writeTimeoutMs: 120000
  maxRetries: 2
```

同时建议降低 Prompt 长度或减少响应体片段。

### 验证没有执行

检查：

- `verification.enabled` 是否为 `true`。
- 是否被状态码、后缀、关键字过滤。
- 目标是否在白名单内；`whitelist: []` 表示默认放行。
- AI 是否只给出了建议但没有候选参数。
- 参数影响性是否被判定为无影响。
- 规则文件中是否存在对应 `attackType`。

### SQLI 误报

SQLI 尤其容易把“参数类型校验错误”误判为注入差异。推荐做法：

- 规则层同时收集正证据和负证据。
- Pair Diff 不只看相似度，还要关注错误来源、业务语义、真/假条件是否符合预期。
- 将请求、响应差异、规则证据交给 LLM 复核。
- 有效漏洞页中应保留人工确认入口。

### 高分辨率下 UI 字体或列宽异常

插件 UI 尽量复用 Burp 字体和 Swing 表格自适应列宽。如果仍然拥挤，优先检查 Burp 自身字体/缩放设置。

## 开发建议

- 修改 UI 文案时优先使用 UTF-8，必要时 Java 字符串可使用 Unicode 转义，避免中文乱码。
- 修改规则时先在参数分析页手动触发目标参数验证，确认稳定后再开启自动验证。
- 修改验证核心时优先保持 `Replay`、`Diff`、`Execution` 的通用性。
- 新增 AI 能力时不要让 AI 直接决定发包，只允许其输出建议、解释和二次研判。
- 对验证准确性问题，优先改 Oracle 和证据结构，不要针对单个框架错误硬编码特判。

## 许可证与状态

当前项目为 AI Burp Copilot v2 开发版本，主要用于授权安全测试、插件架构实验和验证引擎迭代。正式生产使用前建议先在测试环境中校验规则、发包策略和 LLM 数据合规性。
