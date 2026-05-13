# AI Burp Copilot 规则编写指南

这份文档专门说明 `rules/payloads/*.yaml` 的写法。目标是：看完后你可以自己新增或调整一个漏洞大类的最小化验证规则，而不需要改核心引擎。

## 1. 规则系统定位

AI Burp Copilot 的验证规则不是“攻击脚本”，而是“最小化证据探针”。

核心边界：

- AI 只能建议可能的漏洞类型和参数，不能直接发包。
- Workflow 负责组织验证步骤。
- Replay/Execution Engine 统一发包。
- Probe Rule 定义要发什么最小化 PoC、适合哪些参数、如何判断证据。
- Oracle 根据响应差异、关键词、反射、耗时等信号给出本地结论。
- LLM Review 只做二次研判，不替代人工确认。

新增漏洞时，优先新增：

1. `rules/payloads/<name>.yaml`
2. 插件注册或 Workflow Step
3. 必要时新增通用 Oracle 或通用 Step

不要为了某个漏洞去修改 Replay、Diff、Execution Engine 这类 HTTP 核心能力。

## 2. 文件位置与加载优先级

内置规则：

```text
src/main/resources/rules/payloads/*.yaml
```

运行时外置规则：

```text
ai-burp-copilot/rules/payloads/*.yaml
```

插件启动时会优先扫描外置目录。只要外置目录存在规则文件，同一个 `attackType` 会以外置文件为准。也就是说：

- 想改自己本机运行效果：改 `ai-burp-copilot/rules/payloads/*.yaml`。
- 想改项目默认规则并提交 GitHub：改 `src/main/resources/rules/payloads/*.yaml`。
- 发布新版本前，建议把两边规则同步，避免本地测试和打包默认行为不一致。

## 3. 顶层结构

## 2.1 动态能力加载

AI Endpoint 分析不会再使用写死的漏洞类型列表。启动或重新加载规则后，系统会读取当前已启用的 YAML probe，并生成“本地规则能力边界”追加到 prompt 中。

这意味着：

- `enabledByDefault: true` 且成功加载的 probe 会进入能力边界。
- 如果某个漏洞类型的所有 probe 都关闭，它不会出现在 prompt 能力列表中。
- AI 只能从能力边界中选择 attackType 和 technique。
- Workflow 和 GenericProbeStep 会基于已加载规则自动注册，不需要每个漏洞类型都写一个独立 Java Step。

当前仍保留一个兼容限制：`attackType`、`strategy`、`technique` 需要能映射到 Java 中已有枚举。也就是说，新增同类 HTTP 验证规则通常只改 YAML；但新增完全新的漏洞大类或全新的执行策略，仍需要补充一次枚举或通用 oracle。

推荐扩展路径：

1. 优先复用已有 `attackType`、`strategy`、`oracle` 写新 probe。
2. 如果只是新增 payload、优先级、适用参数类型，不改 Java。
3. 如果需要新判断方式，优先新增通用 oracle，例如 `REDIRECT_LOCATION`，不要写 `XxxDiff`。
4. 只有当需要新的 HTTP 行为时，才新增 Java 执行能力。

## 2.2 规则驱动 Workflow

规则文件不仅描述 payload，也可以描述该漏洞类型如何进入验证流程。

```yaml
workflow:
  name: AUTH Verification
  description: Header/Cookie authorization checks can run without parameter influence gate.
  includeInfluenceStep: false
  requiresInfluenceApproval: false
```

字段含义：

- `includeInfluenceStep`：是否执行参数影响性分析步骤。参数型漏洞通常为 `true`；Header、Cookie、端点级规则可设为 `false`。
- `requiresInfluenceApproval`：是否要求影响性结论通过后才继续验证。跳过 Influence Step 的规则通常也设为 `false`。
- `name` / `description`：进入 workflow、日志和 AI 能力边界的说明。

推荐原则：

- 参数型规则：默认走 `InfluenceValidation -> GenericProbeStep`。
- 非参数型规则：由规则显式跳过 Influence Gate。
- 是否跳过 Gate 应该由规则声明，不应在 Java 中针对某个漏洞硬编码。

最小规则文件：

```yaml
attackType: XSS
goal: CONFIRM_ATTACK_TYPE

probes:
  - id: xss_harmless_html_reflection
    technique: REFLECTION
    strategy: BOOLEAN_BASED_MINIMAL
    priority: 10
    stopOnMatch: true
    maxRequests: 1
    evidenceWeight: 0.85
    payloads:
      - value: "<aaaa>bbbb</aaaaa>"
        role: TRIGGER
        mutation: APPEND
    oracle:
      type: HTML_REFLECTION
      minConfidence: 0.72
```

### `attackType`

最终聚合的漏洞大类。

当前常用值：

- `SQLI`
- `XSS`
- `IDOR`
- `SSRF`
- `AUTH`
- `PATH_TRAVERSAL`
- `OPEN_REDIRECT`
- `SSTI`

注意：这里写大类，不写“布尔盲注”“反射型 XSS”这类子类型。

### `goal`

规则目标。当前推荐统一写：

```yaml
goal: CONFIRM_ATTACK_TYPE
```

含义是：规则只负责确认漏洞大类是否有足够证据成立。

### `probes`

探针列表。一个 probe 是一组最小化验证请求及其证据判断方式。

同一漏洞大类可以有多个 probe，通过 `priority` 控制顺序，通过 `stopOnMatch` 控制命中后是否停止。

## 4. Probe 字段

### `id`

探针唯一标识，用于日志、证据和 UI 展示。

建议格式：

```text
<attack>_<scenario>_<oracle>
```

例如：

- `generic_quote_error_recovery`
- `generic_boolean_pair_integer`
- `idor_numeric_neighbor_plus`
- `xss_harmless_html_reflection`

### `technique`

验证技术标签，主要用于 UI、日志、证据描述和能力约束。

示例：

```yaml
technique: BOOLEAN_BASED
technique: ERROR_BASED
technique: REFLECTION
technique: NUMERIC_INCREMENT
```

### `strategy`

执行策略，必须能映射到 `StrategyType`。

当前常用值：

- `BOOLEAN_BASED_MINIMAL`
- `ERROR_BASED`
- `TIME_BASED`
- `UNION_BASED`
- `NUMERIC_INCREMENT`
- `UUID_SWAP`
- `REMOVE_TOKEN`
- `ROLE_SWITCH`
- `LOCALHOST_PROBE`
- `PATH_TRAVERSAL_PROBE`
- `OPEN_REDIRECT_PROBE`
- `TEMPLATE_EXPRESSION`

策略会受到验证策略控制。例如 `TIME_BASED`、`UNION_BASED`、`ERROR_BASED` 可以被 policy 禁用。

### `enabledByDefault`

是否默认启用。

```yaml
enabledByDefault: false
```

建议默认关闭：

- 延时类 PoC
- DBMS 专用 PoC
- 需要真实第二账号/第二对象上下文的 PoC
- Header/Cookie 认证类 PoC
- 可能造成业务状态变化的 PoC

### `priority`

优先级，数字越小越早执行。

建议：

- `1-19`：低风险通用探针
- `20-49`：特定技术或特定参数类型探针
- `50-89`：需要上下文或容易误报的探针
- `90+`：默认关闭或高成本探针

### `stopOnMatch`

命中后是否停止后续 probe。

```yaml
stopOnMatch: true
```

默认推荐 `true`。验证目标是“足够证据”，不是把所有 payload 跑完。

### `maxRequests`

当前 probe 最多发几个请求。

```yaml
maxRequests: 2
```

建议：

- 单 payload：`1`
- 触发/恢复：`2`
- true/false pair：`2`
- 多平台路径遍历：不超过 `3`

最终还会受到全局 `verification.maxRequestsPerEndpoint` 限制。

### `maxPayloadLength`

限制 payload 或变异后值的最大长度。

```yaml
maxPayloadLength: 64
```

这个字段用于降低误发危险 payload 的风险。规则越通用，长度越应该保守。

### `evidenceWeight`

证据权重，范围 `0.0-1.0`。

它不会单独决定漏洞成立，而是参与整体置信度聚合。

建议：

- 强确定证据，例如明确数据库错误：`0.85-0.95`
- 反射证据：`0.70-0.90`
- 语义 diff 候选，例如 IDOR/SSRF：`0.55-0.75`
- 仅相似度变化：不要给太高

### `applicableParamTypes`

限制参数位置。

可选值：

- `QUERY`
- `BODY`
- `HEADER`
- `PATH`
- `COOKIE`

示例：

```yaml
applicableParamTypes: [QUERY, BODY, PATH]
```

建议：

- SQLI/XSS/Path Traversal：通常是 `[QUERY, BODY, PATH]`
- SSRF：通常是 `[QUERY, BODY]`
- AUTH：通常是 `[HEADER, COOKIE]`
- IDOR：通常是 `[QUERY, BODY, PATH]`

如果不写，表示不限制参数位置。

### `valueTypes`

限制原始参数值类型。

可选值来自参数画像：

- `NUMERIC`
- `UUID`
- `JWT`
- `BASE64`
- `BOOLEAN`
- `JSON`
- `EMAIL`
- `URL`
- `STRING`
- `UNKNOWN`

示例：

```yaml
valueTypes: [NUMERIC]
```

这个字段非常关键，能显著降低误报和无效请求。

建议：

- SQLI 字符串探针：`[STRING, EMAIL, URL, UNKNOWN]`
- SQLI 数字探针：`[NUMERIC]`
- XSS：`[STRING, EMAIL, URL, UNKNOWN]`
- IDOR 数字增减：`[NUMERIC]`
- IDOR UUID 替换：`[UUID]`
- SSRF：`[URL, STRING, UNKNOWN]`
- Path Traversal：`[STRING, URL, UNKNOWN]`

### `requiresLlmReview`

是否要求 LLM 二次研判。

```yaml
requiresLlmReview: true
```

当它为 `true` 时：

- 本地 Oracle 命中后，必须有 LLM 可用且返回 `matched=true`，才会作为命中证据。
- 如果 LLM 未配置、超时或返回不可解析 JSON，该 probe 会被降级为未命中。

建议开启：

- IDOR
- SSRF
- AUTH
- SQLI `PAIR_DIFF`
- 任何只靠相似度或语义差异判断的规则

不建议开启：

- 明确关键词命中，例如 `root:x:`、真实数据库报错。
- 简单反射证据，但最终仍需人工确认。

## 5. Payload 写法

### 单 payload：`payloads`

```yaml
payloads:
  - value: "'"
    role: TRIGGER
    mutation: APPEND
```

字段说明：

- `value`：payload 值。
- `role`：payload 角色。
- `mutation`：如何修改原参数。
- `markers`：反射类规则需要命中的标记。

### Payload 角色：`role`

可选值：

- `TRIGGER`：触发异常或差异的 payload。
- `RECOVERY`：恢复 payload，例如 SQLI 中 `''`。
- `TRUE_CASE`：布尔真条件。
- `FALSE_CASE`：布尔假条件。
- `SINGLE`：普通单次探针。

### 变异方式：`mutation`

可选值：

- `REPLACE`：直接替换原值。
- `APPEND`：保留原值，在后面追加 payload。
- `ADD`：数值加法，适合 IDOR。
- `SUBTRACT`：数值减法，适合 IDOR。

示例：

```yaml
# 原始 id=100 -> id=101
payloads:
  - value: "1"
    mutation: ADD
    role: TRIGGER
```

```yaml
# 原始 q=abc -> q=abc'
payloads:
  - value: "'"
    mutation: APPEND
    role: TRIGGER
```

### 成对 payload：`payloadPairs`

用于 true/false 对比。

```yaml
payloadPairs:
  - trueValue: "' AND 1=1--"
    falseValue: "' AND 1=2--"
    trueMutation: APPEND
    falseMutation: APPEND
```

字段说明：

- `trueValue`：真条件 payload。
- `falseValue`：假条件 payload。
- `trueMutation`：真条件变异方式。
- `falseMutation`：假条件变异方式。
- `mutation`：如果两个都一样，也可以用统一字段。

优先使用 `APPEND` 保留原值，尤其是 SQLI。直接 `REPLACE` 很容易让业务参数失去上下文，导致结果不稳定。

## 6. Oracle 写法

Oracle 决定如何把响应转成证据。

### `ERROR_KEYWORD`

只判断响应中是否出现 baseline 没有的新错误关键词。

```yaml
oracle:
  type: ERROR_KEYWORD
  errorKeywords:
    - "sql syntax"
    - "sqlstate"
  minConfidence: 0.82
```

适合：

- 明确数据库错误。
- 文件读取错误。

不适合：

- 普通参数类型错误。
- 框架校验错误。

### `ERROR_KEYWORD_OR_RECOVERY`

触发 payload 出现错误关键词，恢复 payload 不再出现错误关键词时置信度更高。

```yaml
payloads:
  - value: "'"
    role: TRIGGER
    mutation: APPEND
  - value: "''"
    role: RECOVERY
    mutation: APPEND
oracle:
  type: ERROR_KEYWORD_OR_RECOVERY
```

适合 SQLI 最小化报错验证。

### `PAIR_DIFF`

比较 true/false 响应差异，并可结合 LLM 研判。

```yaml
oracle:
  type: PAIR_DIFF
  minSimilarityTrueBaseline: 0.90
  maxSimilarityTrueFalse: 0.80
  minConfidence: 0.78
```

字段含义：

- `minSimilarityTrueBaseline`：真条件响应与 baseline 至少多相似。
- `maxSimilarityTrueFalse`：真/假响应相似度低到什么程度才算差异明显。

建议给 `PAIR_DIFF` 加：

```yaml
requiresLlmReview: true
```

因为很多业务校验错误也会造成 true/false 响应不同。

### `TIME_DELAY`

判断响应耗时是否达到阈值。

```yaml
oracle:
  type: TIME_DELAY
  minDelayMs: 2500
  baselineMultiplier: 2.5
  minConfidence: 0.86
```

建议默认关闭对应 probe：

```yaml
enabledByDefault: false
```

### `KEYWORD`

判断响应中是否出现新增关键词。

```yaml
oracle:
  type: KEYWORD
  keywords:
    - "root:x:"
    - "[extensions]"
  minConfidence: 0.82
```

适合路径遍历、文件读取这类明确标记。

### `REDIRECT_LOCATION`

只根据 HTTP 状态码和 `Location` 响应头判断可控跳转，不依赖响应正文相似度。

```yaml
oracle:
  type: REDIRECT_LOCATION
  requireMarkers:
    - "example.com"
    - "ai-burp-copilot-open-redirect"
  minConfidence: 0.82
```

适合 Open Redirect。要求响应状态码为 `3xx`，且 `Location` 中包含规则指定的 marker。

### `EXPRESSION_EVALUATION`

判断模板表达式是否被服务端求值。它要求结果 marker 出现在响应中，同时原始表达式不能只是被原样反射。

```yaml
payloads:
  - value: "{{7*7}}"
    role: TRIGGER
    mutation: APPEND
    markers:
      - "49"
oracle:
  type: EXPRESSION_EVALUATION
  requireMarkers:
    - "49"
  minConfidence: 0.78
```

适合 SSTI 的低风险算术表达式验证。不要默认使用文件读取、命令执行或高副作用表达式。
### `BASELINE_DIFF`

判断变异响应与 baseline 是否存在显著差异。

```yaml
oracle:
  type: BASELINE_DIFF
  maxSimilarityTrueFalse: 0.96
  minConfidence: 0.55
```

适合：

- IDOR 候选。
- SSRF 候选。

强烈建议配合：

```yaml
requiresLlmReview: true
```

### `BASELINE_SIMILAR`

判断变异后响应仍与 baseline 接近。

```yaml
oracle:
  type: BASELINE_SIMILAR
  minSimilarityTrueBaseline: 0.90
  minConfidence: 0.62
```

常用于认证绕过候选，例如移除 token 后仍能访问。但这类规则非常依赖业务上下文，默认建议关闭。

### `HTML_REFLECTION`

判断响应是否出现未转义 HTML 反射痕迹。

```yaml
oracle:
  type: HTML_REFLECTION
  requireExactPayload: false
  requireUnescaped: true
  requireMarkers:
    - "bbbb"
  minConfidence: 0.72
```

字段说明：

- `requireExactPayload`：是否要求完整 payload 原样出现。
- `requireUnescaped`：是否要求出现未转义 HTML 痕迹。
- `requireMarkers`：必须出现的业务无害标记。

## 7. SQLI 规则建议

推荐默认只开三类：

1. 字符串单引号触发/恢复。
2. 字符串 true/false pair，要求 LLM 复核。
3. 数字 true/false pair，要求 LLM 复核。

示例：

```yaml
- id: generic_boolean_pair_integer
  technique: BOOLEAN_BASED
  strategy: BOOLEAN_BASED_MINIMAL
  priority: 3
  stopOnMatch: true
  maxRequests: 2
  maxPayloadLength: 64
  evidenceWeight: 0.80
  applicableParamTypes: [QUERY, BODY, PATH]
  valueTypes: [NUMERIC]
  requiresLlmReview: true
  payloadPairs:
    - trueValue: " AND 1=1"
      falseValue: " AND 1=2"
      trueMutation: APPEND
      falseMutation: APPEND
  oracle:
    type: PAIR_DIFF
    minSimilarityTrueBaseline: 0.90
    maxSimilarityTrueFalse: 0.80
    minConfidence: 0.78
```

不要把“参数类型校验错误”当 SQLI 证据。一个健康的判断应同时考虑：

- 真条件是否接近 baseline。
- 假条件是否产生业务层差异，而不是纯类型解析错误。
- true/false 是否只是在错误响应中反射了不同 payload。
- LLM 是否能基于响应差异说明“为什么支持 SQLI”。

## 8. XSS 规则建议

优先使用无害 HTML marker，不要默认使用 `<script>alert(1)</script>`。

示例：

```yaml
payloads:
  - value: "<aaaa>bbbb</aaaaa>"
    role: TRIGGER
    mutation: APPEND
    markers:
      - "bbbb"
      - "<aaaa"
oracle:
  type: HTML_REFLECTION
  requireExactPayload: false
  requireUnescaped: true
  requireMarkers:
    - "bbbb"
```

判断目标是：参数值是否以 HTML 语境未转义反射。最终是否可执行仍需要人工结合上下文确认。

## 9. IDOR 规则建议

IDOR 的默认探针应该围绕“对象标识变异”：

- 数字 ID：`ADD 1`、`SUBTRACT 1`
- UUID：只有在有真实相邻对象或测试对象时再启用
- 用户名/订单号：需要业务字典或上下文，不建议写死默认值

示例：

```yaml
- id: idor_numeric_neighbor_plus
  strategy: NUMERIC_INCREMENT
  applicableParamTypes: [QUERY, BODY, PATH]
  valueTypes: [NUMERIC]
  requiresLlmReview: true
  payloads:
    - value: "1"
      mutation: ADD
      role: TRIGGER
  oracle:
    type: BASELINE_DIFF
    maxSimilarityTrueFalse: 0.96
    minConfidence: 0.55
```

LLM 复核应重点看：

- 资源归属字段是否变化。
- 用户 ID、订单 ID、邮箱、手机号等稳定业务字段是否变化。
- 是否只是 404、空列表、通用错误。
- 是否存在“请求成功但对象变了”的证据。

## 10. SSRF 规则建议

没有带外回连时，SSRF 只能做候选验证，不能强确认。

默认低风险样例：

```yaml
payloads:
  - value: "http://127.0.0.1/"
    role: TRIGGER
  - value: "http://localhost/"
    role: TRIGGER
oracle:
  type: BASELINE_DIFF
```

建议：

- `requiresLlmReview: true`
- 限制 `valueTypes: [URL, STRING, UNKNOWN]`
- 默认不要探测内网网段
- 后续最好接入 collaborator/带外 DNS/HTTP 证据

## 11. AUTH 规则建议

认证/授权类规则强依赖上下文。当前默认关闭。

如果你要启用，建议满足至少一个条件：

- 有低权限 token 和高权限 token。
- 有两个测试账号。
- 请求是只读接口。
- 能明确判断“移除 token 后仍访问成功”不是缓存或匿名访问。

启用时在外置规则里改：

```yaml
enabledByDefault: true
```

并把 payload 改成你的测试环境真实安全样本。

## 12. Path Traversal 规则建议

路径遍历适合关键词 Oracle，因为文件内容有明确 marker。

注意：

- 限制参数类型和值类型。
- 默认不超过 3 个 payload。
- 不要默认跑大量编码绕过 payload。

## 13. 策略与规则的关系

规则执行会受到全局配置和 Policy 限制：

```yaml
verification:
  enabled: false
  maxRequestsPerEndpoint: 5
  requestTimeoutSeconds: 10
  whitelist: []
  maxPayloadLength: 128
```

影响：

- `enabled: false` 时不会自动验证，但手动工作台仍可用于验证。
- `maxRequestsPerEndpoint` 会限制单个 endpoint 的总验证请求数。
- `maxPayloadLength` 会限制 payload 长度。
- policy 禁用 `TIME_BASED`、`UNION_BASED`、`ERROR_BASED` 时，对应 probe 不会执行。

## 14. 参数影响性 Gate 与规则的关系

漏洞规则执行前通常会经过 Influence Gate。它现在不是简单判断“响应是否变化”，而是判断“参数是否参与服务端业务语义，是否值得继续验证”。

Influence Gate 有三种结论：

- `INFLUENTIAL`：响应差异、LLM 分析或稳定业务字段变化足以说明参数有影响。
- `UNCERTAIN`：响应差异不明显，但参数具备强业务语义先验，不应该提前剪枝。
- `NOT_INFLUENTIAL`：响应无明显变化，参数名和值类型也缺少业务语义，通常不继续验证。

典型 `UNCERTAIN` 场景：

```text
/?id=1&Submit=Submit
/?id=2&Submit=Submit
```

两个响应都显示“用户存在”，页面摘要几乎一样，但 `id` 是数字对象标识，仍可能影响服务端查询对象。此时 Gate 应放行到 IDOR、SQLI、XSS 等后续规则，而不是直接判“无影响”。

规则编写时要注意：

- IDOR、水平越权、对象访问类规则不要强依赖明显 diff。
- 对 `id/userId/orderId/fileId/*_id` 这类参数，优先使用 `valueTypes: [NUMERIC]` 或 `[UUID]` 进行精确约束。
- `requiresLlmReview: true` 适合对 `UNCERTAIN` 结果做二次研判，但不能替代后续验证证据。
- Influence Gate 只决定“是否继续”，不决定“漏洞成立”。

## 15. 调试流程

写完规则后按这个顺序验证：

1. 打开 Burp，加载插件。
2. 确认日志显示加载的是你期望的 `ai-burp-copilot/rules/payloads/*.yaml`。
3. 在“参数分析”页选择目标参数，必要时手动标记为有影响并触发后续验证。
4. 查看“漏洞验证过程”中的 Request/Response。
5. 检查是否只跑了预期数量的请求。
6. 检查 diff summary 和 evidence 是否能解释命中原因。
7. 在“有效漏洞”页确认漏洞级二次研判状态和 Review 内容。
8. 低风险确认后再开启自动验证。

## 16. 常见错误

### 数字 JSON 字段被拼成非法 JSON

如果原字段是数字，payload 是字符串 SQL 片段，JSON 变异器可能会把该字段转成字符串以保持 JSON 合法，但业务后端仍可能返回类型错误。

解决：

- 给 SQLI 字符串 probe 加 `valueTypes: [STRING, EMAIL, URL, UNKNOWN]`。
- 给数字 probe 单独写 `valueTypes: [NUMERIC]`。
- 对数字 SQLI pair 加 `requiresLlmReview: true`。

### AI 把参数值当参数名

规则不能解决这个问题，需要 Endpoint 分析层约束 AI 输出，并用 `HTTPContext` 中真实参数名纠正。规则侧可以通过 `applicableParamTypes` 和 `valueTypes` 降低后续误跑概率。

### IDOR 响应都显示 update success

这类情况不能只看响应变化。需要：

- 复放后查询对象状态。
- 使用二次请求确认对象归属变化。
- 引入业务上下文或 LLM 语义复核。

当前 `BASELINE_DIFF` 只能作为候选证据，不能替代完整业务验证。

### LLM 未配置导致规则不命中

如果 probe 写了：

```yaml
requiresLlmReview: true
```

那么 LLM 不可用时该 probe 不会确认命中。这是刻意设计，用于避免高误报规则在无人复核时自动报漏洞。

## 17. 推荐规则模板

### 低风险单请求反射模板

```yaml
- id: example_reflection
  technique: REFLECTION
  strategy: BOOLEAN_BASED_MINIMAL
  priority: 10
  stopOnMatch: true
  maxRequests: 1
  maxPayloadLength: 64
  evidenceWeight: 0.80
  applicableParamTypes: [QUERY, BODY, PATH]
  valueTypes: [STRING, UNKNOWN]
  payloads:
    - value: "<aaaa>bbbb</aaaaa>"
      role: TRIGGER
      mutation: APPEND
      markers: ["bbbb"]
  oracle:
    type: HTML_REFLECTION
    requireUnescaped: true
    requireMarkers: ["bbbb"]
    minConfidence: 0.72
```

### 成对差异模板

```yaml
- id: example_pair_diff
  technique: BOOLEAN_BASED
  strategy: BOOLEAN_BASED_MINIMAL
  priority: 20
  stopOnMatch: true
  maxRequests: 2
  maxPayloadLength: 64
  evidenceWeight: 0.75
  applicableParamTypes: [QUERY, BODY]
  valueTypes: [STRING, UNKNOWN]
  requiresLlmReview: true
  payloadPairs:
    - trueValue: "' AND 1=1--"
      falseValue: "' AND 1=2--"
      mutation: APPEND
  oracle:
    type: PAIR_DIFF
    minSimilarityTrueBaseline: 0.90
    maxSimilarityTrueFalse: 0.80
    minConfidence: 0.75
```

### 数值增减模板

```yaml
- id: example_numeric_neighbor
  technique: NUMERIC_INCREMENT
  strategy: NUMERIC_INCREMENT
  priority: 10
  stopOnMatch: true
  maxRequests: 1
  maxPayloadLength: 32
  evidenceWeight: 0.70
  applicableParamTypes: [QUERY, BODY, PATH]
  valueTypes: [NUMERIC]
  requiresLlmReview: true
  payloads:
    - value: "1"
      mutation: ADD
      role: TRIGGER
  oracle:
    type: BASELINE_DIFF
    maxSimilarityTrueFalse: 0.96
    minConfidence: 0.55
```

## 18. 规则质量检查清单

提交规则前逐项确认：

- 是否只确认漏洞大类，而不是过度细分子类型？
- 是否设置了 `applicableParamTypes`？
- 是否设置了 `valueTypes`？
- 是否限制了 `maxRequests`？
- 是否设置了合理的 `priority`？
- 是否命中即停？
- 是否避免危险 payload？
- 是否对语义 diff 类规则开启 `requiresLlmReview`？
- 是否能解释正证据和反证？
- 是否能通过参数分析手动触发并在漏洞验证过程复现？
- 是否不会污染 History 原始流量？
