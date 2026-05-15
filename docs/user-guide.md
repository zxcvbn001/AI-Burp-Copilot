# AI Burp Copilot 使用手册

本文档面向公开使用者，介绍 AI Burp Copilot 的定位、模块功能、使用方式、结果查看方式、常见配置项，以及规则如何编写与扩展。

如果你第一次接触这个项目，建议按下面顺序阅读：

1. 项目定位
2. 首次使用
3. 主要模块说明
4. 如何读验证结果
5. 如何设置
6. 规则怎么写

---

## 1. 项目定位

AI Burp Copilot 不是一个“让大模型自动扫站”的黑盒扫描器，也不是为了替代人工判断。

它更适合被理解为：

- 基于 Burp 真实流量的辅助分析插件
- 以规则驱动验证为核心的验证平台
- 由 LLM 参与解释和二次复核的工作流工具

它主要解决这些问题：

- 把人工测试中的重复动作沉淀下来
- 把请求、响应、差异和证据保留下来
- 把“分析建议”和“最终结论”分开展示
- 帮助测试人员更快复测常见漏洞类型

---

## 2. 整体流程

插件大致按下面的顺序工作：

```text
Burp HTTP 流量
   |
   v
接口识别
   |
   v
攻击面分析
   |
   v
候选参数与候选漏洞类型
   |
   v
参数影响性判断
   |
   v
规则化 Probe 验证
   |
   v
LLM 二次复核
   |
   v
Finding 聚合与结果导出
```

可以把它理解成两条线并行协作：

- **规则线**
  - 负责怎么测、发什么 probe、看哪些证据
- **LLM 线**
  - 负责怎么理解接口、如何解释差异、如何做二次研判

---

## 3. 首次使用

### 3.1 环境准备

你至少需要：

- Burp Suite
- JDK 21
- 编译好的插件 JAR
- 一个可用的配置目录

插件构建产物通常是：

```text
target/ai-burp-copilot-v2-jar-with-dependencies.jar
```

### 3.2 加载插件

在 Burp 中：

1. 打开 `Extensions -> Installed -> Add`
2. 选择扩展类型 `Java`
3. 选择插件 JAR
4. 加载成功后打开插件主 Tab

### 3.3 选择配置目录

插件运行时依赖外部配置目录，目录结构通常如下：

```text
ai-burp-copilot/
├─ application.yml
├─ prompts/
├─ rules/
└─ 报告模板.docx
```

如果只是公开仓库环境下运行测试或演示，也可以使用脱敏模板目录：

```text
ai-burp-copilot-templates/
├─ application.yml
├─ prompts/
└─ rules/
```

加载插件后，在设置页中选择其中一个目录即可。

### 3.4 配置 LLM

在 `application.yml` 中至少需要确认：

- `llm.provider`
- `llm.model`
- `llm.apiUrl`
- `llm.apiKey`
- 连接与读取超时

如果暂时不做真实 LLM 研判，也可以先使用测试或占位配置完成本地规则链路验证。

---

## 4. 主要模块说明

下面按使用时最常接触的几个界面说明。

### 4.1 History

作用：

- 查看哪些请求真正进入了插件
- 作为后续分析和验证的原始入口
- 排查“为什么某条请求没进入后续流程”

建议重点看：

- URL 是否正确
- 方法、参数、响应是否完整
- 是否确实是目标业务流量

如果这里都没有看到目标请求，后面的分析和验证通常也不会成立。

### 4.2 Endpoint Analysis

作用：

- 判断这是不是一个值得分析的业务接口
- 提取接口用途、攻击面和候选风险方向
- 给出更值得关注的参数

建议重点看：

- AI 给出的风险方向是否合理
- 是否漏掉了关键参数
- 是否把静态资源误识别成业务接口

这里更像“建议层”，不是最终漏洞结论。

### 4.3 Parameter Analysis

作用：

- 判断某个参数是否真的影响服务端逻辑
- 避免对明显无影响参数反复发起验证

建议重点看：

- 关键参数是否被误判成无影响
- 差异是否只是噪声
- 是否存在应该人工继续验证的参数

如果一个参数在这一层被挡掉，后续很多漏洞验证都不会继续执行。

### 4.4 Verification

作用：

- 按规则执行 probe
- 保存每次验证请求和响应
- 标出哪些 probe 命中、哪些没有命中

建议重点看：

- 是否真的发出了验证请求
- 跑了哪些 probe
- 命中的是哪一条 probe
- baseline、变异请求、真假对比是否合理

读这一层时，不要只看“命中那一条”，也要结合未命中的 probe 一起判断上下文。

### 4.5 Confirmed / Effective Findings

作用：

- 展示最终被聚合后的有效漏洞结果
- 提供更适合复核和导出的最终口径

建议重点看：

- 最终结论是否与中间证据一致
- 是否有本地命中但最终被复核拒绝的情况
- 是否有需要人工确认的边界场景

这一页不应该理解为“所有中间记录的简单叠加”，而是更接近最终输出层。

### 4.6 Logs

作用：

- 排查配置、LLM、规则、执行链路方面的问题

建议重点看：

- 配置目录是否正确加载
- 为什么某条请求没有进入分析
- 为什么某类漏洞没有执行 probe
- 为什么最终没有进入有效漏洞

---

## 5. 如何读验证结果

使用插件时，最容易出现的问题不是“没有结果”，而是“有结果但不知道怎么解读”。

建议按下面顺序看：

### 5.1 先看原始请求与原始响应

确认：

- 请求本身是否正确
- 返回是否为正常业务流量
- 是否本来就是错误页、重定向页或登录页

### 5.2 再看 Probe 请求与响应

确认：

- probe 是否真的执行
- 变异是否打到了目标参数
- 返回是否出现了有意义差异

### 5.3 再看 Diff 和证据

确认：

- 差异是业务语义变化，还是普通校验失败
- 是否有稳定的关键词、状态码、结构变化
- 是否只是长度、hash 变化但没有实际含义

### 5.4 最后看 LLM 复核与 Final Decision

确认：

- LLM 是支持还是拒绝
- 拒绝原因是什么
- 最终结论是否和证据链一致

一个比较稳妥的阅读顺序是：

```text
原始流量 -> Probe 流量 -> 差异 -> 证据 -> LLM 复核 -> Final Decision
```

---

## 6. 如何设置

### 6.1 `application.yml`

最常调整的是以下几组配置：

- `llm`
  - 模型、接口地址、API Key、超时、重试
- `ai`
  - prompt 长度、超时、调用频率
- `scan`
  - 静态资源过滤、状态码过滤、响应体大小限制
- `verification`
  - 是否开启验证、每个 endpoint 最多请求数、请求超时、payload 长度限制
- `request`
  - 并发和队列大小

### 6.2 常见设置建议

- 第一次接入时，先确认配置目录和 LLM 配置是否正常
- 如果目标环境敏感，先关闭自动验证，只做分析
- 如果噪声太多，先收紧过滤条件和验证范围
- 如果 LLM 响应慢，优先调高超时并降低 prompt 长度

---

## 7. 规则系统定位

插件的验证能力主要来自 YAML 规则文件。

规则目录通常位于：

```text
ai-burp-copilot/rules/payloads/
```

或者公开模板目录下：

```text
ai-burp-copilot-templates/rules/payloads/
```

一般来说，一个漏洞类型对应一个 YAML 文件，例如：

- `sqli.yaml`
- `xss.yaml`
- `idor.yaml`
- `auth.yaml`

规则系统不是“攻击脚本仓库”，而是：

> 用最小化请求生成可解释证据的验证规则集。

建议始终把它理解为“证据探针”，而不是“利用链自动化”。

### 7.1 规则与代码的分工

推荐分工如下：

- **规则**
  - 定义测什么
  - 定义发什么最小化 payload
  - 定义适用哪些参数
  - 定义如何判断命中
- **Java 代码**
  - 提供通用请求执行能力
  - 提供通用差异分析能力
  - 提供通用工作流和证据聚合能力

新增漏洞类型时，优先：

1. 新增或修改 YAML 规则
2. 复用已有 oracle、mutation 和 workflow
3. 只有在机制不够用时再改 Java

不要为了某一个漏洞单独去改 Replay、Diff、Execution 这类通用 HTTP 能力。

---

## 8. 规则怎么写

这一节提供对外可用的规则写法说明。

### 8.1 一个规则文件通常包含什么

常见结构包括：

- `attackType`
- `aliases`
- `goal`
- `workflow`
- `probes`

其中真正决定“怎么测”的核心是 `probes`。

### 8.2 顶层字段说明

#### `attackType`

表示最终聚合的漏洞大类，例如：

- `SQLI`
- `XSS`
- `IDOR`
- `SSRF`
- `AUTH`
- `PATH_TRAVERSAL`
- `OPEN_REDIRECT`
- `SSTI`
- `XXE`
- `JWT`
- `GRAPHQL`
- `CORS`
- `FILE_UPLOAD`
- `COMMAND_INJECTION`
- `LDAP_INJECTION`

这里写的是漏洞大类能力键，不建议把非常细的子类型直接放在这里。

#### `aliases`

用于兼容同义词、历史命名或 AI 输出映射，例如：

```yaml
attackType: AUTH
aliases: [AUTH_BYPASS, AUTHORIZATION, ACCESS_CONTROL]
```

建议只写类型同义词，不写具体 payload 或利用步骤。

#### `goal`

当前推荐统一写：

```yaml
goal: CONFIRM_ATTACK_TYPE
```

含义是：规则负责确认某个漏洞大类是否具备足够证据成立。

#### `workflow`

用于描述这个漏洞类型如何进入验证流程，例如：

```yaml
workflow:
  name: AUTH Verification
  description: Header/Cookie authorization checks can run without parameter influence gate.
  includeInfluenceStep: false
  requiresInfluenceApproval: false
```

常见含义：

- `includeInfluenceStep`
  - 是否先走参数影响性判断
- `requiresInfluenceApproval`
  - 是否要求影响性通过后才继续验证
- `name`
  - 工作流名称
- `description`
  - 工作流说明

参数型漏洞通常会保留 `InfluenceValidation`，而 Header、Cookie、端点级规则可以按需跳过。

### 8.3 什么是 Probe

一个 probe 可以理解为：

> 一组最小化的验证请求，以及判断这些请求是否构成证据的方法。

它通常会说明：

- 适合什么参数
- 发什么 payload
- 发几次请求
- 用什么 oracle 判断是否命中

### 8.4 一个 Probe 常见字段

最常见的字段有：

- `id`
  - 唯一标识
- `technique`
  - 技术分类
- `strategy`
  - 执行策略标签
- `enabledByDefault`
  - 是否默认启用
- `priority`
  - 执行顺序
- `stopOnMatch`
  - 命中后是否停止后续 probe
- `maxRequests`
  - 最多请求数
- `maxPayloadLength`
  - payload 长度限制
- `evidenceWeight`
  - 证据权重
- `applicableParamTypes`
  - 适用于哪种参数位置
- `valueTypes`
  - 适用于哪种值类型
- `requiresLlmReview`
  - 命中后是否交给 LLM 复核
- `payloads` / `payloadPairs`
  - 实际触发用的变异输入
- `oracle`
  - 本地证据判断逻辑

### 8.5 Probe 字段建议

#### `id`

建议能够一眼看出场景，例如：

- `generic_quote_error_recovery`
- `generic_boolean_pair_integer`
- `idor_numeric_neighbor_plus`
- `xss_harmless_html_reflection`

#### `technique`

用于标识检测技术方向，例如：

- `BOOLEAN_BASED`
- `ERROR_BASED`
- `TIME_BASED`
- `REFLECTION`
- `NUMERIC_INCREMENT`

#### `strategy`

用于标识执行策略，例如：

- `BOOLEAN_BASED_MINIMAL`
- `ERROR_BASED`
- `TIME_BASED`
- `NUMERIC_INCREMENT`
- `REMOVE_TOKEN`
- `LOCALHOST_PROBE`
- `PATH_TRAVERSAL_PROBE`
- `OPEN_REDIRECT_PROBE`

优先复用现有策略名，不要随意引入风格不一致的新命名。

#### `enabledByDefault`

对于成本高、风险高或环境依赖强的 probe，建议默认关闭，例如：

- 延时型 probe
- 强环境绑定 probe
- 可能导致状态变化的 probe
- 认证上下文强依赖 probe

#### `priority`

数字越小越早执行。推荐思路：

- 低风险、低成本 probe 优先
- 噪声大、成本高 probe 放后面

#### `stopOnMatch`

命中后是否停止后续 probe。多数情况下建议：

```yaml
stopOnMatch: true
```

目标通常是拿到“足够证据”，而不是把所有 payload 全部跑完。

#### `maxRequests`

建议尽量小：

- 单次验证：`1`
- 触发 / 恢复：`2`
- true / false 对比：`2`
- 特殊场景尽量不超过 `3`

#### `applicableParamTypes`

常见值：

- `QUERY`
- `BODY`
- `HEADER`
- `PATH`
- `COOKIE`

例如：

```yaml
applicableParamTypes: [QUERY, BODY, PATH]
```

#### `valueTypes`

常见值：

- `STRING`
- `NUMERIC`
- `UUID`
- `JWT`
- `URL`
- `UNKNOWN`

不要为了覆盖面而无脑放开，尽量与场景匹配。

#### `requiresLlmReview`

适合开启的场景：

- 业务语义强
- 差异很难纯靠规则解释
- 容易误报

适合关闭的场景：

- 证据极强
- 关键词非常明确
- 误报概率很低

### 8.6 `payloads` 与 `payloadPairs`

- `payloads`
  - 适合单次请求型探针
- `payloadPairs`
  - 适合真假条件成对探针

推荐：

- 反射、关键词、单次触发：`payloads`
- 布尔对比、真假对比：`payloadPairs`

### 8.7 `oracle`

`oracle` 定义系统如何判断 probe 是否命中。

常见类型包括：

- `PAIR_DIFF`
- `ERROR_KEYWORD_OR_RECOVERY`
- `TIME_DELAY`
- `KEYWORD`
- `REDIRECT_LOCATION`
- `HTML_REFLECTION`
- `BASELINE_DIFF`
- `BASELINE_SIMILAR`
- `EXPRESSION_EVALUATION`

优先复用已有 oracle。只有已有 oracle 完全不适合时，才考虑扩展代码。

### 8.8 一个极简示例

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
    payloads:
      - value: "<test>marker</test>"
        role: TRIGGER
        mutation: APPEND
    oracle:
      type: HTML_REFLECTION
      minConfidence: 0.72
```

---

## 9. 如何补充或修改规则

### 9.1 最推荐的顺序

建议按下面顺序扩展：

1. 先调整现有规则参数
2. 再给现有漏洞类型补一个新 probe
3. 最后再新增全新的漏洞类型

这样更容易控制误报、漏报和行为变化范围。

### 9.2 什么时候只改规则就够了

适合只改 YAML 的情况：

- 增加一个 payload 变体
- 增加一个 true / false 对
- 增加一种闭合方式或反射场景
- 调整优先级、阈值、参数类型、值类型
- 调整是否需要 LLM 复核

### 9.3 什么时候要改代码

适合改 Java 的情况：

- 需要新的 oracle 类型
- 需要新的通用变异方式
- 需要新的工作流阶段
- 需要新的通用差异计算能力
- 需要新的证据聚合机制

简单理解：

- **检测内容变化**
  - 大多数时候只改规则
- **检测机制变化**
  - 通常要改代码

### 9.4 补规则时的建议

- 一次只改一个点
- 先在熟悉的流量上验证
- 不要只看“有没有命中”，更要看“为什么命中”
- 改完后同时检查：
  - 日志
  - Probe 执行记录
  - 最终 finding
  - 是否影响其他已有规则

---

## 10. 使用建议

### 10.1 不要把插件当最终裁决器

插件的价值在于：

- 帮你发现值得看的点
- 帮你保留验证过程
- 帮你减少重复劳动

但最终漏洞是否成立，仍然需要结合：

- 原始请求
- 原始响应
- 业务语义
- 人工复核

### 10.2 优先关注三类问题

- 参数是否真的被影响
- Probe 是否真的执行
- Final Decision 是否和证据一致

### 10.3 最稳的使用姿势

推荐顺序：

1. 先看 History
2. 再看 Endpoint Analysis
3. 再看 Parameter Analysis
4. 再看 Verification
5. 最后看 Confirmed Findings

---

## 11. 一句话总结

这个插件最适合的定位是：

> 用真实流量做入口，用规则做验证，用 LLM 做语义复核，帮助测试人员更高效地完成接口安全分析和漏洞确认。
