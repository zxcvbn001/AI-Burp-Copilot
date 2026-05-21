# AI Burp Copilot v2

AI Burp Copilot v2 是一个面向 Burp Suite 的 AI 辅助安全分析插件。

它基于真实 Burp HTTP 流量，结合规则化 probe、JS AST 分析和 LLM 语义复核，帮助测试人员更高效地完成接口分析、漏洞验证、证据整理和报告输出。

它不是“完全替代人工”的自动扫描器，也不是让大模型自由发包的黑盒工具。

---

## 核心特点

- **真实流量驱动**：从 Burp Proxy、Repeater 等真实请求中识别接口和静态资源。
- **AI 辅助理解**：用 LLM 分析接口语义、参数价值、攻击面和验证方向。
- **规则化验证**：通过 YAML 规则库执行最小化 probe，保留请求/响应证据。
- **JS AST 分析**：对 JavaScript 内容调用外部分析引擎，恢复 API、敏感信息和 webpack/script 资源。
- **三类 JS 结果联动**：
  - API / Endpoint：可按配置自动探测，并进入接口分析链路。
  - 敏感信息：使用 JS 分析引擎已复核的结果进行展示和留痕。
  - Webpack / Script：可按配置探测存在性，并继续递归分析。
- **本地历史存储**：支持将历史流量、分析结果和静态扫描详情保存到本地数据库。
- **报告导出**：聚合有效发现和证据，辅助形成可复核的测试输出。

---

## 2.0.2 新增内容

2.0.2 主要围绕“真实可用的 JS 静态分析联动”和“长期使用体验”做增强：

- **接入 JS AST 分析引擎**：支持将 Burp 捕获到的 JavaScript 内容发送到外部 JS 分析引擎进行 AST 分析。
- **三类 JS 结果分流**：
  - API / Endpoint：恢复出的接口可按配置自动探测存在性，并写入历史流量进入接口分析链路。
  - 敏感信息：使用分析引擎已经复核过的敏感信息结果，插件侧不再重复做 LLM 二次判断。
  - Webpack / Script：恢复出的脚本资源可按配置探测存在性，并继续递归分析。
- **异步 JS 分析任务**：支持提交任务、轮询任务状态，并在 UI 和日志中展示提交、轮询、完成、失败、超时等状态。
- **Source Map 探测**：默认探测同名 `.js.map` 是否存在，只展示确认存在的 source map。
- **Send To 插件菜单**：支持从 Proxy / Repeater 的 message editor 右键发送到插件，可选择一键分析、接口分析或静态文件分析。
- **本地数据库历史存储**：支持将历史流量、分析结果、静态扫描详情等保存到本地 SQLite 数据库，并提供清理与导出能力。
- **配置项 UI 化**：JS 分析、静态扫描大小、自动发包、自动接口分析、数据库路径等配置可直接在设置页调整。
- **中文化体验**：README 和设置页主要入口改为中文，方便中文环境下直接使用。

---

## JS 分析引擎

2.0.2 的 JavaScript 静态分析能力依赖外部项目：

- [zxcvbn001/js_analysis_engine](https://github.com/zxcvbn001/js_analysis_engine)

插件侧负责：

- 从 Burp 流量中识别 JavaScript 资源
- 将 JS URL、JS 内容和上下文 base URL 提交给分析引擎
- 接收并规整分析结果
- 对恢复出的 endpoint 和 script 资源按配置执行存在性探测
- 将验证存在的 endpoint 写入历史流量并进入后续接口分析

JS 分析引擎侧负责：

- 使用 AST 分析 JavaScript 内容
- 恢复 API / endpoint、参数、认证信号
- 提取 webpack / script 静态资源
- 识别敏感信息、风险信号和分类 findings
- 对敏感信息做引擎侧增强判断

---

## 工作流程

```text
Burp HTTP 流量
   |
   v
历史记录 / 流量接收
   |
   v
接口识别 / 静态资源识别
   |
   +---- JavaScript 静态分析
   |        |
   |        +---- API / Endpoint 探测与接口分析
   |        +---- 敏感信息展示与留痕
   |        +---- Webpack / Script 探测与递归分析
   |
   v
AI 攻击面分析
   |
   v
候选漏洞类型 + 高价值参数
   |
   v
参数影响性判断
   |
   v
规则化 Probe 验证
   |
   v
LLM 辅助复核
   |
   v
Finding 聚合 / 报告导出
```

---

## 当前覆盖方向

当前规则库覆盖的主要漏洞家族包括：

- SQL 注入
- XSS
- IDOR / 越权访问
- 认证 / JWT 问题
- 命令注入
- SSRF
- 路径遍历
- 开放重定向
- LDAP 注入
- GraphQL 暴露面检测
- 文件上传
- CORS
- SSTI
- XXE

---

## 适合场景

更适合：

- Burp 人工测试过程中的辅助分析
- 接口级、参数级的可复现验证
- 已知漏洞类型的规则化复测
- JavaScript 中隐藏接口和敏感信息的整理
- 证据留存、复盘和报告生成

不适合单独依赖它完成：

- 全量无人值守自动渗透
- 完全替代人工的业务逻辑审计
- 对复杂链路漏洞做最终裁决

---

## 快速开始

### 环境要求

- JDK 21
- Maven 3.9+
- Burp Suite

### 构建

```bash
mvn -DskipTests package
```

构建产物：

```text
target/ai-burp-copilot-v2-jar-with-dependencies.jar
```

### 加载到 Burp

1. 打开 Burp Suite
2. 进入 `Extensions -> Installed -> Add`
3. 扩展类型选择 `Java`
4. 选择 `target/ai-burp-copilot-v2-jar-with-dependencies.jar`
5. 在插件设置页加载配置目录

---

## 配置目录

插件运行时会从外置目录读取配置资源：

```text
ai-burp-copilot/
├─ application.yml
├─ prompts/
├─ rules/
└─ 报告模板.docx
```

仓库中提供了脱敏后的模板目录，适合公开构建、CI 和首次试用：

```text
ai-burp-copilot-templates/
├─ application.yml
├─ prompts/
└─ rules/
```

加载插件后，在设置页选择对应配置目录即可。

---

## 文档

- `docs/user-guide.md`：详细使用手册，包含模块说明、设置项、规则编写和 JS 分析说明。

---

## 设计原则

- **HTTP 优先**：重放、差异计算和执行能力应是通用能力。
- **规则优先**：新增验证逻辑优先通过外部规则扩展。
- **LLM 做分析与复核**：AI 负责理解、解释和复核，不自由主导攻击执行。
- **证据优先**：结论必须能回溯到请求、响应、规则命中和分析结果。
- **低风险默认**：默认尽量使用可控、最小化、可解释的探测方式。

---

## 安全声明

请仅在授权环境中使用本项目。

本项目适用于：

- 授权安全测试
- 安全研究
- 验证引擎与工作流评估

不得用于：

- 未授权攻击
- 破坏性测试
- 任何违法用途

---

## 项目状态

AI Burp Copilot v2 已经具备端到端工作流，包括：

- 流量接入
- 接口分析
- 静态 JS 分析
- 参数判断
- 规则验证
- LLM 复核
- Finding 聚合
- 本地历史存储
- UI 展示与报告导出

项目仍在持续演进中，欢迎基于真实测试场景反馈规则、UI 和工作流问题。
