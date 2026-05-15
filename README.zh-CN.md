# AI Burp Copilot v2

[English](README.md)

AI Burp Copilot v2 是一个面向 Burp Suite 的 AI 辅助安全分析插件。

它的目标是帮助测试人员基于真实 HTTP 流量完成分析、验证和证据复核。  
它**不是**为了替代人工测试，也不是一个让大模型自由发挥的黑盒自动扫描器。

---

## 为什么做这个项目

Burp 人工测试很强，但重复性的验证工作很容易迅速放大成本：

- 判断哪些参数值得优先测试
- 对不同接口重复执行类似探针
- 比对响应差异并过滤噪声
- 把中间证据整理成可复核的结论

AI Burp Copilot v2 主要就是在解决这部分问题。

它把真实经过 Burp 的流量转成一条可持续复用的流程：

- **可分析**
- **可验证**
- **可复核**
- **可追踪**

---

## 它能做什么

AI Burp Copilot v2 把规则化验证和 AI 辅助解释结合在一起：

- 接收并分类 Burp 流量
- 分析接口、参数和攻击面
- 判断参数是否可能真正影响服务端行为
- 对已支持的漏洞类型执行规则化 probe
- 保留每一次 probe 的请求/响应证据
- 在需要时使用 LLM 做二次研判
- 聚合 finding 并产出可导出的结果

---

## 核心流程

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
LLM 辅助复核
   |
   v
Finding 聚合与报告输出
```

---

## 当前覆盖方向

当前规则库覆盖的主要漏洞家族包括：

- SQL 注入
- XSS
- IDOR
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

当前项目更适合用于：

- Burp 场景下的人工测试辅助
- 参数级、接口级验证
- 已知漏洞类型的可复现复测
- 证据留存与报告导出

---

## 快速开始

### 环境要求

- JDK 21
- Maven 3.9+

### 构建

```bash
mvn -DskipTests package
```

产物：

```text
target/ai-burp-copilot-v2-jar-with-dependencies.jar
```

### 加载到 Burp

1. 打开 Burp Suite
2. 进入 `Extensions -> Installed -> Add`
3. 扩展类型选择 `Java`
4. 选择 `target/ai-burp-copilot-v2-jar-with-dependencies.jar`

### 外置配置目录

插件运行时会从外置目录读取配置资源：

```text
ai-burp-copilot/
├─ application.yml
├─ prompts/
├─ rules/
└─ 报告模板.docx
```

为了 GitHub 编译和公开测试，仓库中还提供了一个脱敏后的模板目录：

```text
ai-burp-copilot-templates/
├─ application.yml
├─ prompts/
└─ rules/
```

加载插件后，在设置页选择合适的配置目录即可。

---

## 文档

公开文档入口：

- `docs/rule-authoring.md`
- `docs/workflow-overview.md`
- `docs/ai-workflow-flowchart.md`

---

## 设计原则

这个项目目前遵循几条核心原则：

- **HTTP 优先**：重放、差异计算、执行能力都应该是通用能力，不应绑死在某一种漏洞类型上
- **优先规则化**：新增检测逻辑时，优先用外部规则扩展，而不是在 Java 代码里硬编码
- **LLM 做复核，不做控制器**：AI 负责建议、解释、复核，不应自由主导攻击执行
- **证据优先于直觉**：结论必须能回溯到请求、响应和规则命中证据

---

## Roadmap

当前后续重点主要包括：

- 强化多来源证据的最终判定逻辑
- 改进去重与调度
- 完善报告生成能力
- 持续扩展和调优规则覆盖
- 提升 probe 历史和证据链的 UI 可见性

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
- 任何试图绕过真实防护的非法用途

---

## 项目状态

AI Burp Copilot v2 已经具备一条可工作的端到端链路，包括：

- 流量接入
- 接口分析
- 参数判断
- 规则验证
- LLM 复核
- finding 聚合
- UI 展示

它已经不只是一个 PoC，但仍处于持续演进阶段。
