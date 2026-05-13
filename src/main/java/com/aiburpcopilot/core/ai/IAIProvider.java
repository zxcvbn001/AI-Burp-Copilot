package com.aiburpcopilot.core.ai;

import com.aiburpcopilot.core.context.HTTPContext;

import java.util.concurrent.CompletableFuture;

/**
 * AI 服务提供者接口。
 * <p>
 * 抽象化 LLM（大语言模型）调用，支持多种 AI 服务提供商：
 * <ul>
 *   <li>DeepSeek（Phase 1 默认实现）</li>
 *   <li>OpenAI / Claude / Qwen（后续阶段扩展）</li>
 * </ul>
 * <p>
 * 所有 AI 调用均返回 CompletableFuture，支持异步非阻塞。
 */
public interface IAIProvider {

    /**
     * 获取提供商名称。
     *
     * @return 例如 "DeepSeek"、"OpenAI"、"Claude"
     */
    String getProviderName();

    /**
     * 分析 HTTP 上下文的攻击面。
     * <p>
     * 传递的是 HTTPContext 的摘要信息（不包含完整请求/响应体）。
     *
     * @param context         HTTP 上下文摘要
     * @param systemPrompt    系统级 Prompt 模板
     * @param userPrompt      用户级 Prompt 模板
     * @return CompletableFuture 返回 AI 分析原始文本结果
     */
    CompletableFuture<String> analyzeAttackSurface(
            HTTPContext context,
            String systemPrompt,
            String userPrompt);

    /**
     * 判断端点类型（ENDPOINT vs STATIC_RESOURCE）。
     *
     * @param aiSummary HTTP 上下文摘要（仅 method/path/content-type/body前512字节）
     * @param classifierPrompt 分类 Prompt 模板
     * @return CompletableFuture 返回 "ENDPOINT" / "STATIC_RESOURCE" / "UNKNOWN"
     */
    CompletableFuture<String> classifyEndpoint(
            String aiSummary,
            String classifierPrompt);

    /**
     * 审查静态资源中的敏感信息。
     *
     * @param content        命中的敏感代码片段
     * @param reviewPrompt   审查 Prompt 模板
     * @return CompletableFuture 返回 AI 审查结果
     */
    CompletableFuture<String> reviewStaticResource(
            String content,
            String reviewPrompt);

    default CompletableFuture<String> analyzeDiff(String diffPrompt) {
        CompletableFuture<String> future = new CompletableFuture<>();
        future.completeExceptionally(new UnsupportedOperationException("Diff analysis is not supported"));
        return future;
    }

    /**
     * 检查 AI 服务是否可用（API Key 是否配置、网络是否可达）。
     *
     * @return true 如果服务可用
     */
    boolean isAvailable();
}
