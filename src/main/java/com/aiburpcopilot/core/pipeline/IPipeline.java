package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.HTTPContext;

/**
 * 分析流水线接口。
 * <p>
 * 管理一连串的 IPipelineStage，按顺序处理 HTTPContext。
 * 支持异步执行，不阻塞 Burp Proxy 主线程。
 * <p>
 * Phase 1 流水线顺序：
 * <pre>
 * Proxy 采集 → 跳过判断 → Endpoint 分类 → Static 扫描 → AI 分析 → History 记录
 * </pre>
 */
public interface IPipeline {

    /**
     * 将 HTTPContext 提交到流水线异步处理。
     *
     * @param context HTTP 上下文
     */
    void submit(HTTPContext context);

    /**
     * 注册一个处理阶段到流水线末尾。
     *
     * @param stage 处理阶段
     */
    void registerStage(IPipelineStage stage);

    /**
     * 获取当前注册的阶段数量。
     *
     * @return 阶段数量
     */
    int getStageCount();

    /**
     * 启动流水线。
     */
    void start();

    /**
     * 停止流水线，释放资源。
     */
    void shutdown();
}
