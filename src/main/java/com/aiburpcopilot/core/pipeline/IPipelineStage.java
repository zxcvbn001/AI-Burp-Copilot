package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.HTTPContext;

/**
 * 流水线处理阶段接口。
 * <p>
 * 每个 PipelineStage 负责一个独立的数据处理步骤。
 * Phase 1 包含以下 Stage：
 * <ol>
 *   <li>EndpointClassificationStage - 端点分类</li>
 *   <li>StaticScanStage - 静态资源扫描</li>
 *   <li>AIAnalysisStage - AI 攻击面分析</li>
 * </ol>
 * <p>
 * Phase 2 将增加：
 * <ol>
 *   <li>TestStrategyStage - 测试策略生成</li>
 *   <li>PayloadGenerationStage - Payload 生成</li>
 *   <li>DiffAnalysisStage - 响应 Diff 分析</li>
 * </ol>
 * <p>
 * 每个阶段独立实现，通过 Pipeline 串联。
 * 新增阶段不影响已有阶段。
 */
public interface IPipelineStage {

    /**
     * 获取阶段名称。
     *
     * @return 阶段名称，用于日志和监控
     */
    String getName();

    /**
     * 执行本阶段的处理逻辑。
     *
     * @param context HTTP 上下文（会被修改）
     */
    void process(HTTPContext context);

    /**
     * 判断本阶段是否应对此上下文执行。
     *
     * @param context HTTP 上下文
     * @return true 如果应该执行本阶段
     */
    boolean shouldProcess(HTTPContext context);
}
