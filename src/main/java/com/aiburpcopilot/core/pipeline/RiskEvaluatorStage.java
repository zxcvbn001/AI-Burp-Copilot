package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.RiskLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 风险评估 Pipeline Stage（Phase 1 空实现）。
 * <p>
 * 负责评估 HTTP 上下文的整体风险等级，设置在 context.riskLevel 中。
 * <p>
 * Phase 1 实现逻辑：
 * <ul>
 *   <li>ENDPOINT 类型：取 AI 分析结果中 HighValueParam 的最高风险等级</li>
 *   <li>STATIC_RESOURCE 类型：固定为 INFO（静态资源通常无直接风险）</li>
 *   <li>UNKNOWN 类型：固定为 INFO</li>
 *   <li>分析失败或无结果：固定为 INFO</li>
 * </ul>
 * <p>
 * Phase 2 扩展方向：
 * <ul>
 *   <li>CVSS 风格的量化评分模型</li>
 *   <li>结合参数数量、参数语义、攻击面数量等上下文加权</li>
 *   <li>置信度评估（AI 分析质量打分）</li>
 *   <li>历史同类请求风险对比</li>
 * </ul>
 */
public class RiskEvaluatorStage implements IPipelineStage {

    private static final Logger log = LoggerFactory.getLogger(RiskEvaluatorStage.class);

    @Override
    public String getName() {
        return "Risk Evaluation";
    }

    @Override
    public void process(HTTPContext context) {
        RiskLevel riskLevel = RiskLevel.INFO;

        try {
            if (context.getEndpointType() == EndpointType.ENDPOINT) {
                riskLevel = evaluateEndpointRisk(context);
            } else if (context.getEndpointType() == EndpointType.STATIC_RESOURCE) {
                riskLevel = evaluateStaticRisk(context);
            }
            // UNKNOWN 保持 INFO

            context.setRiskLevel(riskLevel);
            log.debug("Risk evaluated as {} for: {} {}", riskLevel, context.getMethod(), context.getPath());

        } catch (Exception e) {
            log.warn("Risk evaluation failed for: {}, defaulting to INFO", context.getPath(), e);
            context.setRiskLevel(RiskLevel.INFO);
        }
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        // 所有请求都需要风险评估
        return true;
    }

    // ---------- Private ----------

    /**
     * 评估 ENDPOINT 类型请求的风险等级。
     * <p>
     * Phase 1: 取所有高价值参数中的最高 riskLevel。
     */
    private RiskLevel evaluateEndpointRisk(HTTPContext context) {
        AnalysisResult result = context.getAnalysisResult();
        if (result == null) {
            return RiskLevel.INFO;
        }

        // 如果分析失败，返回 INFO
        if (!result.isSuccess()) {
            return RiskLevel.INFO;
        }

        // 取所有高价值参数中的最高风险等级
        RiskLevel maxRisk = RiskLevel.INFO;
        if (result.getHighValueParams() != null) {
            for (AnalysisResult.HighValueParam hvp : result.getHighValueParams()) {
                if (hvp.getRiskLevel() != null && hvp.getRiskLevel().ordinal() > maxRisk.ordinal()) {
                    maxRisk = hvp.getRiskLevel();
                }
            }
        }

        return maxRisk;
    }

    /**
     * 评估 STATIC_RESOURCE 类型请求的风险等级。
     * <p>
     * Phase 1: 固定为 INFO。Phase 2 可扫描扫描结果中最高 severity。
     */
    private RiskLevel evaluateStaticRisk(HTTPContext context) {
        // Phase 1: 静态资源风险统一为 INFO，不自动标记风险
        return RiskLevel.INFO;
    }
}
