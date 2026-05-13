package com.aiburpcopilot.core.verification.technique;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.model.TestStrategy;

import java.util.List;

/**
 * 技术映射器接口。
 * <p>
 * 职责：将 AI 推荐的 TechniqueRecommendation 列表
 * 转换为可执行的 TestStrategy 列表。
 * <p>
 * 核心流程：
 * <ol>
 *   <li>从 AnalysisResult.recommendedTechniques 读取 AI 推荐</li>
 *   <li>通过 TechniqueRegistry 查找匹配的 TechniqueRule</li>
 *   <li>将 (AttackType, VerificationTechnique) 映射到 StrategyType</li>
 *   <li>生成 TestStrategy（带完整的 technique + strategyType）</li>
 *   <li>规则补充：对没有 AI 推荐的参数，根据参数名/类型自动匹配技术</li>
 * </ol>
 * <p>
 * 这是 Strategy Engine 内部的核心抽象，
 * 将"技术映射"与"策略编排"解耦。
 */
public interface ITechniqueMapper {

    /**
     * 将 AI 推荐列表转换为 TestStrategy 列表。
     *
     * @param recommendations AI 推荐的验证技术列表
     * @return 可执行的 TestStrategy 列表
     */
    List<TestStrategy> mapToStrategies(List<TechniqueRecommendation> recommendations);

    /**
     * 根据攻击类型和参数上下文，生成规则补充策略。
     * <p>
     * 当 AI 未明确推荐某参数的技术时，
     * 根据参数名模式自动推断适用的技术。
     *
     * @param attackType   攻击类型
     * @param parameterName 参数名（如 "userId", "id"）
     * @param parameterValue 参数值（用于推断类型，如数字/UUID）
     * @return 补充的 TestStrategy 列表（可能为空）
     */
    List<TestStrategy> supplementStrategies(AttackType attackType, String parameterName, String parameterValue);
}
