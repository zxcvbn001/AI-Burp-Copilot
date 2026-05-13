package com.aiburpcopilot.core.verification.technique;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;

/**
 * 技术规则接口。
 * <p>
 * 每个实现定义一个 (AttackType, VerificationTechnique) → StrategyType 的映射规则。
 * 规则是无状态的，可以注册到 TechniqueRegistry。
 * <p>
 * 设计原则：
 * <ul>
 *   <li>每条规则只负责一个 (AttackType, Technique) 对</li>
 *   <li>规则之间无依赖、无顺序要求</li>
 *   <li>新增规则只需新建一个实现类并注册，不修改核心引擎</li>
 *   <li>禁止在规则中执行 HTTP 请求、文件 I/O 或任何副作用</li>
 * </ul>
 *
 * <h3>未来扩展示例</h3>
 * <pre>{@code
 *   public class GraphqlIntrospectionRule implements TechniqueRule {
 *       ...
 *   }
 * }</pre>
 */
public interface TechniqueRule {

    /**
     * 判断此规则是否匹配给定的攻击类型和技术。
     *
     * @param attackType 攻击类型
     * @param technique  验证技术
     * @return 是否匹配
     */
    boolean supports(AttackType attackType, VerificationTechnique technique);

    /**
     * 获取此规则映射到的策略类型。
     *
     * @return 对应的 StrategyType
     */
    StrategyType getStrategyType();

    /**
     * 获取规则的描述信息。
     *
     * @return 可读的描述字符串
     */
    String getDescription();
}
