package com.aiburpcopilot.core.verification.technique;

import com.aiburpcopilot.core.context.AttackType;

import java.util.List;
import java.util.Optional;

/**
 * 技术注册中心接口。
 * <p>
 * 管理所有 TechniqueRule，提供按 (AttackType, Technique) 查找的能力。
 * 注册表在初始化时一次性注册所有规则，之后只读访问。
 * <p>
 * 核心设计：
 * <ul>
 *   <li>注册表只管"有哪些规则"，不管"如何使用规则"</li>
 *   <li>新增攻击类型只需 {@code register(new MyRule())}</li>
 *   <li>不支持运行时热注册（避免并发问题）</li>
 * </ul>
 */
public interface ITechniqueRegistry {

    /**
     * 注册一条技术规则。
     *
     * @param rule 要注册的规则（不允许 null）
     */
    void register(TechniqueRule rule);

    /**
     * 根据攻击类型和技术查找匹配的规则。
     *
     * @param attackType 攻击类型
     * @param technique  验证技术
     * @return 匹配的规则（可能为空）
     */
    Optional<TechniqueRule> findRule(AttackType attackType, VerificationTechnique technique);

    List<TechniqueRule> getRules();

    /**
     * 获取已注册的规则总数。
     *
     * @return 规则数量
     */
    int getRuleCount();
}
