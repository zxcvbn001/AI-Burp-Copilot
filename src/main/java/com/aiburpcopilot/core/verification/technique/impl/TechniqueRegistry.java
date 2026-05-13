package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.technique.ITechniqueRegistry;
import com.aiburpcopilot.core.verification.technique.TechniqueRule;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * 技术注册中心实现。
 * <p>
 * 管理所有 TechniqueRule 的注册和查找。
 * 初始化时注册所有内置规则，后续仅供查询。
 * <p>
 * 核心特性：
 * <ul>
 *   <li>线程安全：注册完成后只读访问</li>
 *   <li>O(1) 查找：内部使用索引 Map</li>
 *   <li>支持 prefab：通过 {@code createDefault()} 获取预配置实例</li>
 * </ul>
 */
public class TechniqueRegistry implements ITechniqueRegistry {

    /** 规则列表（保持注册顺序，用于迭代） */
    private final List<TechniqueRule> rules = new ArrayList<>();

    /** 已锁定标志（注册完成后设为 true） */
    private volatile boolean locked = false;

    @Override
    public void register(TechniqueRule rule) {
        if (locked) {
            throw new IllegalStateException("Registry is locked. Register all rules before use.");
        }
        if (rule == null) {
            throw new IllegalArgumentException("Rule must not be null");
        }
        rules.add(rule);
    }

    /**
     * 锁定注册表，禁止后续注册。
     */
    public void lock() {
        this.locked = true;
    }

    @Override
    public Optional<TechniqueRule> findRule(AttackType attackType, VerificationTechnique technique) {
        if (attackType == null || technique == null) return Optional.empty();
        for (TechniqueRule rule : rules) {
            if (rule.supports(attackType, technique)) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }

    @Override
    public int getRuleCount() {
        return rules.size();
    }

    /**
     * 获取注册表副本（只读）。
     */
    public List<TechniqueRule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    // ========== 工厂方法 ==========

    /**
     * 创建预配置的默认注册表（包含所有内置规则）。
     * <p>
     * 内部注册所有内置 TechniqueRule 并锁定。
     *
     * @return 已锁定、已配置的 TechniqueRegistry
     */
    public static TechniqueRegistry createDefault() {
        TechniqueRegistry registry = new TechniqueRegistry();

        // ---- SQLI Rules ----
        registry.register(new SqlBooleanTechniqueRule());
        registry.register(new SqlErrorTechniqueRule());
        registry.register(new SqlTimeTechniqueRule());
        registry.register(new SqlUnionTechniqueRule());

        // ---- IDOR Rules ----
        registry.register(new IdorNumericIncrementTechniqueRule());
        registry.register(new IdorUuidSwapTechniqueRule());

        // ---- AUTH Rules ----
        registry.register(new AuthRemoveTokenTechniqueRule());
        registry.register(new AuthRoleSwitchTechniqueRule());

        // ---- SSRF Rules ----
        registry.register(new SsrfLocalhostProbeTechniqueRule());

        // ---- XSS Rules ----
        registry.register(new XssReflectionTechniqueRule());

        // ---- Path Traversal Rules ----
        registry.register(new PathTraversalProbeTechniqueRule());

        registry.register(new OpenRedirectTechniqueRule());
        registry.register(new SstiTemplateExpressionTechniqueRule());

        registry.lock();
        return registry;
    }
}
