package com.aiburpcopilot.core.verification.influence;

import com.aiburpcopilot.core.verification.model.ParameterProfile;

import java.util.List;

/**
 * 最小变异引擎接口。
 * <p>
 * 根据参数类型生成"最小差异"的变异值。
 * 核心原则：只产生最小变化，禁止生成漏洞 payload。
 * <p>
 * 正确示例：1→2, true→false, 1001→1002
 * 错误示例（禁止）：' OR 1=1--, UNION SELECT, SLEEP(5)
 */
public interface IMinimalMutationEngine {

    /**
     * 为指定参数生成最小差异变异值。
     *
     * @param profile 参数特征分析结果
     * @return 变异值列表（通常 1-3 个值）
     */
    List<String> generateMutations(ParameterProfile profile);

    /**
     * 为指定参数生成指定类型的变异值。
     *
     * @param profile     参数特征
     * @param mutationType 变异类型（如 "INCREMENT", "DECREMENT", "NULL", "EMPTY"）
     * @return 变异值
     */
    String generateMutation(ParameterProfile profile, String mutationType);
}
