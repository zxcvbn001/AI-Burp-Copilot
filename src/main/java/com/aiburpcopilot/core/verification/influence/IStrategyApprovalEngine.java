package com.aiburpcopilot.core.verification.influence;

import com.aiburpcopilot.core.verification.model.InfluenceResult;
import com.aiburpcopilot.core.verification.model.ParameterProfile;

/**
 * 策略批准引擎接口。
 * <p>
 * 决定某个参数是否允许进入后续 Technique 验证。
 * 判断依据：
 * - InfluenceScore < minInfluenceScore → reject
 * - parameter.mutable == false → reject
 * - replay failed → reject
 */
public interface IStrategyApprovalEngine {

    /**
     * 评估是否批准该参数进入后续验证。
     *
     * @param result     Influence 验证结果
     * @param profile    参数特征
     * @param minScore   最低影响性评分阈值
     * @return 批准结果（包含批准状态和原因）
     */
    InfluenceResult approve(InfluenceResult result, ParameterProfile profile, double minScore);
}
