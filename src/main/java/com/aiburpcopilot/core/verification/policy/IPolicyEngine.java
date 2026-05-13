package com.aiburpcopilot.core.verification.policy;

import com.aiburpcopilot.core.verification.model.VerificationPolicy;

/**
 * 策略引擎接口。
 * <p>
 * 控制哪些验证行为允许执行。
 * 策略是运行时配置，可动态更新。
 */
public interface IPolicyEngine {

    /**
     * 获取当前验证策略。
     */
    VerificationPolicy getPolicy();

    /**
     * 更新策略（从外部配置加载）。
     */
    void updatePolicy(VerificationPolicy policy);

    /**
     * 判断时间型验证是否允许。
     */
    boolean isTimeBasedAllowed();

    /**
     * 判断联合查询验证是否允许。
     */
    boolean isUnionBasedAllowed();

    /**
     * 判断错误型验证是否允许。
     */
    boolean isErrorBasedAllowed();

    /**
     * 获取最大重放请求数。
     */
    int getMaxReplayRequests();

    /**
     * 获取最大参数测试数。
     */
    int getMaxParameterTests();

    /**
     * 获取最小影响性评分阈值。
     */
    double getMinInfluenceScore();

    /**
     * 检查指定主机是否在验证白名单中。
     */
    boolean isHostAllowed(String url);

    /**
     * 重新加载策略。
     */
    void reload();
}
