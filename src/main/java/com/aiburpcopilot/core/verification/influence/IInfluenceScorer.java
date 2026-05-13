package com.aiburpcopilot.core.verification.influence;

import com.aiburpcopilot.core.verification.model.DiffResult;

/**
 * Influence 评分器接口。
 * <p>
 * 计算参数的影响性评分 (0.0 ~ 1.0)。
 * 推荐权重：
 * Status: 0.35, Length: 0.20, Structure: 0.25, Keyword: 0.10, Timing: 0.10
 */
public interface IInfluenceScorer {

    /**
     * 计算影响性评分。
     *
     * @param diffResult Diff 分析结果
     * @return 影响性评分 (0.0 ~ 1.0)
     */
    double score(DiffResult diffResult);

    /**
     * 对多个 Diff 结果计算平均影响性评分。
     *
     * @param diffResults 多个 Diff 结果
     * @return 平均影响性评分
     */
    double scoreMultiple(DiffResult... diffResults);

    /**
     * 获取评分详情（各项得分分解）。
     *
     * @param diffResult Diff 分析结果
     * @return 评分详情字符串
     */
    String scoreDetails(DiffResult diffResult);
}
