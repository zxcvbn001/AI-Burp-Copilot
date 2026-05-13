package com.aiburpcopilot.core.verification.candidate;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.model.CandidateParameter;

import java.util.List;

/**
 * Candidate 提取器接口。
 * <p>
 * 从 AI 分析结果中提取候选验证参数。
 * 负责将 AI 的高价值参数和推荐技术规范化为统一的 CandidateParameter 列表。
 */
public interface ICandidateExtractor {

    /**
     * 从 HTTP 上下文中提取候选验证参数。
     *
     * @param context HTTP 请求上下文（包含 AI 分析结果）
     * @return 候选参数列表
     */
    List<CandidateParameter> extract(HTTPContext context);

    /**
     * 筛选满足最低置信度的候选参数。
     *
     * @param candidates   候选参数列表
     * @param minConfidence 最低置信度阈值
     * @return 筛选后的候选参数列表
     */
    List<CandidateParameter> filterByConfidence(List<CandidateParameter> candidates, double minConfidence);
}
