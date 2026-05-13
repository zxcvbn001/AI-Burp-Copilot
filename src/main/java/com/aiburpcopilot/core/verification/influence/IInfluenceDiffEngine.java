package com.aiburpcopilot.core.verification.influence;

import com.aiburpcopilot.core.verification.model.DiffResult;

/**
 * Influence Diff 引擎接口。
 * <p>
 * 分析最小差异请求与原始请求之间响应变化。
 * 当前只允许轻量 Diff：
 * HTTP Status、Response Length、JSON Structure、Header Changes、
 * Keyword Changes、Response Time。
 * <p>
 * 禁止漏洞级 Diff（不扫描 sql error、mysql error 等）。
 */
public interface IInfluenceDiffEngine {

    /**
     * 比较原始响应和变异后响应的差异。
     *
     * @param originalResponse   原始响应字节
     * @param mutatedResponse    变异后响应字节
     * @param originalDurationMs 原始请求耗时
     * @param mutatedDurationMs  变异请求耗时
     * @return Diff 分析结果
     */
    DiffResult analyze(byte[] originalResponse, byte[] mutatedResponse,
                       long originalDurationMs, long mutatedDurationMs);
}
