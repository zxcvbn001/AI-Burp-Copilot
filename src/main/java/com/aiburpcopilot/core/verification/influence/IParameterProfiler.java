package com.aiburpcopilot.core.verification.influence;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.model.ParameterProfile;

/**
 * 参数特征分析器接口。
 * <p>
 * 识别参数的数据类型特征（Numeric、UUID、JWT、Boolean 等），
 * 为 MinimalMutationEngine 提供最小差异变异的依据。
 */
public interface IParameterProfiler {

    /**
     * 分析参数的类型特征。
     *
     * @param paramValue 参数值（可为 null）
     * @param paramName  参数名
     * @return 参数特征分析结果
     */
    ParameterProfile profile(String paramName, String paramValue);
}
