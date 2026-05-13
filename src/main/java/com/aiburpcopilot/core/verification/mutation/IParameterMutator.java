package com.aiburpcopilot.core.verification.mutation;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.model.AttackTask;
import com.aiburpcopilot.core.verification.model.MutatedRequest;

/**
 * 参数修改器接口。
 * <p>
 * 将 AttackTask 中的 payload 注入到 HTTP 请求的指定参数中。
 * 不同实现处理不同的参数位置（Query / JSON Body / Form Body）。
 */
public interface IParameterMutator {

    /**
     * 判断此修改器是否支持当前的上下文和任务。
     *
     * @param context HTTP 上下文
     * @param task    攻击任务
     * @return true 如果支持
     */
    boolean supports(HTTPContext context, AttackTask task);

    /**
     * 修改请求，将 payload 注入到目标参数。
     *
     * @param context HTTP 上下文（包含原始请求）
     * @param task    攻击任务（包含 payload 和目标参数信息）
     * @return 修改后的请求
     */
    MutatedRequest mutate(HTTPContext context, AttackTask task);
}
