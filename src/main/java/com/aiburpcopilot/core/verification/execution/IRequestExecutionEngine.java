package com.aiburpcopilot.core.verification.execution;

import com.aiburpcopilot.core.verification.model.MutatedRequest;
import com.aiburpcopilot.core.verification.model.AttackTask;
import com.aiburpcopilot.core.verification.model.VerificationResult;

/**
 * 请求执行引擎接口。
 * <p>
 * 所有 HTTP 验证请求的统一发送入口。
 * 同步执行，在调用线程（pipeline 线程）上发送 Burp HTTP 请求。
 */
public interface IRequestExecutionEngine {

    /**
     * 同步执行一次修改后的请求。
     *
     * @param request 修改后的请求
     * @return 响应字节数组，失败时返回 null
     */
    byte[] execute(MutatedRequest request);

    /**
     * 同步执行完整的验证任务。
     * <p>
     * 包含：参数修改 → Host 限流 → 请求发送 → 响应捕获。
     * 在调用线程上直接执行，不创建新线程。
     *
     * @param task 攻击任务
     * @return 验证结果（不会为 null）
     */
    VerificationResult executeTask(AttackTask task);

    /**
     * 关闭引擎资源。
     */
    void shutdown();
}
