package com.aiburpcopilot.core.verification.execution;

/**
 * 响应捕获接口。
 * <p>
 * 解耦执行引擎与 Diff 引擎 —
 * 原始响应由 Pipeline 阶段捕获，
 * 修改后响应由执行引擎捕获。
 */
public interface ResponseCapture {

    /**
     * 获取原始响应字节。
     *
     * @param requestId 请求 ID
     * @return 原始响应字节，或 null
     */
    byte[] getOriginalResponse(String requestId);

    /**
     * 存储原始响应。
     *
     * @param requestId 请求 ID
     * @param response  响应字节
     */
    void storeOriginalResponse(String requestId, byte[] response);

    /**
     * 捕获修改后响应。
     *
     * @param taskId   任务 ID
     * @param response 响应字节
     */
    void captureMutatedResponse(String taskId, byte[] response);

    /**
     * 获取修改后响应。
     *
     * @param taskId 任务 ID
     * @return 响应字节，或 null
     */
    byte[] getMutatedResponse(String taskId);
}
