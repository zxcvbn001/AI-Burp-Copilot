package com.aiburpcopilot.core.verification.influence;

import com.aiburpcopilot.core.context.HTTPContext;

/**
 * 重放引擎接口。
 * <p>
 * 负责自动重放最小差异请求。
 * 这是 HTTP 能力层，不是漏洞能力层。
 * <p>
 * 必须支持 GET/POST、Query/JSON/Form/Headers 参数类型。
 */
public interface IReplayEngine {

    /**
     * 重放原始请求并获取响应。
     *
     * @param context 原始 HTTP 上下文
     * @return 响应字节数组
     */
    byte[] replayOriginal(HTTPContext context);

    /**
     * 重放带变异参数的请求并获取响应。
     *
     * @param context     原始 HTTP 上下文
     * @param paramName   要变异的参数名
     * @param newValue    新的参数值
     * @return 响应字节数组
     */
    byte[] replayWithMutation(HTTPContext context, String paramName, String newValue);

    default byte[] replayWithAppendedMutation(HTTPContext context, String paramName, String payloadSuffix) {
        return replayWithMutation(context, paramName, payloadSuffix);
    }

    /**
     * 获取最后一次重放的耗时（毫秒）。
     */
    long getLastReplayDurationMs();

    default byte[] getLastRequestBytes() {
        return null;
    }

    default byte[] getLastResponseBytes() {
        return null;
    }
}
