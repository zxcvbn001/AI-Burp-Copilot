package com.aiburpcopilot.scanner.endpoint;

import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.utils.HttpUtil;

/**
 * 端点分类器接口。
 * <p>
 * 负责将 HTTP 请求分类为：
 * <ul>
 *   <li>ENDPOINT - 可交互的业务接口</li>
 *   <li>STATIC_RESOURCE - 静态资源</li>
 *   <li>UNKNOWN - 无法确定</li>
 * </ul>
 * <p>
 * 采用两层判断机制：
 * <ol>
 *   <li>规则引擎（快速、确定性强）</li>
 *   <li>AI 辅助判断（处理规则无法确定的情况）</li>
 * </ol>
 */
public interface IEndpointClassifier {

    /**
     * 对 HTTP 上下文进行第一层规则判断。
     * <p>
     * 基于以下特征判断：
     * <ul>
     *   <li>HTTP Method（POST/PUT/PATCH → 倾向 ENDPOINT）</li>
     *   <li>URL 后缀（.js/.css/.png → STATIC_RESOURCE）</li>
     *   <li>路径关键字（/api/、/auth/ → 倾向 ENDPOINT）</li>
     *   <li>Content-Type（JSON/XML → 倾向 ENDPOINT）</li>
     *   <li>URL 关键字（/static/、/assets/ → 倾向 STATIC_RESOURCE）</li>
     * </ul>
     *
     * @param context HTTP 上下文
     * @return 规则判断结果，CONFIDENT 表示确定，UNCERTAIN 表示需 AI 辅助
     */
    RuleResult classifyByRules(HTTPContext context);

    /**
     * 对 HTTP 上下文进行第二层 AI 辅助判断。
     * <p>
     * 仅在规则判断返回 UNCERTAIN 时调用。
     * 传递给 AI 的最小信息：
     * <ul>
     *   <li>Method</li>
     *   <li>Path</li>
     *   <li>Content-Type</li>
     *   <li>Body 前 512 字节</li>
     *   <li>Response Content-Type</li>
     * </ul>
     *
     * @param context HTTP 上下文
     * @return AI 分类结果
     */
    EndpointType classifyByAI(HTTPContext context);

    /**
     * 对 HTTP 上下文进行完整分类（规则 + 可选 AI）。
     *
     * @param context HTTP 上下文（会被修改 endpointType 字段）
     */
    void classify(HTTPContext context);

    /**
     * 规则判断结果。
     */
    enum RuleResult {
        /** 规则确定判断为 ENDPOINT */
        CONFIDENT_ENDPOINT,
        /** 规则确定判断为 STATIC_RESOURCE */
        CONFIDENT_STATIC,
        /** 规则无法确定，需要 AI 辅助 */
        UNCERTAIN
    }
}
