package com.aiburpcopilot.core.context;

/**
 * 端点类型枚举。
 * <p>
 * 用于标识 HTTP 请求的目标类型：
 * <ul>
 *   <li>ENDPOINT - 可交互的业务接口，需要深入分析</li>
 *   <li>STATIC_RESOURCE - 静态资源文件，仅需检测敏感信息泄露</li>
 *   <li>UNKNOWN - 无法明确判断的类型</li>
 * </ul>
 * <p>
 * 该枚举由 EndpointClassifier 的两层判断（规则 + AI）共同决定。
 * 后续阶段可扩展更多细分类型（如 API_ENDPOINT, GRAPHQL, SOAP 等）。
 */
public enum EndpointType {

    /** 可交互的业务接口，包含参数、API、认证点等 */
    ENDPOINT,

    /** 静态资源文件，如 JS、CSS、图片等 */
    STATIC_RESOURCE,

    /** 无法明确分类 */
    UNKNOWN
}
