package com.aiburpcopilot.core.context;

/**
 * 参数类型枚举。
 * <p>
 * 标识 HTTP 请求中参数所在的位置。
 * 用于后续的 Payload 生成和参数篡改。
 */
public enum ParameterType {

    /** URL 查询参数（Query String） */
    QUERY,

    /** 请求体参数（Form Body 或 JSON） */
    BODY,

    /** HTTP 请求头 */
    HEADER,

    /** URL 路径参数（RESTful 风格） */
    PATH,

    /** Cookie 参数 */
    COOKIE
}
