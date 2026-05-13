package com.aiburpcopilot.core.verification.model;

import com.aiburpcopilot.core.context.ParameterType;

/**
 * 修改后的 HTTP 请求。
 * <p>
 * 由 IParameterMutator 生成，包含完整的原始 HTTP 字节流，
 * 可直接通过 Montoya API 发送。
 */
public class MutatedRequest {

    /** 完整的原始 HTTP 请求字节（可发送到 Montoya API） */
    private byte[] rawRequest;

    /** 请求 URL */
    private String url;

    /** HTTP 方法 */
    private String method;

    /** 被修改的原始参数名 */
    private String originalParameterName;

    /** 注入的 payload */
    private String payload;

    /** 参数位置类型 */
    private ParameterType parameterType;

    public MutatedRequest() {
    }

    public MutatedRequest(byte[] rawRequest, String url, String method,
                          String originalParameterName, String payload,
                          ParameterType parameterType) {
        this.rawRequest = rawRequest;
        this.url = url;
        this.method = method;
        this.originalParameterName = originalParameterName;
        this.payload = payload;
        this.parameterType = parameterType;
    }

    // ---------- Getters & Setters ----------

    public byte[] getRawRequest() { return rawRequest; }
    public void setRawRequest(byte[] rawRequest) { this.rawRequest = rawRequest; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getOriginalParameterName() { return originalParameterName; }
    public void setOriginalParameterName(String originalParameterName) { this.originalParameterName = originalParameterName; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public ParameterType getParameterType() { return parameterType; }
    public void setParameterType(ParameterType parameterType) { this.parameterType = parameterType; }

    @Override
    public String toString() {
        return "MutatedRequest{" +
                "method='" + method + '\'' +
                ", url='" + url + '\'' +
                ", param='" + originalParameterName + '\'' +
                ", payload='" + payload + '\'' +
                ", type=" + parameterType +
                '}';
    }
}
