package com.aiburpcopilot.core.context;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * HTTP 上下文 —— 整个项目的核心统一数据模型。
 * <p>
 * 记录一次 HTTP 请求/响应的完整上下文信息。
 * 所有模块（Pipeline、Scanner、AI、UI、History）均以此模型为中心进行数据交换。
 * <p>
 * 设计原则：
 * <ul>
 *   <li>字段一经定义不再轻易修改，确保跨阶段兼容</li>
 *   <li>所有模块依赖此模型的稳定接口</li>
 *   <li>敏感字段（Cookie、Authorization）在采集时即清理</li>
 * </ul>
 */
public class HTTPContext {

    /** 唯一请求 ID */
    private String requestId;

    /** HTTP 方法（GET、POST、PUT、DELETE 等） */
    private String method;

    /** 完整 URL */
    private String url;

    /** URL 路径（不含查询参数） */
    private String path;

    /** 查询参数字符串（原始格式） */
    private String query;

    /** 请求头（Map 格式，已移除敏感字段） */
    private java.util.Map<String, String> headers;

    /** 请求体（原始字节数组） */
    private byte[] requestBody;

    /** 响应体（原始字节数组） */
    private byte[] responseBody;

    /** HTTP 响应状态码 */
    private int statusCode;

    /** 请求 Content-Type */
    private String contentType;

    /** 响应 Content-Type */
    private String responseContentType;

    /** 提取的参数列表 */
    private List<ParameterContext> parameters;

    /** 端点类型（由 EndpointClassifier 填充） */
    private EndpointType endpointType;

    private EndpointActionType endpointActionType;

    /** AI 分析结果（由 AIAnalysisStage 填充） */
    private AnalysisResult analysisResult;

    /** 分析状态 */
    private AnalysisStatus analysisStatus;

    /** 静态资源扫描结果（仅对 STATIC_RESOURCE 类型有效） */
    private String staticScanResult;

    /** 请求时间戳 */
    private long timestamp;

    /** 请求体大小 */
    private int requestBodySize;

    /** 响应体大小 */
    private int responseBodySize;

    /** 原始HTTP请求完整字节（用于发送到Repeater） */
    private byte[] rawRequest;

    /** 原始HTTP响应完整字节（用于展示完整响应包） */
    private byte[] rawResponse;

    /** 风险评估等级（由 RiskEvaluatorStage 填充） */
    private RiskLevel riskLevel;

    /** 验证结果列表（由 WorkflowVerificationStage 填充） */
    private java.util.List<com.aiburpcopilot.core.verification.model.VerificationResult> verificationResults;

    public HTTPContext() {
        this.requestId = UUID.randomUUID().toString().replace("-", "");
        this.parameters = new ArrayList<>();
        this.endpointType = EndpointType.UNKNOWN;
        this.endpointActionType = EndpointActionType.UNKNOWN;
        this.analysisStatus = AnalysisStatus.PENDING;
        this.riskLevel = RiskLevel.INFO;
        this.timestamp = System.currentTimeMillis();
        this.headers = new java.util.HashMap<>();
    }

    // ---------- Getters & Setters ----------

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public java.util.Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(java.util.Map<String, String> headers) {
        this.headers = headers;
    }

    public void addHeader(String key, String value) {
        this.headers.put(key, value);
    }

    public byte[] getRequestBody() {
        return requestBody;
    }

    public void setRequestBody(byte[] requestBody) {
        this.requestBody = requestBody;
        this.requestBodySize = (requestBody != null) ? requestBody.length : 0;
    }

    public byte[] getResponseBody() {
        return responseBody;
    }

    public void setResponseBody(byte[] responseBody) {
        this.responseBody = responseBody;
        this.responseBodySize = (responseBody != null) ? responseBody.length : 0;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getResponseContentType() {
        return responseContentType;
    }

    public void setResponseContentType(String responseContentType) {
        this.responseContentType = responseContentType;
    }

    public List<ParameterContext> getParameters() {
        return parameters;
    }

    public void setParameters(List<ParameterContext> parameters) {
        this.parameters = parameters;
    }

    public void addParameter(ParameterContext parameter) {
        this.parameters.add(parameter);
    }

    public EndpointType getEndpointType() {
        return endpointType;
    }

    public void setEndpointType(EndpointType endpointType) {
        this.endpointType = endpointType;
    }

    public EndpointActionType getEndpointActionType() {
        return endpointActionType;
    }

    public void setEndpointActionType(EndpointActionType endpointActionType) {
        this.endpointActionType = endpointActionType != null ? endpointActionType : EndpointActionType.UNKNOWN;
    }

    public AnalysisResult getAnalysisResult() {
        return analysisResult;
    }

    public void setAnalysisResult(AnalysisResult analysisResult) {
        this.analysisResult = analysisResult;
    }

    public AnalysisStatus getAnalysisStatus() {
        return analysisStatus;
    }

    public void setAnalysisStatus(AnalysisStatus analysisStatus) {
        this.analysisStatus = analysisStatus;
    }

    public String getStaticScanResult() {
        return staticScanResult;
    }

    public void setStaticScanResult(String staticScanResult) {
        this.staticScanResult = staticScanResult;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public int getRequestBodySize() {
        return requestBodySize;
    }

    public int getResponseBodySize() {
        return responseBodySize;
    }

    public byte[] getRawRequest() {
        return rawRequest;
    }

    public void setRawRequest(byte[] rawRequest) {
        this.rawRequest = rawRequest;
    }

    public byte[] getRawResponse() {
        return rawResponse;
    }

    public void setRawResponse(byte[] rawResponse) {
        this.rawResponse = rawResponse;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public java.util.List<com.aiburpcopilot.core.verification.model.VerificationResult> getVerificationResults() {
        return verificationResults;
    }

    public void setVerificationResults(java.util.List<com.aiburpcopilot.core.verification.model.VerificationResult> verificationResults) {
        this.verificationResults = verificationResults;
    }

    public void addVerificationResult(com.aiburpcopilot.core.verification.model.VerificationResult result) {
        if (this.verificationResults == null) {
            this.verificationResults = new java.util.ArrayList<>();
        }
        this.verificationResults.add(result);
    }

    // ---------- Utility Methods ----------

    /**
     * 生成缓存的 Key。
     * 格式：METHOD + PATH + 参数名哈希
     * 不包含具体参数值，以确保相似的请求共享缓存。
     */
    public String generateCacheKey() {
        StringBuilder sb = new StringBuilder();
        sb.append(method != null ? method : "").append("|");
        sb.append(path != null ? path : "").append("|");
        if (parameters != null && !parameters.isEmpty()) {
            sb.append(parameters.stream()
                    .map(ParameterContext::getName)
                    .filter(Objects::nonNull)
                    .sorted()
                    .reduce((a, b) -> a + "," + b)
                    .orElse(""));
        }
        return sb.toString();
    }

    /**
     * 生成 AI 摘要（用于传递给 AI 进行分析）。
     * 仅包含必要的最小信息，不包含完整请求体。
     */
    public String toAISummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Method: ").append(method).append("\n");
        sb.append("Path: ").append(path).append("\n");
        sb.append("Content-Type: ").append(contentType).append("\n");
        sb.append("Response Content-Type: ").append(responseContentType).append("\n");
        sb.append("Heuristic Endpoint Action: ")
                .append(EndpointActionClassifier.classifyByHttp(this))
                .append("\n");

        // 仅传递参数名和样本值，不传递敏感值
        if (parameters != null && !parameters.isEmpty()) {
            sb.append("Parameters:\n");
            for (ParameterContext param : parameters) {
                String displayValue = param.getValue();
                if (displayValue != null && displayValue.length() > 100) {
                    displayValue = displayValue.substring(0, 100) + "...";
                }
                sb.append("  - ").append(param.getName())
                        .append(": ").append(displayValue)
                        .append(" (").append(param.getType()).append(")\n");
            }
        }

        return sb.toString();
    }

    @Override
    public String toString() {
        return "HTTPContext{" +
                "method='" + method + '\'' +
                ", path='" + path + '\'' +
                ", endpointType=" + endpointType +
                ", analysisStatus=" + analysisStatus +
                '}';
    }
}
