package com.aiburpcopilot.core.history;

import com.aiburpcopilot.core.context.*;
import com.aiburpcopilot.scanner.staticresource.StaticScanResult;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 历史记录条目。
 * <p>
 * 记录一次 HTTP 分析的完整摘要信息。
 */
public class HistoryEntry {

    /** 请求 ID */
    private String requestId;

    /** 请求时间 */
    private long timestamp;

    /** HTTP 方法 */
    private String method;

    /** 完整 URL */
    private String url;

    /** URL 路径 */
    private String path;

    /** HTTP 状态码 */
    private int statusCode;

    /** Content-Type */
    private String contentType;

    /** 端点类型 */
    private EndpointType endpointType;

    private EndpointActionType endpointActionType;

    /** 最高风险等级 */
    private RiskLevel riskLevel;

    /** 分析状态 */
    private AnalysisStatus analysisStatus;

    /** AI 分析摘要 */
    private String aiSummary;

    /** 攻击面类型列表 */
    private List<String> attackSurface;

    /** 可疑漏洞列表 */
    private List<String> possibleVulnerabilities;

    /** 高价值参数列表 */
    private List<String> highValueParams;

    /** 推荐测试列表 */
    private List<String> recommendedTests;

    /** 参数数量 */
    private int parameterCount;

    /** 响应体大小 */
    private int responseBodySize;

    /** AI 调用耗时（毫秒） */
    private long aiCallDurationMs;

    /** 请求体文本 */
    private String requestBody;

    /** 响应体文本 */
    private String responseBody;

    /** 原始HTTP请求完整字节（用于发送到Repeater） */
    private byte[] rawRequest;

    /** 原始HTTP响应完整字节（用于展示完整响应包） */
    private byte[] rawResponse;

    /** 高价值参数完整对象（含风险等级和原因） */
    private List<AnalysisResult.HighValueParam> highValueParamDetails;

    /** 验证结果列表（由 WorkflowVerificationStage 填充） */
    private java.util.List<com.aiburpcopilot.core.verification.model.VerificationResult> verificationResults;

    private StaticScanResult staticScanDetails;

    // ---------- Constructors ----------

    public HistoryEntry() {}

    /**
     * 从 HTTPContext 构建历史记录条目。
     * 只提取摘要信息，不保留完整请求体。
     */
    public static HistoryEntry fromHTTPContext(HTTPContext context) {
        HistoryEntry entry = new HistoryEntry();
        entry.requestId = context.getRequestId();
        entry.timestamp = context.getTimestamp();
        entry.method = context.getMethod();
        entry.url = context.getUrl();
        entry.path = context.getPath();
        entry.statusCode = context.getStatusCode();
        entry.contentType = context.getContentType();
        entry.endpointType = context.getEndpointType();
        entry.endpointActionType = context.getEndpointActionType();
        entry.analysisStatus = context.getAnalysisStatus();
        entry.parameterCount = context.getParameters() != null ? context.getParameters().size() : 0;
        entry.responseBodySize = context.getResponseBodySize();

        // 复制请求/响应体（用于UI展示和Repeater）
        if (context.getRequestBody() != null) {
            entry.requestBody = new String(context.getRequestBody(), StandardCharsets.UTF_8);
        }
        if (context.getResponseBody() != null) {
            entry.responseBody = new String(context.getResponseBody(), StandardCharsets.UTF_8);
        }
        entry.rawRequest = context.getRawRequest();
        entry.rawResponse = context.getRawResponse();

        // 提取 AI 分析结果（如果有）
        if (context.getAnalysisResult() != null) {
            AnalysisResult ar = context.getAnalysisResult();
            entry.attackSurface = ar.getAttackSurface();
            entry.possibleVulnerabilities = ar.getPossibleVulnerabilities();
            entry.recommendedTests = ar.getRecommendedTests();
            entry.aiSummary = ar.getSummary();
            entry.aiCallDurationMs = ar.getAiCallDurationMs();

            // 使用 RiskEvaluatorStage 评估的风险等级（如有），否则计算
            if (context.getRiskLevel() != null) {
                entry.riskLevel = context.getRiskLevel();
            } else {
                RiskLevel maxRisk = RiskLevel.INFO;
                for (AnalysisResult.HighValueParam hvp : ar.getHighValueParams()) {
                    if (hvp.getRiskLevel().ordinal() > maxRisk.ordinal()) {
                        maxRisk = hvp.getRiskLevel();
                    }
                }
                entry.riskLevel = maxRisk;
            }

            // 提取高价值参数名
            if (ar.getHighValueParams() != null) {
                entry.highValueParams = ar.getHighValueParams().stream()
                        .map(AnalysisResult.HighValueParam::getParamName)
                        .toList();
                entry.highValueParamDetails = ar.getHighValueParams();
            }
        }

        // 复制验证结果 (Phase 2)
        if (context.getVerificationResults() != null) {
            entry.verificationResults = new java.util.ArrayList<>(context.getVerificationResults());
        }

        return entry;
    }

    /**
     * 从 HTTPContext 构建静态资源扫描结果。
     */
    public static HistoryEntry fromStaticScan(HTTPContext context) {
        HistoryEntry entry = fromHTTPContext(context);
        entry.analysisStatus = AnalysisStatus.COMPLETED;
        entry.aiSummary = context.getStaticScanResult();
        entry.staticScanDetails = context.getStaticScanDetails();
        return entry;
    }

    // ---------- Getters & Setters ----------

    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }
    public EndpointType getEndpointType() { return endpointType; }
    public void setEndpointType(EndpointType endpointType) { this.endpointType = endpointType; }
    public EndpointActionType getEndpointActionType() { return endpointActionType; }
    public void setEndpointActionType(EndpointActionType endpointActionType) { this.endpointActionType = endpointActionType; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public void setRiskLevel(RiskLevel riskLevel) { this.riskLevel = riskLevel; }
    public AnalysisStatus getAnalysisStatus() { return analysisStatus; }
    public void setAnalysisStatus(AnalysisStatus analysisStatus) { this.analysisStatus = analysisStatus; }
    public String getAiSummary() { return aiSummary; }
    public void setAiSummary(String aiSummary) { this.aiSummary = aiSummary; }
    public List<String> getAttackSurface() { return attackSurface; }
    public void setAttackSurface(List<String> attackSurface) { this.attackSurface = attackSurface; }
    public List<String> getPossibleVulnerabilities() { return possibleVulnerabilities; }
    public void setPossibleVulnerabilities(List<String> possibleVulnerabilities) { this.possibleVulnerabilities = possibleVulnerabilities; }
    public List<String> getHighValueParams() { return highValueParams; }
    public void setHighValueParams(List<String> highValueParams) { this.highValueParams = highValueParams; }
    public List<String> getRecommendedTests() { return recommendedTests; }
    public void setRecommendedTests(List<String> recommendedTests) { this.recommendedTests = recommendedTests; }
    public int getParameterCount() { return parameterCount; }
    public void setParameterCount(int parameterCount) { this.parameterCount = parameterCount; }
    public int getResponseBodySize() { return responseBodySize; }
    public void setResponseBodySize(int responseBodySize) { this.responseBodySize = responseBodySize; }
    public long getAiCallDurationMs() { return aiCallDurationMs; }
    public void setAiCallDurationMs(long aiCallDurationMs) { this.aiCallDurationMs = aiCallDurationMs; }
    public String getRequestBody() { return requestBody; }
    public void setRequestBody(String requestBody) { this.requestBody = requestBody; }
    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }
    public byte[] getRawRequest() { return rawRequest; }
    public void setRawRequest(byte[] rawRequest) { this.rawRequest = rawRequest; }
    public byte[] getRawResponse() { return rawResponse; }
    public void setRawResponse(byte[] rawResponse) { this.rawResponse = rawResponse; }
    public List<AnalysisResult.HighValueParam> getHighValueParamDetails() { return highValueParamDetails; }
    public void setHighValueParamDetails(List<AnalysisResult.HighValueParam> highValueParamDetails) { this.highValueParamDetails = highValueParamDetails; }

    public java.util.List<com.aiburpcopilot.core.verification.model.VerificationResult> getVerificationResults() { return verificationResults; }
    public void setVerificationResults(java.util.List<com.aiburpcopilot.core.verification.model.VerificationResult> verificationResults) { this.verificationResults = verificationResults; }
    public StaticScanResult getStaticScanDetails() { return staticScanDetails; }
    public void setStaticScanDetails(StaticScanResult staticScanDetails) { this.staticScanDetails = staticScanDetails; }
}
