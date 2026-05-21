package com.aiburpcopilot.scanner.staticresource;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;

public class StaticScanResult {

    private boolean hasFindings;
    private List<Finding> findings;
    private String aiReview;
    private List<AnalyzedScript> analyzedScripts;
    private List<RecoveredEndpoint> recoveredEndpoints;
    private List<JsAstTaskStatus> jsAstTasks;
    private List<CloudFinding> cloudFindings;
    private List<CloudApi> cloudApis;
    private List<CloudAsset> cloudAssets;
    private List<CloudParam> cloudParams;
    private List<String> cloudAuthSignals;
    private List<CloudSecret> cloudSecrets;
    private List<CloudRisk> cloudRisks;
    private List<CloudFinding> endpointFindings;
    private List<CloudFinding> exposureFindings;
    private List<CloudFinding> scriptFindings;

    public StaticScanResult() {
        this.hasFindings = false;
    }

    public boolean isHasFindings() { return hasFindings; }
    public void setHasFindings(boolean hasFindings) { this.hasFindings = hasFindings; }
    public List<Finding> getFindings() { return findings; }
    public void setFindings(List<Finding> findings) { this.findings = findings; }
    public String getAiReview() { return aiReview; }
    public void setAiReview(String aiReview) { this.aiReview = aiReview; }
    public List<AnalyzedScript> getAnalyzedScripts() { return analyzedScripts; }
    public void setAnalyzedScripts(List<AnalyzedScript> analyzedScripts) { this.analyzedScripts = analyzedScripts; }
    public List<RecoveredEndpoint> getRecoveredEndpoints() { return recoveredEndpoints; }
    public void setRecoveredEndpoints(List<RecoveredEndpoint> recoveredEndpoints) { this.recoveredEndpoints = recoveredEndpoints; }
    public List<JsAstTaskStatus> getJsAstTasks() { return jsAstTasks; }
    public void setJsAstTasks(List<JsAstTaskStatus> jsAstTasks) { this.jsAstTasks = jsAstTasks; }
    public List<CloudFinding> getCloudFindings() { return cloudFindings; }
    public void setCloudFindings(List<CloudFinding> cloudFindings) { this.cloudFindings = cloudFindings; }
    public List<CloudApi> getCloudApis() { return cloudApis; }
    public void setCloudApis(List<CloudApi> cloudApis) { this.cloudApis = cloudApis; }
    public List<CloudAsset> getCloudAssets() { return cloudAssets; }
    public void setCloudAssets(List<CloudAsset> cloudAssets) { this.cloudAssets = cloudAssets; }
    public List<CloudParam> getCloudParams() { return cloudParams; }
    public void setCloudParams(List<CloudParam> cloudParams) { this.cloudParams = cloudParams; }
    public List<String> getCloudAuthSignals() { return cloudAuthSignals; }
    public void setCloudAuthSignals(List<String> cloudAuthSignals) { this.cloudAuthSignals = cloudAuthSignals; }
    public List<CloudSecret> getCloudSecrets() { return cloudSecrets; }
    public void setCloudSecrets(List<CloudSecret> cloudSecrets) { this.cloudSecrets = cloudSecrets; }
    public List<CloudRisk> getCloudRisks() { return cloudRisks; }
    public void setCloudRisks(List<CloudRisk> cloudRisks) { this.cloudRisks = cloudRisks; }
    public List<CloudFinding> getEndpointFindings() { return endpointFindings; }
    public void setEndpointFindings(List<CloudFinding> endpointFindings) { this.endpointFindings = endpointFindings; }
    public List<CloudFinding> getExposureFindings() { return exposureFindings; }
    public void setExposureFindings(List<CloudFinding> exposureFindings) { this.exposureFindings = exposureFindings; }
    public List<CloudFinding> getScriptFindings() { return scriptFindings; }
    public void setScriptFindings(List<CloudFinding> scriptFindings) { this.scriptFindings = scriptFindings; }

    public static class Finding {
        private String ruleName;
        private String matchedContent;
        private int lineNumber;
        private String severity;

        public Finding() {}

        public Finding(String ruleName, String matchedContent, int lineNumber, String severity) {
            this.ruleName = ruleName;
            this.matchedContent = matchedContent;
            this.lineNumber = lineNumber;
            this.severity = severity;
        }

        public String getRuleName() { return ruleName; }
        public void setRuleName(String ruleName) { this.ruleName = ruleName; }
        public String getMatchedContent() { return matchedContent; }
        public void setMatchedContent(String matchedContent) { this.matchedContent = matchedContent; }
        public int getLineNumber() { return lineNumber; }
        public void setLineNumber(int lineNumber) { this.lineNumber = lineNumber; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }

        @Override
        public String toString() {
            return "Finding{" +
                    "rule='" + ruleName + '\'' +
                    ", line=" + lineNumber +
                    ", severity='" + severity + '\'' +
                    '}';
        }
    }

    public static class AnalyzedScript {
        private String url;
        private boolean validated;
        private int statusCode;
        private String reason;
        private int apiCount;
        private int secretCount;
        private int riskCount;

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public boolean isValidated() { return validated; }
        public void setValidated(boolean validated) { this.validated = validated; }
        public int getStatusCode() { return statusCode; }
        public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public int getApiCount() { return apiCount; }
        public void setApiCount(int apiCount) { this.apiCount = apiCount; }
        public int getSecretCount() { return secretCount; }
        public void setSecretCount(int secretCount) { this.secretCount = secretCount; }
        public int getRiskCount() { return riskCount; }
        public void setRiskCount(int riskCount) { this.riskCount = riskCount; }
    }

    public static class RecoveredEndpoint {
        private String sourceScriptUrl;
        private String rawUrl;
        private String url;
        private String method;
        private boolean validated;
        private int statusCode;
        private String reason;
        private List<String> params;
        @JsonIgnore
        private byte[] requestBytes;
        @JsonIgnore
        private byte[] responseBytes;

        public String getSourceScriptUrl() { return sourceScriptUrl; }
        public void setSourceScriptUrl(String sourceScriptUrl) { this.sourceScriptUrl = sourceScriptUrl; }
        public String getRawUrl() { return rawUrl; }
        public void setRawUrl(String rawUrl) { this.rawUrl = rawUrl; }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public boolean isValidated() { return validated; }
        public void setValidated(boolean validated) { this.validated = validated; }
        public int getStatusCode() { return statusCode; }
        public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public List<String> getParams() { return params; }
        public void setParams(List<String> params) { this.params = params; }
        public byte[] getRequestBytes() { return requestBytes; }
        public void setRequestBytes(byte[] requestBytes) { this.requestBytes = requestBytes; }
        public byte[] getResponseBytes() { return responseBytes; }
        public void setResponseBytes(byte[] responseBytes) { this.responseBytes = responseBytes; }
    }

    public static class JsAstTaskStatus {
        private String scriptUrl;
        private String taskId;
        private String phase;
        private String status;
        private String message;

        public String getScriptUrl() { return scriptUrl; }
        public void setScriptUrl(String scriptUrl) { this.scriptUrl = scriptUrl; }
        public String getTaskId() { return taskId; }
        public void setTaskId(String taskId) { this.taskId = taskId; }
        public String getPhase() { return phase; }
        public void setPhase(String phase) { this.phase = phase; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
    }

    public static class CloudFinding {
        private String sourceScriptUrl;
        private String category;
        private String type;
        private String value;
        private String severity;
        private Double confidence;
        private String source;
        private String evidence;

        public String getSourceScriptUrl() { return sourceScriptUrl; }
        public void setSourceScriptUrl(String sourceScriptUrl) { this.sourceScriptUrl = sourceScriptUrl; }
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public Double getConfidence() { return confidence; }
        public void setConfidence(Double confidence) { this.confidence = confidence; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public String getEvidence() { return evidence; }
        public void setEvidence(String evidence) { this.evidence = evidence; }
    }

    public static class CloudApi {
        private String sourceScriptUrl;
        private String rawUrl;
        private String resolvedUrl;
        private String baseUrl;
        private String method;
        private List<String> params;
        private List<String> headers;
        private String auth;
        private String source;
        private String confidence;
        private List<String> notes;

        public String getSourceScriptUrl() { return sourceScriptUrl; }
        public void setSourceScriptUrl(String sourceScriptUrl) { this.sourceScriptUrl = sourceScriptUrl; }
        public String getRawUrl() { return rawUrl; }
        public void setRawUrl(String rawUrl) { this.rawUrl = rawUrl; }
        public String getResolvedUrl() { return resolvedUrl; }
        public void setResolvedUrl(String resolvedUrl) { this.resolvedUrl = resolvedUrl; }
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public List<String> getParams() { return params; }
        public void setParams(List<String> params) { this.params = params; }
        public List<String> getHeaders() { return headers; }
        public void setHeaders(List<String> headers) { this.headers = headers; }
        public String getAuth() { return auth; }
        public void setAuth(String auth) { this.auth = auth; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public String getConfidence() { return confidence; }
        public void setConfidence(String confidence) { this.confidence = confidence; }
        public List<String> getNotes() { return notes; }
        public void setNotes(List<String> notes) { this.notes = notes; }
    }

    public static class CloudAsset {
        private String sourceScriptUrl;
        private String url;
        private String resolvedUrl;
        private String type;
        private String chunkName;
        private String source;

        public String getSourceScriptUrl() { return sourceScriptUrl; }
        public void setSourceScriptUrl(String sourceScriptUrl) { this.sourceScriptUrl = sourceScriptUrl; }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getResolvedUrl() { return resolvedUrl; }
        public void setResolvedUrl(String resolvedUrl) { this.resolvedUrl = resolvedUrl; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getChunkName() { return chunkName; }
        public void setChunkName(String chunkName) { this.chunkName = chunkName; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
    }

    public static class CloudParam {
        private String sourceScriptUrl;
        private String name;
        private String location;
        private String api;
        private String source;

        public String getSourceScriptUrl() { return sourceScriptUrl; }
        public void setSourceScriptUrl(String sourceScriptUrl) { this.sourceScriptUrl = sourceScriptUrl; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }
        public String getApi() { return api; }
        public void setApi(String api) { this.api = api; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
    }

    public static class CloudSecret {
        private String sourceScriptUrl;
        private String type;
        private String value;
        private String severity;
        private Double confidence;
        private String source;
        private String evidence;

        public String getSourceScriptUrl() { return sourceScriptUrl; }
        public void setSourceScriptUrl(String sourceScriptUrl) { this.sourceScriptUrl = sourceScriptUrl; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public Double getConfidence() { return confidence; }
        public void setConfidence(Double confidence) { this.confidence = confidence; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public String getEvidence() { return evidence; }
        public void setEvidence(String evidence) { this.evidence = evidence; }
    }

    public static class CloudRisk {
        private String sourceScriptUrl;
        private String type;
        private String severity;
        private String evidence;

        public String getSourceScriptUrl() { return sourceScriptUrl; }
        public void setSourceScriptUrl(String sourceScriptUrl) { this.sourceScriptUrl = sourceScriptUrl; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public String getEvidence() { return evidence; }
        public void setEvidence(String evidence) { this.evidence = evidence; }
    }
}
