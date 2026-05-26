package com.aiburpcopilot.scanner.staticresource.js;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonAlias;

import java.util.ArrayList;
import java.util.List;

public class JsAnalysisResponse {

    private boolean success;
    private String url;
    private Error error;
    @JsonProperty("task_id")
    private String taskId;
    private String status;
    @JsonProperty("status_url")
    private String statusUrl;
    private Task task;
    private List<ApiResult> apis = new ArrayList<>();
    private List<AssetResult> assets = new ArrayList<>();
    private List<ParamResult> params = new ArrayList<>();
    private List<String> auth = new ArrayList<>();
    private List<SecretResult> secrets = new ArrayList<>();
    private List<RiskResult> risk = new ArrayList<>();
    private List<FindingResult> findings = new ArrayList<>();
    private Summary summary;
    private Groups groups;

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public Error getError() { return error; }
    public void setError(Error error) { this.error = error; }
    public String getTaskId() { return taskId; }
    public void setTaskId(String taskId) { this.taskId = taskId; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getStatusUrl() { return statusUrl; }
    public void setStatusUrl(String statusUrl) { this.statusUrl = statusUrl; }
    public Task getTask() { return task; }
    public void setTask(Task task) { this.task = task; }
    public List<ApiResult> getApis() { return apis; }
    public void setApis(List<ApiResult> apis) { this.apis = apis != null ? apis : new ArrayList<>(); }
    public List<AssetResult> getAssets() { return assets; }
    public void setAssets(List<AssetResult> assets) { this.assets = assets != null ? assets : new ArrayList<>(); }
    public List<ParamResult> getParams() { return params; }
    public void setParams(List<ParamResult> params) { this.params = params != null ? params : new ArrayList<>(); }
    public List<String> getAuth() { return auth; }
    public void setAuth(List<String> auth) { this.auth = auth != null ? auth : new ArrayList<>(); }
    public List<SecretResult> getSecrets() { return secrets; }
    public void setSecrets(List<SecretResult> secrets) { this.secrets = secrets != null ? secrets : new ArrayList<>(); }
    public List<RiskResult> getRisk() { return risk; }
    public void setRisk(List<RiskResult> risk) { this.risk = risk != null ? risk : new ArrayList<>(); }
    public List<FindingResult> getFindings() { return findings; }
    public void setFindings(List<FindingResult> findings) { this.findings = findings != null ? findings : new ArrayList<>(); }
    public Summary getSummary() { return summary; }
    public void setSummary(Summary summary) { this.summary = summary; }
    public Groups getGroups() { return groups; }
    public void setGroups(Groups groups) { this.groups = groups; }

    public String errorMessage() {
        return error != null ? error.getMessage() : null;
    }

    public static class Task {
        private String id;
        private String status;
        private String createdAt;
        private String updatedAt;
        private Error error;
        private JsAnalysisResponse result;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public String getCreatedAt() { return createdAt; }
        public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }
        public String getUpdatedAt() { return updatedAt; }
        public void setUpdatedAt(String updatedAt) { this.updatedAt = updatedAt; }
        public Error getError() { return error; }
        public void setError(Error error) { this.error = error; }
        public JsAnalysisResponse getResult() { return result; }
        public void setResult(JsAnalysisResponse result) { this.result = result; }
    }

    public static class Error {
        private String message;
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
    }

    public static class Summary {
        private int apiCount;
        private int assetCount;
        private int paramCount;
        private int authCount;
        private int secretCount;
        private int riskCount;
        private int findingCount;
        private int endpointCount;
        private int exposureCount;
        private int scriptCount;
        private LlmSummary llm;

        public int getApiCount() { return apiCount; }
        public void setApiCount(int apiCount) { this.apiCount = apiCount; }
        public int getAssetCount() { return assetCount; }
        public void setAssetCount(int assetCount) { this.assetCount = assetCount; }
        public int getParamCount() { return paramCount; }
        public void setParamCount(int paramCount) { this.paramCount = paramCount; }
        public int getAuthCount() { return authCount; }
        public void setAuthCount(int authCount) { this.authCount = authCount; }
        public int getSecretCount() { return secretCount; }
        public void setSecretCount(int secretCount) { this.secretCount = secretCount; }
        public int getRiskCount() { return riskCount; }
        public void setRiskCount(int riskCount) { this.riskCount = riskCount; }
        public int getFindingCount() { return findingCount; }
        public void setFindingCount(int findingCount) { this.findingCount = findingCount; }
        public int getEndpointCount() { return endpointCount; }
        public void setEndpointCount(int endpointCount) { this.endpointCount = endpointCount; }
        public int getExposureCount() { return exposureCount; }
        public void setExposureCount(int exposureCount) { this.exposureCount = exposureCount; }
        public int getScriptCount() { return scriptCount; }
        public void setScriptCount(int scriptCount) { this.scriptCount = scriptCount; }
        public LlmSummary getLlm() { return llm; }
        public void setLlm(LlmSummary llm) { this.llm = llm; }
    }

    public static class LlmSummary {
        private boolean enabled;
        private int reviewedCount;
        private int confirmedCount;
        private int rejectedCount;
        private int findingReviewedCount;
        private int findingConfirmedCount;
        private int findingRejectedCount;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getReviewedCount() { return reviewedCount; }
        public void setReviewedCount(int reviewedCount) { this.reviewedCount = reviewedCount; }
        public int getConfirmedCount() { return confirmedCount; }
        public void setConfirmedCount(int confirmedCount) { this.confirmedCount = confirmedCount; }
        public int getRejectedCount() { return rejectedCount; }
        public void setRejectedCount(int rejectedCount) { this.rejectedCount = rejectedCount; }
        public int getFindingReviewedCount() { return findingReviewedCount; }
        public void setFindingReviewedCount(int findingReviewedCount) { this.findingReviewedCount = findingReviewedCount; }
        public int getFindingConfirmedCount() { return findingConfirmedCount; }
        public void setFindingConfirmedCount(int findingConfirmedCount) { this.findingConfirmedCount = findingConfirmedCount; }
        public int getFindingRejectedCount() { return findingRejectedCount; }
        public void setFindingRejectedCount(int findingRejectedCount) { this.findingRejectedCount = findingRejectedCount; }
    }

    public static class Groups {
        private EndpointGroup endpoints;
        private ExposureGroup exposures;
        private ScriptGroup scripts;

        public EndpointGroup getEndpoints() { return endpoints; }
        public void setEndpoints(EndpointGroup endpoints) { this.endpoints = endpoints; }
        public ExposureGroup getExposures() { return exposures; }
        public void setExposures(ExposureGroup exposures) { this.exposures = exposures; }
        public ScriptGroup getScripts() { return scripts; }
        public void setScripts(ScriptGroup scripts) { this.scripts = scripts; }
    }

    public static class EndpointGroup {
        private List<ApiResult> apis = new ArrayList<>();
        private List<FindingResult> findings = new ArrayList<>();
        private int count;

        public List<ApiResult> getApis() { return apis; }
        public void setApis(List<ApiResult> apis) { this.apis = apis != null ? apis : new ArrayList<>(); }
        public List<FindingResult> getFindings() { return findings; }
        public void setFindings(List<FindingResult> findings) { this.findings = findings != null ? findings : new ArrayList<>(); }
        public int getCount() { return count; }
        public void setCount(int count) { this.count = count; }
    }

    public static class ExposureGroup {
        private List<SecretResult> secrets = new ArrayList<>();
        private List<FindingResult> findings = new ArrayList<>();
        private int count;

        public List<SecretResult> getSecrets() { return secrets; }
        public void setSecrets(List<SecretResult> secrets) { this.secrets = secrets != null ? secrets : new ArrayList<>(); }
        public List<FindingResult> getFindings() { return findings; }
        public void setFindings(List<FindingResult> findings) { this.findings = findings != null ? findings : new ArrayList<>(); }
        public int getCount() { return count; }
        public void setCount(int count) { this.count = count; }
    }

    public static class ScriptGroup {
        private List<AssetResult> assets = new ArrayList<>();
        private List<FindingResult> findings = new ArrayList<>();
        private int count;

        public List<AssetResult> getAssets() { return assets; }
        public void setAssets(List<AssetResult> assets) { this.assets = assets != null ? assets : new ArrayList<>(); }
        public List<FindingResult> getFindings() { return findings; }
        public void setFindings(List<FindingResult> findings) { this.findings = findings != null ? findings : new ArrayList<>(); }
        public int getCount() { return count; }
        public void setCount(int count) { this.count = count; }
    }

    public static class ApiResult {
        private String url;
        @JsonAlias("resolved_url")
        private String resolvedUrl;
        @JsonAlias("base_url")
        private String baseUrl;
        private String method;
        private List<String> params = new ArrayList<>();
        private List<String> headers = new ArrayList<>();
        private String auth;
        private String source;
        private String confidence;
        private List<String> notes = new ArrayList<>();

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getResolvedUrl() { return resolvedUrl; }
        public void setResolvedUrl(String resolvedUrl) { this.resolvedUrl = resolvedUrl; }
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public List<String> getParams() { return params; }
        public void setParams(List<String> params) { this.params = params != null ? params : new ArrayList<>(); }
        public List<String> getHeaders() { return headers; }
        public void setHeaders(List<String> headers) { this.headers = headers != null ? headers : new ArrayList<>(); }
        public String getAuth() { return auth; }
        public void setAuth(String auth) { this.auth = auth; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public String getConfidence() { return confidence; }
        public void setConfidence(String confidence) { this.confidence = confidence; }
        public List<String> getNotes() { return notes; }
        public void setNotes(List<String> notes) { this.notes = notes != null ? notes : new ArrayList<>(); }
    }

    public static class AssetResult {
        private String url;
        private String type;
        private String chunkName;
        private String source;

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getChunkName() { return chunkName; }
        public void setChunkName(String chunkName) { this.chunkName = chunkName; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
    }

    public static class ParamResult {
        private String name;
        private String location;
        private String api;
        private String source;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }
        public String getApi() { return api; }
        public void setApi(String api) { this.api = api; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
    }

    public static class SecretResult {
        private String type;
        private String value;
        private String severity;
        private Double confidence;
        private String source;
        private String evidence;

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

    public static class RiskResult {
        private String type;
        private String severity;
        private String evidence;

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public String getEvidence() { return evidence; }
        public void setEvidence(String evidence) { this.evidence = evidence; }
    }

    public static class FindingResult {
        private String category;
        private String type;
        private String value;
        private String severity;
        private Double confidence;
        private String source;
        private String evidence;

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
}
