package com.aiburpcopilot.scanner.staticresource.js;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

public class JsAnalysisResponse {

    private boolean success;
    private String url;
    private Error error;
    @JsonProperty("task_id")
    @JsonAlias({"taskId", "id"})
    private String taskId;
    private String status;
    @JsonProperty("status_url")
    @JsonAlias("statusUrl")
    private String statusUrl;
    private Task task;
    private Summary summary;
    private List<LeakResult> leaks = new ArrayList<>();
    private List<ApiResult> endpoints = new ArrayList<>();
    private List<AssetResult> jsFiles = new ArrayList<>();

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public Error getError() { return error; }
    public void setError(Error error) { this.error = error; }
    public String getTaskId() {
        if (taskId != null && !taskId.isBlank()) {
            return taskId;
        }
        return task != null ? task.getId() : null;
    }
    public void setTaskId(String taskId) { this.taskId = taskId; }
    public String getStatus() {
        if (status != null && !status.isBlank()) {
            return status;
        }
        return task != null ? task.getStatus() : null;
    }
    public void setStatus(String status) { this.status = status; }
    public String getStatusUrl() { return statusUrl; }
    public void setStatusUrl(String statusUrl) { this.statusUrl = statusUrl; }
    public Task getTask() { return task; }
    public void setTask(Task task) { this.task = task; }
    public Summary getSummary() { return summary; }
    public void setSummary(Summary summary) { this.summary = summary; }
    public List<LeakResult> getLeaks() { return leaks; }
    public void setLeaks(List<LeakResult> leaks) { this.leaks = leaks != null ? leaks : new ArrayList<>(); }
    public List<ApiResult> getEndpoints() { return endpoints; }
    public void setEndpoints(List<ApiResult> endpoints) { this.endpoints = endpoints != null ? endpoints : new ArrayList<>(); }
    public List<AssetResult> getJsFiles() { return jsFiles; }
    public void setJsFiles(List<AssetResult> jsFiles) { this.jsFiles = jsFiles != null ? jsFiles : new ArrayList<>(); }

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
        private int endpointCount;
        private int leakCount;
        private int jsFileCount;

        public int getEndpointCount() { return endpointCount; }
        public void setEndpointCount(int endpointCount) { this.endpointCount = endpointCount; }
        public int getLeakCount() { return leakCount; }
        public void setLeakCount(int leakCount) { this.leakCount = leakCount; }
        public int getJsFileCount() { return jsFileCount; }
        public void setJsFileCount(int jsFileCount) { this.jsFileCount = jsFileCount; }
    }

    public static class ApiResult {
        private String url;
        @JsonAlias("resolved_url")
        private String resolvedUrl;
        @JsonAlias("base_url")
        private String baseUrl;
        private String kind;
        private String method;
        private List<String> params = new ArrayList<>();
        private List<String> headers = new ArrayList<>();
        private String auth;
        private String source;
        private String confidence;
        private List<String> notes = new ArrayList<>();
        private String evidence;

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getResolvedUrl() { return resolvedUrl; }
        public void setResolvedUrl(String resolvedUrl) { this.resolvedUrl = resolvedUrl; }
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public String getKind() { return kind; }
        public void setKind(String kind) { this.kind = kind; }
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
        public String getEvidence() { return evidence; }
        public void setEvidence(String evidence) { this.evidence = evidence; }
    }

    public static class AssetResult {
        private String url;
        private String type;
        private String chunkName;
        private String source;
        private Double confidence;
        private String evidence;

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getChunkName() { return chunkName; }
        public void setChunkName(String chunkName) { this.chunkName = chunkName; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public Double getConfidence() { return confidence; }
        public void setConfidence(Double confidence) { this.confidence = confidence; }
        public String getEvidence() { return evidence; }
        public void setEvidence(String evidence) { this.evidence = evidence; }
    }

    public static class LeakResult {
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
