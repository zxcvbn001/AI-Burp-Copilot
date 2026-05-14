package com.aiburpcopilot.core.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 应用配置实体类。
 * <p>
 * 映射 application.yml 的结构，Jackson 反序列化。
 * 所有配置项均有默认值。
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AppConfig {

    private LLMConfig llm = new LLMConfig();
    private ScanConfig scan = new ScanConfig();
    private AIConfig ai = new AIConfig();
    private RequestConfig request = new RequestConfig();
    private StorageConfig storage = new StorageConfig();
    private VerificationConfig verification = new VerificationConfig();

    // ---------- LLM Config ----------

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LLMConfig {
        @JsonProperty("provider")
        private String provider = "deepseek";

        @JsonProperty("model")
        private String model = "deepseek-chat";

        @JsonProperty("apiKey")
        private String apiKey = "";

        @JsonProperty("apiUrl")
        private String apiUrl = "https://api.deepseek.com/v1/chat/completions";

        @JsonProperty("temperature")
        private double temperature = 0.3;

        @JsonProperty("connectTimeoutMs")
        private int connectTimeoutMs = 30000;

        @JsonProperty("readTimeoutMs")
        private int readTimeoutMs = 120000;

        @JsonProperty("writeTimeoutMs")
        private int writeTimeoutMs = 120000;

        @JsonProperty("maxRetries")
        private int maxRetries = 2;

        @JsonProperty("sendModel")
        private boolean sendModel = true;

        @JsonProperty("sendTemperature")
        private boolean sendTemperature = true;

        @JsonProperty("sendMaxTokens")
        private boolean sendMaxTokens = true;

        @JsonProperty("authorizationEnabled")
        private boolean authorizationEnabled = true;

        @JsonProperty("authHeaderName")
        private String authHeaderName = "Authorization";

        @JsonProperty("authHeaderPrefix")
        private String authHeaderPrefix = "Bearer";

        @JsonProperty("extraHeaders")
        private Map<String, String> extraHeaders = new LinkedHashMap<>();

        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public String getApiUrl() { return apiUrl; }
        public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }
        public double getTemperature() { return temperature; }
        public void setTemperature(double temperature) { this.temperature = temperature; }
        public int getConnectTimeoutMs() { return connectTimeoutMs; }
        public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }
        public int getReadTimeoutMs() { return readTimeoutMs; }
        public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }
        public int getWriteTimeoutMs() { return writeTimeoutMs; }
        public void setWriteTimeoutMs(int writeTimeoutMs) { this.writeTimeoutMs = writeTimeoutMs; }
        public int getMaxRetries() { return maxRetries; }
        public void setMaxRetries(int maxRetries) { this.maxRetries = maxRetries; }
        public boolean isSendModel() { return sendModel; }
        public void setSendModel(boolean sendModel) { this.sendModel = sendModel; }
        public boolean isSendTemperature() { return sendTemperature; }
        public void setSendTemperature(boolean sendTemperature) { this.sendTemperature = sendTemperature; }
        public boolean isSendMaxTokens() { return sendMaxTokens; }
        public void setSendMaxTokens(boolean sendMaxTokens) { this.sendMaxTokens = sendMaxTokens; }
        public boolean isAuthorizationEnabled() { return authorizationEnabled; }
        public void setAuthorizationEnabled(boolean authorizationEnabled) { this.authorizationEnabled = authorizationEnabled; }
        public String getAuthHeaderName() { return authHeaderName; }
        public void setAuthHeaderName(String authHeaderName) { this.authHeaderName = authHeaderName; }
        public String getAuthHeaderPrefix() { return authHeaderPrefix; }
        public void setAuthHeaderPrefix(String authHeaderPrefix) { this.authHeaderPrefix = authHeaderPrefix; }
        public Map<String, String> getExtraHeaders() { return extraHeaders; }
        public void setExtraHeaders(Map<String, String> extraHeaders) {
            this.extraHeaders = extraHeaders != null ? extraHeaders : new LinkedHashMap<>();
        }
    }

    // ---------- Scan Config ----------

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ScanConfig {
        @JsonProperty("skipExtensions")
        private List<String> skipExtensions = new ArrayList<>(List.of("png", "jpg", "jpeg", "gif", "css", "woff", "woff2", "ttf", "eot", "ico", "mp4", "webm"));

        @JsonProperty("skipKeywords")
        private List<String> skipKeywords = new ArrayList<>(List.of("logout", "heartbeat", "health", "favicon"));

        @JsonProperty("skipStatusCodes")
        private List<Integer> skipStatusCodes = new ArrayList<>(List.of(204, 304));

        @JsonProperty("responseBodyScan")
        private ResponseBodyScanConfig responseBodyScan = new ResponseBodyScanConfig();

        @JsonProperty("staticScanMaxSize")
        private int staticScanMaxSize = 204800; // 200KB

        public List<String> getSkipExtensions() { return skipExtensions; }
        public void setSkipExtensions(List<String> skipExtensions) { this.skipExtensions = skipExtensions; }
        public List<String> getSkipKeywords() { return skipKeywords; }
        public void setSkipKeywords(List<String> skipKeywords) { this.skipKeywords = skipKeywords; }
        public List<Integer> getSkipStatusCodes() { return skipStatusCodes; }
        public void setSkipStatusCodes(List<Integer> skipStatusCodes) {
            this.skipStatusCodes = skipStatusCodes != null ? skipStatusCodes : new ArrayList<>();
        }
        public ResponseBodyScanConfig getResponseBodyScan() { return responseBodyScan; }
        public void setResponseBodyScan(ResponseBodyScanConfig responseBodyScan) { this.responseBodyScan = responseBodyScan; }
        public int getStaticScanMaxSize() { return staticScanMaxSize; }
        public void setStaticScanMaxSize(int staticScanMaxSize) { this.staticScanMaxSize = staticScanMaxSize; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ResponseBodyScanConfig {
        @JsonProperty("enabled")
        private boolean enabled = true;

        @JsonProperty("maxSize")
        private int maxSize = 204800; // 200KB

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getMaxSize() { return maxSize; }
        public void setMaxSize(int maxSize) { this.maxSize = maxSize; }
    }

    // ---------- AI Config ----------

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AIConfig {
        @JsonProperty("maxTokens")
        private int maxTokens = 2048;

        @JsonProperty("timeoutMs")
        private int timeoutMs = 60000;

        @JsonProperty("maxPromptLength")
        private int maxPromptLength = 8000;

        @JsonProperty("rateLimitPerMinute")
        @JsonAlias("rateLimitPerSecond")
        private int rateLimitPerMinute = 60;

        public int getMaxTokens() { return maxTokens; }
        public void setMaxTokens(int maxTokens) { this.maxTokens = maxTokens; }
        public int getTimeoutMs() { return timeoutMs; }
        public void setTimeoutMs(int timeoutMs) { this.timeoutMs = timeoutMs; }
        public int getMaxPromptLength() { return maxPromptLength; }
        public void setMaxPromptLength(int maxPromptLength) { this.maxPromptLength = maxPromptLength; }
        public int getRateLimitPerMinute() { return rateLimitPerMinute; }
        public void setRateLimitPerMinute(int rateLimitPerMinute) { this.rateLimitPerMinute = rateLimitPerMinute; }
    }

    // ---------- Request Config ----------

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class RequestConfig {
        @JsonProperty("concurrency")
        private int concurrency = 5;

        @JsonProperty("maxQueueSize")
        private int maxQueueSize = 1000;

        public int getConcurrency() { return concurrency; }
        public void setConcurrency(int concurrency) { this.concurrency = concurrency; }
        public int getMaxQueueSize() { return maxQueueSize; }
        public void setMaxQueueSize(int maxQueueSize) { this.maxQueueSize = maxQueueSize; }
    }

    // ---------- Storage Config ----------

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class StorageConfig {
        @JsonProperty("maxHistory")
        private int maxHistory = 10000;

        @JsonProperty("cacheTtlSeconds")
        private int cacheTtlSeconds = 3600; // 1 hour

        @JsonProperty("maxCacheEntries")
        private int maxCacheEntries = 5000;

        public int getMaxHistory() { return maxHistory; }
        public void setMaxHistory(int maxHistory) { this.maxHistory = maxHistory; }
        public int getCacheTtlSeconds() { return cacheTtlSeconds; }
        public void setCacheTtlSeconds(int cacheTtlSeconds) { this.cacheTtlSeconds = cacheTtlSeconds; }
        public int getMaxCacheEntries() { return maxCacheEntries; }
        public void setMaxCacheEntries(int maxCacheEntries) { this.maxCacheEntries = maxCacheEntries; }
    }

    // ---------- Verification Config ----------

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class VerificationConfig {
        @JsonProperty("enabled")
        private boolean enabled = false;

        @JsonProperty("maxRequestsPerEndpoint")
        private int maxRequestsPerEndpoint = 5;

        @JsonProperty("requestTimeoutSeconds")
        private int requestTimeoutSeconds = 5;

        @JsonProperty("whitelist")
        private List<String> whitelist = new ArrayList<>();

        @JsonProperty("maxPayloadLength")
        private int maxPayloadLength = 128;

        @JsonProperty("allowedInfluenceActions")
        private List<String> allowedInfluenceActions = new ArrayList<>(List.of("READ"));

        @JsonProperty("allowedVerificationActions")
        private List<String> allowedVerificationActions = new ArrayList<>(List.of("READ"));

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getMaxRequestsPerEndpoint() { return maxRequestsPerEndpoint; }
        public void setMaxRequestsPerEndpoint(int maxRequestsPerEndpoint) { this.maxRequestsPerEndpoint = maxRequestsPerEndpoint; }
        public int getRequestTimeoutSeconds() { return requestTimeoutSeconds; }
        public void setRequestTimeoutSeconds(int requestTimeoutSeconds) { this.requestTimeoutSeconds = requestTimeoutSeconds; }
        public List<String> getWhitelist() { return whitelist; }
        public void setWhitelist(List<String> whitelist) { this.whitelist = whitelist; }
        public int getMaxPayloadLength() { return maxPayloadLength; }
        public void setMaxPayloadLength(int maxPayloadLength) { this.maxPayloadLength = maxPayloadLength; }
        public List<String> getAllowedInfluenceActions() { return allowedInfluenceActions; }
        public void setAllowedInfluenceActions(List<String> allowedInfluenceActions) {
            this.allowedInfluenceActions = allowedInfluenceActions != null ? allowedInfluenceActions : new ArrayList<>();
        }
        public List<String> getAllowedVerificationActions() { return allowedVerificationActions; }
        public void setAllowedVerificationActions(List<String> allowedVerificationActions) {
            this.allowedVerificationActions = allowedVerificationActions != null ? allowedVerificationActions : new ArrayList<>();
        }
    }

    // ---------- Top-level Getters & Setters ----------

    public LLMConfig getLlm() { return llm; }
    public void setLlm(LLMConfig llm) { this.llm = llm; }
    public ScanConfig getScan() { return scan; }
    public void setScan(ScanConfig scan) { this.scan = scan; }
    public AIConfig getAi() { return ai; }
    public void setAi(AIConfig ai) { this.ai = ai; }
    public RequestConfig getRequest() { return request; }
    public void setRequest(RequestConfig request) { this.request = request; }
    public StorageConfig getStorage() { return storage; }
    public void setStorage(StorageConfig storage) { this.storage = storage; }
    public VerificationConfig getVerification() { return verification; }
    public void setVerification(VerificationConfig verification) { this.verification = verification; }
}
