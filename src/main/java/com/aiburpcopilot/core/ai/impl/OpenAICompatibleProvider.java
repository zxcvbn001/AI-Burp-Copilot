package com.aiburpcopilot.core.ai.impl;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.utils.JsonUtil;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public abstract class OpenAICompatibleProvider implements IAIProvider {

    private static final Logger log = LoggerFactory.getLogger(OpenAICompatibleProvider.class);
    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");

    protected final IConfigService configService;

    protected OpenAICompatibleProvider(IConfigService configService) {
        this.configService = configService;
    }

    protected abstract String defaultModel();

    protected abstract String defaultApiUrl();

    protected boolean omitOptionalRequestFieldsForCustomEndpoint(AppConfig.LLMConfig llmConfig) {
        return false;
    }

    protected String diffSystemPromptTemplate() {
        return "diff-judge-v1";
    }

    @Override
    public CompletableFuture<String> analyzeAttackSurface(
            HTTPContext context,
            String systemPrompt,
            String userPrompt) {
        return callLLM(buildChatMessages(systemPrompt, userPrompt));
    }

    @Override
    public CompletableFuture<String> classifyEndpoint(
            String aiSummary,
            String classifierPrompt) {
        return callLLM(buildChatMessages("", classifierPrompt + "\n\n" + safe(aiSummary)));
    }

    @Override
    public CompletableFuture<String> reviewStaticResource(
            String content,
            String reviewPrompt) {
        return callLLM(buildChatMessages("", reviewPrompt + "\n\n```\n" + safe(content) + "\n```"));
    }

    @Override
    public CompletableFuture<String> analyzeDiff(String diffPrompt) {
        String systemPrompt = loadPromptTemplate(diffSystemPromptTemplate()).orElse("");
        return callLLM(buildChatMessages(systemPrompt, diffPrompt));
    }

    @Override
    public boolean isAvailable() {
        AppConfig.LLMConfig llmConfig = configService.getConfig().getLlm();
        if (!llmConfig.isAuthorizationEnabled()) {
            return true;
        }
        return llmConfig.getApiKey() != null && !llmConfig.getApiKey().isBlank();
    }

    protected CompletableFuture<String> callLLM(String messages) {
        CompletableFuture<String> future = new CompletableFuture<>();
        AppConfig config = configService.getConfig();
        AppConfig.LLMConfig llmConfig = config.getLlm();
        AppConfig.AIConfig aiConfig = config.getAi();

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> baseBody = JsonUtil.fromJson(messages, Map.class);
            if (shouldSendModel(llmConfig)) {
                baseBody.put("model", effectiveModel(llmConfig));
            }
            if (shouldSendTemperature(llmConfig)) {
                baseBody.put("temperature", llmConfig.getTemperature());
            }
            if (shouldSendMaxTokens(llmConfig)) {
                baseBody.put("max_tokens", aiConfig.getMaxTokens());
            }
            String requestBody = JsonUtil.toJson(baseBody);

            int maxRetries = Math.max(0, llmConfig.getMaxRetries());
            executeWithRetry(llmConfig, requestBody, 0, maxRetries, future);
        } catch (Exception e) {
            log.error("{} failed to build AI request: {}", getProviderName(), e.getMessage(), e);
            future.completeExceptionally(e);
        }

        return future;
    }

    private void executeWithRetry(AppConfig.LLMConfig llmConfig,
                                  String requestBody,
                                  int attempt,
                                  int maxRetries,
                                  CompletableFuture<String> future) {
        if (future.isDone()) {
            return;
        }

        String apiUrl = effectiveApiUrl(llmConfig);
        String model = effectiveModel(llmConfig);
        Request.Builder requestBuilder = new Request.Builder()
                .url(apiUrl)
                .addHeader("Content-Type", "application/json")
                .addHeader("User-Agent", "AI-Burp-Copilot/2.0")
                .post(RequestBody.create(requestBody, JSON_MEDIA_TYPE));
        applyAuthHeaders(requestBuilder, llmConfig);
        applyExtraHeaders(requestBuilder, llmConfig);
        Request request = requestBuilder.build();

        log.info("{} dispatching request: url={}, model={}, attempt={}/{}",
                getProviderName(), apiUrl, model, attempt + 1, maxRetries + 1);

        newHttpClient(llmConfig).newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                if (attempt < maxRetries) {
                    retryLater(llmConfig, requestBody, attempt, maxRetries, future,
                            "network error: " + e.getMessage());
                    return;
                }
                log.error("{} API call failed after {} attempts: {}",
                        getProviderName(), attempt + 1, e.getMessage());
                future.completeExceptionally(e);
            }

            @Override
            public void onResponse(Call call, Response response) {
                try (ResponseBody body = response.body()) {
                    String responseStr = body != null ? body.string() : "{}";
                    if (!response.isSuccessful()) {
                        if (isRetryableStatus(response.code()) && attempt < maxRetries) {
                            retryLater(llmConfig, requestBody, attempt, maxRetries, future,
                                    "HTTP " + response.code());
                            return;
                        }
                        log.warn("{} API returned error: {} - {}",
                                getProviderName(), response.code(), summarize(responseStr, 500));
                        future.complete("Error: HTTP " + response.code() + " - " + responseStr);
                        return;
                    }

                    future.complete(extractContentFromResponse(responseStr));
                } catch (Exception e) {
                    if (attempt < maxRetries) {
                        retryLater(llmConfig, requestBody, attempt, maxRetries, future,
                                "parse error: " + e.getMessage());
                        return;
                    }
                    log.error("{} failed to parse AI response: {}", getProviderName(), e.getMessage(), e);
                    future.completeExceptionally(e);
                }
            }
        });
    }

    private void applyAuthHeaders(Request.Builder requestBuilder, AppConfig.LLMConfig llmConfig) {
        if (!llmConfig.isAuthorizationEnabled()) {
            return;
        }
        String apiKey = llmConfig.getApiKey();
        if (apiKey == null || apiKey.isBlank()) {
            return;
        }
        String headerName = llmConfig.getAuthHeaderName();
        if (headerName == null || headerName.isBlank()) {
            headerName = "Authorization";
        }
        String prefix = llmConfig.getAuthHeaderPrefix();
        String headerValue = prefix == null || prefix.isBlank()
                ? apiKey
                : prefix.trim() + " " + apiKey;
        requestBuilder.header(headerName, headerValue);
    }

    private void applyExtraHeaders(Request.Builder requestBuilder, AppConfig.LLMConfig llmConfig) {
        if (llmConfig.getExtraHeaders() == null || llmConfig.getExtraHeaders().isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : llmConfig.getExtraHeaders().entrySet()) {
            if (entry.getKey() != null && !entry.getKey().isBlank()
                    && entry.getValue() != null) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }
    }

    private void retryLater(AppConfig.LLMConfig llmConfig,
                            String requestBody,
                            int attempt,
                            int maxRetries,
                            CompletableFuture<String> future,
                            String reason) {
        long delayMs = Math.min(3000L, 500L * (attempt + 1));
        log.warn("{} API attempt {}/{} failed ({}), retrying in {}ms",
                getProviderName(), attempt + 1, maxRetries + 1, reason, delayMs);
        CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS)
                .execute(() -> executeWithRetry(llmConfig, requestBody, attempt + 1, maxRetries, future));
    }

    private OkHttpClient newHttpClient(AppConfig.LLMConfig llmConfig) {
        return new OkHttpClient.Builder()
                .connectTimeout(Math.max(1000, llmConfig.getConnectTimeoutMs()), TimeUnit.MILLISECONDS)
                .readTimeout(Math.max(1000, llmConfig.getReadTimeoutMs()), TimeUnit.MILLISECONDS)
                .writeTimeout(Math.max(1000, llmConfig.getWriteTimeoutMs()), TimeUnit.MILLISECONDS)
                .callTimeout(Math.max(1000, llmConfig.getReadTimeoutMs() + llmConfig.getConnectTimeoutMs()), TimeUnit.MILLISECONDS)
                .build();
    }

    private String buildChatMessages(String systemPrompt, String userPrompt) {
        try {
            AppConfig.AIConfig aiConfig = configService.getConfig().getAi();
            int maxLength = Math.max(1000, aiConfig.getMaxPromptLength());
            String safePrompt = safe(userPrompt);
            String truncatedUserPrompt = safePrompt.length() > maxLength
                    ? safePrompt.substring(0, maxLength) + "...[truncated]"
                    : safePrompt;

            Object messages;
            if (systemPrompt != null && !systemPrompt.isBlank()) {
                messages = Map.of(
                        "messages", List.of(
                                Map.of("role", "system", "content", systemPrompt),
                                Map.of("role", "user", "content", truncatedUserPrompt)
                        )
                );
            } else {
                messages = Map.of(
                        "messages", List.of(
                                Map.of("role", "user", "content", truncatedUserPrompt)
                        )
                );
            }
            return JsonUtil.toJson(messages);
        } catch (Exception e) {
            log.error("{} failed to build chat messages: {}", getProviderName(), e.getMessage(), e);
            return "{}";
        }
    }

    @SuppressWarnings("unchecked")
    private String extractContentFromResponse(String responseStr) {
        try {
            Map<String, Object> responseMap = JsonUtil.fromJson(responseStr, Map.class);
            List<Map<String, Object>> choices = (List<Map<String, Object>>) responseMap.get("choices");
            if (choices != null && !choices.isEmpty()) {
                Map<String, Object> message = (Map<String, Object>) choices.get(0).get("message");
                if (message != null) {
                    String content = (String) message.get("content");
                    if (content != null) {
                        return content;
                    }
                }
            }
            return responseStr;
        } catch (Exception e) {
            log.warn("{} failed to extract AI response content, returning raw: {}",
                    getProviderName(), e.getMessage());
            return responseStr;
        }
    }

    private String effectiveApiUrl(AppConfig.LLMConfig llmConfig) {
        String apiUrl = llmConfig.getApiUrl();
        if (apiUrl == null || apiUrl.isBlank()) {
            return defaultApiUrl();
        }
        return apiUrl;
    }

    private String effectiveModel(AppConfig.LLMConfig llmConfig) {
        String model = llmConfig.getModel();
        if (model == null || model.isBlank()) {
            return defaultModel();
        }
        return model;
    }

    private boolean shouldSendModel(AppConfig.LLMConfig llmConfig) {
        return llmConfig.isSendModel() && !omitOptionalRequestFieldsForCustomEndpoint(llmConfig);
    }

    private boolean shouldSendTemperature(AppConfig.LLMConfig llmConfig) {
        return llmConfig.isSendTemperature() && !omitOptionalRequestFieldsForCustomEndpoint(llmConfig);
    }

    private boolean shouldSendMaxTokens(AppConfig.LLMConfig llmConfig) {
        return llmConfig.isSendMaxTokens() && !omitOptionalRequestFieldsForCustomEndpoint(llmConfig);
    }

    private Optional<String> loadPromptTemplate(String templateName) {
        if (templateName == null || templateName.isBlank()) {
            return Optional.empty();
        }
        Path externalPath = ExternalResourcePaths.promptsDir().resolve(templateName + ".txt");
        try {
            if (Files.exists(externalPath) && Files.isReadable(externalPath)) {
                return Optional.of(Files.readString(externalPath, StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            log.warn("{} failed to load external prompt template {}: {}",
                    getProviderName(), externalPath, e.getMessage());
        }
        String resourcePath = "prompts/" + templateName + ".txt";
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (input == null) {
                log.warn("{} prompt template not found: {}", getProviderName(), resourcePath);
                return Optional.empty();
            }
            return Optional.of(new String(input.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.warn("{} failed to load prompt template {}: {}",
                    getProviderName(), resourcePath, e.getMessage());
            return Optional.empty();
        }
    }

    private boolean isRetryableStatus(int statusCode) {
        return statusCode == 408 || statusCode == 409 || statusCode == 425
                || statusCode == 429 || statusCode >= 500;
    }

    private String safe(String value) {
        return value != null ? value : "";
    }

    private String summarize(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        String normalized = value.replaceAll("\\s+", " ").trim();
        return normalized.length() <= maxLength
                ? normalized
                : normalized.substring(0, Math.max(0, maxLength - 3)) + "...";
    }
}
