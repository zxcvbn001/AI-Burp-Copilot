package com.aiburpcopilot.scanner.staticresource.js;

import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.utils.JsonUtil;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

public class JsAnalysisApiClient {

    private static final Logger log = LoggerFactory.getLogger(JsAnalysisApiClient.class);
    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");

    private final AppConfig.JsAnalysisConfig config;
    private final OkHttpClient httpClient;
    private volatile long lastHealthCheckAt;
    private volatile boolean lastHealthStatus;
    private volatile String lastHealthMessage = "Not checked yet";

    public JsAnalysisApiClient(AppConfig.JsAnalysisConfig config) {
        this.config = config;
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofMillis(Math.max(1000, config.getConnectTimeoutMs())))
                .readTimeout(Duration.ofMillis(Math.max(1000, config.getReadTimeoutMs())))
                .writeTimeout(Duration.ofMillis(Math.max(1000, config.getWriteTimeoutMs())))
                .build();
    }

    public boolean isHealthy() {
        long now = System.currentTimeMillis();
        if (now - lastHealthCheckAt < 30_000L) {
            return lastHealthStatus;
        }
        lastHealthCheckAt = now;
        Request request = new Request.Builder()
                .url(joinUrl(config.getBaseUrl(), config.getHealthPath()))
                .get()
                .build();
        try (Response response = httpClient.newCall(request).execute()) {
            lastHealthStatus = response.isSuccessful();
            lastHealthMessage = "HTTP " + response.code();
            return lastHealthStatus;
        } catch (IOException e) {
            lastHealthStatus = false;
            lastHealthMessage = e.getClass().getSimpleName() + ": " + e.getMessage();
            log.warn("JS analysis health check failed: {}", lastHealthMessage);
            return false;
        }
    }

    public String getLastHealthMessage() {
        return lastHealthMessage;
    }

    public JsAnalysisResponse analyze(String url, String content) {
        return analyze(url, content, null, null);
    }

    public JsAnalysisResponse analyze(String url, String content, Consumer<TaskProgress> progressConsumer) {
        return analyze(url, content, null, progressConsumer);
    }

    public JsAnalysisResponse analyze(String url,
                                      String content,
                                      String baseUrl,
                                      Consumer<TaskProgress> progressConsumer) {
        String mode = normalizeMode(config.getMode(), config.isFastMode());
        log.info("JS AST analyze request: url={}, mode={}, async={}, fastMode={}",
                url, mode, config.isSubmitAsync(), "fast".equals(mode));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("url", url);
        payload.put("content", content);
        payload.put("base_url", deriveBaseUrl(url, baseUrl));
        boolean fastMode = "fast".equals(mode);
        payload.put("fast_mode", fastMode);
        payload.put("mode", mode);
        payload.put("response_mode", normalizeResponseMode(config.getResponseMode()));
        payload.put("async", config.isSubmitAsync());
        log.info("JS AST request payload summary: url={}, base_url={}, mode={}, response_mode={}, fast_mode={}, async={}, contentLength={}",
                url,
                payload.get("base_url"),
                mode,
                payload.get("response_mode"),
                fastMode,
                config.isSubmitAsync(),
                content != null ? content.length() : 0);

        JsAnalysisResponse initial = executePost(config.getAnalyzePath(), payload);
        if (initial != null && (initial.getUrl() == null || initial.getUrl().isBlank())) {
            initial.setUrl(url);
        }
        notifyProgress(progressConsumer, new TaskProgress(
                url,
                initial != null ? initial.getTaskId() : null,
                "SUBMITTED",
                initial != null ? initial.getStatus() : "failed",
                initial != null && initial.isSuccess()
                        ? "JS AST task submitted"
                        : (initial != null ? initial.errorMessage() : "empty response")));
        if (!config.isSubmitAsync()) {
            return initial;
        }
        return awaitTaskResult(initial, url, progressConsumer);
    }

    private String normalizeMode(String mode, boolean fastMode) {
        if (mode != null) {
            String normalized = mode.trim().toLowerCase(Locale.ROOT);
            if ("fast".equals(normalized) || "full".equals(normalized)) {
                return normalized;
            }
        }
        return fastMode ? "fast" : "full";
    }

    private String normalizeResponseMode(String responseMode) {
        if (responseMode != null) {
            String normalized = responseMode.trim().toLowerCase(Locale.ROOT);
            if ("full".equals(normalized) || "compact".equals(normalized)) {
                return normalized;
            }
        }
        return "compact";
    }

    private JsAnalysisResponse awaitTaskResult(JsAnalysisResponse initial,
                                               String fallbackScriptUrl,
                                               Consumer<TaskProgress> progressConsumer) {
        if (initial == null) {
            return errorResponse("JS AST async submission failed: empty response");
        }
        if (!initial.isSuccess()) {
            return initial;
        }
        if (initial.getTaskId() == null || initial.getTaskId().isBlank()) {
            return initial;
        }

        String statusPath = initial.getStatusUrl();
        if (statusPath == null || statusPath.isBlank()) {
            statusPath = "/analyze/tasks/" + initial.getTaskId();
        }

        long deadline = System.currentTimeMillis() + Math.max(1000, config.getTaskTimeoutMs());
        int pollIntervalMs = Math.max(200, config.getTaskPollIntervalMs());
        String lastStatus = initial.getStatus();

        while (System.currentTimeMillis() <= deadline) {
            JsAnalysisResponse taskResponse = executeGet(statusPath);
            if (taskResponse == null) {
                return errorResponse("JS AST async polling failed: empty response");
            }
            if (!taskResponse.isSuccess()) {
                return taskResponse;
            }

            JsAnalysisResponse.Task task = taskResponse.getTask();
            if (task == null) {
                return errorResponse("JS AST async response missing task object");
            }

            String status = task.getStatus() != null
                    ? task.getStatus().trim().toLowerCase(Locale.ROOT)
                    : "";
            lastStatus = status;
            notifyProgress(progressConsumer, new TaskProgress(
                    initial.getUrl() != null && !initial.getUrl().isBlank() ? initial.getUrl() : fallbackScriptUrl,
                    task.getId(),
                    "POLLING",
                    status,
                    "JS AST task status: " + status));

            if ("completed".equals(status)) {
                JsAnalysisResponse result = task.getResult();
                if (result == null) {
                    return errorResponse("JS AST async task completed with empty result");
                }
                result.setTaskId(task.getId());
                result.setStatus(status);
                if (result.getUrl() == null || result.getUrl().isBlank()) {
                    result.setUrl(initial.getUrl() != null && !initial.getUrl().isBlank()
                            ? initial.getUrl()
                            : fallbackScriptUrl);
                }
                notifyProgress(progressConsumer, new TaskProgress(
                        result.getUrl() != null && !result.getUrl().isBlank()
                                ? result.getUrl()
                                : (initial.getUrl() != null && !initial.getUrl().isBlank()
                                ? initial.getUrl() : fallbackScriptUrl),
                        task.getId(),
                        "COMPLETED",
                        status,
                        "JS AST task completed"));
                return result;
            }
            if ("failed".equals(status)) {
                JsAnalysisResponse result = task.getResult();
                if (result != null) {
                    result.setTaskId(task.getId());
                    result.setStatus(status);
                    if (result.getUrl() == null || result.getUrl().isBlank()) {
                        result.setUrl(initial.getUrl() != null && !initial.getUrl().isBlank()
                                ? initial.getUrl()
                                : fallbackScriptUrl);
                    }
                }
                notifyProgress(progressConsumer, new TaskProgress(
                        initial.getUrl() != null && !initial.getUrl().isBlank() ? initial.getUrl() : fallbackScriptUrl,
                        task.getId(),
                        "FAILED",
                        status,
                        task.getError() != null ? task.getError().getMessage() : "unknown failure"));
                if (result != null) {
                    return result;
                }
                String message = task.getError() != null ? task.getError().getMessage() : "unknown failure";
                return errorResponse("JS AST async task failed: " + message);
            }

            try {
                Thread.sleep(pollIntervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                notifyProgress(progressConsumer, new TaskProgress(
                        initial.getUrl() != null && !initial.getUrl().isBlank() ? initial.getUrl() : fallbackScriptUrl,
                        initial.getTaskId(),
                        "INTERRUPTED",
                        lastStatus,
                        "JS AST async polling interrupted"));
                return errorResponse("JS AST async polling interrupted");
            }
        }

        notifyProgress(progressConsumer, new TaskProgress(
                initial.getUrl() != null && !initial.getUrl().isBlank() ? initial.getUrl() : fallbackScriptUrl,
                initial.getTaskId(),
                "TIMEOUT",
                lastStatus,
                "JS AST async task timed out"));
        return errorResponse("JS AST async task timed out, last status: " + lastStatus);
    }

    private JsAnalysisResponse executePost(String path, Map<String, Object> payload) {
        RequestBody requestBody = RequestBody.create(JsonUtil.toJson(payload), JSON_MEDIA_TYPE);
        Request.Builder requestBuilder = new Request.Builder()
                .url(joinUrl(config.getBaseUrl(), path))
                .post(requestBody)
                .addHeader("Content-Type", "application/json");
        applyApiKey(requestBuilder);
        return execute(requestBuilder.build());
    }

    private JsAnalysisResponse executeGet(String path) {
        Request.Builder requestBuilder = new Request.Builder()
                .url(joinUrl(config.getBaseUrl(), path))
                .get();
        applyApiKey(requestBuilder);
        return execute(requestBuilder.build());
    }

    private JsAnalysisResponse execute(Request request) {
        try (Response response = httpClient.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";
            JsAnalysisResponse parsed = JsonUtil.fromJsonSafe(body, JsAnalysisResponse.class);
            if (parsed != null) {
                if (!response.isSuccessful() && parsed.getError() == null) {
                    JsAnalysisResponse.Error error = new JsAnalysisResponse.Error();
                    error.setMessage("HTTP " + response.code());
                    parsed.setError(error);
                    parsed.setSuccess(false);
                }
                return parsed;
            }
            return errorResponse("Unable to parse JS AST response: HTTP " + response.code());
        } catch (IOException e) {
            return errorResponse("Calling JS AST API failed: " + e.getMessage());
        }
    }

    private void applyApiKey(Request.Builder requestBuilder) {
        if (config.getApiKey() != null && !config.getApiKey().isBlank()) {
            requestBuilder.addHeader(config.getApiKeyHeader(), config.getApiKey());
        }
    }

    private JsAnalysisResponse errorResponse(String message) {
        JsAnalysisResponse fallback = new JsAnalysisResponse();
        fallback.setSuccess(false);
        JsAnalysisResponse.Error error = new JsAnalysisResponse.Error();
        error.setMessage(message);
        fallback.setError(error);
        return fallback;
    }

    private void notifyProgress(Consumer<TaskProgress> progressConsumer, TaskProgress progress) {
        if (progressConsumer != null && progress != null) {
            progressConsumer.accept(progress);
        }
    }

    private String joinUrl(String base, String path) {
        String normalizedBase = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        return normalizedBase + normalizedPath;
    }

    private String deriveBaseUrl(String url, String preferredBaseUrl) {
        String normalizedPreferred = normalizeBaseUrl(preferredBaseUrl);
        if (normalizedPreferred != null) {
            return normalizedPreferred;
        }
        return normalizeBaseUrl(url);
    }

    private String normalizeBaseUrl(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(url.trim());
            if (uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            StringBuilder builder = new StringBuilder()
                    .append(uri.getScheme())
                    .append("://")
                    .append(uri.getHost());
            if (uri.getPort() > 0) {
                builder.append(':').append(uri.getPort());
            }
            String path = uri.getPath();
            if (path != null && !path.isBlank() && !"/".equals(path)) {
                int lastSlash = path.lastIndexOf('/');
                if (lastSlash > 0) {
                    builder.append(path, 0, lastSlash);
                }
            }
            return builder.toString();
        } catch (Exception ignored) {
            return null;
        }
    }

    public record TaskProgress(
            String scriptUrl,
            String taskId,
            String phase,
            String status,
            String message
    ) {
    }
}
