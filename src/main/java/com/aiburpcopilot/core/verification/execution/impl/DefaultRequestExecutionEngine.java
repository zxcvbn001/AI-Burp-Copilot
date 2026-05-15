package com.aiburpcopilot.core.verification.execution.impl;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.aiburpcopilot.core.verification.execution.IRequestExecutionEngine;
import com.aiburpcopilot.core.verification.execution.ResponseCapture;
import com.aiburpcopilot.core.verification.model.AttackTask;
import com.aiburpcopilot.core.verification.model.MutatedRequest;
import com.aiburpcopilot.core.verification.model.VerificationResult;
import com.aiburpcopilot.core.verification.mutation.impl.ParameterMutatorRegistry;
import com.aiburpcopilot.core.verification.rate_limit.HostRateLimiter;
import com.aiburpcopilot.core.verification.safety.VerificationGuard;
import com.aiburpcopilot.core.config.Timeouts;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Default request execution engine.
 * <p>
 * The primary execution path uses Burp Montoya HTTP APIs so replay traffic
 * keeps the same target service semantics as Burp. Java HttpClient remains as
 * a fallback for non-Burp tests or when Montoya execution is unavailable.
 */
public class DefaultRequestExecutionEngine implements IRequestExecutionEngine {

    private static final Logger log = LoggerFactory.getLogger(DefaultRequestExecutionEngine.class);
    private final PluginLogger pluginLog = PluginLogger.getInstance();

    private final MontoyaApi api;
    private final HostRateLimiter rateLimiter;
    private final VerificationGuard guard;
    private final ResponseCapture responseCapture;
    private final ParameterMutatorRegistry mutatorRegistry;
    private final Duration requestTimeout;

    private final HttpClient httpClient;

    public DefaultRequestExecutionEngine(MontoyaApi api,
                                          HostRateLimiter rateLimiter,
                                          VerificationGuard guard,
                                          ResponseCapture responseCapture,
                                          ParameterMutatorRegistry mutatorRegistry) {
        this.api = api;
        this.rateLimiter = rateLimiter;
        this.guard = guard;
        this.responseCapture = responseCapture;
        this.mutatorRegistry = mutatorRegistry;
        this.requestTimeout = Duration.ofMillis(Timeouts.effectiveVerificationRequestTimeoutMs(guard));
        this.httpClient = createHttpClient(this.requestTimeout);
    }

    /**
     * 创建 HttpClient，信任所有证书（用于测试环境）。
     */
    private static HttpClient createHttpClient(Duration requestTimeout) {
        try {
            TrustManager[] trustAll = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAll, new java.security.SecureRandom());
            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(requestTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        } catch (Exception e) {
            log.warn("Failed to create trust-all HttpClient, using default", e);
            return HttpClient.newBuilder()
                    .connectTimeout(requestTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        }
    }

    @Override
    public byte[] execute(MutatedRequest request) {
        return executeWithPolicy(request);
    }

    private byte[] executeWithPolicy(MutatedRequest request) {
        if (request.getRawRequest() == null) {
            log.warn("MutatedRequest has no raw bytes to send");
            return null;
        }

        if (guard != null && !guard.isHostAllowed(request.getUrl())) {
            pluginLog.warn(PluginLogger.Category.VERIFICATION,
                    "Verification", "  BLOCKED by host policy: " + request.getUrl());
            return null;
        }

        try {
            if (rateLimiter != null) {
                rateLimiter.acquire(request.getUrl());
            }
            try {
                return executeWithoutPolicy(request);
            } finally {
                if (rateLimiter != null) {
                    rateLimiter.release(request.getUrl());
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("HTTP request interrupted for: {}", request.getUrl());
            return null;
        }
    }

    private byte[] executeWithoutPolicy(MutatedRequest request) {
        if (request.getRawRequest() == null) {
            log.warn("MutatedRequest has no raw bytes to send");
            return null;
        }

        byte[] rawRequest = request.getRawRequest();
        log.debug("Executing request: {} bytes to {}", rawRequest.length, request.getUrl());

        try {
            // 1. 解析原始 HTTP 请求字节
            if (api != null) {
                byte[] montoyaResponse = executeWithMontoya(request);
                if (montoyaResponse != null) {
                    return montoyaResponse;
                }
            }

            ParsedHttpRequest parsed = parseRawHttpRequest(rawRequest, request.getUrl());

            log.debug("Parsed: {} {} ({} headers, {} body bytes)",
                    parsed.method, parsed.uri, parsed.headers.size(),
                    parsed.body != null ? parsed.body.length : 0);

            // 2. 构建 Java HttpClient 请求
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(parsed.uri)
                    .timeout(requestTimeout);

            // 设置 headers
            for (String[] header : parsed.headers) {
                String name = header[0];
                String value = header[1];
                // 跳过受限 headers（HttpClient 会自动设置）
                if (name.equalsIgnoreCase("Host")
                        || name.equalsIgnoreCase("Content-Length")
                        || name.equalsIgnoreCase("Connection")
                        || name.equalsIgnoreCase("Transfer-Encoding")) {
                    continue;
                }
                try {
                    builder.header(name, value);
                } catch (IllegalArgumentException e) {
                    log.debug("Skipping restricted header: {} = {}", name, value);
                }
            }

            // 设置 method + body
            if (parsed.body != null && parsed.body.length > 0) {
                builder.method(parsed.method,
                        java.net.http.HttpRequest.BodyPublishers.ofByteArray(parsed.body));
            } else {
                builder.method(parsed.method,
                        java.net.http.HttpRequest.BodyPublishers.noBody());
            }

            HttpRequest httpReq = builder.build();

            // 3. 发送请求
            HttpResponse<byte[]> response = httpClient.send(httpReq,
                    HttpResponse.BodyHandlers.ofByteArray());

            // 4. 构建完整的 HTTP 响应字节
            byte[] responseBytes = buildHttpResponseBytes(response);
            log.debug("Response: {} {} ({} bytes)",
                    response.statusCode(), parsed.uri, responseBytes.length);
            return responseBytes;

        } catch (Exception e) {
            log.error("HTTP request failed for: {} — {}: {}",
                    request.getUrl(), e.getClass().getSimpleName(), e.getMessage());
            pluginLog.warn(PluginLogger.Category.VERIFICATION,
                    "Verification", "Request failed: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
            return null;
        }
    }

    private byte[] executeWithMontoya(MutatedRequest request) {
        try {
            ParsedHttpRequest parsed = parseRawHttpRequest(request.getRawRequest(), request.getUrl());
            URI targetUri = parsed.uri;

            if (targetUri == null || targetUri.getHost() == null) {
                log.debug("Montoya execution skipped: no target host for {}", request.getUrl());
                return null;
            }

            boolean secure = "https".equalsIgnoreCase(targetUri.getScheme());
            int port = targetUri.getPort();
            if (port < 0) {
                port = secure ? 443 : 80;
            }

            HttpService service = HttpService.httpService(targetUri.getHost(), port, secure);
            pluginLog.debug(PluginLogger.Category.VERIFICATION, "Verification", "Montoya target: "
                    + (secure ? "https" : "http") + "://" + targetUri.getHost() + ":" + port
                    + " " + parsed.method + " " + targetUri.getRawPath());
            burp.api.montoya.http.message.requests.HttpRequest httpRequest =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                            service, ByteArray.byteArray(request.getRawRequest()));
            HttpRequestResponse requestResponse = api.http().sendRequest(httpRequest);
            if (requestResponse == null || !requestResponse.hasResponse()) {
                return null;
            }
            byte[] responseBytes = requestResponse.response().toByteArray().getBytes();
            log.debug("Montoya response: {} bytes from {}", responseBytes.length, targetUri);
            return responseBytes;
        } catch (Exception e) {
            log.warn("Montoya request failed for {}, falling back to Java HttpClient: {}",
                    request.getUrl(), e.getMessage());
            return null;
        }
    }

    @Override
    public VerificationResult executeTask(AttackTask task) {
        try {
            // 1. 参数修改
            pluginLog.info(PluginLogger.Category.VERIFICATION, "Verification", "  Task: param='" + task.getParameterName()
                    + "' payload='" + task.getPayload()
                    + "' type=" + task.getAttackTypeName()
                    + " strategy=" + task.getStrategyType());
            var mutator = mutatorRegistry.findMutator(task.getBaseRequest(), task);
            if (mutator == null) {
                pluginLog.warn(PluginLogger.Category.VERIFICATION, "Verification", "  NO mutator for param='" + task.getParameterName()
                        + "' type=" + task.getAttackTypeName()
                        + " | params=" + task.getBaseRequest().getParameters().stream()
                        .map(p -> p.getType() + ":" + p.getName())
                        .toList());
                VerificationResult result = new VerificationResult();
                result.setAttackType(task.getAttackType());
                result.setAttackTypeName(task.getAttackTypeName());
                result.setParameter(task.getParameterName());
                result.setPayload(task.getPayload());
                result.setStrategyType(task.getStrategyType());
                result.setRequestId(task.getBaseRequest().getRequestId());
                result.setUrl(task.getBaseRequest().getUrl());
                result.setReasoning("No suitable mutator found");
                return result;
            }

            MutatedRequest mutatedRequest = mutator.mutate(task.getBaseRequest(), task);
            pluginLog.info(PluginLogger.Category.VERIFICATION, "Verification", "  Mutator: " + mutator.getClass().getSimpleName()
                    + " -> url=" + mutatedRequest.getUrl());

            if (guard != null && !guard.isHostAllowed(mutatedRequest.getUrl())) {
                pluginLog.warn(PluginLogger.Category.VERIFICATION,
                        "Verification", "  BLOCKED by host policy: " + mutatedRequest.getUrl());
                VerificationResult result = new VerificationResult();
                result.setAttackType(task.getAttackType());
                result.setAttackTypeName(task.getAttackTypeName());
                result.setParameter(task.getParameterName());
                result.setPayload(task.getPayload());
                result.setStrategyType(task.getStrategyType());
                result.setRequestId(task.getBaseRequest().getRequestId());
                result.setUrl(mutatedRequest.getUrl());
                result.setReasoning("Blocked by verification host policy");
                return result;
            }

            // 2. Host 限流
            // 3. 同步执行请求
            rateLimiter.acquire(mutatedRequest.getUrl());
            long startTime = System.currentTimeMillis();
            byte[] response;
            long elapsed;
            try {
                response = executeWithoutPolicy(mutatedRequest);
                elapsed = System.currentTimeMillis() - startTime;

                // 4. 捕获响应
                if (response != null) {
                    responseCapture.captureMutatedResponse(task.getTaskId().toString(), response);
                }
            } finally {
                // 5. 释放限流
                rateLimiter.release(mutatedRequest.getUrl());
            }

            // 6. 构建基础结果
            VerificationResult result = new VerificationResult();
            result.setAttackType(task.getAttackType());
            result.setAttackTypeName(task.getAttackTypeName());
            result.setParameter(task.getParameterName());
            result.setPayload(task.getPayload());
            result.setStrategyType(task.getStrategyType());
            result.setRequestId(task.getBaseRequest().getRequestId());
            result.setUrl(mutatedRequest.getUrl());
            result.setResponseTimeMs(elapsed);
            if (response != null) {
                result.setResponseLength(response.length);
                result.setMutatedResponseBytes(response);
            }
            result.setMutatedRequestBytes(mutatedRequest.getRawRequest());
            result.setReasoning("Response received in " + elapsed + "ms");

            if (response == null) {
                result.setReasoning("Request failed or timed out");
            }

            log.debug("Task {} completed in {}ms ({})",
                    task.getTaskId(), elapsed, task.getAttackTypeName());
            return result;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            VerificationResult result = new VerificationResult();
            result.setAttackType(task.getAttackType());
            result.setAttackTypeName(task.getAttackTypeName());
            result.setParameter(task.getParameterName());
            result.setPayload(task.getPayload());
            result.setUrl(task.getBaseRequest().getUrl());
            result.setReasoning("Verification interrupted");
            return result;
        } catch (Exception e) {
            log.error("Task {} failed: {}", task.getTaskId(), e.getMessage(), e);
            pluginLog.warn(PluginLogger.Category.VERIFICATION,
                    "Verification", "Task failed: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
            VerificationResult result = new VerificationResult();
            result.setAttackType(task.getAttackType());
            result.setAttackTypeName(task.getAttackTypeName());
            result.setParameter(task.getParameterName());
            result.setPayload(task.getPayload());
            result.setStrategyType(task.getStrategyType());
            result.setRequestId(task.getBaseRequest().getRequestId());
            result.setUrl(task.getBaseRequest().getUrl());
            result.setReasoning("Verification failed: " + e.getMessage());
            return result;
        }
    }

    // ========== Raw HTTP Parsing ==========

    /**
     * 解析后的 HTTP 请求。
     */
    private static class ParsedHttpRequest {
        String method;
        URI uri;
        List<String[]> headers = new ArrayList<>();
        byte[] body;
    }

    /**
     * 从原始 HTTP 请求字节解析请求结构。
     * 使用字节级解析确保 body 不丢失或损坏。
     */
    private ParsedHttpRequest parseRawHttpRequest(byte[] rawBytes) {
        return parseRawHttpRequest(rawBytes, null);
    }

    private ParsedHttpRequest parseRawHttpRequest(byte[] rawBytes, String fallbackUrl) {
        ParsedHttpRequest result = new ParsedHttpRequest();
        String raw = new String(rawBytes, StandardCharsets.UTF_8);

        // 找到 header/body 分隔符 \r\n\r\n
        int bodySepIdx = raw.indexOf("\r\n\r\n");
        if (bodySepIdx < 0) {
            bodySepIdx = raw.indexOf("\n\n");
        }

        String headerPart;
        int bodyStartByteIdx;
        if (bodySepIdx >= 0) {
            headerPart = raw.substring(0, bodySepIdx);
            // 计算 body 在原始字节中的起始位置
            String separator = raw.substring(bodySepIdx, bodySepIdx + (raw.startsWith("\r\n\r\n", bodySepIdx) ? 4 : 2));
            bodyStartByteIdx = headerPart.getBytes(StandardCharsets.UTF_8).length
                    + separator.getBytes(StandardCharsets.UTF_8).length;
            if (bodyStartByteIdx < rawBytes.length) {
                result.body = new byte[rawBytes.length - bodyStartByteIdx];
                System.arraycopy(rawBytes, bodyStartByteIdx, result.body, 0, result.body.length);
            }
        } else {
            headerPart = raw;
        }

        // 解析 headers 部分
        String[] lines = headerPart.split("\r\n|\n", -1);
        if (lines.length == 0) return result;

        // 第一行：请求行
        String[] requestParts = lines[0].split(" ", 3);
        result.method = requestParts[0];
        String pathAndQuery = requestParts.length > 1 ? requestParts[1] : "/";

        // 解析 headers
        String host = null;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) continue;
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                String value = line.substring(colonIdx + 1).trim();
                result.headers.add(new String[]{name, value});
                if (name.equalsIgnoreCase("Host")) {
                    host = value;
                }
            }
        }

        // 构建完整 URI
        result.uri = buildTargetUri(fallbackUrl, host, pathAndQuery);

        return result;
    }

    private URI buildTargetUri(String fallbackUrl, String hostHeader, String pathAndQuery) {
        if (pathAndQuery != null
                && (pathAndQuery.startsWith("http://") || pathAndQuery.startsWith("https://"))) {
            return URI.create(pathAndQuery);
        }

        URI fallback = parseUri(fallbackUrl);
        String scheme = fallback != null && fallback.getScheme() != null
                ? fallback.getScheme()
                : "http";
        String authority = fallback != null && fallback.getRawAuthority() != null
                ? fallback.getRawAuthority()
                : hostHeader;

        String requestTarget = pathAndQuery != null && !pathAndQuery.isBlank()
                ? pathAndQuery
                : "/";
        if (!requestTarget.startsWith("/")) {
            requestTarget = "/" + requestTarget;
        }

        if (authority != null && !authority.isBlank()) {
            return URI.create(scheme + "://" + authority + requestTarget);
        }
        return URI.create(requestTarget);
    }

    private URI parseUri(String url) {
        try {
            if (url == null || url.isBlank()) {
                return null;
            }
            return URI.create(url);
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * 将 Java HttpResponse 转换为完整的 HTTP 响应字节数组（状态行 + headers + body）。
     */
    private byte[] buildHttpResponseBytes(HttpResponse<byte[]> response) {
        StringBuilder sb = new StringBuilder();
        // 状态行
        sb.append("HTTP/1.1 ").append(response.statusCode()).append(" OK\r\n");
        // Headers
        response.headers().map().forEach((name, values) -> {
            for (String value : values) {
                sb.append(name).append(": ").append(value).append("\r\n");
            }
        });
        sb.append("\r\n");

        byte[] headerBytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] bodyBytes = response.body();

        // 合并 header + body
        byte[] full = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, full, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, full, headerBytes.length, bodyBytes.length);
        return full;
    }

    @Override
    public void shutdown() {
        log.info("Verification execution engine shutdown complete");
    }
}
