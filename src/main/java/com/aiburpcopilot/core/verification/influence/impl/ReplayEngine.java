package com.aiburpcopilot.core.verification.influence.impl;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.config.Timeouts;
import com.aiburpcopilot.core.verification.execution.IRequestExecutionEngine;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;
import com.aiburpcopilot.core.verification.model.MutatedRequest;
import com.aiburpcopilot.core.verification.safety.VerificationGuard;
import com.aiburpcopilot.utils.InternalTrafficMarker;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * Replay 引擎实现。
 * 使用 Java HttpClient 重放 HTTP 请求。
 */
public class ReplayEngine implements IReplayEngine {

    private static final Logger log = LoggerFactory.getLogger(ReplayEngine.class);
    private final PluginLogger pluginLog = PluginLogger.getInstance();

    private final HttpClient httpClient;
    private final VerificationGuard guard;
    private final IRequestExecutionEngine executionEngine;
    private final Duration requestTimeout;
    private long lastDurationMs;
    private byte[] lastRequestBytes;
    private byte[] lastResponseBytes;

    public ReplayEngine() {
        this(null, null);
    }

    public ReplayEngine(VerificationGuard guard) {
        this(guard, null);
    }

    public ReplayEngine(VerificationGuard guard, IRequestExecutionEngine executionEngine) {
        this.guard = guard;
        this.executionEngine = executionEngine;
        this.requestTimeout = Duration.ofMillis(Timeouts.effectiveVerificationRequestTimeoutMs(guard));
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(requestTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public byte[] replayOriginal(HTTPContext context) {
        long start = System.currentTimeMillis();
        try {
            byte[] rawRequest = context.getRawRequest();
            if (rawRequest == null) return null;

            ParsedHttpRequest parsed = parseRawHttpRequest(rawRequest, context);
            if (parsed == null) return null;
            if (!isAllowed(parsed.uri)) return null;

            byte[] response = executeOrSend(parsed, context, null, null);
            lastResponseBytes = response;
            lastDurationMs = System.currentTimeMillis() - start;
            return response;
        } catch (Exception e) {
            log.error("Replay original failed: {}", e.getMessage());
            lastDurationMs = System.currentTimeMillis() - start;
            return null;
        }
    }

    @Override
    public byte[] replayWithMutation(HTTPContext context, String paramName, String newValue) {
        long start = System.currentTimeMillis();
        try {
            byte[] rawRequest = context.getRawRequest();
            if (rawRequest == null) return null;

            ParsedHttpRequest parsed = parseRawHttpRequest(rawRequest, context);
            if (parsed == null) return null;

            applyMutation(parsed, context, paramName, newValue != null ? newValue : "");
            if (!isAllowed(parsed.uri)) return null;

            byte[] response = executeOrSend(parsed, context, paramName, newValue);
            lastResponseBytes = response;
            lastDurationMs = System.currentTimeMillis() - start;
            pluginLog.info(PluginLogger.Category.VERIFICATION,
                    "Replay", "Replayed with mutation: param='" + paramName + "' -> '" + newValue + "' (" + lastDurationMs + "ms)");
            return response;
        } catch (Exception e) {
            log.error("Replay with mutation failed: {}", e.getMessage());
            lastDurationMs = System.currentTimeMillis() - start;
            return null;
        }
    }

    @Override
    public byte[] replayWithAppendedMutation(HTTPContext context, String paramName, String payloadSuffix) {
        String originalValue = resolveOriginalValue(context, paramName);
        String finalValue = originalValue + (payloadSuffix != null ? payloadSuffix : "");
        long start = System.currentTimeMillis();
        try {
            byte[] rawRequest = context.getRawRequest();
            if (rawRequest == null) return null;

            ParsedHttpRequest parsed = parseRawHttpRequest(rawRequest, context);
            if (parsed == null) return null;

            applyMutation(parsed, context, paramName, finalValue);
            if (!isAllowed(parsed.uri)) return null;

            byte[] response = executeOrSend(parsed, context, paramName, finalValue);
            lastResponseBytes = response;
            lastDurationMs = System.currentTimeMillis() - start;
            pluginLog.info(PluginLogger.Category.VERIFICATION, "Replay",
                    "Replayed with appended mutation: param='" + paramName
                    + "' original='" + originalValue + "' suffix='" + payloadSuffix
                    + "' (" + lastDurationMs + "ms)");
            return response;
        } catch (Exception e) {
            log.error("Replay with appended mutation failed: {}", e.getMessage());
            lastDurationMs = System.currentTimeMillis() - start;
            return null;
        }
    }

    @Override
    public long getLastReplayDurationMs() {
        return lastDurationMs;
    }

    @Override
    public byte[] getLastRequestBytes() {
        return lastRequestBytes;
    }

    @Override
    public byte[] getLastResponseBytes() {
        return lastResponseBytes;
    }

    // === Private ===

    private byte[] executeOrSend(ParsedHttpRequest parsed, HTTPContext context, String paramName, String payload) {
        byte[] rawRequest = buildHttpRequestBytes(parsed);
        lastRequestBytes = rawRequest;
        lastResponseBytes = null;
        byte[] executableRequest = InternalTrafficMarker.ensureMarked(rawRequest);
        if (executionEngine != null) {
            MutatedRequest request = new MutatedRequest(
                    executableRequest,
                    parsed.uri != null ? parsed.uri.toString() : context.getUrl(),
                    parsed.method,
                    paramName,
                    payload,
                    null);
            return executionEngine.execute(request);
        }
        parsed.headers.put(InternalTrafficMarker.HEADER_NAME, InternalTrafficMarker.HEADER_VALUE);
        return sendRequest(parsed);
    }

    private boolean isAllowed(URI uri) {
        if (guard == null || uri == null) {
            return true;
        }
        boolean allowed = guard.isHostAllowed(uri.toString());
        if (!allowed) {
            pluginLog.warn(PluginLogger.Category.VERIFICATION,
                    "Replay", "Blocked by host policy: " + uri);
        }
        return allowed;
    }

    private byte[] sendRequest(ParsedHttpRequest parsed) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(parsed.uri)
                    .timeout(requestTimeout);

            for (Map.Entry<String, String> e : parsed.headers.entrySet()) {
                String name = e.getKey();
                if (name.equalsIgnoreCase("Host") || name.equalsIgnoreCase("Content-Length")
                        || name.equalsIgnoreCase("Connection") || name.equalsIgnoreCase("Transfer-Encoding")) {
                    continue;
                }
                try {
                    builder.header(name, e.getValue());
                } catch (IllegalArgumentException ex) {
                    log.debug("Skipping header: {}", name);
                }
            }

            if (parsed.body != null && parsed.body.length > 0) {
                builder.method(parsed.method, HttpRequest.BodyPublishers.ofByteArray(parsed.body));
            } else {
                builder.method(parsed.method, HttpRequest.BodyPublishers.noBody());
            }

            HttpResponse<byte[]> response = httpClient.send(builder.build(),
                    HttpResponse.BodyHandlers.ofByteArray());

            return buildHttpResponseBytes(response);
        } catch (Exception e) {
            log.error("Send request failed: {}", e.getMessage());
            return null;
        }
    }

    private byte[] buildHttpResponseBytes(HttpResponse<byte[]> response) {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(response.statusCode()).append(" OK\r\n");
        response.headers().map().forEach((name, values) -> {
            for (String value : values) {
                sb.append(name).append(": ").append(value).append("\r\n");
            }
        });
        sb.append("\r\n");

        byte[] headerBytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] bodyBytes = response.body() != null ? response.body() : new byte[0];

        byte[] full = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, full, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, full, headerBytes.length, bodyBytes.length);
        return full;
    }

    private byte[] buildHttpRequestBytes(ParsedHttpRequest request) {
        StringBuilder sb = new StringBuilder();
        String path = "/";
        if (request.uri != null) {
            path = request.uri.getRawPath() != null && !request.uri.getRawPath().isBlank()
                    ? request.uri.getRawPath()
                    : "/";
            if (request.uri.getRawQuery() != null && !request.uri.getRawQuery().isBlank()) {
                path += "?" + request.uri.getRawQuery();
            }
        }

        sb.append(request.method != null ? request.method : "GET")
                .append(" ")
                .append(path)
                .append(" HTTP/1.1\r\n");

        boolean hasHost = false;
        for (Map.Entry<String, String> e : request.headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase("Host")) {
                hasHost = true;
            }
            if (e.getKey().equalsIgnoreCase("Content-Length")) {
                if (request.body != null) {
                    sb.append(e.getKey()).append(": ").append(request.body.length).append("\r\n");
                }
            } else {
                sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            }
        }
        if (!hasHost && request.uri != null && request.uri.getHost() != null) {
            sb.append("Host: ").append(request.uri.getHost());
            if (request.uri.getPort() > 0) {
                sb.append(":").append(request.uri.getPort());
            }
            sb.append("\r\n");
        }
        if (request.body != null && request.body.length > 0 && !hasHeader(request.headers, "Content-Length")) {
            sb.append("Content-Length: ").append(request.body.length).append("\r\n");
        }
        sb.append("\r\n");

        byte[] headerBytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] bodyBytes = request.body != null ? request.body : new byte[0];
        byte[] full = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, full, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, full, headerBytes.length, bodyBytes.length);
        return full;
    }

    private boolean hasHeader(Map<String, String> headers, String headerName) {
        for (String name : headers.keySet()) {
            if (name.equalsIgnoreCase(headerName)) {
                return true;
            }
        }
        return false;
    }

    private ParsedHttpRequest parseRawHttpRequest(byte[] rawBytes, HTTPContext context) {
        ParsedHttpRequest result = new ParsedHttpRequest();
        String raw = new String(rawBytes, StandardCharsets.UTF_8);

        int bodySepIdx = raw.indexOf("\r\n\r\n");
        if (bodySepIdx < 0) bodySepIdx = raw.indexOf("\n\n");

        String headerPart;
        int bodyStartByteIdx;
        if (bodySepIdx >= 0) {
            headerPart = raw.substring(0, bodySepIdx);
            String separator;
            if (raw.startsWith("\r\n\r\n", bodySepIdx)) {
                separator = "\r\n\r\n";
            } else {
                separator = "\n\n";
            }
            bodyStartByteIdx = headerPart.getBytes(StandardCharsets.UTF_8).length
                    + separator.getBytes(StandardCharsets.UTF_8).length;
            if (bodyStartByteIdx < rawBytes.length) {
                result.body = new byte[rawBytes.length - bodyStartByteIdx];
                System.arraycopy(rawBytes, bodyStartByteIdx, result.body, 0, result.body.length);
            }
        } else {
            headerPart = raw;
        }

        String[] lines = headerPart.split("\r\n|\n", -1);
        if (lines.length == 0) return result;

        String[] requestParts = lines[0].split(" ", 3);
        result.method = requestParts[0];
        String pathAndQuery = requestParts.length > 1 ? requestParts[1] : "/";

        String host = null;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) continue;
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                String value = line.substring(colonIdx + 1).trim();
                result.headers.put(name, value);
                if (name.equalsIgnoreCase("Host")) host = value;
            }
        }

        result.uri = buildTargetUri(context != null ? context.getUrl() : null, host, pathAndQuery);

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

    // === Mutation ===

    private void applyMutation(ParsedHttpRequest parsed, HTTPContext context,
                                String paramName, String newValue) {
        ParameterContext param = findParameter(context, paramName);
        if (param == null || param.getType() == null) {
            // Try URI replacement
            parsed.uri = URI.create(replaceQueryParam(parsed.uri.toString(), paramName, newValue));
            return;
        }

        switch (param.getType().name()) {
            case "QUERY" -> parsed.uri = URI.create(replaceQueryParam(parsed.uri.toString(), paramName, newValue));
            case "HEADER" -> parsed.headers.put(paramName, newValue);
            case "BODY" -> {
                String ct = getContentType(parsed.headers);
                if (ct != null && ct.toLowerCase().contains("json")) {
                    if (parsed.body != null) {
                        parsed.body = replaceJsonBodyParam(parsed.body, paramName, newValue);
                    }
                } else if (ct != null && ct.toLowerCase().contains("multipart/form-data")) {
                    if (parsed.body != null) {
                        parsed.body = replaceMultipartFormDataParam(parsed.body, paramName, newValue);
                    }
                } else {
                    if (parsed.body != null) {
                        parsed.body = replaceFormBodyParam(parsed.body, paramName, newValue);
                    }
                }
            }
            default -> parsed.uri = URI.create(replaceQueryParam(parsed.uri.toString(), paramName, newValue));
        }
    }

    private String replaceQueryParam(String url, String paramName, String newValue) {
        try {
            if (url == null) return url;
            URI uri = URI.create(url);
            String query = uri.getRawQuery();
            if (query == null) return url;

            String[] params = query.split("&");
            StringBuilder sb = new StringBuilder();
            for (String param : params) {
                if (sb.length() > 0) sb.append("&");
                int eqIdx = param.indexOf('=');
                String key = eqIdx > 0 ? param.substring(0, eqIdx) : param;
                String decodedKey = URLDecoder.decode(key, StandardCharsets.UTF_8);
                if (decodedKey.equals(paramName)) {
                    sb.append(key).append("=").append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
                } else {
                    sb.append(param);
                }
            }

            String scheme = uri.getScheme();
            String authority = uri.getRawAuthority();
            String path = uri.getRawPath() != null ? uri.getRawPath() : "";
            String fragment = uri.getRawFragment();

            StringBuilder newUrl = new StringBuilder();
            newUrl.append(scheme).append("://").append(authority).append(path);
            if (sb.length() > 0) newUrl.append("?").append(sb);
            if (fragment != null) newUrl.append("#").append(fragment);
            return newUrl.toString();
        } catch (Exception e) {
            log.warn("Query param replacement failed: {}", e.getMessage());
            return url;
        }
    }

    @SuppressWarnings("unchecked")
    private byte[] replaceJsonBodyParam(byte[] body, String paramName, String newValue) {
        try {
            String bodyStr = new String(body, StandardCharsets.UTF_8);
            Map<String, Object> map = com.aiburpcopilot.utils.JsonUtil.getMapper()
                    .readValue(bodyStr, Map.class);
            if (replaceJsonPath(map, paramName, newValue)) {
                String newBody = com.aiburpcopilot.utils.JsonUtil.getMapper().writeValueAsString(map);
                return newBody.getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) {}
        return body;
    }

    private byte[] replaceMultipartFormDataParam(byte[] body, String paramName, String newValue) {
        if (paramName == null || paramName.isBlank()) {
            return body;
        }
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        String quotedName = java.util.regex.Pattern.quote(paramName);
        java.util.regex.Pattern filenamePattern = java.util.regex.Pattern.compile(
                "(?i)(Content-Disposition:\\s*form-data\\s*;[^\\r\\n]*name\\s*=\\s*\"" + quotedName
                        + "\"[^\\r\\n]*filename\\s*=\\s*\")([^\"]*)(\")");
        java.util.regex.Matcher filenameMatcher = filenamePattern.matcher(bodyStr);
        if (filenameMatcher.find()) {
            return filenameMatcher.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                    filenameMatcher.group(1) + newValue + filenameMatcher.group(3))).getBytes(StandardCharsets.UTF_8);
        }

        java.util.regex.Pattern valuePattern = java.util.regex.Pattern.compile(
                "(?is)(Content-Disposition:\\s*form-data\\s*;[^\\r\\n]*name\\s*=\\s*\"" + quotedName
                        + "\"[^\\r\\n]*(?:\\r?\\n[^\\r\\n]*)*?\\r?\\n\\r?\\n)(.*?)(\\r?\\n--)");
        java.util.regex.Matcher valueMatcher = valuePattern.matcher(bodyStr);
        if (valueMatcher.find()) {
            return valueMatcher.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                    valueMatcher.group(1) + newValue + valueMatcher.group(3))).getBytes(StandardCharsets.UTF_8);
        }
        return body;
    }

    @SuppressWarnings("unchecked")
    private boolean replaceJsonPath(Map<String, Object> map, String paramName, String newValue) {
        if (map.containsKey(paramName)) {
            map.put(paramName, adaptJsonValue(map.get(paramName), newValue));
            return true;
        }
        if (paramName == null || !paramName.contains(".")) {
            return false;
        }
        String[] parts = paramName.split("\\.");
        Map<String, Object> current = map;
        for (int i = 0; i < parts.length - 1; i++) {
            Object child = current.get(parts[i]);
            if (!(child instanceof Map<?, ?> childMap)) {
                return false;
            }
            current = (Map<String, Object>) childMap;
        }
        String leaf = parts[parts.length - 1];
        if (!current.containsKey(leaf)) {
            return false;
        }
        current.put(leaf, adaptJsonValue(current.get(leaf), newValue));
        return true;
    }

    private Object adaptJsonValue(Object originalValue, String newValue) {
        String safeValue = newValue != null ? newValue : "";
        if (originalValue instanceof String || originalValue == null) {
            return safeValue;
        }
        if (originalValue instanceof Integer) {
            try {
                return Integer.parseInt(safeValue);
            } catch (Exception ignored) {
                return safeValue;
            }
        }
        if (originalValue instanceof Long) {
            try {
                return Long.parseLong(safeValue);
            } catch (Exception ignored) {
                return safeValue;
            }
        }
        if (originalValue instanceof Number) {
            try {
                return new java.math.BigDecimal(safeValue);
            } catch (Exception ignored) {
                return safeValue;
            }
        }
        if (originalValue instanceof Boolean) {
            if ("true".equalsIgnoreCase(safeValue) || "false".equalsIgnoreCase(safeValue)) {
                return Boolean.parseBoolean(safeValue);
            }
            return safeValue;
        }
        return safeValue;
    }

    private byte[] replaceFormBodyParam(byte[] body, String paramName, String newValue) {
        try {
            String bodyStr = new String(body, StandardCharsets.UTF_8);
            String[] params = bodyStr.split("&");
            StringBuilder sb = new StringBuilder();
            for (String param : params) {
                if (sb.length() > 0) sb.append("&");
                int eqIdx = param.indexOf('=');
                String key = eqIdx > 0 ? param.substring(0, eqIdx) : param;
                String decodedKey = URLDecoder.decode(key, StandardCharsets.UTF_8);
                if (decodedKey.equals(paramName)) {
                    sb.append(key).append("=").append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
                } else {
                    sb.append(param);
                }
            }
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
        return body;
    }

    private String getContentType(Map<String, String> headers) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase("Content-Type")) return e.getValue();
        }
        return null;
    }

    private ParameterContext findParameter(HTTPContext context, String paramName) {
        if (context.getParameters() == null) return null;
        for (ParameterContext p : context.getParameters()) {
            if (p.getName() != null && p.getName().equals(paramName)) return p;
        }
        return null;
    }

    private String resolveOriginalValue(HTTPContext context, String paramName) {
        ParameterContext param = findParameter(context, paramName);
        if (param != null && param.getValue() != null) {
            return param.getValue();
        }
        return "";
    }

    private static class ParsedHttpRequest {
        String method = "GET";
        URI uri;
        Map<String, String> headers = new LinkedHashMap<>();
        byte[] body;
    }
}
