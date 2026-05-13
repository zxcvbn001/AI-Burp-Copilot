package com.aiburpcopilot.core.verification.mutation.impl;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.context.ParameterType;
import com.aiburpcopilot.core.verification.model.AttackTask;
import com.aiburpcopilot.core.verification.model.MutatedRequest;
import com.aiburpcopilot.core.verification.mutation.IParameterMutator;
import com.aiburpcopilot.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON Body 参数修改器。
 * <p>
 * 修改 JSON 请求体中指定字段的值为 payload。
 * 保持原始值的类型（字符串 → 字符串、数字 → 字符串）。
 */
public class JsonBodyMutator implements IParameterMutator {

    private static final Logger log = LoggerFactory.getLogger(JsonBodyMutator.class);

    @Override
    public boolean supports(HTTPContext context, AttackTask task) {
        if (context.getRequestBody() == null || context.getRequestBody().length == 0) return false;
        String ct = context.getContentType();
        if (ct == null || (!ct.contains("json") && !ct.contains("javascript"))) return false;

        String targetName = task.getParameterName();
        for (ParameterContext param : context.getParameters()) {
            if (param.getType() == ParameterType.BODY) {
                if (param.getName().equals(targetName)) {
                    return true;
                }
                if (param.getName().equalsIgnoreCase(targetName)) {
                    log.warn("JsonMutator: case-insensitive match '{}' -> '{}'",
                            targetName, param.getName());
                    return true;
                }
            }
        }

        log.debug("JsonMutator: NO match for target='{}', body params: {}",
                targetName,
                context.getParameters().stream()
                        .filter(p -> p.getType() == ParameterType.BODY)
                        .map(ParameterContext::getName)
                        .toList());
        return false;
    }

    @Override
    @SuppressWarnings("unchecked")
    public MutatedRequest mutate(HTTPContext context, AttackTask task) {
        byte[] rawRequest = context.getRawRequest();
        String bodyStr = new String(context.getRequestBody(), StandardCharsets.UTF_8);

        try {
            Map<String, Object> bodyMap = JsonUtil.getMapper().readValue(bodyStr, LinkedHashMap.class);
            replaceJsonPath(bodyMap, task.getParameterName(), task.getPayload());

            String newBody = JsonUtil.getMapper().writeValueAsString(bodyMap);

            if (rawRequest != null && rawRequest.length > 0) {
                byte[] modified = replaceBodyInRequest(rawRequest, bodyStr, newBody);
                return new MutatedRequest(modified, context.getUrl(),
                        context.getMethod(), task.getParameterName(),
                        task.getPayload(), ParameterType.BODY);
            }
        } catch (Exception e) {
            // JSON 解析失败，回退
        }

        return new MutatedRequest(rawRequest, context.getUrl(),
                context.getMethod(), task.getParameterName(),
                task.getPayload(), ParameterType.BODY);
    }

    @SuppressWarnings("unchecked")
    private boolean replaceJsonPath(Map<String, Object> bodyMap, String parameterName, String payload) {
        if (bodyMap.containsKey(parameterName)) {
            bodyMap.put(parameterName, adaptJsonValue(bodyMap.get(parameterName), payload, false));
            return true;
        }
        if (parameterName == null || !parameterName.contains(".")) {
            return false;
        }
        String[] parts = parameterName.split("\\.");
        Map<String, Object> current = bodyMap;
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
        current.put(leaf, adaptJsonValue(current.get(leaf), payload, false));
        return true;
    }

    private Object adaptJsonValue(Object originalValue, String payload, boolean append) {
        String safePayload = payload != null ? payload : "";
        if (append) {
            String originalText = originalValue != null ? String.valueOf(originalValue) : "";
            safePayload = originalText + safePayload;
        }
        if (originalValue instanceof String || originalValue == null) {
            return safePayload;
        }
        if (originalValue instanceof Integer) {
            return parseIntegerOrString(safePayload);
        }
        if (originalValue instanceof Long) {
            return parseLongOrString(safePayload);
        }
        if (originalValue instanceof Float || originalValue instanceof Double
                || originalValue instanceof java.math.BigDecimal) {
            return parseDecimalOrString(safePayload);
        }
        if (originalValue instanceof Number) {
            return parseDecimalOrString(safePayload);
        }
        if (originalValue instanceof Boolean) {
            if ("true".equalsIgnoreCase(safePayload) || "false".equalsIgnoreCase(safePayload)) {
                return Boolean.parseBoolean(safePayload);
            }
            return safePayload;
        }
        return safePayload;
    }

    private Object parseIntegerOrString(String value) {
        try {
            return Integer.parseInt(value);
        } catch (Exception ignored) {
            return value;
        }
    }

    private Object parseLongOrString(String value) {
        try {
            return Long.parseLong(value);
        } catch (Exception ignored) {
            return value;
        }
    }

    private Object parseDecimalOrString(String value) {
        try {
            return new java.math.BigDecimal(value);
        } catch (Exception ignored) {
            return value;
        }
    }

    /**
     * 替换 HTTP 原始字节中的请求体部分。
     */
    private byte[] replaceBodyInRequest(byte[] rawRequest, String oldBody, String newBody) {
        String requestStr = new String(rawRequest, StandardCharsets.UTF_8);
        // 找到 body 起始位置（\r\n\r\n 或 \n\n）
        int bodyStart = requestStr.indexOf("\r\n\r\n");
        if (bodyStart < 0) {
            bodyStart = requestStr.indexOf("\n\n");
            if (bodyStart >= 0) bodyStart += 2;
        } else {
            bodyStart += 4;
        }

        if (bodyStart > 0) {
            String headers = requestStr.substring(0, bodyStart);
            // 更新 Content-Length
            headers = headers.replaceAll(
                    "(?i)Content-Length:\\s*\\d+",
                    "Content-Length: " + newBody.getBytes(StandardCharsets.UTF_8).length);
            return (headers + newBody).getBytes(StandardCharsets.UTF_8);
        }

        return rawRequest;
    }
}
