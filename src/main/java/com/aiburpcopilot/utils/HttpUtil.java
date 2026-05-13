package com.aiburpcopilot.utils;

import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.context.ParameterType;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * HTTP 工具类。
 * <p>
 * 提供 HTTP 请求/响应的解析辅助方法。
 * 包括参数提取、Content-Type 解析、敏感 Header 过滤等。
 */
public final class HttpUtil {

    private HttpUtil() {}

    /**
     * 从查询字符串中提取参数。
     *
     * @param queryString 查询字符串（如 "id=1&name=test"）
     * @return 参数列表
     */
    public static List<ParameterContext> parseQueryParams(String queryString) {
        if (queryString == null || queryString.isEmpty()) {
            return Collections.emptyList();
        }

        List<ParameterContext> params = new ArrayList<>();
        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String name = urlDecode(pair.substring(0, idx));
                String value = idx < pair.length() - 1 ? urlDecode(pair.substring(idx + 1)) : "";
                params.add(new ParameterContext(name, truncateValue(value), ParameterType.QUERY));
            }
        }
        return params;
    }

    /**
     * 从 Form Body 中提取参数。
     *
     * @param body 请求体字符串
     * @return 参数列表
     */
    public static List<ParameterContext> parseFormBodyParams(String body) {
        if (body == null || body.isEmpty()) {
            return Collections.emptyList();
        }

        List<ParameterContext> params = new ArrayList<>();
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String name = urlDecode(pair.substring(0, idx));
                String value = idx < pair.length() - 1 ? urlDecode(pair.substring(idx + 1)) : "";
                params.add(new ParameterContext(name, truncateValue(value), ParameterType.BODY));
            }
        }
        return params;
    }

    /**
     * 从 JSON Body 中提取顶层字段作为参数。
     *
     * @param body JSON 请求体
     * @return 参数列表
     */
    public static List<ParameterContext> parseJsonBodyParams(String body) {
        if (body == null || body.isEmpty()) {
            return Collections.emptyList();
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = JsonUtil.getMapper().readValue(body, Map.class);
            List<ParameterContext> params = new ArrayList<>();
            flattenJsonParams("", map, params);
            return params;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    public static List<ParameterContext> parseMultipartBodyParams(String body) {
        if (body == null || body.isEmpty()) {
            return Collections.emptyList();
        }
        List<ParameterContext> params = new ArrayList<>();
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("(?i)Content-Disposition:\\s*form-data\\s*;([^\\r\\n]+)")
                .matcher(body);
        while (matcher.find()) {
            String disposition = matcher.group(1);
            String name = extractDispositionValue(disposition, "name");
            if (name == null || name.isBlank()) {
                continue;
            }
            String filename = extractDispositionValue(disposition, "filename");
            params.add(new ParameterContext(name, truncateValue(filename != null ? filename : ""), ParameterType.BODY));
        }
        return params;
    }

    public static boolean isMultipartContent(String contentType) {
        String mime = extractMimeType(contentType);
        return mime.contains("multipart/form-data");
    }

    @SuppressWarnings("unchecked")
    private static void flattenJsonParams(String prefix, Map<String, Object> map, List<ParameterContext> params) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String name = prefix.isBlank() ? entry.getKey() : prefix + "." + entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map<?, ?> childMap) {
                flattenJsonParams(name, (Map<String, Object>) childMap, params);
            } else {
                String text = value != null ? value.toString() : "";
                params.add(new ParameterContext(name, truncateValue(text), ParameterType.BODY));
            }
        }
    }

    /**
     * 从字节数组获取 Content-Type 的值（不含 charset 等参数）。
     *
     * @param contentTypeHeader Content-Type 头值
     * @return 纯 MIME 类型
     */
    public static String extractMimeType(String contentTypeHeader) {
        if (contentTypeHeader == null) return "";
        int idx = contentTypeHeader.indexOf(';');
        return (idx > 0) ? contentTypeHeader.substring(0, idx).trim().toLowerCase() : contentTypeHeader.trim().toLowerCase();
    }

    /**
     * 判断是否 JSON Content-Type。
     */
    public static boolean isJsonContent(String contentType) {
        String mime = extractMimeType(contentType);
        return mime.contains("json") || mime.contains("javascript");
    }

    /**
     * 判断是否 Form Content-Type。
     */
    public static boolean isFormContent(String contentType) {
        String mime = extractMimeType(contentType);
        return mime.contains("x-www-form-urlencoded");
    }

    /**
     * 判断是否需要进行 AI 分析的端点（基于后缀）。
     *
     * @param path URL 路径
     * @return true 如果是明显的静态资源后缀
     */
    public static boolean isStaticExtension(String path) {
        return hasExtension(path, Constants.STATIC_EXTENSIONS);
    }

    public static boolean hasExtension(String path, Collection<String> extensions) {
        if (path == null || extensions == null || extensions.isEmpty()) return false;
        String lower = stripUrlSuffix(path).toLowerCase(Locale.ROOT);
        int dotIdx = lower.lastIndexOf('.');
        if (dotIdx < 0 || dotIdx >= lower.length() - 1) return false;

        String ext = lower.substring(dotIdx + 1);
        if ("map".equals(ext) && dotIdx > 0) {
            int prevDot = lower.lastIndexOf('.', dotIdx - 1);
            if (prevDot >= 0 && prevDot < lower.length() - 1) {
                ext = lower.substring(prevDot + 1);
            }
        }

        String normalizedExt = normalizeExtension(ext);
        for (String configured : extensions) {
            if (normalizeExtension(configured).equals(normalizedExt)) {
                return true;
            }
        }
        return false;
    }

    public static String stripUrlSuffix(String path) {
        if (path == null) return "";
        int end = path.length();
        int queryIndex = path.indexOf('?');
        if (queryIndex >= 0) end = Math.min(end, queryIndex);
        int fragmentIndex = path.indexOf('#');
        if (fragmentIndex >= 0) end = Math.min(end, fragmentIndex);
        return path.substring(0, end);
    }

    private static String normalizeExtension(String extension) {
        if (extension == null) return "";
        String normalized = extension.trim().toLowerCase(Locale.ROOT);
        return normalized.startsWith(".") ? normalized.substring(1) : normalized;
    }

    private static String extractDispositionValue(String disposition, String key) {
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("(?i)(?:^|;)\\s*" + java.util.regex.Pattern.quote(key) + "\\s*=\\s*\"([^\"]*)\"")
                .matcher(disposition);
        if (matcher.find()) {
            return matcher.group(1);
        }
        matcher = java.util.regex.Pattern
                .compile("(?i)(?:^|;)\\s*" + java.util.regex.Pattern.quote(key) + "\\s*=\\s*([^;\\s]+)")
                .matcher(disposition);
        return matcher.find() ? matcher.group(1) : null;
    }

    /**
     * 检查路径是否包含跳过的关键字。
     *
     * @param path        URL 路径
     * @param skipKeywords 跳过的关键字列表
     * @return true 如果应该跳过
     */
    public static boolean shouldSkipByKeyword(String path, List<String> skipKeywords) {
        if (path == null || skipKeywords == null) return false;
        String lower = path.toLowerCase();
        return skipKeywords.stream().anyMatch(kw -> lower.contains(kw.toLowerCase()));
    }

    /**
     * 检查 Header 是否为敏感 Header。
     *
     * @param headerName Header 名
     * @return true 如果是敏感 Header
     */
    public static boolean isSensitiveHeader(String headerName) {
        return Constants.SENSITIVE_HEADERS.contains(headerName.toLowerCase());
    }

    /**
     * 截断参数值（避免过大的值存入内存）。
     */
    private static String truncateValue(String value) {
        if (value == null) return "";
        return value.length() > 200 ? value.substring(0, 200) + "..." : value;
    }

    /**
     * URL 解码。
     */
    private static String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }
}
