package com.aiburpcopilot.core.verification.mutation.impl;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.context.ParameterType;
import com.aiburpcopilot.core.verification.model.AttackTask;
import com.aiburpcopilot.core.verification.model.MutatedRequest;
import com.aiburpcopilot.core.verification.mutation.IParameterMutator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Query 参数修改器。
 * <p>
 * 修改 URL 中 query string 的目标参数值为 payload。
 */
public class QueryParameterMutator implements IParameterMutator {

    private static final Logger log = LoggerFactory.getLogger(QueryParameterMutator.class);

    @Override
    public boolean supports(HTTPContext context, AttackTask task) {
        if (context.getQuery() == null || context.getQuery().isEmpty()) return false;

        String targetName = task.getParameterName();
        for (ParameterContext param : context.getParameters()) {
            if (param.getType() == ParameterType.QUERY) {
                if (param.getName().equals(targetName)) {
                    return true;
                }
                if (param.getName().equalsIgnoreCase(targetName)) {
                    log.warn("QueryMutator: case-insensitive match '{}' -> '{}'",
                            targetName, param.getName());
                    return true;
                }
            }
        }

        log.debug("QueryMutator: NO match for target='{}', query params: {}",
                targetName,
                context.getParameters().stream()
                        .filter(p -> p.getType() == ParameterType.QUERY)
                        .map(ParameterContext::getName)
                        .toList());
        return false;
    }

    @Override
    public MutatedRequest mutate(HTTPContext context, AttackTask task) {
        String originalQuery = context.getQuery();
        String encodedPayload = urlEncode(task.getPayload());

        // 替换目标参数值
        String newQuery = replaceQueryParamValue(originalQuery, task.getParameterName(), encodedPayload);

        // 从原始请求中重建（修改第一行的 URL）
        byte[] rawRequest = context.getRawRequest();
        if (rawRequest != null && rawRequest.length > 0) {
            byte[] modified = rebuildRequestWithQuery(rawRequest, newQuery);
            return new MutatedRequest(modified, context.getUrl(),
                    context.getMethod(), task.getParameterName(),
                    task.getPayload(), ParameterType.QUERY);
        }

        // 回退：使用原始 URL
        String newUrl = context.getUrl();
        int queryIdx = newUrl.indexOf('?');
        if (queryIdx >= 0) {
            newUrl = newUrl.substring(0, queryIdx + 1) + newQuery;
        } else {
            newUrl = newUrl + "?" + newQuery;
        }

        return new MutatedRequest(null, newUrl, context.getMethod(),
                task.getParameterName(), task.getPayload(), ParameterType.QUERY);
    }

    /**
     * 替换 query string 中指定参数的值（仅替换目标参数，不影响其他参数）。
     */
    private String replaceQueryParamValue(String query, String paramName, String newValue) {
        StringBuilder sb = new StringBuilder();
        String[] pairs = query.split("&");
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) sb.append("&");
            int idx = pairs[i].indexOf('=');
            String name = idx >= 0 ? pairs[i].substring(0, idx) : pairs[i];
            String value = idx >= 0 && idx < pairs[i].length() - 1 ? pairs[i].substring(idx + 1) : "";

            if (name.equals(paramName)) {
                sb.append(name).append("=").append(newValue);
            } else {
                sb.append(pairs[i]);
            }
        }
        return sb.toString();
    }

    /**
     * 重建 HTTP 原始字节中的 URL query 部分。
     */
    private byte[] rebuildRequestWithQuery(byte[] rawRequest, String newQuery) throws RuntimeException {
        String requestStr = new String(rawRequest, StandardCharsets.UTF_8);
        // 修改第一行（request line）中的 URL
        int firstLineEnd = requestStr.indexOf("\r\n");
        if (firstLineEnd < 0) firstLineEnd = requestStr.indexOf('\n');

        if (firstLineEnd > 0) {
            String requestLine = requestStr.substring(0, firstLineEnd);
            String[] parts = requestLine.split(" ", 3);
            if (parts.length < 3) {
                return rawRequest;
            }
            String requestTarget = parts[1];
            int queryIdx = requestTarget.indexOf('?');
            String newRequestTarget = queryIdx >= 0
                    ? requestTarget.substring(0, queryIdx + 1) + newQuery
                    : requestTarget + "?" + newQuery;
            String newRequestLine = parts[0] + " " + newRequestTarget + " " + parts[2];

            String modified = newRequestLine + requestStr.substring(firstLineEnd);
            return modified.getBytes(StandardCharsets.UTF_8);
        }

        return rawRequest;
    }

    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }
}
