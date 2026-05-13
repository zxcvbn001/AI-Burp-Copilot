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
 * Form-urlencoded Body 参数修改器。
 * <p>
 * 修改 application/x-www-form-urlencoded 请求体中指定参数的值。
 */
public class FormBodyMutator implements IParameterMutator {

    private static final Logger log = LoggerFactory.getLogger(FormBodyMutator.class);

    @Override
    public boolean supports(HTTPContext context, AttackTask task) {
        if (context.getRequestBody() == null || context.getRequestBody().length == 0) return false;
        String ct = context.getContentType();
        if (ct == null || !ct.contains("x-www-form-urlencoded")) return false;

        String targetName = task.getParameterName();
        for (ParameterContext param : context.getParameters()) {
            if (param.getType() == ParameterType.BODY) {
                if (param.getName().equals(targetName)) {
                    return true;
                }
                if (param.getName().equalsIgnoreCase(targetName)) {
                    log.warn("FormMutator: case-insensitive match '{}' -> '{}'",
                            targetName, param.getName());
                    return true;
                }
            }
        }

        log.debug("FormMutator: NO match for target='{}', body params: {}",
                targetName,
                context.getParameters().stream()
                        .filter(p -> p.getType() == ParameterType.BODY)
                        .map(ParameterContext::getName)
                        .toList());
        return false;
    }

    @Override
    public MutatedRequest mutate(HTTPContext context, AttackTask task) {
        byte[] rawRequest = context.getRawRequest();
        String oldBody = new String(context.getRequestBody(), StandardCharsets.UTF_8);

        String encodedPayload = urlEncode(task.getPayload());
        String newBody = replaceFormParam(oldBody, task.getParameterName(), encodedPayload);

        if (rawRequest != null && rawRequest.length > 0) {
            byte[] modified = replaceBodyInRequest(rawRequest, oldBody, newBody);
            return new MutatedRequest(modified, context.getUrl(),
                    context.getMethod(), task.getParameterName(),
                    task.getPayload(), ParameterType.BODY);
        }

        return new MutatedRequest(rawRequest, context.getUrl(),
                context.getMethod(), task.getParameterName(),
                task.getPayload(), ParameterType.BODY);
    }

    /**
     * 替换 form-urlencoded body 中指定参数的值。
     */
    private String replaceFormParam(String body, String paramName, String newValue) {
        StringBuilder sb = new StringBuilder();
        String[] pairs = body.split("&");
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) sb.append('&');
            String[] kv = pairs[i].split("=", 2);
            if (kv.length >= 1 && kv[0].equals(paramName)) {
                sb.append(kv[0]).append('=').append(newValue);
            } else {
                sb.append(pairs[i]);
            }
        }
        return sb.toString();
    }

    private byte[] replaceBodyInRequest(byte[] rawRequest, String oldBody, String newBody) {
        String requestStr = new String(rawRequest, StandardCharsets.UTF_8);
        int bodyStart = requestStr.indexOf("\r\n\r\n");
        if (bodyStart < 0) {
            bodyStart = requestStr.indexOf("\n\n");
            if (bodyStart >= 0) bodyStart += 2;
        } else {
            bodyStart += 4;
        }

        if (bodyStart > 0) {
            String headers = requestStr.substring(0, bodyStart);
            headers = headers.replaceAll(
                    "(?i)Content-Length:\\s*\\d+",
                    "Content-Length: " + newBody.getBytes(StandardCharsets.UTF_8).length);
            return (headers + newBody).getBytes(StandardCharsets.UTF_8);
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
