package com.aiburpcopilot.burp.support;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.utils.HttpUtil;
import com.aiburpcopilot.utils.InternalTrafficMarker;
import com.aiburpcopilot.utils.SecurityUtil;

import java.nio.charset.StandardCharsets;
import java.util.List;

public final class HttpContextFactory {

    private HttpContextFactory() {
    }

    public static HTTPContext from(HttpRequest request, HttpResponse response) {
        HTTPContext context = new HTTPContext();
        context.setMethod(request.method());
        context.setUrl(request.url());
        context.setPath(request.pathWithoutQuery());
        context.setQuery(request.query());

        request.headers().forEach(header -> {
            String name = header.name();
            String value = header.value();
            if (InternalTrafficMarker.isMarkerHeader(name)) {
                return;
            }
            if (!HttpUtil.isSensitiveHeader(name)) {
                context.addHeader(name, value);
            }
            if ("Content-Type".equalsIgnoreCase(name)) {
                context.setContentType(value);
            }
        });

        context.setRequestBody(safeBytes(request.body()));
        context.setRawRequest(safeBytes(request.toByteArray()));
        extractParameters(context, request);

        if (response != null) {
            context.setStatusCode(response.statusCode());
            response.headers().stream()
                    .filter(h -> "Content-Type".equalsIgnoreCase(h.name()))
                    .findFirst()
                    .ifPresent(h -> context.setResponseContentType(h.value()));

            context.setResponseBody(safeBytes(response.body()));
            byte[] truncatedBody = SecurityUtil.truncateResponseBody(context.getResponseBody());
            if (truncatedBody != context.getResponseBody()) {
                context.setResponseBody(truncatedBody);
            }
            context.setRawResponse(safeBytes(response.toByteArray()));
        }

        return context;
    }

    private static byte[] safeBytes(burp.api.montoya.core.ByteArray bytes) {
        if (bytes == null) {
            return new byte[0];
        }
        byte[] raw = bytes.getBytes();
        return raw != null ? raw : new byte[0];
    }

    private static void extractParameters(HTTPContext context, HttpRequest request) {
        if (context.getQuery() != null && !context.getQuery().isEmpty()) {
            List<ParameterContext> queryParams = HttpUtil.parseQueryParams(context.getQuery());
            queryParams.forEach(context::addParameter);
        }

        if (context.getRequestBody() != null && context.getRequestBody().length > 0) {
            String body = new String(context.getRequestBody(), StandardCharsets.UTF_8);
            String contentType = context.getContentType();

            if (HttpUtil.isFormContent(contentType)) {
                HttpUtil.parseFormBodyParams(body).forEach(context::addParameter);
            } else if (HttpUtil.isJsonContent(contentType)) {
                HttpUtil.parseJsonBodyParams(body).forEach(context::addParameter);
            } else if (HttpUtil.isMultipartContent(contentType)) {
                HttpUtil.parseMultipartBodyParams(body).forEach(context::addParameter);
            }
        }
    }
}
