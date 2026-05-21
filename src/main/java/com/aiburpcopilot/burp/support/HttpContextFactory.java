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

        context.setRequestBody(request.body().getBytes());
        context.setRawRequest(request.toByteArray().getBytes());
        extractParameters(context, request);

        if (response != null) {
            context.setStatusCode(response.statusCode());
            response.headers().stream()
                    .filter(h -> "Content-Type".equalsIgnoreCase(h.name()))
                    .findFirst()
                    .ifPresent(h -> context.setResponseContentType(h.value()));

            context.setResponseBody(response.body().getBytes());
            byte[] truncatedBody = SecurityUtil.truncateResponseBody(context.getResponseBody());
            if (truncatedBody != context.getResponseBody()) {
                context.setResponseBody(truncatedBody);
            }
            context.setRawResponse(response.toByteArray().getBytes());
        }

        return context;
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
