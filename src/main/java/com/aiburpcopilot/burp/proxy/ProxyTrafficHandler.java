package com.aiburpcopilot.burp.proxy;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.pipeline.IPipeline;
import com.aiburpcopilot.utils.HttpUtil;
import com.aiburpcopilot.utils.InternalTrafficMarker;
import com.aiburpcopilot.utils.PluginLogger;
import com.aiburpcopilot.utils.SecurityUtil;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Proxy 流量处理器。
 * <p>
 * 基于 Montoya API 的 HttpHandler，在请求/响应通过 Burp Proxy 时触发。
 * 采集 HTTP 流量并构建 HTTPContext，然后提交到分析 Pipeline。
 * <p>
 * 使用 Montoya API 2024.12 的 HttpHandler 接口：
 * <ul>
 *   <li>handleHttpRequestToBeSent → 只采集，不修改请求</li>
 *   <li>handleHttpResponseReceived → 采集请求+响应，提交到 Pipeline</li>
 * </ul>
 */
public class ProxyTrafficHandler implements HttpHandler {

    private static final Logger log = LoggerFactory.getLogger(ProxyTrafficHandler.class);
    private final PluginLogger pluginLog = PluginLogger.getInstance();

    private final IPipeline pipeline;

    public ProxyTrafficHandler(IPipeline pipeline) {
        this.pipeline = pipeline;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        // Phase 1: 只采集不修改请求
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            // 获取发起请求的 HttpRequest
            HttpRequest httpRequest = response.initiatingRequest();

            if (isInternalVerificationTraffic(httpRequest)) {
                pluginLog.debug(PluginLogger.Category.SYSTEM, "Proxy", "Skipped internal verification replay: "
                        + httpRequest.method() + " " + httpRequest.pathWithoutQuery());
                return ResponseReceivedAction.continueWith(response);
            }

            String path = httpRequest.pathWithoutQuery();
            String method = httpRequest.method();
            pluginLog.debug(PluginLogger.Category.SYSTEM, "Proxy",
                    "Captured: " + method + " " + path + " [status=" + response.statusCode() + "]");

            // 构建 HTTPContext（HttpResponseReceived 本身 extends HttpResponse）
            HTTPContext context = buildContext(httpRequest, response);

            // 提交到 Pipeline 异步处理
            pipeline.submit(context);

        } catch (Exception e) {
            log.warn("Failed to process HTTP traffic: {}", e.getMessage());
            pluginLog.error(PluginLogger.Category.SYSTEM, "Proxy",
                    "Failed to process traffic: " + e.getMessage(), e);
        }

        // Phase 1: 不修改响应
        return ResponseReceivedAction.continueWith(response);
    }

    private boolean isInternalVerificationTraffic(HttpRequest request) {
        return request.headers().stream()
                .anyMatch(header -> InternalTrafficMarker.isMarked(header.name(), header.value()));
    }

    /**
     * 从 HttpRequest 和 HttpResponse（HttpResponseReceived 即 HttpResponse）构建 HTTPContext。
     * 敏感 Header（Authorization、Cookie 等）在构建时即过滤。
     */
    private HTTPContext buildContext(HttpRequest request, burp.api.montoya.http.message.responses.HttpResponse response) {
        HTTPContext context = new HTTPContext();

        // ---------- 请求信息 ----------
        context.setMethod(request.method());
        context.setUrl(request.url());
        context.setPath(request.pathWithoutQuery());
        context.setQuery(request.query());

        // 提取请求头（过滤敏感 Header）
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

        // 请求体
        context.setRequestBody(request.body().getBytes());

        // 保存原始请求字节（用于发送到Repeater）
        context.setRawRequest(request.toByteArray().getBytes());

        // ---------- 提取参数 ----------
        extractParameters(context, request);

        // ---------- 响应信息 ----------
        if (response != null) {
            context.setStatusCode(response.statusCode());

            response.headers().stream()
                    .filter(h -> "Content-Type".equalsIgnoreCase(h.name()))
                    .findFirst()
                    .ifPresent(h -> context.setResponseContentType(h.value()));

            context.setResponseBody(response.body().getBytes());

            // 截断过大的响应体，防止内存膨胀（原始响应保留完整用于 Repeater）
            byte[] truncatedBody = SecurityUtil.truncateResponseBody(context.getResponseBody());
            if (truncatedBody != context.getResponseBody()) {
                context.setResponseBody(truncatedBody);
            }

            // 保存原始响应字节（用于展示完整响应包）
            context.setRawResponse(response.toByteArray().getBytes());
        }

        return context;
    }

    /**
     * 从请求中提取参数（Query、Form、JSON）。
     */
    private void extractParameters(HTTPContext context, HttpRequest request) {
        if (context.getQuery() != null && !context.getQuery().isEmpty()) {
            List<ParameterContext> queryParams = HttpUtil.parseQueryParams(context.getQuery());
            queryParams.forEach(context::addParameter);
        }

        if (context.getRequestBody() != null && context.getRequestBody().length > 0) {
            String body = new String(context.getRequestBody(), StandardCharsets.UTF_8);
            String contentType = context.getContentType();

            if (HttpUtil.isFormContent(contentType)) {
                List<ParameterContext> formParams = HttpUtil.parseFormBodyParams(body);
                formParams.forEach(context::addParameter);
            } else if (HttpUtil.isJsonContent(contentType)) {
                List<ParameterContext> jsonParams = HttpUtil.parseJsonBodyParams(body);
                jsonParams.forEach(context::addParameter);
            } else if (HttpUtil.isMultipartContent(contentType)) {
                List<ParameterContext> multipartParams = HttpUtil.parseMultipartBodyParams(body);
                multipartParams.forEach(context::addParameter);
            }
        }

        log.debug("Extracted {} parameters from: {} {}", context.getParameters().size(),
                context.getMethod(), context.getPath());
    }
}
