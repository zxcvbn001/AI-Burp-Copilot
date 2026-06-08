package com.aiburpcopilot.burp.proxy;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.pipeline.IPipeline;
import com.aiburpcopilot.utils.InternalTrafficMarker;
import com.aiburpcopilot.utils.PluginLogger;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.aiburpcopilot.burp.support.HttpContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final String SCANNER_SOURCE_HEADER = "X-Scanner-Source";
    private static final String SCANNER_SOURCE_XRAY = "xray";
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

            if (isIgnoredBurpToolTraffic(response)) {
                pluginLog.debug(PluginLogger.Category.SYSTEM, "Proxy",
                        "Skipped Burp scanner/extender traffic: " + toolName(response));
                return ResponseReceivedAction.continueWith(response);
            }

            if (isXrayScannerTraffic(httpRequest)) {
                pluginLog.debug(PluginLogger.Category.SYSTEM, "Proxy", "Skipped xray scanner traffic: "
                        + httpRequest.method() + " " + httpRequest.pathWithoutQuery());
                return ResponseReceivedAction.continueWith(response);
            }

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
            HTTPContext context = HttpContextFactory.from(httpRequest, response);

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

    private boolean isXrayScannerTraffic(HttpRequest request) {
        return request.headers().stream()
                .anyMatch(header -> SCANNER_SOURCE_HEADER.equalsIgnoreCase(header.name())
                        && SCANNER_SOURCE_XRAY.equalsIgnoreCase(header.value() != null ? header.value().trim() : ""));
    }

    private boolean isIgnoredBurpToolTraffic(HttpResponseReceived response) {
        if (response.toolSource() == null) {
            return false;
        }
        return response.toolSource().isFromTool(ToolType.SCANNER, ToolType.EXTENSIONS);
    }

    private String toolName(HttpResponseReceived response) {
        try {
            if (response.toolSource() == null || response.toolSource().toolType() == null) {
                return "-";
            }
            return response.toolSource().toolType().toolName();
        } catch (Exception ignored) {
            return "-";
        }
    }

}
