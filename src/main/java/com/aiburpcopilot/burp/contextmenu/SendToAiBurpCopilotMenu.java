package com.aiburpcopilot.burp.contextmenu;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.aiburpcopilot.burp.support.HttpContextFactory;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.pipeline.IPipeline;
import com.aiburpcopilot.utils.PluginLogger;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.List;

public class SendToAiBurpCopilotMenu implements ContextMenuItemsProvider {

    private final IPipeline pipeline;

    public SendToAiBurpCopilotMenu(IPipeline pipeline) {
        this.pipeline = pipeline;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        HttpRequestResponse requestResponse = extractRequestResponse(event);
        if (requestResponse == null || requestResponse.request() == null) {
            return List.of();
        }

        JMenuItem full = new JMenuItem("一键分析（全流程）");
        full.addActionListener(e -> submit(requestResponse, null, "full-pipeline"));

        JMenuItem endpoint = new JMenuItem("Endpoint 分析");
        endpoint.addActionListener(e -> submit(requestResponse, EndpointType.ENDPOINT, "endpoint-analysis"));

        JMenuItem staticScan = new JMenuItem("静态文件分析");
        staticScan.addActionListener(e -> submit(requestResponse, EndpointType.STATIC_RESOURCE, "static-analysis"));

        return List.of(full, endpoint, staticScan);
    }

    private HttpRequestResponse extractRequestResponse(ContextMenuEvent event) {
        if (event == null) {
            return null;
        }
        if (event.messageEditorRequestResponse().isPresent()) {
            return event.messageEditorRequestResponse().get().requestResponse();
        }
        List<HttpRequestResponse> items = event.selectedRequestResponses();
        return items != null && !items.isEmpty() ? items.get(0) : null;
    }

    private void submit(HttpRequestResponse requestResponse, EndpointType forcedType, String mode) {
        try {
            HTTPContext context = HttpContextFactory.from(requestResponse.request(), requestResponse.response());
            context.setManualSubmission(true);
            if (forcedType != null) {
                context.setEndpointType(forcedType);
            }
            pipeline.submit(context);
            PluginLogger.getInstance().info(
                    PluginLogger.Category.SYSTEM,
                    "ContextMenu",
                    "Manual send submitted: mode=" + mode + ", method=" + context.getMethod() + ", path=" + context.getPath());
        } catch (Exception ex) {
            PluginLogger.getInstance().error(
                    PluginLogger.Category.SYSTEM,
                    "ContextMenu",
                    "Manual send failed: " + ex.getMessage(),
                    ex instanceof Exception ? (Exception) ex : new RuntimeException(ex));
        }
    }
}
