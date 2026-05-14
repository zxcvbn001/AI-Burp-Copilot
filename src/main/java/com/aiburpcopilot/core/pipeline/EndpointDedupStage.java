package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.utils.PluginLogger;

import java.net.URI;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class EndpointDedupStage implements IPipelineStage {

    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    @Override
    public String getName() {
        return "Endpoint Dedup";
    }

    @Override
    public void process(HTTPContext context) {
        String key = fingerprint(context);
        if (key == null) {
            return;
        }
        if (!seen.add(key)) {
            context.setAnalysisStatus(AnalysisStatus.SKIPPED);
            PluginLogger.getInstance().debug(PluginLogger.Category.SYSTEM,
                    "Dedup", "Skip repeated endpoint: " + key);
        }
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        return context != null && context.getAnalysisStatus() != AnalysisStatus.SKIPPED;
    }

    public static String fingerprint(HTTPContext context) {
        if (context == null) {
            return null;
        }
        String origin = origin(context.getUrl());
        String params = context.getParameters() == null ? "" : context.getParameters().stream()
                .map(ParameterContext::getName)
                .filter(Objects::nonNull)
                .sorted()
                .collect(Collectors.joining(","));
        return nullToEmpty(context.getMethod())
                + "|" + origin
                + "|" + nullToEmpty(context.getPath())
                + "|" + params;
    }

    private static String origin(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
            String host = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
            int port = uri.getPort();
            return scheme + "://" + host + (port > 0 ? ":" + port : "");
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String nullToEmpty(String value) {
        return value != null ? value : "";
    }
}
