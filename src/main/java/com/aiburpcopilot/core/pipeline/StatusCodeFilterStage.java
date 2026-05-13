package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.utils.PluginLogger;

import java.util.List;

public class StatusCodeFilterStage implements IPipelineStage {

    private final IConfigService configService;

    public StatusCodeFilterStage(IConfigService configService) {
        this.configService = configService;
    }

    @Override
    public String getName() {
        return "Status Code Filter";
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        if (context == null || configService == null || configService.getConfig() == null) {
            return false;
        }
        List<Integer> skipCodes = configService.getConfig().getScan().getSkipStatusCodes();
        return skipCodes != null && skipCodes.contains(context.getStatusCode());
    }

    @Override
    public void process(HTTPContext context) {
        List<Integer> skipCodes = configService.getConfig().getScan().getSkipStatusCodes();
        context.setAnalysisStatus(AnalysisStatus.SKIPPED);
        context.setStaticScanResult("扫描已跳过：HTTP 状态码 " + context.getStatusCode()
                + " 命中状态码黑名单 " + skipCodes);
        PluginLogger.getInstance().debug("StatusFilter",
                "Skipped by status code: " + context.getStatusCode() + " " + context.getPath());
    }
}
