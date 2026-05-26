package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.scanner.staticresource.IStaticScanner;
import com.aiburpcopilot.scanner.staticresource.StaticScanResult;
import com.aiburpcopilot.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 静态资源扫描 Pipeline Stage。
 * <p>
 * 仅对 STATIC_RESOURCE 类型的请求执行。
 * 扫描响应体中的敏感信息泄露（硬编码密钥、内网地址等）。
 */
public class StaticScanStage implements IPipelineStage {

    private static final Logger log = LoggerFactory.getLogger(StaticScanStage.class);

    private final IStaticScanner staticScanner;
    private final IHistoryService historyService;

    public StaticScanStage(IStaticScanner staticScanner) {
        this(staticScanner, null);
    }

    public StaticScanStage(IStaticScanner staticScanner, IHistoryService historyService) {
        this.staticScanner = staticScanner;
        this.historyService = historyService;
    }

    @Override
    public String getName() {
        return "Static Resource Scan";
    }

    @Override
    public void process(HTTPContext context) {
        StaticScanResult result = staticScanner.scan(context);
        StaticScanResult snapshot = snapshotResult(result);
        context.setStaticScanDetails(snapshot);
        attachStructuredResult(context, snapshot);

        if (snapshot != null && snapshot.isHasFindings()) {
            log.info("Static scan found {} issues for: {}",
                    snapshot.getFindings() != null ? snapshot.getFindings().size() : 0,
                    context.getPath());
        }
    }

    private void attachStructuredResult(HTTPContext context, StaticScanResult result) {
        if (historyService == null || context == null || context.getRequestId() == null) {
            return;
        }
        HistoryEntry existing = historyService.getById(context.getRequestId());
        if (existing != null) {
            if (hasStructuredDetails(result) || existing.getStaticScanDetails() == null) {
                existing.setStaticScanDetails(result);
            }
            if (!isFailureSummary(context.getStaticScanResult()) || !hasStructuredDetails(existing.getStaticScanDetails())) {
                existing.setAiSummary(context.getStaticScanResult());
            }
            historyService.update(existing);
        }
    }

    private boolean hasStructuredDetails(StaticScanResult result) {
        return result != null && (notEmpty(result.getCloudApis())
                || notEmpty(result.getCloudAssets())
                || notEmpty(result.getCloudSecrets())
                || notEmpty(result.getAnalyzedScripts())
                || notEmpty(result.getRecoveredEndpoints())
                || result.getCloudSummary() != null);
    }

    private boolean notEmpty(java.util.List<?> values) {
        return values != null && values.stream().anyMatch(java.util.Objects::nonNull);
    }

    private boolean isFailureSummary(String summary) {
        return summary != null && summary.startsWith("静态分析失败");
    }

    private StaticScanResult snapshotResult(StaticScanResult result) {
        if (result == null) {
            return null;
        }
        StaticScanResult snapshot = JsonUtil.fromJsonSafe(JsonUtil.toJson(result), StaticScanResult.class);
        return snapshot != null ? snapshot : result;
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        return context.getEndpointType() == EndpointType.STATIC_RESOURCE
                && context.getAnalysisStatus() != com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED
                && staticScanner.shouldScan(context);
    }
}
