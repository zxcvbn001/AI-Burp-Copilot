package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.utils.InternalTrafficMarker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Records only original proxy traffic into history.
 * Internal verification replay traffic is skipped so history stores the
 * original request plus analysis/verification conclusions, not replay packets.
 */
public class HistoryStage implements IPipelineStage {

    private static final Logger log = LoggerFactory.getLogger(HistoryStage.class);

    private final IHistoryService historyService;
    private final boolean markCompleted;

    public HistoryStage(IHistoryService historyService) {
        this(historyService, false);
    }

    public HistoryStage(IHistoryService historyService, boolean markCompleted) {
        this.historyService = historyService;
        this.markCompleted = markCompleted;
    }

    @Override
    public String getName() {
        return markCompleted ? "History Final Update" : "History Snapshot";
    }

    boolean isFinalUpdate() {
        return markCompleted;
    }

    @Override
    public void process(HTTPContext context) {
        try {
            if (markCompleted
                    && context.getAnalysisStatus() != com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED) {
                context.setAnalysisStatus(com.aiburpcopilot.core.context.AnalysisStatus.COMPLETED);
            }
            boolean isNew = historyService.getById(context.getRequestId()) == null;
            HistoryEntry entry;
            if (context.getStaticScanResult() != null) {
                entry = HistoryEntry.fromStaticScan(context);
            } else {
                entry = HistoryEntry.fromHTTPContext(context);
            }
            HistoryEntry existing = historyService.getById(context.getRequestId());
            if (entry.getStaticScanDetails() == null && existing != null && existing.getStaticScanDetails() != null) {
                entry.setStaticScanDetails(existing.getStaticScanDetails());
            }
            if (existing != null
                    && isFailureSummary(entry.getAiSummary())
                    && hasStructuredDetails(existing.getStaticScanDetails())) {
                entry.setAiSummary(existing.getAiSummary());
                entry.setStaticScanDetails(existing.getStaticScanDetails());
            }
            historyService.update(entry);
            if (isNew) {
                HistoryEventBus.getInstance().fireHistoryAdded(entry);
            } else {
                HistoryEventBus.getInstance().fireRefreshNeeded();
            }
        } catch (Exception e) {
            log.error("Failed to record history for: {}", context.getPath(), e);
        }
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        if (context == null || context.getHeaders() == null) {
            return false;
        }
        return context.getHeaders().entrySet().stream()
                .noneMatch(entry -> InternalTrafficMarker.isMarked(entry.getKey(), entry.getValue()));
    }

    private boolean isFailureSummary(String summary) {
        return summary != null && summary.startsWith("静态分析失败");
    }

    private boolean hasStructuredDetails(com.aiburpcopilot.scanner.staticresource.StaticScanResult result) {
        return result != null && (notEmpty(result.getCloudApis())
                || notEmpty(result.getCloudAssets())
                || notEmpty(result.getCloudParams())
                || notEmpty(result.getCloudAuthSignals())
                || notEmpty(result.getCloudSecrets())
                || notEmpty(result.getCloudRisks())
                || notEmpty(result.getCloudFindings())
                || notEmpty(result.getEndpointFindings())
                || notEmpty(result.getExposureFindings())
                || notEmpty(result.getScriptFindings())
                || notEmpty(result.getAnalyzedScripts())
                || notEmpty(result.getRecoveredEndpoints())
                || result.getCloudSummary() != null);
    }

    private boolean notEmpty(java.util.List<?> values) {
        return values != null && values.stream().anyMatch(java.util.Objects::nonNull);
    }
}
