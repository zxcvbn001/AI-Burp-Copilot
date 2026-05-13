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
}
