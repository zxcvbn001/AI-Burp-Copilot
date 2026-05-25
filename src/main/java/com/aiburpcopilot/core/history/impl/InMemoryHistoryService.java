package com.aiburpcopilot.core.history.impl;

import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.discovery.DiscoveryCandidate;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.HistoryStorageStatus;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.report.ReportExportTaskRecord;
import com.aiburpcopilot.utils.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * 鍐呭瓨鍘嗗彶璁板綍鏈嶅姟瀹炵幇銆? * <p>
 * 鍩轰簬 CopyOnWriteArrayList锛岀嚎绋嬪畨鍏ㄣ€? * 杈惧埌鏈€澶ф潯鐩暟鏃惰嚜鍔ㄦ窐姹版渶鏃ц褰曘€? */
public class InMemoryHistoryService implements IHistoryService {

    private static final Logger log = LoggerFactory.getLogger(InMemoryHistoryService.class);

    private final List<HistoryEntry> entries = new CopyOnWriteArrayList<>();
    private final List<DiscoveryCandidate> discoveryCandidates = new CopyOnWriteArrayList<>();
    private final List<ReportExportTaskRecord> reportExportTasks = new CopyOnWriteArrayList<>();
    private final int maxEntries;

    public InMemoryHistoryService() {
        this(Constants.HISTORY_DEFAULT_MAX);
    }

    public InMemoryHistoryService(int maxEntries) {
        this.maxEntries = maxEntries;
    }

    @Override
    public void add(HistoryEntry entry) {
        entries.add(0, entry); // 鏈€鏂拌褰曞湪鍒楄〃澶撮儴
        // 瓒呭嚭闄愬埗鏃剁Щ闄ゆ渶鏃х殑
        if (entries.size() > maxEntries) {
            int overflow = entries.size() - maxEntries;
            for (int i = 0; i < overflow && !entries.isEmpty(); i++) {
                entries.remove(entries.size() - 1);
            }
        }
        log.debug("History entry added: {} {}", entry.getMethod(), entry.getPath());
    }

    @Override
    public void update(HistoryEntry entry) {
        if (entry == null || entry.getRequestId() == null) {
            return;
        }
        for (int index = 0; index < entries.size(); index++) {
            HistoryEntry existing = entries.get(index);
            if (entry.getRequestId().equals(existing.getRequestId())) {
                entries.set(index, entry);
                log.debug("History entry updated: {} {}", entry.getMethod(), entry.getPath());
                return;
            }
        }
        add(entry);
    }
    @Override
    public List<HistoryEntry> getAll() {
        return new ArrayList<>(entries);
    }

    @Override
    public List<HistoryEntry> search(String keyword,
                                     EndpointType endpointType,
                                     RiskLevel riskLevel,
                                     AnalysisStatus status,
                                     int offset,
                                     int limit) {
        return searchAdvanced(keyword, null, endpointType, riskLevel, status, null, null, offset, limit);
    }

    @Override
    public List<HistoryEntry> searchAdvanced(String keyword,
                                             String site,
                                             EndpointType endpointType,
                                             RiskLevel riskLevel,
                                             AnalysisStatus status,
                                             Long timeFrom,
                                             Long timeTo,
                                             int offset,
                                             int limit) {
        return entries.stream()
                .filter(e -> matchesKeyword(e, keyword))
                .filter(e -> matchesSite(e, site))
                .filter(e -> endpointType == null || e.getEndpointType() == endpointType)
                .filter(e -> riskLevel == null || e.getRiskLevel() == riskLevel)
                .filter(e -> status == null || e.getAnalysisStatus() == status)
                .filter(e -> matchesTime(e, timeFrom, timeTo))
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList());
    }

    @Override
    public HistoryEntry getById(String requestId) {
        return entries.stream()
                .filter(e -> requestId.equals(e.getRequestId()))
                .findFirst()
                .orElse(null);
    }

    @Override
    public boolean deleteById(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return false;
        }
        boolean removed = entries.removeIf(e -> requestId.equals(e.getRequestId()));
        if (removed) {
            log.info("History entry deleted: {}", requestId);
        }
        return removed;
    }

    @Override
    public void clear() {
        entries.clear();
        log.info("History cleared");
    }

    @Override
    public int size() {
        return entries.size();
    }

    @Override
    public int count(String keyword,
                     EndpointType endpointType,
                     RiskLevel riskLevel,
                     AnalysisStatus status) {
        return countAdvanced(keyword, null, endpointType, riskLevel, status, null, null);
    }

    @Override
    public int countAdvanced(String keyword,
                             String site,
                             EndpointType endpointType,
                             RiskLevel riskLevel,
                             AnalysisStatus status,
                             Long timeFrom,
                             Long timeTo) {
        return (int) entries.stream()
                .filter(e -> matchesKeyword(e, keyword))
                .filter(e -> matchesSite(e, site))
                .filter(e -> endpointType == null || e.getEndpointType() == endpointType)
                .filter(e -> riskLevel == null || e.getRiskLevel() == riskLevel)
                .filter(e -> status == null || e.getAnalysisStatus() == status)
                .filter(e -> matchesTime(e, timeFrom, timeTo))
                .count();
    }

    @Override
    public int clearAdvanced(String keyword,
                             String site,
                             EndpointType endpointType,
                             RiskLevel riskLevel,
                             AnalysisStatus status,
                             Long timeFrom,
                             Long timeTo) {
        int before = entries.size();
        entries.removeIf(e -> matchesKeyword(e, keyword)
                && matchesSite(e, site)
                && (endpointType == null || e.getEndpointType() == endpointType)
                && (riskLevel == null || e.getRiskLevel() == riskLevel)
                && (status == null || e.getAnalysisStatus() == status)
                && matchesTime(e, timeFrom, timeTo));
        return before - entries.size();
    }

    @Override
    public HistoryStorageStatus getStorageStatus() {
        return new HistoryStorageStatus(
                HistoryStorageStatus.Mode.IN_MEMORY,
                "In-Memory",
                null);
    }

    @Override
    public void saveDiscoveryCandidate(String host, DiscoveryCandidate candidate) {
        if (candidate == null || candidate.getKey() == null || candidate.getKey().isBlank()) {
            return;
        }
        for (int index = 0; index < discoveryCandidates.size(); index++) {
            DiscoveryCandidate existing = discoveryCandidates.get(index);
            if (existing != null && candidate.getKey().equals(existing.getKey())) {
                discoveryCandidates.set(index, candidate.copy());
                return;
            }
        }
        discoveryCandidates.add(0, candidate.copy());
    }

    @Override
    public List<DiscoveryCandidate> listDiscoveryCandidates(String hostFilter) {
        return discoveryCandidates.stream()
                .filter(candidate -> hostFilter == null
                        || hostFilter.isBlank()
                        || "ALL".equalsIgnoreCase(hostFilter)
                        || hostFilter.equals(candidate.getHost()))
                .map(DiscoveryCandidate::copy)
                .toList();
    }

    @Override
    public void clearDiscoveryCandidates(String hostFilter) {
        discoveryCandidates.removeIf(candidate -> hostFilter == null
                || hostFilter.isBlank()
                || "ALL".equalsIgnoreCase(hostFilter)
                || hostFilter.equals(candidate.getHost()));
    }

    @Override
    public void saveReportExportTask(ReportExportTaskRecord taskRecord) {
        if (taskRecord == null || taskRecord.getTaskId() == null || taskRecord.getTaskId().isBlank()) {
            return;
        }
        for (int index = 0; index < reportExportTasks.size(); index++) {
            ReportExportTaskRecord existing = reportExportTasks.get(index);
            if (existing != null && taskRecord.getTaskId().equals(existing.getTaskId())) {
                reportExportTasks.set(index, copyTaskRecord(taskRecord));
                return;
            }
        }
        reportExportTasks.add(0, copyTaskRecord(taskRecord));
    }

    @Override
    public List<ReportExportTaskRecord> listReportExportTasks() {
        return reportExportTasks.stream()
                .map(this::copyTaskRecord)
                .toList();
    }

    // ---------- Private ----------

    private boolean matchesKeyword(HistoryEntry entry, String keyword) {
        if (keyword == null || keyword.isEmpty()) return true;
        String lower = keyword.toLowerCase();
        return (entry.getUrl() != null && entry.getUrl().toLowerCase().contains(lower))
                || (entry.getPath() != null && entry.getPath().toLowerCase().contains(lower))
                || (entry.getMethod() != null && entry.getMethod().toLowerCase().contains(lower))
                || (entry.getAiSummary() != null && entry.getAiSummary().toLowerCase().contains(lower));
    }

    private boolean matchesSite(HistoryEntry entry, String site) {
        if (site == null || site.isBlank()) {
            return true;
        }
        String url = entry.getUrl();
        return url != null && url.toLowerCase().contains(site.toLowerCase());
    }

    private boolean matchesTime(HistoryEntry entry, Long timeFrom, Long timeTo) {
        long timestamp = entry.getTimestamp();
        if (timeFrom != null && timestamp < timeFrom) {
            return false;
        }
        return timeTo == null || timestamp <= timeTo;
    }

    private ReportExportTaskRecord copyTaskRecord(ReportExportTaskRecord source) {
        ReportExportTaskRecord copy = new ReportExportTaskRecord();
        copy.setTaskId(source.getTaskId());
        copy.setCreatedAt(source.getCreatedAt());
        copy.setUpdatedAt(source.getUpdatedAt());
        copy.setHost(source.getHost());
        copy.setItemCount(source.getItemCount());
        copy.setOutputPath(source.getOutputPath());
        copy.setStatus(source.getStatus());
        copy.setPercent(source.getPercent());
        copy.setStage(source.getStage());
        copy.setMessage(source.getMessage());
        copy.setCompletedPath(source.getCompletedPath());
        copy.setError(source.getError());
        copy.setLogs(source.getLogs());
        return copy;
    }
}
