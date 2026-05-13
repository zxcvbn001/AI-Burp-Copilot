package com.aiburpcopilot.core.history.impl;

import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
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
        return entries.stream()
                .filter(e -> matchesKeyword(e, keyword))
                .filter(e -> endpointType == null || e.getEndpointType() == endpointType)
                .filter(e -> riskLevel == null || e.getRiskLevel() == riskLevel)
                .filter(e -> status == null || e.getAnalysisStatus() == status)
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
        return (int) entries.stream()
                .filter(e -> matchesKeyword(e, keyword))
                .filter(e -> endpointType == null || e.getEndpointType() == endpointType)
                .filter(e -> riskLevel == null || e.getRiskLevel() == riskLevel)
                .filter(e -> status == null || e.getAnalysisStatus() == status)
                .count();
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
}
