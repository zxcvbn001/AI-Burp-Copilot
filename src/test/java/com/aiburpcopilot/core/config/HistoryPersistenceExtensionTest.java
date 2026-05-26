package com.aiburpcopilot.core.config;

import com.aiburpcopilot.core.discovery.DiscoveryAssetType;
import com.aiburpcopilot.core.discovery.DiscoveryCandidate;
import com.aiburpcopilot.core.discovery.DiscoveryJudgment;
import com.aiburpcopilot.core.discovery.DiscoveryValidation;
import com.aiburpcopilot.core.discovery.DiscoveryValidationStatus;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.history.impl.InMemoryHistoryService;
import com.aiburpcopilot.core.history.impl.SqliteHistoryService;
import com.aiburpcopilot.core.report.ReportExportTaskRecord;
import com.aiburpcopilot.scanner.staticresource.StaticScanResult;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class HistoryPersistenceExtensionTest {

    @Test
    void inMemoryHistoryShouldPersistDiscoveryCandidatesAndReportTasks() {
        IHistoryService historyService = new InMemoryHistoryService();
        DiscoveryCandidate candidate = sampleCandidate();
        historyService.saveDiscoveryCandidate(candidate.getHost(), candidate);

        List<DiscoveryCandidate> candidates = historyService.listDiscoveryCandidates(candidate.getHost());
        assertEquals(1, candidates.size());
        assertEquals(DiscoveryJudgment.EXISTS, candidates.get(0).getValidation().getJudgment());

        ReportExportTaskRecord task = sampleTask();
        historyService.saveReportExportTask(task);
        List<ReportExportTaskRecord> tasks = historyService.listReportExportTasks();
        assertEquals(1, tasks.size());
        assertEquals("DONE", tasks.get(0).getStatus());
    }

    @Test
    void sqliteHistoryShouldPersistDiscoveryCandidatesAndReportTasks() throws Exception {
        Path homeDir = Files.createTempDirectory("aiburpcopilot-history-ext");
        AppConfig.StorageConfig storageConfig = new AppConfig.StorageConfig();
        storageConfig.setHistoryDbPath(homeDir.resolve("history.db").toString());
        IHistoryService historyService = new SqliteHistoryService(storageConfig);

        DiscoveryCandidate candidate = sampleCandidate();
        historyService.saveDiscoveryCandidate(candidate.getHost(), candidate);

        List<DiscoveryCandidate> candidates = historyService.listDiscoveryCandidates(candidate.getHost());
        assertEquals(1, candidates.size());
        assertEquals(candidate.getKey(), candidates.get(0).getKey());
        assertEquals(DiscoveryJudgment.EXISTS, candidates.get(0).getValidation().getJudgment());
        assertFalse(candidates.get(0).getValidation().getAttempts().isEmpty());

        ReportExportTaskRecord task = sampleTask();
        historyService.saveReportExportTask(task);
        List<ReportExportTaskRecord> tasks = historyService.listReportExportTasks();
        assertEquals(1, tasks.size());
        assertEquals(task.getTaskId(), tasks.get(0).getTaskId());
        assertEquals("DONE", tasks.get(0).getStatus());
    }

    @Test
    void sqliteHistoryShouldKeepStaticDetailsWhenUpdateHasEmptyDetails() throws Exception {
        Path homeDir = Files.createTempDirectory("aiburpcopilot-history-static");
        AppConfig.StorageConfig storageConfig = new AppConfig.StorageConfig();
        storageConfig.setHistoryDbPath(homeDir.resolve("history.db").toString());
        IHistoryService historyService = new SqliteHistoryService(storageConfig);

        HistoryEntry first = new HistoryEntry();
        first.setRequestId("static-1");
        first.setTimestamp(System.currentTimeMillis());
        first.setUrl("https://example.com/app.js");
        first.setPath("/app.js");
        first.setEndpointType(EndpointType.STATIC_RESOURCE);
        first.setAiSummary("Static scan done");
        StaticScanResult details = new StaticScanResult();
        StaticScanResult.CloudSummary cloudSummary = new StaticScanResult.CloudSummary();
        cloudSummary.setFindingCount(2);
        details.setCloudSummary(cloudSummary);
        first.setStaticScanDetails(details);
        historyService.update(first);

        HistoryEntry second = new HistoryEntry();
        second.setRequestId("static-1");
        second.setTimestamp(System.currentTimeMillis());
        second.setUrl("https://example.com/app.js");
        second.setPath("/app.js");
        second.setEndpointType(EndpointType.STATIC_RESOURCE);
        second.setAiSummary("静态分析失败: transient");
        historyService.update(second);

        HistoryEntry loaded = historyService.getById("static-1");
        assertEquals(2, loaded.getStaticScanDetails().getCloudSummary().getFindingCount());
    }

    @Test
    void sqliteHistoryShouldMigrateOldHistorySchema() throws Exception {
        Path homeDir = Files.createTempDirectory("aiburpcopilot-history-migrate");
        Path dbPath = homeDir.resolve("history.db");
        Class.forName("org.sqlite.JDBC");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE history_entries (
                        request_id TEXT PRIMARY KEY,
                        timestamp INTEGER NOT NULL,
                        method TEXT,
                        url TEXT,
                        path TEXT
                    )
                    """);
        }

        AppConfig.StorageConfig storageConfig = new AppConfig.StorageConfig();
        storageConfig.setHistoryDbPath(dbPath.toString());
        IHistoryService historyService = new SqliteHistoryService(storageConfig);

        HistoryEntry entry = new HistoryEntry();
        entry.setRequestId("migrated-1");
        entry.setTimestamp(System.currentTimeMillis());
        entry.setUrl("https://example.com/app.js");
        entry.setPath("/app.js");
        entry.setEndpointType(EndpointType.STATIC_RESOURCE);
        StaticScanResult details = new StaticScanResult();
        StaticScanResult.CloudSummary cloudSummary = new StaticScanResult.CloudSummary();
        cloudSummary.setFindingCount(1);
        details.setCloudSummary(cloudSummary);
        entry.setStaticScanDetails(details);
        historyService.update(entry);

        HistoryEntry loaded = historyService.getById("migrated-1");
        assertEquals(1, loaded.getStaticScanDetails().getCloudSummary().getFindingCount());
        assertEquals(1, historyService.getAll().size());
    }

    private DiscoveryCandidate sampleCandidate() {
        DiscoveryCandidate candidate = new DiscoveryCandidate();
        candidate.setKey("ENDPOINT|https://example.com|/api/test|GET");
        candidate.setHost("https://example.com");
        candidate.setPath("/api/test");
        candidate.setUrl("https://example.com/api/test");
        candidate.setAssetType(DiscoveryAssetType.ENDPOINT);
        candidate.setScore(0.91);
        candidate.setMethodHint("GET");
        candidate.setSourceReason("unit-test");
        candidate.setSupportingObservationCount(3);
        candidate.setSupportingPaths(List.of("/api/list", "/api/detail"));
        candidate.setSupportingParameters(List.of("id", "page"));
        candidate.setSupportingMethods(List.of("GET"));

        DiscoveryValidation validation = new DiscoveryValidation();
        validation.setStatus(DiscoveryValidationStatus.COMPLETED);
        validation.setJudgment(DiscoveryJudgment.EXISTS);
        validation.setReasoning("exists");
        validation.setFinalStatusCode(200);
        validation.setValidatedAt(System.currentTimeMillis());
        com.aiburpcopilot.core.discovery.DiscoveryAttempt attempt = new com.aiburpcopilot.core.discovery.DiscoveryAttempt();
        attempt.setSequence(1);
        attempt.setMethod("GET");
        attempt.setStatusCode(200);
        attempt.setSummary("HTTP 200");
        attempt.setSignalMatched(true);
        attempt.setRequestBytes("GET /api/test HTTP/1.1".getBytes());
        attempt.setResponseBytes("HTTP/1.1 200 OK".getBytes());
        validation.setAttempts(List.of(attempt));
        candidate.setValidation(validation);
        return candidate;
    }

    private ReportExportTaskRecord sampleTask() {
        ReportExportTaskRecord task = new ReportExportTaskRecord();
        task.setTaskId("task-1");
        task.setCreatedAt(System.currentTimeMillis());
        task.setUpdatedAt(System.currentTimeMillis());
        task.setHost("example.com");
        task.setItemCount(2);
        task.setOutputPath("C:\\tmp\\report.docx");
        task.setStatus("DONE");
        task.setPercent(100);
        task.setStage("DONE");
        task.setMessage("Report ready");
        task.setCompletedPath("C:\\tmp\\report.docx");
        task.setLogs(List.of("created", "done"));
        return task;
    }
}
