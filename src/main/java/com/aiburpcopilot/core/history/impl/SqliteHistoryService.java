package com.aiburpcopilot.core.history.impl;

import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.discovery.DiscoveryCandidate;
import com.aiburpcopilot.core.context.EndpointActionType;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.HistoryStorageStatus;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.report.ReportExportTaskRecord;
import com.aiburpcopilot.core.verification.model.VerificationResult;
import com.aiburpcopilot.scanner.staticresource.StaticScanResult;
import com.aiburpcopilot.utils.Constants;
import com.aiburpcopilot.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

public class SqliteHistoryService implements IHistoryService {

    private static final Logger log = LoggerFactory.getLogger(SqliteHistoryService.class);
    private static final String DB_NAME = "history.db";
    private static volatile boolean driverRegistered;

    private final Path dbPath;
    private final int maxEntries;

    public SqliteHistoryService() {
        this(null);
    }

    public SqliteHistoryService(AppConfig.StorageConfig storageConfig) {
        this.maxEntries = storageConfig != null && storageConfig.getMaxHistory() > 0
                ? storageConfig.getMaxHistory()
                : Constants.HISTORY_DEFAULT_MAX;
        this.dbPath = resolveDbPath(storageConfig);
        ensureDriverRegistered();
        initDatabase();
    }

    @Override
    public synchronized void add(HistoryEntry entry) {
        upsert(entry);
    }

    @Override
    public synchronized void update(HistoryEntry entry) {
        upsert(entry);
    }

    @Override
    public synchronized List<HistoryEntry> getAll() {
        return query(summarySelect("ORDER BY timestamp DESC", false), ps -> {});
    }

    @Override
    public synchronized List<HistoryEntry> search(String keyword,
                                                  EndpointType endpointType,
                                                  RiskLevel riskLevel,
                                                  AnalysisStatus status,
                                                  int offset,
                                                  int limit) {
        return searchAdvanced(keyword, null, endpointType, riskLevel, status, null, null, offset, limit);
    }

    @Override
    public synchronized List<HistoryEntry> searchAdvanced(String keyword,
                                                          String site,
                                                          EndpointType endpointType,
                                                          RiskLevel riskLevel,
                                                          AnalysisStatus status,
                                                          Long timeFrom,
                                                          Long timeTo,
                                                          int offset,
                                                          int limit) {
        boolean includeStaticDetails = endpointType == EndpointType.STATIC_RESOURCE;
        StringBuilder sql = new StringBuilder(summarySelect("WHERE 1=1", includeStaticDetails));
        List<Object> params = new ArrayList<>();
        appendFilters(sql, params, keyword, site, endpointType, riskLevel, status, timeFrom, timeTo);
        sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);
        return query(sql.toString(), ps -> bindParams(ps, params));
    }

    @Override
    public synchronized HistoryEntry getById(String requestId) {
        List<HistoryEntry> matches = query(
                "SELECT * FROM history_entries WHERE request_id = ? LIMIT 1",
                ps -> ps.setString(1, requestId));
        return matches.isEmpty() ? null : matches.get(0);
    }

    @Override
    public synchronized boolean deleteById(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return false;
        }
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(
                     "DELETE FROM history_entries WHERE request_id = ?")) {
            ps.setString(1, requestId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to delete history entry", e);
        }
    }

    @Override
    public synchronized void clear() {
        execute("DELETE FROM history_entries");
    }

    @Override
    public synchronized int size() {
        return count(null, null, null, null);
    }

    @Override
    public synchronized int count(String keyword,
                                  EndpointType endpointType,
                                  RiskLevel riskLevel,
                                  AnalysisStatus status) {
        return countAdvanced(keyword, null, endpointType, riskLevel, status, null, null);
    }

    @Override
    public synchronized int countAdvanced(String keyword,
                                          String site,
                                          EndpointType endpointType,
                                          RiskLevel riskLevel,
                                          AnalysisStatus status,
                                          Long timeFrom,
                                          Long timeTo) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM history_entries WHERE 1=1");
        List<Object> params = new ArrayList<>();
        appendFilters(sql, params, keyword, site, endpointType, riskLevel, status, timeFrom, timeTo);
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            bindParams(ps, params);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to count history", e);
        }
    }

    @Override
    public synchronized int clearAdvanced(String keyword,
                                          String site,
                                          EndpointType endpointType,
                                          RiskLevel riskLevel,
                                          AnalysisStatus status,
                                          Long timeFrom,
                                          Long timeTo) {
        StringBuilder sql = new StringBuilder("DELETE FROM history_entries WHERE 1=1");
        List<Object> params = new ArrayList<>();
        appendFilters(sql, params, keyword, site, endpointType, riskLevel, status, timeFrom, timeTo);
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            bindParams(ps, params);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to clear filtered history", e);
        }
    }

    @Override
    public HistoryStorageStatus getStorageStatus() {
        return new HistoryStorageStatus(
                HistoryStorageStatus.Mode.SQLITE,
                "SQLite",
                dbPath != null ? dbPath.toAbsolutePath().toString() : null);
    }

    @Override
    public synchronized void saveDiscoveryCandidate(String host, DiscoveryCandidate candidate) {
        if (candidate == null || candidate.getKey() == null || candidate.getKey().isBlank()) {
            return;
        }
        String sql = """
                INSERT INTO discovery_candidates (
                    candidate_key, host, path, url, asset_type, score, method_hint, source_reason,
                    supporting_observation_count, supporting_paths_json, supporting_parameters_json,
                    supporting_methods_json, validation_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(candidate_key) DO UPDATE SET
                    host=excluded.host,
                    path=excluded.path,
                    url=excluded.url,
                    asset_type=excluded.asset_type,
                    score=excluded.score,
                    method_hint=excluded.method_hint,
                    source_reason=excluded.source_reason,
                    supporting_observation_count=excluded.supporting_observation_count,
                    supporting_paths_json=excluded.supporting_paths_json,
                    supporting_parameters_json=excluded.supporting_parameters_json,
                    supporting_methods_json=excluded.supporting_methods_json,
                    validation_json=excluded.validation_json,
                    updated_at=excluded.updated_at
                """;
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            int index = 1;
            ps.setString(index++, candidate.getKey());
            ps.setString(index++, candidate.getHost());
            ps.setString(index++, candidate.getPath());
            ps.setString(index++, candidate.getUrl());
            ps.setString(index++, candidate.getAssetType() != null ? candidate.getAssetType().name() : null);
            ps.setDouble(index++, candidate.getScore());
            ps.setString(index++, candidate.getMethodHint());
            ps.setString(index++, candidate.getSourceReason());
            ps.setInt(index++, candidate.getSupportingObservationCount());
            ps.setString(index++, JsonUtil.toJson(candidate.getSupportingPaths()));
            ps.setString(index++, JsonUtil.toJson(candidate.getSupportingParameters()));
            ps.setString(index++, JsonUtil.toJson(candidate.getSupportingMethods()));
            ps.setString(index++, JsonUtil.toJson(candidate.getValidation()));
            ps.setLong(index++, System.currentTimeMillis());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to persist discovery candidate", e);
        }
    }

    @Override
    public synchronized List<DiscoveryCandidate> listDiscoveryCandidates(String hostFilter) {
        StringBuilder sql = new StringBuilder("""
                SELECT candidate_key, host, path, url, asset_type, score, method_hint, source_reason,
                       supporting_observation_count, supporting_paths_json, supporting_parameters_json,
                       supporting_methods_json, validation_json
                FROM discovery_candidates
                WHERE 1=1
                """);
        List<Object> params = new ArrayList<>();
        if (hostFilter != null && !hostFilter.isBlank() && !"ALL".equalsIgnoreCase(hostFilter)) {
            sql.append(" AND host = ?");
            params.add(hostFilter);
        }
        sql.append(" ORDER BY updated_at DESC, score DESC");
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            bindParams(ps, params);
            try (ResultSet rs = ps.executeQuery()) {
                List<DiscoveryCandidate> rows = new ArrayList<>();
                while (rs.next()) {
                    rows.add(mapDiscoveryCandidate(rs));
                }
                return rows;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query discovery candidates", e);
        }
    }

    @Override
    public synchronized void clearDiscoveryCandidates(String hostFilter) {
        String sql = "DELETE FROM discovery_candidates";
        List<Object> params = new ArrayList<>();
        if (hostFilter != null && !hostFilter.isBlank() && !"ALL".equalsIgnoreCase(hostFilter)) {
            sql += " WHERE host = ?";
            params.add(hostFilter);
        }
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            bindParams(ps, params);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to clear discovery candidates", e);
        }
    }

    @Override
    public synchronized void saveReportExportTask(ReportExportTaskRecord taskRecord) {
        if (taskRecord == null || taskRecord.getTaskId() == null || taskRecord.getTaskId().isBlank()) {
            return;
        }
        String sql = """
                INSERT INTO report_export_tasks (
                    task_id, created_at, updated_at, host, item_count, output_path, status,
                    percent, stage, message, completed_path, error, logs_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    host=excluded.host,
                    item_count=excluded.item_count,
                    output_path=excluded.output_path,
                    status=excluded.status,
                    percent=excluded.percent,
                    stage=excluded.stage,
                    message=excluded.message,
                    completed_path=excluded.completed_path,
                    error=excluded.error,
                    logs_json=excluded.logs_json
                """;
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            int index = 1;
            ps.setString(index++, taskRecord.getTaskId());
            ps.setLong(index++, taskRecord.getCreatedAt());
            ps.setLong(index++, taskRecord.getUpdatedAt());
            ps.setString(index++, taskRecord.getHost());
            ps.setInt(index++, taskRecord.getItemCount());
            ps.setString(index++, taskRecord.getOutputPath());
            ps.setString(index++, taskRecord.getStatus());
            ps.setInt(index++, taskRecord.getPercent());
            ps.setString(index++, taskRecord.getStage());
            ps.setString(index++, taskRecord.getMessage());
            ps.setString(index++, taskRecord.getCompletedPath());
            ps.setString(index++, taskRecord.getError());
            ps.setString(index++, JsonUtil.toJson(taskRecord.getLogs()));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to persist report export task", e);
        }
    }

    @Override
    public synchronized List<ReportExportTaskRecord> listReportExportTasks() {
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement("""
                     SELECT task_id, created_at, updated_at, host, item_count, output_path, status,
                            percent, stage, message, completed_path, error, logs_json
                     FROM report_export_tasks
                     ORDER BY created_at DESC
                     """);
             ResultSet rs = ps.executeQuery()) {
            List<ReportExportTaskRecord> rows = new ArrayList<>();
            while (rs.next()) {
                rows.add(mapReportExportTask(rs));
            }
            return rows;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query report export tasks", e);
        }
    }

    private String summarySelect(String suffix, boolean includeStaticDetails) {
        String staticScanDetailsColumn = includeStaticDetails
                ? "static_scan_details_json"
                : "NULL AS static_scan_details_json";
        return """
                SELECT
                    request_id, timestamp, method, url, path, status_code, content_type,
                    endpoint_type, endpoint_action_type, risk_level, analysis_status, ai_summary,
                    attack_surface_json, possible_vulnerabilities_json, high_value_params_json,
                    recommended_tests_json, parameter_count, response_body_size, ai_call_duration_ms,
                    NULL AS request_body, NULL AS response_body,
                    NULL AS raw_request_b64, NULL AS raw_response_b64,
                    high_value_param_details_json, verification_results_json,
                    """ + staticScanDetailsColumn + """
                FROM history_entries
                """ + suffix;
    }

    private void upsert(HistoryEntry entry) {
        if (entry == null || entry.getRequestId() == null || entry.getRequestId().isBlank()) {
            return;
        }
        String sql = """
                INSERT INTO history_entries (
                    request_id, timestamp, method, url, path, status_code, content_type,
                    endpoint_type, endpoint_action_type, risk_level, analysis_status, ai_summary,
                    attack_surface_json, possible_vulnerabilities_json, high_value_params_json,
                    recommended_tests_json, parameter_count, response_body_size, ai_call_duration_ms,
                    request_body, response_body, raw_request_b64, raw_response_b64,
                    high_value_param_details_json, verification_results_json, static_scan_details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    timestamp=excluded.timestamp,
                    method=excluded.method,
                    url=excluded.url,
                    path=excluded.path,
                    status_code=excluded.status_code,
                    content_type=excluded.content_type,
                    endpoint_type=excluded.endpoint_type,
                    endpoint_action_type=excluded.endpoint_action_type,
                    risk_level=excluded.risk_level,
                    analysis_status=excluded.analysis_status,
                    ai_summary=excluded.ai_summary,
                    attack_surface_json=excluded.attack_surface_json,
                    possible_vulnerabilities_json=excluded.possible_vulnerabilities_json,
                    high_value_params_json=excluded.high_value_params_json,
                    recommended_tests_json=excluded.recommended_tests_json,
                    parameter_count=excluded.parameter_count,
                    response_body_size=excluded.response_body_size,
                    ai_call_duration_ms=excluded.ai_call_duration_ms,
                    request_body=excluded.request_body,
                    response_body=excluded.response_body,
                    raw_request_b64=excluded.raw_request_b64,
                    raw_response_b64=excluded.raw_response_b64,
                    high_value_param_details_json=excluded.high_value_param_details_json,
                    verification_results_json=excluded.verification_results_json,
                    static_scan_details_json=CASE
                        WHEN excluded.static_scan_details_json IS NULL
                             OR excluded.static_scan_details_json = ''
                             OR excluded.static_scan_details_json = 'null'
                             OR excluded.static_scan_details_json = '{}'
                        THEN history_entries.static_scan_details_json
                        ELSE excluded.static_scan_details_json
                    END
                """;
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            int index = 1;
            ps.setString(index++, entry.getRequestId());
            ps.setLong(index++, entry.getTimestamp());
            ps.setString(index++, entry.getMethod());
            ps.setString(index++, entry.getUrl());
            ps.setString(index++, entry.getPath());
            ps.setInt(index++, entry.getStatusCode());
            ps.setString(index++, entry.getContentType());
            ps.setString(index++, enumName(entry.getEndpointType()));
            ps.setString(index++, enumName(entry.getEndpointActionType()));
            ps.setString(index++, enumName(entry.getRiskLevel()));
            ps.setString(index++, enumName(entry.getAnalysisStatus()));
            ps.setString(index++, entry.getAiSummary());
            ps.setString(index++, JsonUtil.toJson(entry.getAttackSurface()));
            ps.setString(index++, JsonUtil.toJson(entry.getPossibleVulnerabilities()));
            ps.setString(index++, JsonUtil.toJson(entry.getHighValueParams()));
            ps.setString(index++, JsonUtil.toJson(entry.getRecommendedTests()));
            ps.setInt(index++, entry.getParameterCount());
            ps.setInt(index++, entry.getResponseBodySize());
            ps.setLong(index++, entry.getAiCallDurationMs());
            ps.setString(index++, entry.getRequestBody());
            ps.setString(index++, entry.getResponseBody());
            ps.setString(index++, toBase64(entry.getRawRequest()));
            ps.setString(index++, toBase64(entry.getRawResponse()));
            ps.setString(index++, JsonUtil.toJson(entry.getHighValueParamDetails()));
            ps.setString(index++, JsonUtil.toJson(entry.getVerificationResults()));
            ps.setString(index++, staticScanDetailsJson(entry.getStaticScanDetails()));
            ps.executeUpdate();
            trimOverflow(connection);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to persist history entry", e);
        }
    }

    private String staticScanDetailsJson(StaticScanResult details) {
        if (details == null) {
            return null;
        }
        String json = JsonUtil.toJson(details);
        return json != null && !json.isBlank() && !"{}".equals(json) && !"null".equalsIgnoreCase(json)
                ? json
                : null;
    }

    private List<HistoryEntry> query(String sql, SqlConsumer<PreparedStatement> binder) {
        try (Connection connection = openConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            binder.accept(ps);
            try (ResultSet rs = ps.executeQuery()) {
                List<HistoryEntry> entries = new ArrayList<>();
                while (rs.next()) {
                    entries.add(mapRow(rs));
                }
                return entries;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query history", e);
        }
    }

    private HistoryEntry mapRow(ResultSet rs) throws SQLException {
        HistoryEntry entry = new HistoryEntry();
        entry.setRequestId(rs.getString("request_id"));
        entry.setTimestamp(rs.getLong("timestamp"));
        entry.setMethod(rs.getString("method"));
        entry.setUrl(rs.getString("url"));
        entry.setPath(rs.getString("path"));
        entry.setStatusCode(rs.getInt("status_code"));
        entry.setContentType(rs.getString("content_type"));
        entry.setEndpointType(enumValue(EndpointType.class, rs.getString("endpoint_type"), EndpointType.UNKNOWN));
        entry.setEndpointActionType(enumValue(EndpointActionType.class, rs.getString("endpoint_action_type"), EndpointActionType.UNKNOWN));
        entry.setRiskLevel(enumValue(RiskLevel.class, rs.getString("risk_level"), RiskLevel.INFO));
        entry.setAnalysisStatus(enumValue(AnalysisStatus.class, rs.getString("analysis_status"), AnalysisStatus.PENDING));
        entry.setAiSummary(rs.getString("ai_summary"));
        entry.setAttackSurface(readList(rs.getString("attack_surface_json")));
        entry.setPossibleVulnerabilities(readList(rs.getString("possible_vulnerabilities_json")));
        entry.setHighValueParams(readList(rs.getString("high_value_params_json")));
        entry.setRecommendedTests(readList(rs.getString("recommended_tests_json")));
        entry.setParameterCount(rs.getInt("parameter_count"));
        entry.setResponseBodySize(rs.getInt("response_body_size"));
        entry.setAiCallDurationMs(rs.getLong("ai_call_duration_ms"));
        entry.setRequestBody(rs.getString("request_body"));
        entry.setResponseBody(rs.getString("response_body"));
        entry.setRawRequest(fromBase64(rs.getString("raw_request_b64")));
        entry.setRawResponse(fromBase64(rs.getString("raw_response_b64")));
        entry.setHighValueParamDetails(readHighValueParams(rs.getString("high_value_param_details_json")));
        entry.setVerificationResults(readVerificationResults(rs.getString("verification_results_json")));
        entry.setStaticScanDetails(readStaticScanResult(rs.getString("static_scan_details_json")));
        return entry;
    }

    private void appendFilters(StringBuilder sql,
                               List<Object> params,
                               String keyword,
                               String site,
                               EndpointType endpointType,
                               RiskLevel riskLevel,
                               AnalysisStatus status,
                               Long timeFrom,
                               Long timeTo) {
        if (keyword != null && !keyword.isBlank()) {
            sql.append(" AND (LOWER(url) LIKE ? OR LOWER(path) LIKE ? OR LOWER(method) LIKE ? OR LOWER(COALESCE(ai_summary,'')) LIKE ?)");
            String like = "%" + keyword.toLowerCase() + "%";
            params.add(like);
            params.add(like);
            params.add(like);
            params.add(like);
        }
        if (site != null && !site.isBlank()) {
            sql.append(" AND LOWER(COALESCE(url,'')) LIKE ?");
            params.add("%" + site.toLowerCase() + "%");
        }
        if (endpointType != null) {
            sql.append(" AND endpoint_type = ?");
            params.add(endpointType.name());
        }
        if (riskLevel != null) {
            sql.append(" AND risk_level = ?");
            params.add(riskLevel.name());
        }
        if (status != null) {
            sql.append(" AND analysis_status = ?");
            params.add(status.name());
        }
        if (timeFrom != null) {
            sql.append(" AND timestamp >= ?");
            params.add(timeFrom);
        }
        if (timeTo != null) {
            sql.append(" AND timestamp <= ?");
            params.add(timeTo);
        }
    }

    private void bindParams(PreparedStatement ps, List<Object> params) throws SQLException {
        for (int i = 0; i < params.size(); i++) {
            ps.setObject(i + 1, params.get(i));
        }
    }

    private void trimOverflow(Connection connection) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement("""
                DELETE FROM history_entries
                WHERE request_id IN (
                    SELECT request_id FROM history_entries
                    ORDER BY timestamp DESC
                    LIMIT -1 OFFSET ?
                )
                """)) {
            ps.setInt(1, maxEntries);
            ps.executeUpdate();
        }
    }

    private void initDatabase() {
        try {
            Files.createDirectories(dbPath.getParent());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create history db directory", e);
        }
        execute("""
                CREATE TABLE IF NOT EXISTS history_entries (
                    request_id TEXT PRIMARY KEY,
                    timestamp INTEGER NOT NULL,
                    method TEXT,
                    url TEXT,
                    path TEXT,
                    status_code INTEGER,
                    content_type TEXT,
                    endpoint_type TEXT,
                    endpoint_action_type TEXT,
                    risk_level TEXT,
                    analysis_status TEXT,
                    ai_summary TEXT,
                    attack_surface_json TEXT,
                    possible_vulnerabilities_json TEXT,
                    high_value_params_json TEXT,
                    recommended_tests_json TEXT,
                    parameter_count INTEGER,
                    response_body_size INTEGER,
                    ai_call_duration_ms INTEGER,
                    request_body TEXT,
                    response_body TEXT,
                    raw_request_b64 TEXT,
                    raw_response_b64 TEXT,
                    high_value_param_details_json TEXT,
                    verification_results_json TEXT,
                    static_scan_details_json TEXT
                )
                """);
        execute("CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history_entries(timestamp DESC)");
        execute("CREATE INDEX IF NOT EXISTS idx_history_url ON history_entries(url)");
        execute("CREATE INDEX IF NOT EXISTS idx_history_path ON history_entries(path)");
        execute("""
                CREATE TABLE IF NOT EXISTS discovery_candidates (
                    candidate_key TEXT PRIMARY KEY,
                    host TEXT,
                    path TEXT,
                    url TEXT,
                    asset_type TEXT,
                    score REAL,
                    method_hint TEXT,
                    source_reason TEXT,
                    supporting_observation_count INTEGER,
                    supporting_paths_json TEXT,
                    supporting_parameters_json TEXT,
                    supporting_methods_json TEXT,
                    validation_json TEXT,
                    updated_at INTEGER
                )
                """);
        execute("CREATE INDEX IF NOT EXISTS idx_discovery_candidates_host ON discovery_candidates(host)");
        execute("CREATE INDEX IF NOT EXISTS idx_discovery_candidates_updated ON discovery_candidates(updated_at DESC)");
        execute("""
                CREATE TABLE IF NOT EXISTS report_export_tasks (
                    task_id TEXT PRIMARY KEY,
                    created_at INTEGER,
                    updated_at INTEGER,
                    host TEXT,
                    item_count INTEGER,
                    output_path TEXT,
                    status TEXT,
                    percent INTEGER,
                    stage TEXT,
                    message TEXT,
                    completed_path TEXT,
                    error TEXT,
                    logs_json TEXT
                )
                """);
        execute("CREATE INDEX IF NOT EXISTS idx_report_export_tasks_created ON report_export_tasks(created_at DESC)");
        log.info("SQLite history initialized at {}", dbPath);
    }

    private void execute(String sql) {
        try (Connection connection = openConnection();
             Statement statement = connection.createStatement()) {
            statement.execute(sql);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to execute history SQL", e);
        }
    }

    private Connection openConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + dbPath.toAbsolutePath());
    }

    private void ensureDriverRegistered() {
        if (driverRegistered) {
            return;
        }
        synchronized (SqliteHistoryService.class) {
            if (driverRegistered) {
                return;
            }
            try {
                Class<?> driverClass = Class.forName("org.sqlite.JDBC");
                Driver driver = (Driver) driverClass.getDeclaredConstructor().newInstance();
                DriverManager.registerDriver(new DriverShim(driver));
                driverRegistered = true;
                log.info("SQLite JDBC driver registered explicitly");
            } catch (Exception e) {
                throw new IllegalStateException("Failed to register SQLite JDBC driver", e);
            }
        }
    }

    private Path resolveDbPath(AppConfig.StorageConfig storageConfig) {
        if (storageConfig != null && storageConfig.getHistoryDbPath() != null
                && !storageConfig.getHistoryDbPath().isBlank()) {
            return Path.of(storageConfig.getHistoryDbPath().trim()).toAbsolutePath().normalize();
        }
        Path home = ExternalResourcePaths.homeDirOrNull();
        if (home == null) {
            home = Path.of(System.getProperty("user.dir"), Constants.CONFIG_TEMPLATE_DIR_NAME);
        }
        return home.resolve("data").resolve(DB_NAME);
    }

    private String enumName(Enum<?> value) {
        return value != null ? value.name() : null;
    }

    private <E extends Enum<E>> E enumValue(Class<E> enumClass, String value, E fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Enum.valueOf(enumClass, value);
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private String toBase64(byte[] data) {
        return data != null && data.length > 0 ? Base64.getEncoder().encodeToString(data) : null;
    }

    private byte[] fromBase64(String value) {
        return value != null && !value.isBlank() ? Base64.getDecoder().decode(value) : null;
    }

    @SuppressWarnings("unchecked")
    private List<String> readList(String json) {
        List<?> parsed = JsonUtil.fromJsonSafe(json != null ? json : "[]", List.class);
        List<String> values = new ArrayList<>();
        if (parsed != null) {
            for (Object item : parsed) {
                values.add(item != null ? String.valueOf(item) : null);
            }
        }
        return values;
    }

    private List<AnalysisResult.HighValueParam> readHighValueParams(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        AnalysisResult.HighValueParam[] items = JsonUtil.fromJsonSafe(json, AnalysisResult.HighValueParam[].class);
        return items != null ? List.of(items) : List.of();
    }

    private List<VerificationResult> readVerificationResults(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        VerificationResult[] items = JsonUtil.fromJsonSafe(json, VerificationResult[].class);
        return items != null ? List.of(items) : List.of();
    }

    private StaticScanResult readStaticScanResult(String json) {
        return json != null && !json.isBlank() ? JsonUtil.fromJsonSafe(json, StaticScanResult.class) : null;
    }

    private DiscoveryCandidate mapDiscoveryCandidate(ResultSet rs) throws SQLException {
        DiscoveryCandidate candidate = new DiscoveryCandidate();
        candidate.setKey(rs.getString("candidate_key"));
        candidate.setHost(rs.getString("host"));
        candidate.setPath(rs.getString("path"));
        candidate.setUrl(rs.getString("url"));
        String assetType = rs.getString("asset_type");
        if (assetType != null && !assetType.isBlank()) {
            try {
                candidate.setAssetType(com.aiburpcopilot.core.discovery.DiscoveryAssetType.valueOf(assetType));
            } catch (Exception ignored) {
            }
        }
        candidate.setScore(rs.getDouble("score"));
        candidate.setMethodHint(rs.getString("method_hint"));
        candidate.setSourceReason(rs.getString("source_reason"));
        candidate.setSupportingObservationCount(rs.getInt("supporting_observation_count"));
        candidate.setSupportingPaths(readList(rs.getString("supporting_paths_json")));
        candidate.setSupportingParameters(readList(rs.getString("supporting_parameters_json")));
        candidate.setSupportingMethods(readList(rs.getString("supporting_methods_json")));
        var validation = JsonUtil.fromJsonSafe(rs.getString("validation_json"),
                com.aiburpcopilot.core.discovery.DiscoveryValidation.class);
        candidate.setValidation(validation);
        return candidate;
    }

    private ReportExportTaskRecord mapReportExportTask(ResultSet rs) throws SQLException {
        ReportExportTaskRecord task = new ReportExportTaskRecord();
        task.setTaskId(rs.getString("task_id"));
        task.setCreatedAt(rs.getLong("created_at"));
        task.setUpdatedAt(rs.getLong("updated_at"));
        task.setHost(rs.getString("host"));
        task.setItemCount(rs.getInt("item_count"));
        task.setOutputPath(rs.getString("output_path"));
        task.setStatus(rs.getString("status"));
        task.setPercent(rs.getInt("percent"));
        task.setStage(rs.getString("stage"));
        task.setMessage(rs.getString("message"));
        task.setCompletedPath(rs.getString("completed_path"));
        task.setError(rs.getString("error"));
        task.setLogs(readList(rs.getString("logs_json")));
        return task;
    }

    @FunctionalInterface
    private interface SqlConsumer<T> {
        void accept(T value) throws SQLException;
    }

    private static final class DriverShim implements Driver {
        private final Driver delegate;

        private DriverShim(Driver delegate) {
            this.delegate = delegate;
        }

        @Override
        public Connection connect(String url, Properties info) throws SQLException {
            return delegate.connect(url, info);
        }

        @Override
        public boolean acceptsURL(String url) throws SQLException {
            return delegate.acceptsURL(url);
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
            return delegate.getPropertyInfo(url, info);
        }

        @Override
        public int getMajorVersion() {
            return delegate.getMajorVersion();
        }

        @Override
        public int getMinorVersion() {
            return delegate.getMinorVersion();
        }

        @Override
        public boolean jdbcCompliant() {
            return delegate.jdbcCompliant();
        }

        @Override
        public java.util.logging.Logger getParentLogger() throws SQLFeatureNotSupportedException {
            return delegate.getParentLogger();
        }
    }
}
