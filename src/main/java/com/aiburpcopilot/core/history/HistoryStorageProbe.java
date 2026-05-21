package com.aiburpcopilot.core.history;

import org.sqlite.JDBC;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public final class HistoryStorageProbe {

    private HistoryStorageProbe() {
    }

    public static ProbeResult testSqlite(Path dbPath) {
        if (dbPath == null) {
            return new ProbeResult(false, "Database path is null");
        }
        try {
            Path parent = dbPath.toAbsolutePath().normalize().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            DriverManager.registerDriver(new JDBC());
            String jdbcUrl = "jdbc:sqlite:" + dbPath.toAbsolutePath().normalize();
            try (Connection connection = DriverManager.getConnection(jdbcUrl);
                 Statement statement = connection.createStatement()) {
                statement.execute("SELECT 1");
            }
            return new ProbeResult(true, "SQLite connection OK: " + dbPath.toAbsolutePath().normalize());
        } catch (Exception e) {
            return new ProbeResult(false, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    public record ProbeResult(boolean success, String message) {
    }
}
