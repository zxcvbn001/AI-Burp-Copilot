package com.aiburpcopilot.core.history;

public class HistoryStorageStatus {

    public enum Mode {
        SQLITE,
        IN_MEMORY
    }

    private final Mode mode;
    private final String description;
    private final String databasePath;

    public HistoryStorageStatus(Mode mode, String description, String databasePath) {
        this.mode = mode;
        this.description = description;
        this.databasePath = databasePath;
    }

    public Mode getMode() {
        return mode;
    }

    public String getDescription() {
        return description;
    }

    public String getDatabasePath() {
        return databasePath;
    }
}
