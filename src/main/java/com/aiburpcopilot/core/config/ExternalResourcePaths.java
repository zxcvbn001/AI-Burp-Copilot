package com.aiburpcopilot.core.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public final class ExternalResourcePaths {

    private static final Logger log = LoggerFactory.getLogger(ExternalResourcePaths.class);

    private static volatile Path manualHomeDir;

    private ExternalResourcePaths() {}

    public static Path homeDir() {
        Path resolved = resolveHomeDir();
        if (resolved == null) {
            throw new IllegalStateException(
                    "Config directory is not configured. Please select a config directory first.");
        }
        return resolved;
    }

    public static Path homeDirOrNull() {
        return resolveHomeDir();
    }

    private static Path resolveHomeDir() {
        if (manualHomeDir != null) {
            return manualHomeDir;
        }
        String stored = ConfigDirectoryStore.load();
        if (stored == null || stored.isBlank()) {
            return null;
        }
        Path path = Paths.get(stored.trim()).toAbsolutePath().normalize();
        manualHomeDir = path;
        return path;
    }

    public static synchronized void setManualHomeDir(Path homeDir) {
        manualHomeDir = homeDir != null ? homeDir.toAbsolutePath().normalize() : null;
        ConfigDirectoryStore.save(manualHomeDir != null ? manualHomeDir.toString() : "");
    }

    public static synchronized void setManualConfigFile(Path configDirectoryOrFile) {
        if (configDirectoryOrFile == null) {
            setManualHomeDir(null);
            return;
        }
        Path normalized = configDirectoryOrFile.toAbsolutePath().normalize();
        if (Files.isDirectory(normalized)) {
            setManualHomeDir(normalized);
            return;
        }
        Path parent = normalized.getParent();
        setManualHomeDir(parent != null ? parent : normalized);
    }

    public static Path configFile() {
        return homeDir().resolve("application.yml");
    }

    public static Path promptsDir() {
        return homeDir().resolve("prompts");
    }

    public static Path rulesDir() {
        return homeDir().resolve("rules");
    }

    public static Path staticRulesFile() {
        return rulesDir().resolve("static-resource-rules.yaml");
    }

    public static Path payloadRulesDir() {
        return rulesDir().resolve("payloads");
    }

    public static synchronized List<Path> initialize() {
        List<Path> created = new ArrayList<>();
        Path home = resolveHomeDir();
        if (home == null) {
            log.info("Config directory not set yet; skipping external resource initialization");
            return created;
        }
        try {
            Files.createDirectories(home);
            Files.createDirectories(promptsDir());
            Files.createDirectories(rulesDir());
            Files.createDirectories(payloadRulesDir());
        } catch (Exception e) {
            log.error("Failed to initialize configured resource directory {}", home, e);
        }
        return created;
    }
}
