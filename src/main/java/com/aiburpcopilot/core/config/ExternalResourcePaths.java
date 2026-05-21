package com.aiburpcopilot.core.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.aiburpcopilot.utils.Constants;

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

    public static String validateConfigDirectory(Path directoryOrFile) {
        if (directoryOrFile == null) {
            return "Config directory is null";
        }
        try {
            Path normalized = directoryOrFile.toAbsolutePath().normalize();
            Path path = Files.isDirectory(normalized) ? normalized : normalized.getParent();
            if (path == null) {
                return "Config directory parent cannot be resolved";
            }
            if (!Files.exists(path)) {
                return "Directory does not exist: " + path;
            }
            if (!Files.isDirectory(path)) {
                return "Path is not a directory: " + path;
            }
            Path configFile = path.resolve(Constants.CONFIG_FILE_NAME);
            Path promptsDir = path.resolve("prompts");
            Path rulesDir = path.resolve("rules");
            if (!Files.exists(configFile) || !Files.isRegularFile(configFile)) {
                return "Missing application.yml: " + configFile;
            }
            if (!Files.exists(promptsDir) || !Files.isDirectory(promptsDir)) {
                return "Missing prompts directory: " + promptsDir;
            }
            if (!Files.exists(rulesDir) || !Files.isDirectory(rulesDir)) {
                return "Missing rules directory: " + rulesDir;
            }
            return null;
        } catch (Exception e) {
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    private static Path resolveHomeDir() {
        if (manualHomeDir != null) {
            Path validatedManual = configuredPath(manualHomeDir.toString());
            if (validatedManual != null) {
                manualHomeDir = validatedManual;
                return validatedManual;
            }
            manualHomeDir = null;
        }
        Path systemPropertyPath = configuredPath(System.getProperty("aiburpcopilot.home"));
        if (systemPropertyPath != null) {
            manualHomeDir = systemPropertyPath;
            return systemPropertyPath;
        }
        Path envPath = configuredPath(System.getenv("AI_BURP_COPILOT_HOME"));
        if (envPath != null) {
            manualHomeDir = envPath;
            return envPath;
        }
        String stored = ConfigDirectoryStore.load();
        if (stored != null && !stored.isBlank()) {
            Path storedPath = configuredPath(stored);
            if (storedPath != null) {
                manualHomeDir = storedPath;
                return storedPath;
            }
            ConfigDirectoryStore.save("");
        }
        Path cwdPath = configuredPath(Paths.get("").toAbsolutePath().normalize().resolve(Constants.CONFIG_DIR_NAME).toString());
        if (cwdPath != null) {
            manualHomeDir = cwdPath;
            return cwdPath;
        }
        Path templatePath = configuredPath(Paths.get("").toAbsolutePath().normalize().resolve(Constants.CONFIG_TEMPLATE_DIR_NAME).toString());
        if (templatePath != null) {
            manualHomeDir = templatePath;
            return templatePath;
        }
        return null;
    }

    private static Path configuredPath(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return null;
        }
        try {
            Path path = Paths.get(rawPath.trim()).toAbsolutePath().normalize();
            if (validateConfigDirectory(path) != null) {
                return null;
            }
            return path;
        } catch (Exception ignored) {
            return null;
        }
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
