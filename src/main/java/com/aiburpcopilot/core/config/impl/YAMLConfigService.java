package com.aiburpcopilot.core.config.impl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.utils.JsonUtil;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class YAMLConfigService implements IConfigService {

    private static final Logger log = LoggerFactory.getLogger(YAMLConfigService.class);
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory())
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private Path configDir;
    private Path configFile;
    private final List<ConfigChangeListener> listeners = new ArrayList<>();

    private volatile AppConfig currentConfig;

    public YAMLConfigService() {
        refreshConfigLocation();
    }

    @Override
    public synchronized void reloadFrom(Path configDirectory) {
        String validationError = ExternalResourcePaths.validateConfigDirectory(configDirectory);
        if (validationError != null) {
            throw new IllegalStateException(validationError);
        }
        ExternalResourcePaths.setManualConfigFile(configDirectory);
        this.configDir = ExternalResourcePaths.homeDir();
        this.configFile = ExternalResourcePaths.configFile();
        reload();
    }

    @Override
    public Path getConfigFilePath() {
        if (configFile == null) {
            refreshConfigLocation();
        }
        return configFile;
    }

    @Override
    public synchronized void reload() {
        try {
            refreshConfigLocation();
            if (configFile == null) {
                throw new IllegalStateException("Config directory is not configured");
            }
            ExternalResourcePaths.initialize();
            if (!Files.exists(configFile) || Files.size(configFile) <= 0) {
                throw new FileNotFoundException("application.yml not found: " + configFile.toAbsolutePath());
            }

            String content = Files.readString(configFile, StandardCharsets.UTF_8);
            AppConfig parsedConfig = YAML_MAPPER.readValue(content, AppConfig.class);
            if (parsedConfig == null) {
                throw new IllegalStateException("Failed to parse config: " + configFile.toAbsolutePath());
            }

            currentConfig = parsedConfig;
            log.info("Configuration loaded from: {}", configFile.toAbsolutePath());
            PluginLogger.getInstance().info(
                    PluginLogger.Category.SYSTEM,
                    "Config",
                    "Loaded application.yml from: " + configFile.toAbsolutePath());
            notifyListeners();
        } catch (Exception e) {
            log.error("Failed to load configuration from {}", configFile, e);
            String rootMessage = rootCauseMessage(e);
            throw new IllegalStateException("Unable to load application.yml from configured directory"
                    + (rootMessage != null && !rootMessage.isBlank() ? ": " + rootMessage : ""), e);
        }
    }

    @Override
    public synchronized void save() {
        ensureConfigLocation();
        saveInternal();
        notifyListeners();
    }

    @Override
    public AppConfig getConfig() {
        if (currentConfig == null) {
            reload();
        }
        return currentConfig;
    }

    @Override
    public void updateConfig(AppConfig config) {
        this.currentConfig = config;
    }

    @Override
    public void addChangeListener(ConfigChangeListener listener) {
        listeners.add(listener);
    }

    private void saveInternal() {
        Path tempFile = null;
        try {
            ensureConfigLocation();
            if (configDir == null || configFile == null) {
                throw new IllegalStateException("Config directory is not configured");
            }
            if (currentConfig == null) {
                throw new IllegalStateException("Current config is null");
            }
            Files.createDirectories(configDir);
            Yaml yaml = new Yaml();
            Map<String, Object> existingMap = readExistingYamlMap(yaml);
            Map<String, Object> updatedMap = toConfigMap();
            if (updatedMap.isEmpty()) {
                throw new IllegalStateException("Current config serialized to an empty map");
            }
            Map<String, Object> merged = mergeMaps(existingMap, updatedMap);
            String yamlOutput = yaml.dumpAsMap(merged);
            if (yamlOutput == null || yamlOutput.isBlank()) {
                throw new IllegalStateException("Generated YAML content is empty");
            }
            tempFile = Files.createTempFile(configDir, "application-", ".yml.tmp");
            Files.writeString(
                    tempFile,
                    yamlOutput,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING);
            if (!Files.exists(tempFile) || Files.size(tempFile) <= 0) {
                throw new IllegalStateException("Temporary config file was written as empty");
            }
            moveTempFileAtomically(tempFile, configFile);
            log.debug("Configuration saved to: {}", configFile.toAbsolutePath());
        } catch (Exception e) {
            log.error("Failed to save configuration", e);
            throw new IllegalStateException("Unable to save application.yml to configured directory", e);
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (Exception ignored) {
                }
            }
        }
    }

    private void moveTempFileAtomically(Path tempFile, Path targetFile) throws java.io.IOException {
        try {
            Files.move(
                    tempFile,
                    targetFile,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(tempFile, targetFile, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void ensureConfigLocation() {
        if (configDir == null || configFile == null) {
            refreshConfigLocation();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readExistingYamlMap(Yaml yaml) {
        if (configFile == null || !Files.exists(configFile)) {
            return new LinkedHashMap<>();
        }
        try {
            String existingContent = Files.readString(configFile, StandardCharsets.UTF_8);
            Object loaded = yaml.load(existingContent);
            if (loaded instanceof Map<?, ?> map) {
                Map<String, Object> result = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    result.put(String.valueOf(entry.getKey()), entry.getValue());
                }
                return result;
            }
        } catch (Exception e) {
            log.warn("Failed to parse existing YAML as map, falling back to config-only save: {}", e.getMessage());
        }
        return new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> toConfigMap() {
        Object converted = JsonUtil.getMapper().convertValue(currentConfig, LinkedHashMap.class);
        if (converted instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                result.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            return result;
        }
        return new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mergeMaps(Map<String, Object> existing, Map<String, Object> updated) {
        Map<String, Object> merged = new LinkedHashMap<>();
        if (existing != null) {
            for (Map.Entry<String, Object> entry : existing.entrySet()) {
                String key = entry.getKey();
                if (updated != null && updated.containsKey(key)) {
                    merged.put(key, mergeValue(entry.getValue(), updated.get(key)));
                } else {
                    merged.put(key, entry.getValue());
                }
            }
        }
        if (updated != null) {
            for (Map.Entry<String, Object> entry : updated.entrySet()) {
                if (!merged.containsKey(entry.getKey())) {
                    merged.put(entry.getKey(), entry.getValue());
                }
            }
        }
        return merged;
    }

    @SuppressWarnings("unchecked")
    private Object mergeValue(Object existingValue, Object updatedValue) {
        if (existingValue instanceof Map<?, ?> existingMap && updatedValue instanceof Map<?, ?> updatedMap) {
            Map<String, Object> existing = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : existingMap.entrySet()) {
                existing.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            Map<String, Object> updated = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : updatedMap.entrySet()) {
                updated.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            return mergeMaps(existing, updated);
        }
        return updatedValue;
    }

    private void notifyListeners() {
        AppConfig config = currentConfig;
        for (ConfigChangeListener listener : listeners) {
            try {
                listener.onConfigChanged(config);
            } catch (Exception e) {
                log.warn("Config change listener error", e);
            }
        }
    }

    private void refreshConfigLocation() {
        Path homeDir = ExternalResourcePaths.homeDirOrNull();
        this.configDir = homeDir;
        this.configFile = homeDir != null ? homeDir.resolve("application.yml") : null;
    }

    private String rootCauseMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current != null && current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        if (current == null) {
            return null;
        }
        String message = current.getMessage();
        if (message == null || message.isBlank()) {
            return current.getClass().getSimpleName();
        }
        if (message.contains("rateLimitPerSecond")) {
            return current.getClass().getSimpleName()
                    + ": " + message
                    + " | Please rename 'ai.rateLimitPerSecond' to 'ai.rateLimitPerMinute' in the active application.yml";
        }
        return current.getClass().getSimpleName() + ": " + message;
    }
}
