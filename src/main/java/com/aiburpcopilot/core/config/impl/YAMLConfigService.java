package com.aiburpcopilot.core.config.impl;

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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class YAMLConfigService implements IConfigService {

    private static final Logger log = LoggerFactory.getLogger(YAMLConfigService.class);

    private Path configDir;
    private Path configFile;
    private final List<ConfigChangeListener> listeners = new ArrayList<>();

    private volatile AppConfig currentConfig;

    public YAMLConfigService() {
        Path homeDir = ExternalResourcePaths.homeDirOrNull();
        this.configDir = homeDir;
        this.configFile = homeDir != null ? homeDir.resolve("application.yml") : null;
    }

    @Override
    public synchronized void reloadFrom(Path configDirectory) {
        ExternalResourcePaths.setManualConfigFile(configDirectory);
        this.configDir = ExternalResourcePaths.homeDir();
        this.configFile = ExternalResourcePaths.configFile();
        reload();
    }

    @Override
    public Path getConfigFilePath() {
        return configFile;
    }

    @Override
    public synchronized void reload() {
        try {
            if (configFile == null) {
                throw new IllegalStateException("Config directory is not configured");
            }
            ExternalResourcePaths.initialize();
            if (!Files.exists(configFile) || Files.size(configFile) <= 0) {
                throw new FileNotFoundException("application.yml not found: " + configFile.toAbsolutePath());
            }

            String content = Files.readString(configFile, StandardCharsets.UTF_8);
            Yaml yaml = new Yaml();
            Object loaded = yaml.loadAs(content, AppConfig.class);
            if (!(loaded instanceof AppConfig parsedConfig)) {
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
            throw new IllegalStateException("Unable to load application.yml from configured directory", e);
        }
    }

    @Override
    public synchronized void save() {
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
        try {
            if (configDir == null || configFile == null) {
                throw new IllegalStateException("Config directory is not configured");
            }
            Files.createDirectories(configDir);
            String json = JsonUtil.toPrettyJson(currentConfig);
            Yaml yaml = new Yaml();
            Object jsonObject = new Yaml().load(json);
            String yamlOutput = yaml.dumpAsMap(jsonObject);
            Files.writeString(configFile, yamlOutput, StandardCharsets.UTF_8);
            log.debug("Configuration saved to: {}", configFile.toAbsolutePath());
        } catch (Exception e) {
            log.error("Failed to save configuration", e);
            throw new IllegalStateException("Unable to save application.yml to configured directory", e);
        }
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
}
