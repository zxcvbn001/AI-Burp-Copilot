package com.aiburpcopilot.core.config.impl;

import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.utils.JsonUtil;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

/**
 * YAML 文件配置服务实现。
 * <p>
 * 从用户主目录下的 .ai-burp-copilot/application.yml 加载配置。
 * 支持热更新：UI 修改配置后调用 save() 立即生效。
 * <p>
 * 配置加载优先级：
 * <ol>
 *   <li>外部文件（用户主目录下的配置）</li>
 *   <li>内置默认配置（打包在 resources/config/ 中）</li>
 * </ol>
 */
public class YAMLConfigService implements IConfigService {

    private static final Logger log = LoggerFactory.getLogger(YAMLConfigService.class);

    private Path configDir;
    private Path configFile;
    private final List<ConfigChangeListener> listeners = new ArrayList<>();

    private volatile AppConfig currentConfig;

    public YAMLConfigService() {
        this.configDir = ExternalResourcePaths.homeDir();
        this.configFile = ExternalResourcePaths.configFile();
    }

    @Override
    public synchronized void reloadFrom(Path configFile) {
        ExternalResourcePaths.setManualConfigFile(configFile);
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
            // 确保目录存在
            ExternalResourcePaths.initialize();

            // 尝试加载外部配置文件
            if (Files.exists(configFile) && Files.size(configFile) > 0) {
                String content = Files.readString(configFile, StandardCharsets.UTF_8);
                Yaml yaml = new Yaml();
                Object loaded = yaml.loadAs(content, AppConfig.class);
                if (loaded instanceof AppConfig) {
                    currentConfig = (AppConfig) loaded;
                    log.info("Configuration loaded from: {}", configFile.toAbsolutePath());
                    PluginLogger.getInstance().info("Config",
                            "Loaded application.yml from: " + configFile.toAbsolutePath());
                } else {
                    currentConfig = createDefaultConfig();
                    log.warn("Failed to parse config, using defaults");
                }
            } else {
                // 首次运行：创建默认配置并写入
                currentConfig = createDefaultConfig();
                saveInternal();
                log.info("Created default configuration at: {}", configFile.toAbsolutePath());
            }

            // 确保 prompts、rules 等子目录存在，并从 classpath 复制默认文件
            notifyListeners();
        } catch (Exception e) {
            log.error("Failed to load configuration, using defaults", e);
            currentConfig = createDefaultConfig();
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

    // ---------- Private Helpers ----------

    /**
     * 确保外部资源目录存在，并从 classpath 复制默认文件。
     * 仅当外部文件不存在时才复制，不覆盖已有文件。
     */
    private void saveInternal() {
        try {
            Files.createDirectories(configDir);
            // 使用 Jackson 输出 YAML（通过 Json -> YAML 转换）
            String json = JsonUtil.toPrettyJson(currentConfig);
            Yaml yaml = new Yaml();
            Object jsonObject = new Yaml().load(json);
            String yamlOutput = yaml.dumpAsMap(jsonObject);
            Files.writeString(configFile, yamlOutput, StandardCharsets.UTF_8);
            log.debug("Configuration saved to: {}", configFile.toAbsolutePath());
        } catch (Exception e) {
            log.error("Failed to save configuration", e);
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

    private AppConfig createDefaultConfig() {
        return new AppConfig();
    }
}
