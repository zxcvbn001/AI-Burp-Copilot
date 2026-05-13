package com.aiburpcopilot.core.config;

/**
 * 配置服务接口。
 * <p>
 * 管理插件所有配置项，支持 YAML 文件加载和 UI 热更新。
 * Phase 1 实现 YAMLConfigService。
 */
public interface IConfigService {

    /**
     * 重新加载配置（从文件读取）。
     */
    void reload();

    default void reloadFrom(java.nio.file.Path configFile) {
        reload();
    }

    default java.nio.file.Path getConfigFilePath() {
        return ExternalResourcePaths.configFile();
    }

    /**
     * 保存当前配置到文件。
     */
    void save();

    /**
     * 获取所有配置项。
     *
     * @return AppConfig 对象
     */
    AppConfig getConfig();

    /**
     * 更新配置（内存中修改，需调用 save() 持久化）。
     *
     * @param config 新的配置对象
     */
    void updateConfig(AppConfig config);

    /**
     * 注册配置变更监听器。
     *
     * @param listener 变更监听器
     */
    void addChangeListener(ConfigChangeListener listener);

    /**
     * 配置变更监听器接口。
     */
    @FunctionalInterface
    interface ConfigChangeListener {
        void onConfigChanged(AppConfig newConfig);
    }
}
