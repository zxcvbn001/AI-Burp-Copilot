package com.aiburpcopilot.prompts;

import java.util.Optional;

/**
 * Prompt 模板服务接口。
 * <p>
 * 管理插件的所有 Prompt 模板，从 prompts/ 目录加载。
 * 支持版本化，后续可替换模板而不影响代码。
 * <p>
 * Phase 1 实现 FilePromptService，从资源目录加载 .txt 模板文件。
 */
public interface IPromptService {

    /**
     * 根据模板名称加载 Prompt 模板。
     *
     * @param templateName 模板名（不含路径，如 "endpoint-analysis-v1"）
     * @return 模板内容
     */
    Optional<String> loadTemplate(String templateName);

    /**
     * 根据模板名称加载系统级 Prompt。
     *
     * @param templateName 模板名
     * @return 系统 Prompt 内容
     */
    Optional<String> loadSystemPrompt(String templateName);

    /**
     * 加载并填充模板中的占位符。
     * 占位符格式：{{placeholderName}}
     *
     * @param templateName 模板名
     * @param params       占位符参数
     * @return 填充后的模板内容
     */
    Optional<String> loadAndFill(String templateName, java.util.Map<String, String> params);

    /**
     * 获取所有可用的模板名称列表。
     *
     * @return 模板名称列表
     */
    java.util.List<String> listTemplates();

    /**
     * 重新加载所有模板。
     */
    void reload();
}
