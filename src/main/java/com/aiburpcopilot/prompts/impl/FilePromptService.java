package com.aiburpcopilot.prompts.impl;

import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.prompts.IPromptService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 文件 Prompt 模板服务实现。
 * <p>
 * 从以下路径加载 Prompt 模板（按优先级）：
 * <ol>
 *   <li>外部目录：~/.ai-burp-copilot/prompts/（支持用户自定义覆盖）</li>
 *   <li>内置资源：classpath:/prompts/（打包在 JAR 中的默认模板）</li>
 * </ol>
 * <p>
 * 模板文件命名规范：{name}-v{version}.txt
 * 例如：endpoint-analysis-v1.txt
 */
public class FilePromptService implements IPromptService {

    private static final Logger log = LoggerFactory.getLogger(FilePromptService.class);

    private static final String PROMPTS_DIR = "prompts";
    private static final String PROMPT_EXTENSION = ".txt";

    private final Path externalPromptDir;
    private final Map<String, String> templateCache = new HashMap<>();

    public FilePromptService() {
        ExternalResourcePaths.initialize();
        this.externalPromptDir = ExternalResourcePaths.promptsDir();
        reload();
    }

    @Override
    public Optional<String> loadTemplate(String templateName) {
        return Optional.ofNullable(templateCache.get(normalizeName(templateName)));
    }

    @Override
    public Optional<String> loadSystemPrompt(String templateName) {
        // 系统 Prompt 使用 system- 前缀的模板
        return loadTemplate("system-" + templateName);
    }

    @Override
    public Optional<String> loadAndFill(String templateName, Map<String, String> params) {
        Optional<String> template = loadTemplate(templateName);
        if (template.isEmpty()) return Optional.empty();

        String content = template.get();
        if (params != null) {
            for (Map.Entry<String, String> entry : params.entrySet()) {
                content = content.replace("{{" + entry.getKey() + "}}", entry.getValue() != null ? entry.getValue() : "");
            }
        }
        return Optional.of(content);
    }

    @Override
    public List<String> listTemplates() {
        return new ArrayList<>(templateCache.keySet());
    }

    @Override
    public synchronized void reload() {
        templateCache.clear();

        // 1. 加载内置资源
        loadBuiltinTemplates();

        // 2. 加载外部模板（覆盖内置）
        loadExternalTemplates();

        log.info("Loaded {} prompt templates", templateCache.size());
    }

    // ---------- Private Helpers ----------

    private String normalizeName(String name) {
        // 移除扩展名（如果传入）
        if (name.endsWith(PROMPT_EXTENSION)) {
            name = name.substring(0, name.length() - PROMPT_EXTENSION.length());
        }
        return name;
    }

    /**
     * 从 classpath:/prompts/ 加载内置模板。
     */
    private void loadBuiltinTemplates() {
        try {
            // 通过类加载器获取 prompts 目录下的资源列表
            ClassLoader classLoader = getClass().getClassLoader();
            java.net.URL promptsUrl = classLoader.getResource(PROMPTS_DIR);
            if (promptsUrl == null) {
                log.warn("No built-in prompts directory found");
                return;
            }

            // 尝试从文件系统加载（开发环境）或从 JAR 加载
            try (InputStream dirStream = classLoader.getResourceAsStream(PROMPTS_DIR)) {
                if (dirStream == null) return;
            }

            // 使用目录遍历方式加载
            Path resourcePath;
            try {
                resourcePath = Paths.get(promptsUrl.toURI());
                if (Files.isDirectory(resourcePath)) {
                    try (var stream = Files.list(resourcePath)) {
                        stream.filter(p -> p.toString().endsWith(PROMPT_EXTENSION))
                                .forEach(this::loadFromPath);
                    }
                }
            } catch (Exception e) {
                // 在 JAR 包中运行时，无法通过 FileSystem 遍历，使用已知模板列表
                loadKnownBuiltinTemplates(classLoader);
            }
        } catch (Exception e) {
            log.warn("Failed to load builtin prompts: {}", e.getMessage());
        }
    }

    /**
     * 从已知模板名列表加载内置模板（适用于 JAR 包环境）。
     */
    private void loadKnownBuiltinTemplates(ClassLoader classLoader) {
        String[] knownTemplates = {
                "endpoint-classifier-v1",
                "endpoint-analysis-v1",
                "static-review-v1",
                "diff-judge-v1"
        };

        for (String name : knownTemplates) {
            String resourcePath = PROMPTS_DIR + "/" + name + PROMPT_EXTENSION;
            try (InputStream is = classLoader.getResourceAsStream(resourcePath)) {
                if (is != null) {
                    String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                    templateCache.put(name, content);
                    log.debug("Loaded builtin prompt: {}", name);
                }
            } catch (Exception e) {
                log.warn("Failed to load builtin prompt {}: {}", name, e.getMessage());
            }
        }
    }

    /**
     * 从外部目录加载模板（覆盖内置）。
     */
    private void loadExternalTemplates() {
        try {
            if (!Files.exists(externalPromptDir)) {
                Files.createDirectories(externalPromptDir);
                return;
            }

            try (var stream = Files.list(externalPromptDir)) {
                stream.filter(p -> p.toString().endsWith(PROMPT_EXTENSION))
                        .forEach(this::loadFromPath);
            }
        } catch (Exception e) {
            log.warn("Failed to load external prompts: {}", e.getMessage());
        }
    }

    private void loadFromPath(Path filePath) {
        try {
            String fileName = filePath.getFileName().toString();
            String name = fileName.substring(0, fileName.length() - PROMPT_EXTENSION.length());
            String content = Files.readString(filePath, StandardCharsets.UTF_8);
            templateCache.put(name, content);
            log.debug("Loaded prompt: {} from {}", name, filePath);
        } catch (Exception e) {
            log.warn("Failed to load prompt file {}: {}", filePath, e.getMessage());
        }
    }
}
