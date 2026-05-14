package com.aiburpcopilot.prompts.impl;

import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.prompts.IPromptService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class FilePromptService implements IPromptService {

    private static final Logger log = LoggerFactory.getLogger(FilePromptService.class);
    private static final String PROMPT_EXTENSION = ".txt";

    private final Map<String, String> templateCache = new HashMap<>();

    public FilePromptService() {
        ExternalResourcePaths.initialize();
        reload();
    }

    @Override
    public Optional<String> loadTemplate(String templateName) {
        return Optional.ofNullable(templateCache.get(normalizeName(templateName)));
    }

    @Override
    public Optional<String> loadSystemPrompt(String templateName) {
        return loadTemplate("system-" + templateName);
    }

    @Override
    public Optional<String> loadAndFill(String templateName, Map<String, String> params) {
        Optional<String> template = loadTemplate(templateName);
        if (template.isEmpty()) {
            return Optional.empty();
        }
        String content = template.get();
        if (params != null) {
            for (Map.Entry<String, String> entry : params.entrySet()) {
                content = content.replace("{{" + entry.getKey() + "}}",
                        entry.getValue() != null ? entry.getValue() : "");
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
        Path promptDir = ExternalResourcePaths.promptsDir();
        try {
            if (!Files.exists(promptDir)) {
                throw new IllegalStateException("Prompts directory not found: " + promptDir.toAbsolutePath());
            }
            try (var stream = Files.list(promptDir)) {
                stream.filter(path -> path.toString().endsWith(PROMPT_EXTENSION))
                        .forEach(this::loadFromPath);
            }
            log.info("Loaded {} prompt templates from {}", templateCache.size(), promptDir.toAbsolutePath());
        } catch (Exception e) {
            log.error("Failed to load prompts from {}", promptDir, e);
            throw new IllegalStateException("Unable to load prompt templates from configured directory", e);
        }
    }

    private String normalizeName(String name) {
        if (name.endsWith(PROMPT_EXTENSION)) {
            return name.substring(0, name.length() - PROMPT_EXTENSION.length());
        }
        return name;
    }

    private void loadFromPath(Path filePath) {
        try {
            String fileName = filePath.getFileName().toString();
            String name = fileName.substring(0, fileName.length() - PROMPT_EXTENSION.length());
            String content = Files.readString(filePath, StandardCharsets.UTF_8);
            templateCache.put(name, content);
            log.debug("Loaded prompt: {} from {}", name, filePath);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load prompt file: " + filePath, e);
        }
    }
}
