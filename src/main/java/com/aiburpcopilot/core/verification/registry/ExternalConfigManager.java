package com.aiburpcopilot.core.verification.registry;

import com.aiburpcopilot.core.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Central configuration manager for ALL external configuration resources.
 * <p>
 * Manages all resources under the {@code ~/.ai-burp-copilot/} directory:
 * <ul>
 *   <li>{@code application.yml} - Application configuration</li>
 *   <li>{@code prompts/*.txt} - AI prompt templates</li>
 *   <li>{@code rules/static-resource-rules.yaml} - Static resource scan rules</li>
 *   <li>{@code rules/payloads/*.yaml} - Payload rule files per attack type</li>
 * </ul>
 * <p>
 * On first run, if the external directory does not exist, this manager
 * creates it and copies all built-in (classpath) resources into it.
 * Existing external resources are never overwritten.
 * <p>
 * Supports full reload of all or individual resource categories,
 * and tracks the loading status of each resource.
 */
public class ExternalConfigManager {

    private static final Logger log = LoggerFactory.getLogger(ExternalConfigManager.class);

    /** User home subdirectory for all external configuration */
    private static final String CONFIG_HOME_NAME = ".ai-burp-copilot";

    /** Status constants for resource tracking */
    public static final String STATUS_LOADED = "LOADED";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_NOT_FOUND = "NOT_FOUND";

    // ---- External directories ----
    private final Path configHomeDir;
    private final Path promptsDir;
    private final Path rulesDir;
    private final Path payloadRulesDir;

    // ---- External files ----
    private final Path configFile;
    private final Path staticRulesFile;

    // ---- Loaded data ----
    private volatile AppConfig config;
    private final Map<String, String> prompts = new LinkedHashMap<>();
    private final List<Path> loadedFilePaths = new ArrayList<>();
    private final Map<String, String> resourceStatuses = new LinkedHashMap<>();
    private final Object lock = new Object();

    /** Known classpath resources for first-run copy */
    private static final List<String> CLASS_PATH_PROMPT_FILES = List.of(
            "endpoint-analysis-v1.txt",
            "endpoint-classifier-v1.txt",
            "static-review-v1.txt"
    );

    private static final List<String> CLASS_PATH_PAYLOAD_FILES = List.of(
            "auth.yaml",
            "command_injection.yaml",
            "cors.yaml",
            "file_upload.yaml",
            "graphql.yaml",
            "idor.yaml",
            "jwt.yaml",
            "ldap_injection.yaml",
            "open_redirect.yaml",
            "path_traversal.yaml",
            "sqli.yaml",
            "ssrf.yaml",
            "ssti.yaml",
            "xxe.yaml",
            "xss.yaml"
    );

    public ExternalConfigManager() {
        String userHome = System.getProperty("user.home", ".");
        this.configHomeDir = Paths.get(userHome, CONFIG_HOME_NAME);
        this.promptsDir = configHomeDir.resolve("prompts");
        this.rulesDir = configHomeDir.resolve("rules");
        this.payloadRulesDir = rulesDir.resolve("payloads");
        this.configFile = configHomeDir.resolve("application.yml");
        this.staticRulesFile = rulesDir.resolve("static-resource-rules.yaml");
    }

    // ===================== Initialization =====================

    /**
     * Initializes the external config directory.
     * <p>
     * If the config home directory does not exist, creates all subdirectories
     * and copies built-in resources from the classpath. Existing files are
     * never overwritten.
     *
     * @return list of paths for files that were created during initialization
     */
    public synchronized List<Path> initialize() {
        List<Path> created = new ArrayList<>();
        try {
            if (!Files.exists(configHomeDir)) {
                log.info("External config directory not found. Creating: {}", configHomeDir.toAbsolutePath());
                Files.createDirectories(configHomeDir);
                Files.createDirectories(promptsDir);
                Files.createDirectories(rulesDir);
                Files.createDirectories(payloadRulesDir);

                created.addAll(copyConfigResource());
                created.addAll(copyPromptResources());
                created.addAll(copyStaticRulesResource());
                created.addAll(copyPayloadRuleResources());

                log.info("Initialization complete. {} resources copied to {}", created.size(), configHomeDir.toAbsolutePath());
            } else {
                log.info("External config directory already exists: {}", configHomeDir.toAbsolutePath());
            }
        } catch (IOException e) {
            log.error("Failed to initialize external config directory", e);
        }
        return created;
    }

    // ===================== Resource Copy Helpers =====================

    private List<Path> copyConfigResource() throws IOException {
        List<Path> created = new ArrayList<>();
        if (!Files.exists(configFile)) {
            copyResource("config/application.yml", configFile);
            created.add(configFile);
        }
        return created;
    }

    private List<Path> copyPromptResources() throws IOException {
        List<Path> created = new ArrayList<>();
        for (String promptFile : CLASS_PATH_PROMPT_FILES) {
            Path target = promptsDir.resolve(promptFile);
            if (!Files.exists(target)) {
                copyResource("prompts/" + promptFile, target);
                created.add(target);
            }
        }
        return created;
    }

    private List<Path> copyStaticRulesResource() throws IOException {
        List<Path> created = new ArrayList<>();
        if (!Files.exists(staticRulesFile)) {
            copyResource("rules/static-resource-rules.yaml", staticRulesFile);
            created.add(staticRulesFile);
        }
        return created;
    }

    private List<Path> copyPayloadRuleResources() throws IOException {
        List<Path> created = new ArrayList<>();
        for (String payloadFile : CLASS_PATH_PAYLOAD_FILES) {
            Path target = payloadRulesDir.resolve(payloadFile);
            if (!Files.exists(target)) {
                copyResource("rules/payloads/" + payloadFile, target);
                created.add(target);
            }
        }
        return created;
    }

    /**
     * Copies a single resource from classpath to the filesystem.
     */
    private void copyResource(String classPathResource, Path targetPath) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(classPathResource)) {
            if (in == null) {
                log.warn("Classpath resource not found: {}", classPathResource);
                throw new FileNotFoundException("Classpath resource not found: " + classPathResource);
            }
            Files.copy(in, targetPath, StandardCopyOption.REPLACE_EXISTING);
            log.debug("Copied classpath resource: {} -> {}", classPathResource, targetPath.toAbsolutePath());
        }
    }

    // ===================== Reload Methods =====================

    /**
     * Reloads all external configuration resources from disk.
     */
    public synchronized void reloadAll() {
        synchronized (lock) {
            loadedFilePaths.clear();
            resourceStatuses.clear();
            prompts.clear();
            reloadConfig();
            reloadPrompts();
            reloadRules();
            reloadPayloadRules();
            log.info("All resources reloaded. Config: {}, Prompts: {}, Status entries: {}",
                    config != null ? "OK" : "FAILED",
                    prompts.size(),
                    resourceStatuses.size());
        }
    }

    /**
     * Reloads the application.yml configuration from the external directory.
     */
    public synchronized void reloadConfig() {
        String resourceKey = "config/application.yml";
        try {
            if (!Files.exists(configFile)) {
                log.warn("Config file not found: {}", configFile.toAbsolutePath());
                resourceStatuses.put(resourceKey, STATUS_NOT_FOUND);
                config = new AppConfig();
                return;
            }
            String content = Files.readString(configFile, StandardCharsets.UTF_8);
            Yaml yaml = new Yaml();
            Object loaded = yaml.loadAs(content, AppConfig.class);
            if (loaded instanceof AppConfig) {
                config = (AppConfig) loaded;
                resourceStatuses.put(resourceKey, STATUS_LOADED);
                if (!loadedFilePaths.contains(configFile)) {
                    loadedFilePaths.add(configFile);
                }
                log.debug("Configuration loaded from: {}", configFile.toAbsolutePath());
            } else {
                log.warn("Failed to parse AppConfig from: {}", configFile.toAbsolutePath());
                resourceStatuses.put(resourceKey, STATUS_FAILED);
                config = new AppConfig();
            }
        } catch (Exception e) {
            log.error("Failed to load configuration from: {}", configFile.toAbsolutePath(), e);
            resourceStatuses.put(resourceKey, STATUS_FAILED);
            config = new AppConfig();
        }
    }

    /**
     * Reloads all prompt files (*.txt) from the prompts directory.
     */
    public synchronized void reloadPrompts() {
        prompts.clear();
        try {
            if (!Files.exists(promptsDir) || !Files.isDirectory(promptsDir)) {
                log.warn("Prompts directory not found: {}", promptsDir.toAbsolutePath());
                return;
            }
            try (Stream<Path> files = Files.list(promptsDir)) {
                List<Path> txtFiles = files
                        .filter(p -> p.getFileName().toString().endsWith(".txt"))
                        .sorted()
                        .collect(Collectors.toList());

                for (Path file : txtFiles) {
                    String resourceKey = "prompts/" + file.getFileName().toString();
                    try {
                        String content = Files.readString(file, StandardCharsets.UTF_8);
                        String promptName = file.getFileName().toString();
                        // Strip .txt extension for the key
                        if (promptName.endsWith(".txt")) {
                            promptName = promptName.substring(0, promptName.length() - 4);
                        }
                        prompts.put(promptName, content);
                        resourceStatuses.put(resourceKey, STATUS_LOADED);
                        if (!loadedFilePaths.contains(file)) {
                            loadedFilePaths.add(file);
                        }
                        log.debug("Loaded prompt: {}", file.getFileName());
                    } catch (IOException e) {
                        log.error("Failed to load prompt: {}", file.getFileName(), e);
                        resourceStatuses.put(resourceKey, STATUS_FAILED);
                    }
                }
                log.info("Loaded {} prompt files from {}", prompts.size(), promptsDir.toAbsolutePath());
            }
        } catch (IOException e) {
            log.error("Failed to list prompts directory: {}", promptsDir.toAbsolutePath(), e);
        }
    }

    /**
     * Reloads the static resource rules YAML file.
     */
    public synchronized void reloadRules() {
        String resourceKey = "rules/static-resource-rules.yaml";
        try {
            if (!Files.exists(staticRulesFile)) {
                log.warn("Static rules file not found: {}", staticRulesFile.toAbsolutePath());
                resourceStatuses.put(resourceKey, STATUS_NOT_FOUND);
                return;
            }
            // Just verify the file can be read; actual parsing is done by StaticScanStage
            String content = Files.readString(staticRulesFile, StandardCharsets.UTF_8);
            if (content != null && !content.isBlank()) {
                resourceStatuses.put(resourceKey, STATUS_LOADED);
                if (!loadedFilePaths.contains(staticRulesFile)) {
                    loadedFilePaths.add(staticRulesFile);
                }
                log.debug("Static rules loaded from: {}", staticRulesFile.toAbsolutePath());
            } else {
                resourceStatuses.put(resourceKey, STATUS_FAILED);
            }
        } catch (Exception e) {
            log.error("Failed to load static rules from: {}", staticRulesFile.toAbsolutePath(), e);
            resourceStatuses.put(resourceKey, STATUS_FAILED);
        }
    }

    /**
     * Reloads all payload rule YAML files from the payloads directory.
     */
    public synchronized void reloadPayloadRules() {
        try {
            if (!Files.exists(payloadRulesDir) || !Files.isDirectory(payloadRulesDir)) {
                log.warn("Payload rules directory not found: {}", payloadRulesDir.toAbsolutePath());
                return;
            }
            try (Stream<Path> files = Files.list(payloadRulesDir)) {
                List<Path> yamlFiles = files
                        .filter(p -> p.getFileName().toString().endsWith(".yaml") || p.getFileName().toString().endsWith(".yml"))
                        .sorted()
                        .collect(Collectors.toList());

                for (Path file : yamlFiles) {
                    String resourceKey = "rules/payloads/" + file.getFileName().toString();
                    try {
                        // Verify the file is readable YAML
                        String content = Files.readString(file, StandardCharsets.UTF_8);
                        if (content != null && !content.isBlank()) {
                            resourceStatuses.put(resourceKey, STATUS_LOADED);
                            if (!loadedFilePaths.contains(file)) {
                                loadedFilePaths.add(file);
                            }
                            log.debug("Loaded payload rules: {}", file.getFileName());
                        } else {
                            resourceStatuses.put(resourceKey, STATUS_FAILED);
                        }
                    } catch (Exception e) {
                        log.error("Failed to load payload rules: {}", file.getFileName(), e);
                        resourceStatuses.put(resourceKey, STATUS_FAILED);
                    }
                }
                log.info("Loaded {} payload rule files from {}", yamlFiles.size(), payloadRulesDir.toAbsolutePath());
            }
        } catch (IOException e) {
            log.error("Failed to list payload rules directory: {}", payloadRulesDir.toAbsolutePath(), e);
        }
    }

    // ===================== Getters =====================

    /**
     * Returns a map of resource paths to their loading status.
     * <p>
     * Status values: {@link #STATUS_LOADED}, {@link #STATUS_FAILED}, {@link #STATUS_NOT_FOUND}
     *
     * @return unmodifiable map of resource key to status
     */
    public Map<String, String> getResourceStatuses() {
        synchronized (lock) {
            return Collections.unmodifiableMap(new LinkedHashMap<>(resourceStatuses));
        }
    }

    /**
     * Returns the list of all successfully loaded file paths.
     *
     * @return unmodifiable list of loaded file paths
     */
    public List<Path> getLoadedFilePaths() {
        synchronized (lock) {
            return Collections.unmodifiableList(new ArrayList<>(loadedFilePaths));
        }
    }

    /**
     * Returns the loaded AppConfig, or a default if not loaded.
     *
     * @return the loaded AppConfig, never null
     */
    public AppConfig getConfig() {
        if (config == null) {
            synchronized (lock) {
                if (config == null) {
                    reloadConfig();
                }
            }
        }
        return config != null ? config : new AppConfig();
    }

    /**
     * Returns the loaded prompts as a map of prompt name (without .txt extension)
     * to content.
     *
     * @return unmodifiable map of prompt name to content
     */
    public Map<String, String> getPrompts() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(prompts));
    }

    /**
     * Checks whether the external config directory exists and contains content.
     *
     * @return true if the external directory exists and has content
     */
    public boolean isInitialized() {
        if (!Files.exists(configHomeDir) || !Files.isDirectory(configHomeDir)) {
            return false;
        }
        try (Stream<Path> entries = Files.list(configHomeDir)) {
            return entries.findAny().isPresent();
        } catch (IOException e) {
            return false;
        }
    }
}
