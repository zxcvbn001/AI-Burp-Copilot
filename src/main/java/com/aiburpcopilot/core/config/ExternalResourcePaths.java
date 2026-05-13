package com.aiburpcopilot.core.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

public final class ExternalResourcePaths {

    private static final Logger log = LoggerFactory.getLogger(ExternalResourcePaths.class);

    private static final String HOME_PROPERTY = "aiburpcopilot.home";
    private static final String HOME_ENV = "AI_BURP_COPILOT_HOME";
    private static final String DIR_NAME = "ai-burp-copilot";
    private static final String LEGACY_DIR_NAME = ".ai-burp-copilot";

    private static final List<ResourceCopy> DEFAULT_RESOURCES = List.of(
            new ResourceCopy("config/application.yml", "application.yml"),
            new ResourceCopy("prompts/endpoint-analysis-v1.txt", "prompts/endpoint-analysis-v1.txt"),
            new ResourceCopy("prompts/endpoint-classifier-v1.txt", "prompts/endpoint-classifier-v1.txt"),
            new ResourceCopy("prompts/static-review-v1.txt", "prompts/static-review-v1.txt"),
            new ResourceCopy("prompts/diff-judge-v1.txt", "prompts/diff-judge-v1.txt"),
            new ResourceCopy("rules/static-resource-rules.yaml", "rules/static-resource-rules.yaml"),
            new ResourceCopy("rules/payloads/auth.yaml", "rules/payloads/auth.yaml"),
            new ResourceCopy("rules/payloads/idor.yaml", "rules/payloads/idor.yaml"),
            new ResourceCopy("rules/payloads/jwt.yaml", "rules/payloads/jwt.yaml"),
            new ResourceCopy("rules/payloads/graphql.yaml", "rules/payloads/graphql.yaml"),
            new ResourceCopy("rules/payloads/cors.yaml", "rules/payloads/cors.yaml"),
            new ResourceCopy("rules/payloads/file_upload.yaml", "rules/payloads/file_upload.yaml"),
            new ResourceCopy("rules/payloads/command_injection.yaml", "rules/payloads/command_injection.yaml"),
            new ResourceCopy("rules/payloads/ldap_injection.yaml", "rules/payloads/ldap_injection.yaml"),
            new ResourceCopy("rules/payloads/path_traversal.yaml", "rules/payloads/path_traversal.yaml"),
            new ResourceCopy("rules/payloads/sqli.yaml", "rules/payloads/sqli.yaml"),
            new ResourceCopy("rules/payloads/ssrf.yaml", "rules/payloads/ssrf.yaml"),
            new ResourceCopy("rules/payloads/ssti.yaml", "rules/payloads/ssti.yaml"),
            new ResourceCopy("rules/payloads/open_redirect.yaml", "rules/payloads/open_redirect.yaml"),
            new ResourceCopy("rules/payloads/xxe.yaml", "rules/payloads/xxe.yaml"),
            new ResourceCopy("rules/payloads/xss.yaml", "rules/payloads/xss.yaml")
    );
    private static volatile Path manualHomeDir;

    private ExternalResourcePaths() {}

    public static Path homeDir() {
        if (manualHomeDir != null) {
            return manualHomeDir;
        }
        String override = System.getProperty(HOME_PROPERTY);
        if (override == null || override.isBlank()) {
            override = System.getenv(HOME_ENV);
        }
        if (override != null && !override.isBlank()) {
            return Paths.get(override.trim()).toAbsolutePath().normalize();
        }

        Path userDir = Paths.get(System.getProperty("user.dir", "."), DIR_NAME)
                .toAbsolutePath()
                .normalize();
        if (Files.exists(userDir)) {
            return userDir;
        }
        Path codeDir = codeLocationParent();
        if (codeDir != null && !codeDir.toString().toLowerCase().contains("temp")) {
            Path codeHome = codeDir.resolve(DIR_NAME).toAbsolutePath().normalize();
            if (Files.exists(codeHome)) {
                return codeHome;
            }
        }
        return Paths.get(System.getProperty("user.dir", "."), DIR_NAME)
                .toAbsolutePath()
                .normalize();
    }

    public static synchronized void setManualHomeDir(Path homeDir) {
        manualHomeDir = homeDir != null ? homeDir.toAbsolutePath().normalize() : null;
        if (manualHomeDir != null) {
            System.setProperty(HOME_PROPERTY, manualHomeDir.toString());
        } else {
            System.clearProperty(HOME_PROPERTY);
        }
    }

    public static synchronized void setManualConfigFile(Path configFile) {
        if (configFile == null) {
            setManualHomeDir(null);
            return;
        }
        Path normalized = configFile.toAbsolutePath().normalize();
        Path parent = normalized.getParent();
        setManualHomeDir(parent != null ? parent : normalized);
    }

    public static Path legacyHomeDir() {
        return Paths.get(System.getProperty("user.home", "."), LEGACY_DIR_NAME)
                .toAbsolutePath()
                .normalize();
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
        Path home = homeDir();
        try {
            Files.createDirectories(home);
            Files.createDirectories(promptsDir());
            Files.createDirectories(rulesDir());
            Files.createDirectories(payloadRulesDir());

            Path legacy = legacyHomeDir();
            for (ResourceCopy resource : DEFAULT_RESOURCES) {
                Path target = home.resolve(resource.externalPath());
                if (Files.exists(target)) {
                    migrateLegacyPayloadRule(resource, target);
                    continue;
                }
                Path legacyFile = legacy.resolve(resource.externalPath());
                if (!home.equals(legacy) && Files.exists(legacyFile)) {
                    Files.createDirectories(target.getParent());
                    Files.copy(legacyFile, target, StandardCopyOption.COPY_ATTRIBUTES);
                    created.add(target);
                    log.info("Migrated external resource: {} -> {}", legacyFile, target);
                    continue;
                }
                copyClasspathResource(resource.classpathPath(), target);
                created.add(target);
            }
        } catch (Exception e) {
            log.error("Failed to initialize external resources under {}", home, e);
        }
        return created;
    }

    private static void copyClasspathResource(String classpathPath, Path target) throws IOException {
        try (InputStream input = ExternalResourcePaths.class.getClassLoader()
                .getResourceAsStream(classpathPath)) {
            if (input == null) {
                throw new FileNotFoundException("Classpath resource not found: " + classpathPath);
            }
            Files.createDirectories(target.getParent());
            Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
            log.info("Copied default resource: {} -> {}", classpathPath, target);
        }
    }

    private static void migrateLegacyPayloadRule(ResourceCopy resource, Path target) {
        if (!resource.externalPath().startsWith("rules/payloads/")
                || !resource.externalPath().endsWith(".yaml")) {
            return;
        }
        try {
            String content = Files.readString(target);
            if (content.contains("\nprobes:") || content.contains("\r\nprobes:")) {
                return;
            }
            if (!content.contains("\nrules:") && !content.contains("\r\nrules:")) {
                return;
            }
            Path backup = target.resolveSibling(target.getFileName() + ".legacy.bak");
            if (!Files.exists(backup)) {
                Files.copy(target, backup, StandardCopyOption.COPY_ATTRIBUTES);
            }
            copyClasspathResource(resource.classpathPath(), target);
            log.warn("Migrated legacy payload rule to probe format: {} (backup: {})", target, backup);
        } catch (Exception e) {
            log.warn("Unable to migrate legacy payload rule: {}", target, e);
        }
    }

    private static Path codeLocationParent() {
        try {
            URI location = ExternalResourcePaths.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI();
            Path path = Paths.get(location).toAbsolutePath().normalize();
            if (Files.isRegularFile(path) || path.toString().toLowerCase().endsWith(".jar")) {
                return path.getParent();
            }
            return Paths.get(System.getProperty("user.dir", ".")).toAbsolutePath().normalize();
        } catch (Exception e) {
            log.debug("Unable to resolve code location: {}", e.getMessage());
            return null;
        }
    }

    private record ResourceCopy(String classpathPath, String externalPath) {}
}
