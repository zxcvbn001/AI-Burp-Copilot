package com.aiburpcopilot.core.config;

import com.aiburpcopilot.core.config.impl.YAMLConfigService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class YAMLConfigServiceTest {

    private Path originalHomeDir;

    @AfterEach
    void cleanup() {
        ExternalResourcePaths.setManualHomeDir(originalHomeDir);
    }

    @Test
    void saveShouldNotWriteEmptyApplicationYmlAndShouldPreserveUnknownFields() throws Exception {
        originalHomeDir = ExternalResourcePaths.homeDirOrNull();
        Path tempHome = Files.createTempDirectory("aiburpcopilot-config-test");
        Files.createDirectories(tempHome.resolve("prompts"));
        Files.createDirectories(tempHome.resolve("rules").resolve("payloads"));

        String yaml = """
                llm:
                  provider: deepseek
                  model: deepseek-chat
                  apiKey: test-key
                  apiUrl: https://api.deepseek.com/v1/chat/completions
                scan:
                  skipExtensions: [png]
                  skipKeywords: [health]
                  skipStatusCodes: [204]
                  responseBodyScan:
                    enabled: true
                    maxSize: 204800
                  staticScanMaxSize: 200
                ai:
                  maxTokens: 2048
                  timeoutMs: 60000
                  maxPromptLength: 8000
                  rateLimitPerMinute: 60
                jsAnalysis:
                  enabled: true
                  baseUrl: http://127.0.0.1:3000
                  apiKey: test
                  apiKeyHeader: x-api-key
                  healthPath: /health
                  analyzePath: /analyze/js
                  fastMode: true
                  mode: fast
                  submitAsync: true
                  taskPollIntervalMs: 1000
                  taskTimeoutMs: 60000
                  connectTimeoutMs: 8000
                  readTimeoutMs: 30000
                  writeTimeoutMs: 30000
                  maxReferencedScripts: 6
                  maxRecursiveDepth: 1
                  maxVerifiedEndpointsPerScript: 12
                  autoVerifyRecoveredApis: true
                  autoAnalyzeVerifiedApis: true
                  autoFetchReferencedScripts: true
                  requestBuilder:
                    enabled: true
                    appendParamsToQuery: true
                    buildBodyForUnsafeMethods: false
                    defaultBodyFormat: json
                    placeholderValue: ""
                    copyJsHeaders: true
                    copyAuthSignalHeaders: false
                    maxParams: 20
                    maxHeaders: 12
                  customServerSideFlag: keep-me
                request:
                  concurrency: 5
                  maxQueueSize: 1000
                storage:
                  maxHistory: 2000
                  cacheTtlSeconds: 3600
                  maxCacheEntries: 5000
                  historyDbPath: ""
                verification:
                  enabled: true
                  maxRequestsPerEndpoint: 5
                  requestTimeoutSeconds: 10
                  whitelist: []
                  maxPayloadLength: 128
                  allowedInfluenceActions: [READ]
                  allowedVerificationActions: [READ]
                experimentalTopLevel:
                  enabled: true
                  note: preserve-me
                """;
        Files.writeString(tempHome.resolve("application.yml"), yaml, StandardCharsets.UTF_8);

        ExternalResourcePaths.setManualHomeDir(tempHome);

        YAMLConfigService service = new YAMLConfigService();
        service.reload();
        AppConfig config = service.getConfig();
        config.getAi().setTimeoutMs(61000);
        config.getStorage().setMaxHistory(2100);
        service.updateConfig(config);
        service.save();

        String saved = Files.readString(tempHome.resolve("application.yml"), StandardCharsets.UTF_8);
        assertFalse(saved.isBlank(), "saved application.yml should not be empty");
        assertTrue(saved.contains("timeoutMs: 61000"), "updated field should be written");
        assertTrue(saved.contains("maxHistory: 2100"), "updated storage field should be written");
        assertTrue(saved.contains("customServerSideFlag: keep-me"), "unknown nested field should be preserved");
        assertTrue(saved.contains("experimentalTopLevel:"), "unknown top-level field should be preserved");
        assertTrue(saved.contains("note: preserve-me"), "unknown top-level nested value should be preserved");
    }
}
