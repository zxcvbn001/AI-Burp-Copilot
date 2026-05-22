package com.aiburpcopilot.core.verification;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.context.ParameterType;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.verification.model.*;
import com.aiburpcopilot.core.verification.capability.AnalysisResultCapabilityFilter;
import com.aiburpcopilot.core.verification.capability.RuleCapabilityCatalog;
import com.aiburpcopilot.core.verification.influence.impl.InfluenceDiffEngine;
import com.aiburpcopilot.core.verification.influence.impl.InfluenceScorer;
import com.aiburpcopilot.core.verification.influence.impl.MinimalMutationEngine;
import com.aiburpcopilot.core.verification.influence.impl.ParameterProfiler;
import com.aiburpcopilot.core.verification.influence.impl.StrategyApprovalEngine;
import com.aiburpcopilot.core.verification.influence.impl.ReplayEngine;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;
import com.aiburpcopilot.core.verification.payload.impl.YamlPayloadRuleEngine;
import com.aiburpcopilot.core.verification.finding.FindingAggregator;
import com.aiburpcopilot.core.verification.probe.IProbeRuleEngine;
import com.aiburpcopilot.core.verification.probe.OracleDefinition;
import com.aiburpcopilot.core.verification.probe.ProbeDefinition;
import com.aiburpcopilot.core.verification.probe.ProbeOracleEngine;
import com.aiburpcopilot.core.verification.probe.ProbePayload;
import com.aiburpcopilot.core.verification.probe.ProbeRole;
import com.aiburpcopilot.core.verification.technique.TechniqueRecommendation;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;
import com.aiburpcopilot.core.verification.workflow.WorkflowContext;
import com.aiburpcopilot.core.verification.workflow.impl.GenericProbeStep;
import com.aiburpcopilot.core.verification.workflow.impl.InfluenceValidationStep;
import com.aiburpcopilot.core.verification.workflow.impl.WorkflowRegistry;
import com.aiburpcopilot.core.verification.workflow.impl.WorkflowStepFactory;
import com.aiburpcopilot.core.verification.candidate.impl.CandidateExtractor;
import com.aiburpcopilot.core.verification.capability.AnalysisResultCapabilityFilter;
import com.aiburpcopilot.core.verification.review.FindingReviewService;
import com.aiburpcopilot.core.pipeline.AIAnalysisStage;
import com.aiburpcopilot.core.pipeline.EndpointDedupStage;
import com.aiburpcopilot.scanner.endpoint.EndpointClassifier;
import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.core.config.ExternalResourcePaths;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.prompts.IPromptService;
import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.utils.HttpUtil;
import org.junit.jupiter.api.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 3 Verification Engine Comprehensive Tests.
 * <p>
 * Covers: Numeric Mutation, Replay, Influence Diff, Influence Score,
 * Strategy Approval, Workflow Step, Workflow Stop, JSON Response, Header Change.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Phase3VerificationTest {

    private static Path originalHomeDir;
    private static Path testHomeDir;
    private static boolean createdTempHomeDir;

    @BeforeAll
    static void setupExternalConfigDir() throws Exception {
        Path existing = ExternalResourcePaths.homeDirOrNull();
        originalHomeDir = existing;
        if (existing != null) {
            testHomeDir = existing;
            return;
        }

        Path templateDir = resolveTemplateDir();
        if (templateDir != null) {
            testHomeDir = templateDir;
            ExternalResourcePaths.setManualHomeDir(templateDir);
            return;
        }

        testHomeDir = Files.createTempDirectory("aiburpcopilot-test-home");
        createdTempHomeDir = true;
        ExternalResourcePaths.setManualHomeDir(testHomeDir);
        Files.createDirectories(testHomeDir.resolve("prompts"));
        Files.createDirectories(testHomeDir.resolve("rules").resolve("payloads"));
        copyDirectory(templateDir.resolve("prompts"), testHomeDir.resolve("prompts"));
        copyDirectory(templateDir.resolve("rules"), testHomeDir.resolve("rules"));
        Files.copy(templateDir.resolve("application.yml"),
                testHomeDir.resolve("application.yml"),
                StandardCopyOption.REPLACE_EXISTING);
    }

    private static void copyDirectory(Path source, Path target) throws Exception {
        if (!Files.exists(source)) {
            return;
        }
        try (var walk = Files.walk(source)) {
            for (Path path : walk.toList()) {
                Path relative = source.relativize(path);
                Path destination = target.resolve(relative);
                if (Files.isDirectory(path)) {
                    Files.createDirectories(destination);
                } else {
                    Files.createDirectories(destination.getParent());
                    Files.copy(path, destination, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    @AfterAll
    static void cleanupExternalConfigDir() throws Exception {
        ExternalResourcePaths.setManualHomeDir(originalHomeDir);
        if (originalHomeDir == null && createdTempHomeDir && testHomeDir != null && Files.exists(testHomeDir)) {
            try (var walk = Files.walk(testHomeDir)) {
                walk.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                        .forEach(path -> {
                            try {
                                Files.deleteIfExists(path);
                            } catch (Exception ignored) {
                            }
                        });
            }
        }
    }

    private static Path resolveTemplateDir() {
        Path fromProperty = pathIfValid(System.getProperty("aiburpcopilot.testTemplateDir"));
        if (fromProperty != null) {
            return fromProperty;
        }

        Path fromHomeProperty = pathIfValid(System.getProperty("aiburpcopilot.home"));
        if (fromHomeProperty != null) {
            return fromHomeProperty;
        }

        Path fromEnv = pathIfValid(System.getenv("AI_BURP_COPILOT_HOME"));
        if (fromEnv != null) {
            return fromEnv;
        }

        Path fromUserDir = pathIfValid(Path.of("").toAbsolutePath().normalize()
                .resolve("ai-burp-copilot-templates").toString());
        if (fromUserDir != null) {
            return fromUserDir;
        }

        throw new IllegalStateException("Unable to locate ai-burp-copilot-templates for tests");
    }

    private static Path pathIfValid(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return null;
        }
        try {
            Path dir = Path.of(rawPath).toAbsolutePath().normalize();
            if (!Files.isDirectory(dir)) {
                return null;
            }
            if (!Files.isRegularFile(dir.resolve("application.yml"))) {
                return null;
            }
            if (!Files.isDirectory(dir.resolve("prompts"))) {
                return null;
            }
            Path payloadDir = dir.resolve("rules").resolve("payloads");
            if (!Files.isDirectory(payloadDir)) {
                return null;
            }
            try (var files = Files.list(payloadDir)) {
                if (files.findAny().isEmpty()) {
                    return null;
                }
            }
            return dir;
        } catch (Exception ignored) {
            return null;
        }
    }

    // ============================================================
    // Test 1: Numeric Mutation
    // ============================================================

    @Test
    @Order(1)
    @DisplayName("Numeric parameter mutation - increment/decrement")
    void testNumericMutation() {
        MinimalMutationEngine engine = new MinimalMutationEngine();
        ParameterProfile profile = new ParameterProfile();
        profile.setParameterName("id");
        profile.setDetectedType(ParameterProfile.TYPE_NUMERIC);
        profile.setOriginalValue("42");
        profile.setConfidence(0.9);

        List<String> mutations = engine.generateMutations(profile);
        assertNotNull(mutations);
        assertTrue(mutations.size() >= 2, "Should generate at least 2 mutations");
        assertTrue(mutations.contains("43"), "Should contain increment value");
        assertTrue(mutations.contains("41"), "Should contain decrement value");
    }

    @Test
    @Order(2)
    @DisplayName("Numeric mutation - specific mutation types")
    void testNumericSpecificMutations() {
        MinimalMutationEngine engine = new MinimalMutationEngine();
        ParameterProfile profile = new ParameterProfile();
        profile.setParameterName("id");
        profile.setDetectedType(ParameterProfile.TYPE_NUMERIC);
        profile.setOriginalValue("100");
        profile.setConfidence(0.9);

        assertEquals("101", engine.generateMutation(profile, "INCREMENT"));
        assertEquals("99", engine.generateMutation(profile, "DECREMENT"));
        assertEquals("0", engine.generateMutation(profile, "NULL"));
        assertEquals("", engine.generateMutation(profile, "EMPTY"));

        // Negative value test
        profile.setOriginalValue("-5");
        assertEquals("-4", engine.generateMutation(profile, "INCREMENT"));
    }

    @Test
    @Order(3)
    @DisplayName("Boolean parameter mutation - flip")
    void testBooleanMutation() {
        MinimalMutationEngine engine = new MinimalMutationEngine();
        ParameterProfile profile = new ParameterProfile();
        profile.setParameterName("enabled");
        profile.setDetectedType(ParameterProfile.TYPE_BOOLEAN);
        profile.setOriginalValue("true");
        profile.setConfidence(0.9);

        List<String> mutations = engine.generateMutations(profile);
        assertNotNull(mutations);
        assertTrue(mutations.contains("false"), "Should flip to false");
    }

    @Test
    @Order(4)
    @DisplayName("UUID parameter mutation")
    void testUuidMutation() {
        MinimalMutationEngine engine = new MinimalMutationEngine();
        ParameterProfile profile = new ParameterProfile();
        profile.setParameterName("userId");
        profile.setDetectedType(ParameterProfile.TYPE_UUID);
        profile.setOriginalValue("550e8400-e29b-41d4-a716-446655440000");
        profile.setConfidence(0.9);

        List<String> mutations = engine.generateMutations(profile);
        assertNotNull(mutations);
        assertFalse(mutations.isEmpty());
        // Should contain null UUID variant
        boolean hasNullUuid = mutations.stream().anyMatch(m ->
                m.contains("00000000"));
        assertTrue(hasNullUuid, "Should contain null UUID variant");
    }

    // ============================================================
    // Test 2: Parameter Profiling (Replay context)
    // ============================================================

    @Test
    @Order(5)
    @DisplayName("Parameter profiler - type detection")
    void testParameterProfiler() {
        ParameterProfiler profiler = new ParameterProfiler();

        // Numeric
        ParameterProfile numeric = profiler.profile("id", "42");
        assertEquals(ParameterProfile.TYPE_NUMERIC, numeric.getDetectedType());
        assertTrue(numeric.isMutable());

        // UUID
        ParameterProfile uuid = profiler.profile("userId", "550e8400-e29b-41d4-a716-446655440000");
        assertEquals(ParameterProfile.TYPE_UUID, uuid.getDetectedType());

        // Boolean
        ParameterProfile bool1 = profiler.profile("enabled", "true");
        assertEquals(ParameterProfile.TYPE_BOOLEAN, bool1.getDetectedType());

        ParameterProfile bool2 = profiler.profile("active", "false");
        assertEquals(ParameterProfile.TYPE_BOOLEAN, bool2.getDetectedType());

        // Email
        ParameterProfile email = profiler.profile("email", "test@example.com");
        assertEquals(ParameterProfile.TYPE_EMAIL, email.getDetectedType());

        // URL
        ParameterProfile url = profiler.profile("url", "https://example.com/path");
        assertEquals(ParameterProfile.TYPE_URL, url.getDetectedType());

        // String (default)
        ParameterProfile str = profiler.profile("name", "hello world");
        assertEquals(ParameterProfile.TYPE_STRING, str.getDetectedType());
    }

    @Test
    @Order(6)
    @DisplayName("Parameter profiler - JWT detection")
    void testJwtDetection() {
        ParameterProfiler profiler = new ParameterProfiler();
        ParameterProfile jwt = profiler.profile("token",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
        assertEquals(ParameterProfile.TYPE_JWT, jwt.getDetectedType());
        assertFalse(jwt.isMutable(), "JWT should not be mutable");
    }

    // ============================================================
    // Test 3: Influence Diff
    // ============================================================

    @Test
    @Order(7)
    @DisplayName("Influence diff - status code change")
    void testInfluenceDiffStatusChange() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();

        byte[] original = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n{\"result\":\"ok\"}".getBytes();
        byte[] mutated = "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n\r\n{\"error\":\"access denied\"}".getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 150);
        assertTrue(result.isStatusChanged(), "Status should be changed");
        assertTrue(result.isSignificant(), "Should be significant diff");
        assertTrue(result.getSimilarity() < 0.85, "Similarity should be low");
    }

    @Test
    @Order(8)
    @DisplayName("Influence diff - no significant change")
    void testInfluenceDiffNoChange() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();

        byte[] original = "HTTP/1.1 200 OK\r\n\r\n{\"key\":\"value\"}".getBytes();
        byte[] mutated = "HTTP/1.1 200 OK\r\n\r\n{\"key\":\"value\"}".getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 105);
        assertFalse(result.isSignificant(), "Identical responses should not be significant");
        assertEquals(1.0, result.getSimilarity(), 0.01, "Similarity should be ~1.0");
    }

    @Test
    @Order(9)
    @DisplayName("Influence diff - length change detection")
    void testInfluenceDiffLengthChange() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();

        byte[] original = "HTTP/1.1 200 OK\r\n\r\nshort".getBytes();
        byte[] mutated = "HTTP/1.1 200 OK\r\n\r\nmuch longer response with significantly more content".getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 120);
        assertTrue(result.isLengthChanged(), "Length should be detected as changed");
        assertTrue(result.isSignificant());
    }

    @Test
    @Order(9)
    @DisplayName("Influence diff - dynamic JSON noise is ignored")
    void testInfluenceDiffDynamicJsonNoiseIgnored() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();
        InfluenceScorer scorer = new InfluenceScorer();

        byte[] original = (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"status\":\"ok\",\"requestId\":\"550e8400-e29b-41d4-a716-446655440000\"," +
                "\"timestamp\":\"2026-05-12T12:00:00Z\",\"data\":{\"id\":1,\"name\":\"alice\"}}"
        ).getBytes();
        byte[] mutated = (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"status\":\"ok\",\"requestId\":\"550e8400-e29b-41d4-a716-446655440001\"," +
                "\"timestamp\":\"2026-05-12T12:00:01Z\",\"data\":{\"id\":1,\"name\":\"alice\"}}"
        ).getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 110);
        assertFalse(result.isSignificant(), "Dynamic noise-only JSON changes should not be significant");
        assertEquals(0, result.getStableChangeCount(), "No stable changed paths expected");
        assertTrue(result.getNoiseChangeCount() >= 2, "requestId/timestamp should be classified as noise");
        assertEquals(0.0, scorer.score(result), 0.01, "Noise-only diff should score zero");
    }

    @Test
    @Order(9)
    @DisplayName("Influence diff - stable JSON field changes are extracted")
    void testInfluenceDiffStableJsonChangesExtracted() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();
        InfluenceScorer scorer = new InfluenceScorer();

        byte[] original = (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"status\":\"ok\",\"user\":{\"id\":1,\"role\":\"user\",\"amount\":10}}"
        ).getBytes();
        byte[] mutated = (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"status\":\"forbidden\",\"user\":{\"id\":1,\"role\":\"admin\",\"amount\":999}}"
        ).getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 110);
        assertTrue(result.isSignificant(), "Stable business field changes should be significant");
        assertTrue(result.getChangedPaths().contains("$.status"));
        assertTrue(result.getChangedPaths().contains("$.user.role"));
        assertTrue(result.getChangedPaths().contains("$.user.amount"));
        assertFalse(result.getDiffSummary().isEmpty(), "Diff summary should be available for advisory LLM");
        assertTrue(scorer.score(result) > 0.1, "Stable changes should receive non-zero score");
    }

    @Test
    @Order(9)
    @DisplayName("Influence diff - dynamic text tokens are normalized")
    void testInfluenceDiffDynamicTextTokensIgnored() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();
        InfluenceScorer scorer = new InfluenceScorer();

        byte[] original = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>trace=550e8400-e29b-41d4-a716-446655440000 time=2026-05-12T12:00:00Z</html>".getBytes();
        byte[] mutated = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>trace=550e8400-e29b-41d4-a716-446655440001 time=2026-05-12T12:00:01Z</html>".getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 110);
        assertFalse(result.isSignificant(), "Dynamic text token changes should be normalized away");
        assertEquals(0.0, scorer.score(result), 0.01);
    }

    // ============================================================
    // Test 4: Influence Score
    // ============================================================

    @Test
    @Order(10)
    @DisplayName("Influence scorer - high influence")
    void testInfluenceScorerHigh() {
        InfluenceScorer scorer = new InfluenceScorer();
        DiffResult diff = new DiffResult();
        diff.setStatusChanged(true);
        diff.setLengthChanged(true);
        diff.setStructureChanged(true);
        diff.setKeywordChanged(true);
        diff.setSimilarity(0.3);
        diff.setResponseTimeDiff(500);

        double score = scorer.score(diff);
        assertTrue(score > 0.7, "Should have high influence score, got: " + score);
    }

    @Test
    @Order(11)
    @DisplayName("Influence scorer - no influence")
    void testInfluenceScorerNone() {
        InfluenceScorer scorer = new InfluenceScorer();
        DiffResult diff = new DiffResult();
        diff.setStatusChanged(false);
        diff.setLengthChanged(false);
        diff.setStructureChanged(false);
        diff.setKeywordChanged(false);
        diff.setSimilarity(1.0);
        diff.setResponseTimeDiff(0);

        double score = scorer.score(diff);
        assertEquals(0.0, score, 0.01, "Should have zero influence score");
    }

    @Test
    @Order(12)
    @DisplayName("Influence scorer - partial influence")
    void testInfluenceScorerPartial() {
        InfluenceScorer scorer = new InfluenceScorer();
        DiffResult diff = new DiffResult();
        diff.setStatusChanged(true);
        diff.setLengthChanged(false);
        diff.setStructureChanged(false);
        diff.setKeywordChanged(false);
        diff.setSimilarity(0.95);
        diff.setResponseTimeDiff(100);

        double score = scorer.score(diff);
        assertTrue(score >= 0.30, "Status change alone should give moderate score, got: " + score);
        assertTrue(score <= 0.50);

        // Test scoreDetails doesn't throw
        String details = scorer.scoreDetails(diff);
        assertNotNull(details);
        assertTrue(details.contains("Status"));
    }

    @Test
    @Order(13)
    @DisplayName("Influence scorer - scoreMultiple")
    void testInfluenceScorerMultiple() {
        InfluenceScorer scorer = new InfluenceScorer();

        DiffResult diff1 = new DiffResult();
        diff1.setStatusChanged(true);
        diff1.setSimilarity(0.5);

        DiffResult diff2 = new DiffResult();
        diff2.setLengthChanged(true);
        diff2.setStableChangeCount(3);
        diff2.setSimilarity(0.7);

        double avgScore = scorer.scoreMultiple(diff1, diff2);
        assertTrue(avgScore > 0.25, "Average should be above minimum, got: " + avgScore);
    }

    @Test
    @Order(13)
    @DisplayName("Influence scorer - length-only diff is not influence")
    void testInfluenceScorerLengthOnlyIgnored() {
        InfluenceScorer scorer = new InfluenceScorer();
        DiffResult diff = new DiffResult();
        diff.setLengthChanged(true);
        diff.setSimilarity(0.5);

        assertEquals(0.0, scorer.score(diff), 0.01,
                "Length-only changes should not approve influence without stable signals");
    }

    // ============================================================
    // Test 5: Strategy Approval
    // ============================================================

    @Test
    @Order(14)
    @DisplayName("Strategy approval - approve valid parameter")
    void testStrategyApprovalApprove() {
        StrategyApprovalEngine engine = new StrategyApprovalEngine();

        ParameterProfile profile = new ParameterProfile();
        profile.setMutable(true);

        InfluenceResult result = new InfluenceResult();
        result.setParameterName("id");
        result.setInfluenceScore(0.85);
        result.setReplaySuccess(true);

        InfluenceResult approved = engine.approve(result, profile, 0.1);
        assertTrue(approved.isApproved(), "Parameter with high influence should be approved");
    }

    @Test
    @Order(15)
    @DisplayName("Strategy approval - reject low influence")
    void testStrategyApprovalRejectLowInfluence() {
        StrategyApprovalEngine engine = new StrategyApprovalEngine();

        ParameterProfile profile = new ParameterProfile();
        profile.setMutable(true);

        InfluenceResult result = new InfluenceResult();
        result.setParameterName("dummy");
        result.setInfluenceScore(0.03);
        result.setReplaySuccess(true);

        InfluenceResult approved = engine.approve(result, profile, 0.1);
        assertFalse(approved.isApproved(), "Low influence parameter should be rejected");
        assertNotNull(approved.getApprovalReason());
    }

    @Test
    @Order(16)
    @DisplayName("Strategy approval - reject non-mutable parameter")
    void testStrategyApprovalRejectImmutable() {
        StrategyApprovalEngine engine = new StrategyApprovalEngine();

        ParameterProfile profile = new ParameterProfile();
        profile.setMutable(false);
        profile.setDetectedType(ParameterProfile.TYPE_JWT);

        InfluenceResult result = new InfluenceResult();
        result.setParameterName("token");
        result.setInfluenceScore(0.5);
        result.setReplaySuccess(true);

        InfluenceResult approved = engine.approve(result, profile, 0.1);
        assertFalse(approved.isApproved(), "Non-mutable parameter should be rejected");
    }

    @Test
    @Order(17)
    @DisplayName("Strategy approval - reject failed replay")
    void testStrategyApprovalRejectFailedReplay() {
        StrategyApprovalEngine engine = new StrategyApprovalEngine();

        ParameterProfile profile = new ParameterProfile();
        profile.setMutable(true);

        InfluenceResult result = new InfluenceResult();
        result.setParameterName("id");
        result.setInfluenceScore(0.8);
        result.setReplaySuccess(false);

        InfluenceResult approved = engine.approve(result, profile, 0.1);
        assertFalse(approved.isApproved(), "Failed replay should cause rejection");
    }

    // ============================================================
    // Test 7: Workflow Step (StepResult model)
    // ============================================================

    @Test
    @Order(18)
    @DisplayName("Workflow step - success result")
    void testStepResultSuccess() {
        StepResult result = StepResult.success("BooleanBased", "Boolean injection detected");
        assertTrue(result.isSuccess());
        assertTrue(result.isContinueWorkflow());
        assertEquals("BooleanBased", result.getStepName());
    }

    @Test
    @Order(19)
    @DisplayName("Workflow step - hard fail stops workflow")
    void testStepResultHardFail() {
        StepResult result = StepResult.hardFail("InfluenceValidation",
                "Parameter has no influence on response");
        assertFalse(result.isSuccess());
        assertFalse(result.isContinueWorkflow(), "Hard fail should stop workflow");
    }

    @Test
    @Order(20)
    @DisplayName("Workflow step - soft fail continues workflow")
    void testStepResultSoftFail() {
        StepResult result = StepResult.softFail("ErrorBased", "Error technique not applicable");
        assertFalse(result.isSuccess());
        assertTrue(result.isContinueWorkflow(), "Soft fail should continue workflow");
    }

    @Test
    @Order(21)
    @DisplayName("Workflow step - evidence collection")
    void testStepResultEvidence() {
        StepResult result = StepResult.success("TestStep", "Testing");
        Evidence evidence = Evidence.statusChanged("200", "403");
        result.addEvidence(evidence);
        assertEquals(1, result.getEvidences().size());
        assertEquals("STATUS_CHANGE", result.getEvidences().get(0).getEvidenceType());
    }

    // ============================================================
    // Test 9: Evicence Model
    // ============================================================

    @Test
    @Order(22)
    @DisplayName("Evidence - factory methods")
    void testEvidenceFactoryMethods() {
        Evidence statusEvidence = Evidence.statusChanged("200", "403");
        assertEquals("STATUS_CHANGE", statusEvidence.getEvidenceType());
        assertTrue(statusEvidence.getConfidence() > 0.8);

        Evidence lengthEvidence = Evidence.lengthChanged(1000, 5000);
        assertEquals("LENGTH_CHANGE", lengthEvidence.getEvidenceType());

        Evidence structEvidence = Evidence.structureChanged("Added 'error' key in root");
        assertEquals("STRUCTURE_CHANGE", structEvidence.getEvidenceType());

        Evidence keywordEvidence = Evidence.keywordMatched("error", "response body");
        assertEquals("KEYWORD_MATCH", keywordEvidence.getEvidenceType());

        Evidence timingEvidence = Evidence.timingChanged(500);
        assertEquals("TIMING_CHANGE", timingEvidence.getEvidenceType());
    }

    // ============================================================
    // Test 10: JSON Response Analysis
    // ============================================================

    @Test
    @Order(23)
    @DisplayName("JSON structure diff - structure changed")
    void testJsonStructureDiff() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();

        byte[] original = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\",\"id\":1}".getBytes();
        byte[] mutated = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\",\"id\":1,\"error\":\"not found\"}".getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 110);
        assertTrue(result.isStructureChanged() || result.isLengthChanged() || result.isKeywordChanged(),
                "JSON key change should be detected");
    }

    @Test
    @Order(24)
    @DisplayName("JSON structure diff - no change")
    void testJsonStructureNoDiff() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();

        byte[] original = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}".getBytes();
        byte[] mutated = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}".getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 105);
        assertFalse(result.isSignificant(), "Identical JSON should not be significant");
    }

    // ============================================================
    // Test 11: Header Change Detection
    // ============================================================

    @Test
    @Order(25)
    @DisplayName("Header change detection")
    void testHeaderChangeDetection() {
        InfluenceDiffEngine engine = new InfluenceDiffEngine();

        byte[] original = (
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                "X-Request-ID: abc123\r\n" +
                "\r\n" +
                "{\"status\":\"ok\"}"
        ).getBytes();

        byte[] mutated = (
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/html\r\n" +
                "X-Request-ID: abc123\r\n" +
                "\r\n" +
                "<html><body><h1>Error</h1>An error occurred</body></html>"
        ).getBytes();

        DiffResult result = engine.analyze(original, mutated, 100, 110);
        // Content-Type changed (json閳姍tml), body structure changed 閳?should be detected
        assertTrue(result.isSignificant() || result.isStructureChanged() || result.isKeywordChanged(),
                "Header and body structure changes should be detected");
    }

    // ============================================================
    // Test 12: Model Validation
    // ============================================================

    @Test
    @Order(26)
    @DisplayName("CandidateParameter model")
    void testCandidateParameterModel() {
        CandidateParameter cp = new CandidateParameter();
        cp.setParameterName("id");
        cp.setParameterType("QUERY");
        cp.setAttackType(AttackType.SQLI);
        cp.setConfidence(0.85);
        cp.setSource("AI_RECOMMENDATION");

        assertEquals("id", cp.getParameterName());
        assertEquals(AttackType.SQLI, cp.getAttackType());
        assertEquals(0.85, cp.getConfidence(), 0.001);
    }

    @Test
    @Order(27)
    @DisplayName("ParameterProfile model")
    void testParameterProfileModel() {
        ParameterProfile profile = new ParameterProfile();
        profile.setParameterName("id");
        profile.setDetectedType(ParameterProfile.TYPE_NUMERIC);
        profile.setConfidence(0.95);
        profile.setMutable(true);
        profile.setOriginalValue("42");

        assertTrue(profile.isMutable());
        assertEquals("42", profile.getOriginalValue());
    }

    @Test
    @Order(28)
    @DisplayName("WorkflowDefinition model")
    void testWorkflowDefinitionModel() {
        WorkflowDefinition def = new WorkflowDefinition();
        def.setAttackType(AttackType.SQLI);
        def.setName("SQLI Workflow");
        def.setStepNames(List.of("InfluenceValidation", "BooleanBased", "ErrorBased"));

        assertEquals(3, def.getStepNames().size());
        assertTrue(def.isRequiresInfluenceApproval());
        assertEquals("InfluenceValidation", def.getStepNames().get(0));
    }

    @Test
    @Order(29)
    @DisplayName("WorkflowResult model")
    void testWorkflowResultModel() {
        WorkflowResult result = new WorkflowResult();
        result.setAttackType(AttackType.SQLI);
        result.setParameterName("id");
        result.setCompleted(true);
        result.setOverallConfidence(0.75);

        StepResult step1 = StepResult.success("Step1", "ok");
        StepResult step2 = StepResult.success("Step2", "ok too");

        result.getStepResults().add(step1);
        result.getStepResults().add(step2);
        result.collectEvidence();

        assertEquals(2, result.getStepResults().size());
        assertTrue(result.isCompleted());
    }

    @Test
    @Order(30)
    @DisplayName("VerificationPolicy model")
    void testVerificationPolicyModel() {
        VerificationPolicy policy = new VerificationPolicy();
        policy.setAllowTimeBased(false);
        policy.setAllowUnionBased(false);
        policy.setAllowErrorBased(true);
        policy.setMaxReplayRequests(5);
        policy.setMinInfluenceScore(0.1);

        assertTrue(policy.isAllowErrorBased());
        assertFalse(policy.isAllowTimeBased());
        assertFalse(policy.isAllowUnionBased());
        assertEquals(5, policy.getMaxReplayRequests());
    }

    @Test
    @Order(31)
    @DisplayName("XSS workflow is registered when payload rules exist")
    void testXssWorkflowRegistered() {
        WorkflowRegistry registry = WorkflowRegistry.fromRules(new YamlPayloadRuleEngine());
        assertTrue(registry.findWorkflow(AttackType.XSS).isPresent(),
                "XSS payload rules must have a matching workflow");
    }

    @Test
    @Order(32)
    @DisplayName("XSS probe step is created by workflow factory")
    void testXssStepFactoryRegistration() {
        WorkflowStepFactory factory = new WorkflowStepFactory(new ReplayEngine());
        factory.setPayloadRuleEngine(new YamlPayloadRuleEngine());

        assertNotNull(factory.createXssProbeStep(),
                "XSS workflow must have an executable VerificationStep");
    }

    @Test
    @Order(33)
    @DisplayName("Rule capability catalog exposes only locally backed capabilities")
    void testRuleCapabilityCatalog() {
        RuleCapabilityCatalog catalog = new RuleCapabilityCatalog(
                null, new YamlPayloadRuleEngine());

        assertTrue(catalog.supportsTechnique(AttackType.XSS, VerificationTechnique.REFLECTION));
        assertTrue(catalog.supportsTechnique(
                AttackType.PATH_TRAVERSAL, VerificationTechnique.PATH_TRAVERSAL_PROBE));
        assertFalse(catalog.supportsTechnique(AttackType.XSS, VerificationTechnique.TIME_BASED));

        String promptConstraint = catalog.toPromptConstraint();
        assertTrue(promptConstraint.contains("AllowedAttackTypes"));
        assertTrue(promptConstraint.contains("SQLI"));
        assertFalse(promptConstraint.contains("BOOLEAN_BASED"));
        assertFalse(promptConstraint.contains("generic_boolean_pair"));
    }

    @Test
    @Order(34)
    @DisplayName("AI capability filter drops unsupported recommendations")
    void testAnalysisCapabilityFilter() {
        RuleCapabilityCatalog catalog = new RuleCapabilityCatalog(
                null, new YamlPayloadRuleEngine());
        AnalysisResult result = new AnalysisResult();
        result.setPossibleVulnerabilities(List.of("XSS -> q", "UNSUPPORTED_CUSTOM -> xml"));
        result.setRecommendedTechniques(List.of(
                new TechniqueRecommendation("q", AttackType.XSS,
                        VerificationTechnique.REFLECTION, 0.8, "supported"),
                new TechniqueRecommendation("q", AttackType.XSS,
                        VerificationTechnique.TIME_BASED, 0.8, "unsupported")
        ));

        new AnalysisResultCapabilityFilter(catalog).filter(result);

        assertEquals(1, result.getPossibleVulnerabilities().size());
        assertEquals(1, result.getRecommendedTechniques().size());
        assertEquals(VerificationTechnique.REFLECTION,
                result.getRecommendedTechniques().get(0).getTechnique());
    }

    @Test
    @Order(35)
    @DisplayName("AI capability filter corrects parameter value mistaken as name")
    void testAnalysisCapabilityFilterCorrectsValueAsParameterName() {
        RuleCapabilityCatalog catalog = new RuleCapabilityCatalog(
                null, new YamlPayloadRuleEngine());
        HTTPContext context = new HTTPContext();
        context.addParameter(new ParameterContext("name", "asd", ParameterType.QUERY));

        AnalysisResult result = new AnalysisResult();
        result.setHighValueParams(List.of(
                new AnalysisResult.HighValueParam("asd", "reflected value", com.aiburpcopilot.core.context.RiskLevel.HIGH)
        ));
        result.setPossibleVulnerabilities(List.of("XSS -> asd"));
        result.setRecommendedTechniques(List.of(
                new TechniqueRecommendation("asd", AttackType.XSS,
                        VerificationTechnique.REFLECTION, 0.8, "value mistaken as parameter")
        ));

        new AnalysisResultCapabilityFilter(catalog).filter(result, context);

        assertEquals("name", result.getHighValueParams().get(0).getParamName());
        assertEquals(List.of("XSS -> name"), result.getPossibleVulnerabilities());
        assertEquals("name", result.getRecommendedTechniques().get(0).getParameterName());
    }

    @Test
    @Order(36)
    @DisplayName("AI capability filter resolves combined Chinese aliases")
    void testAnalysisCapabilityFilterChineseAliasContains() {
        RuleCapabilityCatalog catalog = new RuleCapabilityCatalog(
                null, new YamlPayloadRuleEngine());
        HTTPContext context = new HTTPContext();
        context.addParameter(new ParameterContext("id", "1", ParameterType.QUERY));

        AnalysisResult result = new AnalysisResult();
        result.setPossibleVulnerabilities(List.of(
                "SQL注入 -> id",
                "IDOR越权 -> id",
                "认证绕过 -> id（结合会话权限）"
        ));

        new AnalysisResultCapabilityFilter(catalog).filter(result, context);

        assertEquals(List.of("SQLI -> id", "IDOR -> id", "AUTH -> id"),
                result.getPossibleVulnerabilities());
    }

    @Test
    @Order(36)
    @DisplayName("Endpoint dedup uses method origin path and parameter schema")
    void testEndpointDedupFingerprint() {
        HTTPContext first = new HTTPContext();
        first.setMethod("GET");
        first.setUrl("http://example.com/app?id=1");
        first.setPath("/app");
        first.addParameter(new ParameterContext("id", "1", ParameterType.QUERY));

        HTTPContext second = new HTTPContext();
        second.setMethod("GET");
        second.setUrl("http://example.com/app?id=2");
        second.setPath("/app");
        second.addParameter(new ParameterContext("id", "2", ParameterType.QUERY));

        EndpointDedupStage stage = new EndpointDedupStage();
        stage.process(first);
        stage.process(second);

        assertNotEquals(com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED, first.getAnalysisStatus());
        assertEquals(com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED, second.getAnalysisStatus());
    }

    @Test
    @Order(36)
    @DisplayName("Endpoint dedup collapses numeric URI templates")
    void testEndpointDedupUriTemplate() {
        HTTPContext first = new HTTPContext();
        first.setMethod("GET");
        first.setUrl("http://example.com/users/1001");
        first.setPath("/users/1001");

        HTTPContext second = new HTTPContext();
        second.setMethod("GET");
        second.setUrl("http://example.com/users/1002");
        second.setPath("/users/1002");

        EndpointDedupStage stage = new EndpointDedupStage();
        stage.process(first);
        stage.process(second);

        assertNotEquals(com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED, first.getAnalysisStatus());
        assertEquals(com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED, second.getAnalysisStatus());
    }

    @Test
    @Order(37)
    @DisplayName("Form body params are typed as BODY")
    void testFormBodyParamsAreBodyType() {
        List<ParameterContext> params = HttpUtil.parseFormBodyParams("name=asd&id=1");

        assertEquals(2, params.size());
        assertEquals("name", params.get(0).getName());
        assertEquals(ParameterType.BODY, params.get(0).getType());
        assertEquals("id", params.get(1).getName());
        assertEquals(ParameterType.BODY, params.get(1).getType());
    }

    @Test
    @Order(37)
    @DisplayName("JSON body params include nested dot paths")
    void testJsonBodyParamsIncludeNestedPaths() {
        List<ParameterContext> params = HttpUtil.parseJsonBodyParams(
                "{\"user\":{\"id\":1,\"name\":\"alice\"},\"active\":true}");

        assertTrue(params.stream().anyMatch(p ->
                "user.id".equals(p.getName()) && "1".equals(p.getValue())
                        && p.getType() == ParameterType.BODY));
        assertTrue(params.stream().anyMatch(p ->
                "user.name".equals(p.getName()) && "alice".equals(p.getValue())
                        && p.getType() == ParameterType.BODY));
        assertTrue(params.stream().anyMatch(p ->
                "active".equals(p.getName()) && "true".equals(p.getValue())
                        && p.getType() == ParameterType.BODY));
    }

    @Test
    @Order(38)
    @DisplayName("Path traversal workflow and step are available")
    void testPathTraversalWorkflowAndStep() {
        WorkflowRegistry registry = WorkflowRegistry.fromRules(new YamlPayloadRuleEngine());
        assertTrue(registry.findWorkflow(AttackType.PATH_TRAVERSAL).isPresent());

        WorkflowStepFactory factory = new WorkflowStepFactory(new ReplayEngine());
        factory.setPayloadRuleEngine(new YamlPayloadRuleEngine());
        assertNotNull(factory.createPathTraversalProbeStep());
    }

    @Test
    @Order(39)
    @DisplayName("SQLI workflow only references registered executable steps")
    void testSqliWorkflowStepsRegistered() {
        WorkflowStepFactory factory = new WorkflowStepFactory(new ReplayEngine());
        factory.setPayloadRuleEngine(new YamlPayloadRuleEngine());

        var engine = factory.createEngine();
        var registry = WorkflowRegistry.fromRules(new YamlPayloadRuleEngine());
        var workflow = registry.findWorkflow(AttackType.SQLI).orElseThrow();

        assertTrue(workflow.getStepNames().contains("SQLIProbes"));
        assertFalse(workflow.getStepNames().contains("ErrorBased"),
                "SQLI workflow should use the generic probe step instead of legacy ErrorBased");
        assertFalse(workflow.getStepNames().contains("TimeBased"),
                "SQLI workflow must not reference unimplemented TimeBased step");
        for (String stepName : workflow.getStepNames()) {
            if ("InfluenceValidation".equals(stepName)) {
                continue;
            }
            assertNotNull(engine.findStep(stepName), "Missing step implementation: " + stepName);
        }
    }

    @Test
    @Order(40)
    @DisplayName("Generic SQLI probe step is backed by YAML payload rules")
    void testErrorBasedStepFactoryRegistration() {
        WorkflowStepFactory factory = new WorkflowStepFactory(new ReplayEngine());
        factory.setPayloadRuleEngine(new YamlPayloadRuleEngine());

        assertNotNull(factory.createSqliProbeStep(),
                "SQLI generic probe workflow step must be executable");
    }

    @Test
    @Order(41)
    @DisplayName("Probe YAML loads applicability and LLM review fields")
    void testProbeRuleApplicabilityFieldsLoaded() {
        YamlPayloadRuleEngine ruleEngine = new YamlPayloadRuleEngine();

        var sqliIntegerProbe = ruleEngine.getProbes(AttackType.SQLI).stream()
                .filter(probe -> "generic_boolean_pair_integer".equals(probe.getId()))
                .findFirst()
                .orElseThrow();
        assertTrue(sqliIntegerProbe.getApplicableParamTypes().contains("QUERY"));
        assertEquals(List.of("NUMERIC"), sqliIntegerProbe.getValueTypes());
        assertTrue(sqliIntegerProbe.isRequiresLlmReview());
        assertEquals("APPEND", sqliIntegerProbe.getPayloadPairs().get(0).getTrueMutation());

        var idorProbe = ruleEngine.getProbes(AttackType.IDOR).stream()
                .filter(probe -> "idor_numeric_neighbor_plus".equals(probe.getId()))
                .findFirst()
                .orElseThrow();
        assertEquals(List.of("NUMERIC"), idorProbe.getValueTypes());
        assertTrue(idorProbe.isRequiresLlmReview());

        var sqliErrorProbe = ruleEngine.getProbes(AttackType.SQLI).stream()
                .filter(probe -> "generic_quote_error_recovery".equals(probe.getId()))
                .findFirst()
                .orElseThrow();
        assertEquals("WEAK", sqliErrorProbe.getStrength());

        var uploadProbe = ruleEngine.getProbes("FILE_UPLOAD").stream()
                .filter(probe -> "upload_extension_marker_probe".equals(probe.getId()))
                .findFirst()
                .orElseThrow();
        assertTrue(uploadProbe.getHttpMethods().contains("POST"));
    }

    @Test
    @Order(42)
    @DisplayName("Auth probes are rule-backed and enabled by default")
    void testAuthProbesEnabledByDefault() {
        RuleCapabilityCatalog catalog = new RuleCapabilityCatalog(
                null, new YamlPayloadRuleEngine());

        assertTrue(catalog.supportsAttackType(AttackType.AUTH));
    }

    @Test
    @Order(43)
    @DisplayName("External payload rule reload updates probe filters and catalog capabilities")
    void testExternalPayloadRuleReloadUpdatesRuntimeViews() throws Exception {
        Path previousHome = ExternalResourcePaths.homeDirOrNull();
        Path tempHome = Files.createTempDirectory("aiburpcopilot-rule-reload");
        try {
            ExternalResourcePaths.setManualHomeDir(tempHome);
            Path sqliRule = tempHome.resolve("rules").resolve("payloads").resolve("sqli.yaml");
            Files.createDirectories(sqliRule.getParent());
            Files.writeString(sqliRule, """
                    attackType: SQLI
                    aliases: [SQL]
                    probes:
                      - id: generic_quote_error_recovery
                        technique: ERROR_BASED
                        strategy: ERROR_BASED
                        applicableParamTypes: [QUERY, BODY, PATH]
                        valueTypes: [STRING, EMAIL, URL, UNKNOWN]
                        payloads:
                          - value: "'"
                            role: TRIGGER
                            mutation: APPEND
                        oracle:
                          type: ERROR_KEYWORD
                          minConfidence: 0.78
                    """, StandardCharsets.UTF_8);

            YamlPayloadRuleEngine ruleEngine = new YamlPayloadRuleEngine();
            RuleCapabilityCatalog catalog = new RuleCapabilityCatalog(null, ruleEngine);

            String updated = Files.readString(sqliRule, StandardCharsets.UTF_8)
                    .replace("valueTypes: [STRING, EMAIL, URL, UNKNOWN]",
                            "valueTypes: [STRING, EMAIL, URL, UNKNOWN, NUMERIC]");
            Files.writeString(sqliRule, updated, StandardCharsets.UTF_8);

            ruleEngine.reload();

            var reloadedProbe = ruleEngine.getProbes(AttackType.SQLI).stream()
                    .filter(probe -> "generic_quote_error_recovery".equals(probe.getId()))
                    .findFirst()
                    .orElseThrow();

            assertTrue(reloadedProbe.getValueTypes().contains("NUMERIC"));
            assertTrue(catalog.supportsAttackType(AttackType.SQLI));
            assertTrue(catalog.supportsStrategy("SQLI", "ERROR_BASED"));
        } finally {
            ExternalResourcePaths.setManualHomeDir(previousHome);
        }
    }

    @Test
    @Order(44)
    @DisplayName("File upload candidate falls back to multipart body field when AI omits parameter name")
    void testFileUploadCandidateFallsBackToMultipartBodyField() {
        HTTPContext context = new HTTPContext();
        context.setMethod("POST");
        context.setUrl("http://example.test/upload");
        context.setPath("/upload");
        context.addParameter(new ParameterContext("uploaded", "demo.txt", ParameterType.BODY));

        AnalysisResult result = new AnalysisResult();
        result.setPossibleVulnerabilities(List.of("文件上传"));
        context.setAnalysisResult(result);

        CandidateExtractor extractor = new CandidateExtractor(
                new RuleCapabilityCatalog(null, new YamlPayloadRuleEngine()));
        List<CandidateParameter> candidates = extractor.extract(context);

        assertTrue(candidates.stream().anyMatch(candidate ->
                        "FILE_UPLOAD".equals(candidate.getAttackTypeName())
                                && "uploaded".equals(candidate.getParameterName())),
                "FILE_UPLOAD should fall back to multipart body parameter when AI provides endpoint-level hint");
    }

    @Test
    @Order(42)
    @DisplayName("Endpoint-level AUTH vulnerability hint should not be dropped")
    void testEndpointLevelAuthHintShouldBePreserved() {
        RuleCapabilityCatalog catalog = new RuleCapabilityCatalog(
                null, new YamlPayloadRuleEngine());
        AnalysisResult result = new AnalysisResult();
        result.setPossibleVulnerabilities(List.of("AUTH绕过 -> 整个端点（缺少会话验证）"));

        new AnalysisResultCapabilityFilter(catalog).filter(result, new HTTPContext());

        assertEquals(List.of("AUTH"), result.getPossibleVulnerabilities());
    }

    @Test
    @Order(42)
    @DisplayName("Candidate extraction should not convert XSS surface text into SQLI candidate")
    void testCandidateExtractionDoesNotUseAttackSurfaceAsVerificationHint() {
        HTTPContext context = new HTTPContext();
        context.setMethod("GET");
        context.setUrl("http://example.test/xss_r/?name=aaa");
        context.setPath("/xss_r/");
        context.addParameter(new ParameterContext("name", "aaa", ParameterType.QUERY));

        AnalysisResult result = new AnalysisResult();
        result.setAttackSurface(List.of("XSS reflection and user controlled injection surface"));
        result.setHighValueParams(List.of(
                new AnalysisResult.HighValueParam("name", "reflected parameter", RiskLevel.HIGH)));
        result.setPossibleVulnerabilities(List.of("XSS -> name"));
        context.setAnalysisResult(result);

        CandidateExtractor extractor = new CandidateExtractor(
                new RuleCapabilityCatalog(null, new YamlPayloadRuleEngine()));
        List<CandidateParameter> candidates = extractor.extract(context);

        assertTrue(candidates.stream().anyMatch(candidate ->
                "XSS".equals(candidate.getAttackTypeName())
                        && "name".equals(candidate.getParameterName())));
        assertFalse(candidates.stream().anyMatch(candidate ->
                "SQLI".equals(candidate.getAttackTypeName())
                        && "name".equals(candidate.getParameterName())));
    }

    @Test
    @Order(42)
    @DisplayName("Finding aggregation ignores influence-only evidence")
    void testFindingAggregationIgnoresInfluenceOnlyEvidence() {
        WorkflowResult workflowResult = new WorkflowResult();
        workflowResult.setAttackTypeName("SQLI");
        workflowResult.setParameterName("id");

        StepResult influenceStep = new StepResult();
        influenceStep.setStepName("InfluenceValidation");
        influenceStep.setPhase("Influence Gate");
        influenceStep.setSuccess(true);
        influenceStep.setConfidence(0.95);
        influenceStep.addEvidence(Evidence.general("parameter has business meaning", "INFLUENCE_LLM", 0.95));
        influenceStep.addEvidence(Evidence.general("parameter role looks important", "PARAMETER_ROLE", 0.90));
        workflowResult.getStepResults().add(influenceStep);
        workflowResult.collectEvidence();

        assertNull(new FindingAggregator().aggregate(
                "req-1", "http://example.test/item?id=1", workflowResult));
    }

    @Test
    @Order(42)
    @DisplayName("Finding aggregation uses payload verification evidence only")
    void testFindingAggregationUsesPayloadVerificationEvidenceOnly() {
        WorkflowResult workflowResult = new WorkflowResult();
        workflowResult.setAttackTypeName("XSS");
        workflowResult.setParameterName("name");

        StepResult influenceStep = new StepResult();
        influenceStep.setStepName("InfluenceValidation");
        influenceStep.setPhase("Influence Gate");
        influenceStep.setSuccess(true);
        influenceStep.setConfidence(0.95);
        influenceStep.addEvidence(Evidence.general("parameter role looks important", "PARAMETER_ROLE", 0.90));
        workflowResult.getStepResults().add(influenceStep);

        StepResult payloadStep = new StepResult();
        payloadStep.setStepName("XSSProbes");
        payloadStep.setPhase("Payload Verification");
        payloadStep.setSuccess(true);
        payloadStep.setConfidence(0.80);
        payloadStep.addEvidence(Evidence.general("marker reflected in response", "REFLECTION", 0.80));
        workflowResult.getStepResults().add(payloadStep);
        workflowResult.collectEvidence();

        var finding = new FindingAggregator().aggregate(
                "req-1", "http://example.test/xss?name=aaa", workflowResult);

        assertNotNull(finding);
        assertEquals("XSS", finding.getAttackTypeName());
        assertEquals(1, finding.getEvidences().size());
        assertEquals("REFLECTION", finding.getEvidences().get(0).getEvidenceType());
    }

    @Test
    @Order(42)
    @DisplayName("Probe variables render consistently for payload and oracle")
    void testProbeVariablesRenderConsistentlyForPayloadAndOracle() {
        ProbeDefinition probe = new ProbeDefinition();
        probe.setAttackType(AttackType.XSS);
        probe.setId("xss_random_marker");
        probe.setStrategyName("REFLECTION");
        probe.setMaxRequests(1);
        probe.setEvidenceWeight(1.0);

        ProbePayload payload = new ProbePayload();
        payload.setValue("<{{randAlpha:marker:10}}>");
        payload.setRole(ProbeRole.SINGLE);
        payload.setMarkers(List.of("{{randAlpha:marker:10}}"));
        probe.setPayloads(List.of(payload));

        OracleDefinition oracle = new OracleDefinition();
        oracle.setType("KEYWORD");
        oracle.setKeywords(List.of("{{randAlpha:marker:10}}"));
        oracle.setMinConfidence(0.8);
        probe.setOracle(oracle);

        ReflectingReplayEngine replay = new ReflectingReplayEngine();
        GenericProbeStep step = new GenericProbeStep(
                "XSSProbes",
                AttackType.XSS,
                replay,
                new SingleProbeRuleEngine(probe),
                new ProbeOracleEngine(new InfluenceDiffEngine()),
                null,
                128);

        HTTPContext httpContext = new HTTPContext();
        httpContext.setMethod("GET");
        httpContext.setUrl("http://example.test/search?q=base");
        httpContext.setPath("/search");
        httpContext.addParameter(new ParameterContext("q", "base", ParameterType.QUERY));
        httpContext.setRawResponse("HTTP/1.1 200 OK\r\n\r\nbaseline".getBytes(StandardCharsets.UTF_8));

        CandidateParameter candidate = new CandidateParameter();
        candidate.setAttackType(AttackType.XSS);
        candidate.setParameterName("q");
        candidate.setParameterType("QUERY");
        candidate.setConfidence(1.0);

        WorkflowContext workflowContext = new WorkflowContext(httpContext, candidate);
        workflowContext.setBaselineResponse(httpContext.getRawResponse());
        workflowContext.setReplayEngine(replay);
        workflowContext.setPayloadVerificationAllowed(true);

        StepResult result = step.execute(workflowContext);

        assertTrue(result.isSuccess());
        assertEquals(1, result.getExchangeRecords().size());
        String payloadValue = result.getExchangeRecords().get(0).getPayload();
        assertNotNull(payloadValue);
        assertFalse(payloadValue.contains("{{"));
        assertTrue(payloadValue.matches("<[A-Za-z]{10}>"));
        String marker = payloadValue.substring(1, payloadValue.length() - 1);
        assertTrue(result.getReasoning().contains("matchedEvidence=1"));
        assertTrue(result.getEvidences().stream().anyMatch(evidence ->
                evidence.getDescription() != null && evidence.getDescription().contains(marker)));
    }

    @Test
    @Order(42)
    @DisplayName("AI analysis prompt includes authoritative parameter contract")
    void testAiAnalysisPromptIncludesParameterContract() {
        CapturingAiProvider aiProvider = new CapturingAiProvider(
                "{\"success\":true,\"highValueParams\":[],\"possibleVulnerabilities\":[],\"recommendedTechniques\":[]}");
        AIAnalysisStage stage = new AIAnalysisStage(
                aiProvider,
                new StubPromptService("Analyze endpoint."),
                new NoopCacheService(),
                new StubConfigService(),
                new RuleCapabilityCatalog(null, new YamlPayloadRuleEngine()));

        HTTPContext context = new HTTPContext();
        context.setMethod("GET");
        context.setEndpointType(com.aiburpcopilot.core.context.EndpointType.ENDPOINT);
        context.setPath("/xss_r/");
        context.setUrl("http://example.test/xss_r/?name=bbb");
        context.setQuery("name=bbb");
        context.addParameter(new ParameterContext("name", "bbb", ParameterType.QUERY));

        stage.process(context);

        assertTrue(aiProvider.lastUserPrompt.contains("[AUTHORITATIVE PARAMETER CONTRACT]"));
        assertTrue(aiProvider.lastUserPrompt.contains("AllowedParameterNames: [name]"));
        assertTrue(aiProvider.lastUserPrompt.contains("ParameterSamples(name=sampleValue): name(QUERY)=bbb"));
        assertFalse(aiProvider.lastUserPrompt.contains("Never output a sample value as a parameter name"));
    }

    @Test
    @Order(42)
    @DisplayName("Rejected LLM finding review should revoke confirmed vulnerability status")
    void testRejectedReviewRevokesConfirmedFinding() {
        VerificationResult result = new VerificationResult();
        result.setAttackTypeName("SQLI");
        result.setParameter("name");
        result.setUrl("http://example.test/xss_r/?name=aaa");
        result.setConfidence(0.95);
        result.setRiskLevel(RiskLevel.CRITICAL);
        result.setConfirmedVulnerability(true);
        result.setReviewStatus(ReviewStatus.PENDING);

        FindingReviewService service = new FindingReviewService(new FixedReviewAiProvider(
                "{\"supported\":false,\"confidence\":0.0,"
                        + "\"conclusion\":\"not SQLI\",\"reasoning\":\"evidence is reflected XSS\","
                        + "\"supportingEvidence\":[],\"counterEvidence\":[\"no SQL evidence\"],"
                        + "\"manualReviewPoints\":[]}"));
        service.review(result);

        assertEquals(ReviewStatus.REJECTED, result.getReviewStatus());
        assertFalse(result.isConfirmedVulnerability());
        assertEquals(0.0, result.getConfidence(), 0.01);
        assertEquals(RiskLevel.INFO, result.getRiskLevel());
        assertEquals(FinalVerdicts.REJECTED, result.getFinalDecision());
    }

    @Test
    @Order(42)
    @DisplayName("Local confirmed finding should be treated as effective before LLM review")
    void testLocalConfirmedFindingVerdict() {
        VerificationResult result = new VerificationResult();
        result.setPhase("Finding");
        result.setAttackTypeName("SQLI");
        result.setParameter("id");
        result.setFindingGenerated(true);
        result.setFindingConfidenceRaw(0.72);
        result.setFindingThreshold(0.55);
        result.setLocalMatched(true);
        result.setReviewStatus(ReviewStatus.PENDING);

        FinalVerdicts.recompute(result);

        assertEquals(FinalVerdicts.LOCAL_CONFIRMED, result.getFinalDecision());
        assertTrue(result.isConfirmedVulnerability());
    }

    @Test
    @Order(42)
    @DisplayName("Manual reject should always win over local finding")
    void testManualRejectedVerdict() {
        VerificationResult result = new VerificationResult();
        result.setPhase("Finding");
        result.setAttackTypeName("SQLI");
        result.setParameter("id");
        result.setFindingGenerated(true);
        result.setFindingConfidenceRaw(0.88);
        result.setFindingThreshold(0.55);
        result.setLocalMatched(true);
        result.setManualConfirmedOverride(Boolean.FALSE);

        FinalVerdicts.recompute(result);

        assertEquals(FinalVerdicts.MANUAL_REJECTED, result.getFinalDecision());
        assertFalse(result.isConfirmedVulnerability());
    }

    @Test
    @Order(42)
    @DisplayName("Below-threshold finding should not become effective")
    void testBelowThresholdFindingVerdict() {
        VerificationResult result = new VerificationResult();
        result.setPhase("Finding");
        result.setAttackTypeName("SQLI");
        result.setParameter("id");
        result.setFindingGenerated(true);
        result.setFindingConfidenceRaw(0.42);
        result.setFindingThreshold(0.55);
        result.setLocalMatched(true);
        result.setReviewStatus(ReviewStatus.PENDING);

        FinalVerdicts.recompute(result);

        assertEquals(FinalVerdicts.BELOW_THRESHOLD, result.getFinalDecision());
        assertFalse(result.isConfirmedVulnerability());
    }

    @Test
    @Order(42)
    @DisplayName("Workflow context keeps original baseline request and response")
    void testWorkflowContextCarriesBaselineArtifacts() {
        HTTPContext httpContext = new HTTPContext();
        httpContext.setRawRequest("GET /demo HTTP/1.1\r\nHost: example.test\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        httpContext.setRawResponse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok".getBytes(StandardCharsets.UTF_8));

        CandidateParameter candidate = new CandidateParameter();
        candidate.setParameterName("id");
        candidate.setAttackType(AttackType.SQLI);

        WorkflowContext workflowContext = new WorkflowContext(httpContext, candidate);

        assertArrayEquals(httpContext.getRawRequest(), workflowContext.getBaselineRequest());
        assertArrayEquals(httpContext.getRawResponse(), workflowContext.getBaselineResponse());
    }

    @Test
    @Order(42)
    @DisplayName("Dynamic GET page falls back to ENDPOINT when AI classification times out")
    void testDynamicGetPageFallsBackToEndpointWhenAiClassificationTimeouts() {
        EndpointClassifier classifier = new EndpointClassifier(
                new TimeoutAiProvider(),
                new StubPromptService(),
                new NoopCacheService(),
                new StubConfigService());

        HTTPContext context = new HTTPContext();
        context.setMethod("GET");
        context.setPath("/DVWA/vulnerabilities/sqli_blind/index.php");
        context.setUrl("http://example.test/DVWA/vulnerabilities/sqli_blind/index.php?id=1");
        context.setQuery("id=1");

        classifier.classify(context);

        assertEquals(com.aiburpcopilot.core.context.EndpointType.ENDPOINT, context.getEndpointType());
    }

    @Test
    @Order(43)
    @DisplayName("Influence gate keeps high-value ID parameters as uncertain when response is unchanged")
    void testInfluenceGateUncertainForSemanticIdWithoutDiff() {
        byte[] response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n鐢ㄦ埛瀛樺湪".getBytes();
        IReplayEngine replay = new FixedReplayEngine(response);
        InfluenceValidationStep step = new InfluenceValidationStep(
                replay,
                new MinimalMutationEngine(),
                new InfluenceDiffEngine(),
                new InfluenceScorer(),
                new StrategyApprovalEngine(),
                0.1);

        HTTPContext httpContext = new HTTPContext();
        httpContext.setMethod("GET");
        httpContext.setUrl("http://example.test/?id=2&Submit=Submit");
        httpContext.setPath("/");
        httpContext.addParameter(new ParameterContext("id", "2", ParameterType.QUERY));

        CandidateParameter candidate = new CandidateParameter();
        candidate.setParameterName("id");
        candidate.setParameterType("QUERY");
        candidate.setAttackType(AttackType.SQLI);
        candidate.setConfidence(0.3);

        WorkflowContext workflowContext = new WorkflowContext(httpContext, candidate);
        workflowContext.setParameterProfile(new ParameterProfiler().profile("id", "2"));

        StepResult result = step.execute(workflowContext);

        assertTrue(result.isContinueWorkflow(),
                "High-value object identifiers should not be pruned only because the response summary is unchanged");
        assertTrue(result.isSuccess());
        assertNotNull(workflowContext.getInfluenceResult());
        assertEquals(InfluenceStatus.UNCERTAIN, workflowContext.getInfluenceResult().getStatus());
        assertTrue(workflowContext.getInfluenceResult().isApproved());
    }

    @Test
    @Order(44)
    @DisplayName("Influence gate rejects low-semantic parameters with no response change")
    void testInfluenceGateRejectsLowSemanticNoDiff() {
        byte[] response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n鐢ㄦ埛瀛樺湪".getBytes();
        IReplayEngine replay = new FixedReplayEngine(response);
        InfluenceValidationStep step = new InfluenceValidationStep(
                replay,
                new MinimalMutationEngine(),
                new InfluenceDiffEngine(),
                new InfluenceScorer(),
                new StrategyApprovalEngine(),
                0.1);

        HTTPContext httpContext = new HTTPContext();
        httpContext.setMethod("GET");
        httpContext.setUrl("http://example.test/?Submit=Submit");
        httpContext.setPath("/");
        httpContext.addParameter(new ParameterContext("Submit", "Submit", ParameterType.QUERY));

        CandidateParameter candidate = new CandidateParameter();
        candidate.setParameterName("Submit");
        candidate.setParameterType("QUERY");
        candidate.setAttackType(AttackType.XSS);
        candidate.setConfidence(0.4);

        WorkflowContext workflowContext = new WorkflowContext(httpContext, candidate);
        workflowContext.setParameterProfile(new ParameterProfiler().profile("Submit", "Submit"));

        StepResult result = step.execute(workflowContext);

        assertFalse(result.isContinueWorkflow());
        assertFalse(result.isSuccess());
        assertEquals(InfluenceStatus.NOT_INFLUENTIAL, workflowContext.getInfluenceResult().getStatus());
    }

    private static class FixedReplayEngine implements IReplayEngine {
        private final byte[] response;
        private byte[] lastRequestBytes = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".getBytes();

        private FixedReplayEngine(byte[] response) {
            this.response = response;
        }

        @Override
        public byte[] replayOriginal(HTTPContext context) {
            return response;
        }

        @Override
        public byte[] replayWithMutation(HTTPContext context, String paramName, String newValue) {
            lastRequestBytes = ("GET /?" + paramName + "=" + newValue
                    + " HTTP/1.1\r\nHost: example.test\r\n\r\n").getBytes();
            return response;
        }

        @Override
        public byte[] replayWithAppendedMutation(HTTPContext context, String paramName, String payloadSuffix) {
            return replayWithMutation(context, paramName, payloadSuffix);
        }

        @Override
        public long getLastReplayDurationMs() {
            return 10;
        }

        @Override
        public byte[] getLastRequestBytes() {
            return lastRequestBytes;
        }

        @Override
        public byte[] getLastResponseBytes() {
            return response;
        }
    }

    private static class ReflectingReplayEngine implements IReplayEngine {
        private byte[] lastRequestBytes = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        private byte[] lastResponseBytes = "HTTP/1.1 200 OK\r\n\r\nbaseline".getBytes(StandardCharsets.UTF_8);

        @Override
        public byte[] replayOriginal(HTTPContext context) {
            return "HTTP/1.1 200 OK\r\n\r\nbaseline".getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public byte[] replayWithMutation(HTTPContext context, String paramName, String newValue) {
            lastRequestBytes = ("GET /search?" + paramName + "=" + newValue
                    + " HTTP/1.1\r\nHost: example.test\r\n\r\n").getBytes(StandardCharsets.UTF_8);
            lastResponseBytes = ("HTTP/1.1 200 OK\r\n\r\n" + newValue).getBytes(StandardCharsets.UTF_8);
            return lastResponseBytes;
        }

        @Override
        public long getLastReplayDurationMs() {
            return 10;
        }

        @Override
        public byte[] getLastRequestBytes() {
            return lastRequestBytes;
        }

        @Override
        public byte[] getLastResponseBytes() {
            return lastResponseBytes;
        }
    }

    private static class SingleProbeRuleEngine implements IProbeRuleEngine {
        private final ProbeDefinition probe;

        private SingleProbeRuleEngine(ProbeDefinition probe) {
            this.probe = probe;
        }

        @Override
        public List<ProbeDefinition> getProbes(String attackTypeName) {
            return List.of(probe);
        }

        @Override
        public void reload() {
        }
    }

    private static class TimeoutAiProvider implements IAIProvider {
        @Override
        public String getProviderName() {
            return "timeout-stub";
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public CompletableFuture<String> classifyEndpoint(String content, String promptTemplate) {
            return CompletableFuture.failedFuture(new java.util.concurrent.TimeoutException("timeout"));
        }

        @Override
        public CompletableFuture<String> analyzeAttackSurface(HTTPContext httpContext, String systemPrompt, String userPrompt) {
            return CompletableFuture.completedFuture("{}");
        }

        @Override
        public CompletableFuture<String> reviewStaticResource(String content, String reviewPrompt) {
            return CompletableFuture.completedFuture("{}");
        }

        @Override
        public CompletableFuture<String> analyzeDiff(String content) {
            return CompletableFuture.completedFuture("{\"matched\":false,\"confidence\":0.0,\"reasoning\":\"stub\"}");
        }
    }

    private static class FixedReviewAiProvider implements IAIProvider {
        private final String reviewResponse;

        private FixedReviewAiProvider(String reviewResponse) {
            this.reviewResponse = reviewResponse;
        }

        @Override
        public String getProviderName() {
            return "fixed-review";
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public CompletableFuture<String> analyzeAttackSurface(HTTPContext context, String systemPrompt, String userPrompt) {
            return CompletableFuture.completedFuture("{}");
        }

        @Override
        public CompletableFuture<String> classifyEndpoint(String aiSummary, String classifierPrompt) {
            return CompletableFuture.completedFuture("ENDPOINT");
        }

        @Override
        public CompletableFuture<String> reviewStaticResource(String content, String reviewPrompt) {
            return CompletableFuture.completedFuture("{}");
        }

        @Override
        public CompletableFuture<String> analyzeDiff(String diffPrompt) {
            return CompletableFuture.completedFuture(reviewResponse);
        }
    }

    private static class StubPromptService implements IPromptService {
        private final String template;

        private StubPromptService() {
            this("classify");
        }

        private StubPromptService(String template) {
            this.template = template;
        }

        @Override
        public Optional<String> loadTemplate(String promptName) {
            return Optional.of(template);
        }

        @Override
        public Optional<String> loadSystemPrompt(String promptName) {
            return Optional.of("");
        }

        @Override
        public Optional<String> loadAndFill(String templateName, java.util.Map<String, String> params) {
            return loadTemplate(templateName);
        }

        @Override
        public List<String> listTemplates() {
            return List.of("endpoint-classifier-v1");
        }

        @Override
        public void reload() {
        }
    }

    private static class NoopCacheService implements ICacheService {
        @Override public Optional<String> get(String key) { return Optional.empty(); }
        @Override public void put(String key, String value) {}
        @Override public void put(String key, String value, long ttlSeconds) {}
        @Override public boolean contains(String key) { return false; }
        @Override public void remove(String key) {}
        @Override public void clear() {}
        @Override public int size() { return 0; }
    }

    private static class CapturingAiProvider implements IAIProvider {
        private final String response;
        private String lastUserPrompt = "";

        private CapturingAiProvider(String response) {
            this.response = response;
        }

        @Override
        public String getProviderName() {
            return "capturing";
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public CompletableFuture<String> analyzeAttackSurface(HTTPContext context, String systemPrompt, String userPrompt) {
            lastUserPrompt = userPrompt;
            return CompletableFuture.completedFuture(response);
        }

        @Override
        public CompletableFuture<String> classifyEndpoint(String aiSummary, String classifierPrompt) {
            return CompletableFuture.completedFuture("ENDPOINT");
        }

        @Override
        public CompletableFuture<String> reviewStaticResource(String content, String reviewPrompt) {
            return CompletableFuture.completedFuture("{}");
        }

        @Override
        public CompletableFuture<String> analyzeDiff(String diffPrompt) {
            return CompletableFuture.completedFuture("{}");
        }
    }

    private static class StubConfigService implements IConfigService {
        private final com.aiburpcopilot.core.config.AppConfig config = new com.aiburpcopilot.core.config.AppConfig();

        @Override
        public com.aiburpcopilot.core.config.AppConfig getConfig() {
            config.getAi().setTimeoutMs(100);
            config.getLlm().setConnectTimeoutMs(10);
            config.getLlm().setReadTimeoutMs(10);
            return config;
        }

        @Override
        public void updateConfig(com.aiburpcopilot.core.config.AppConfig config) {
        }

        @Override
        public void reload() {
        }

        @Override
        public void save() {
        }

        @Override
        public void addChangeListener(IConfigService.ConfigChangeListener listener) {
        }
    }
}
