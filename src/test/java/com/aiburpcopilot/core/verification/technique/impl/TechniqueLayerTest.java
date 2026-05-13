package com.aiburpcopilot.core.verification.technique.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;
import com.aiburpcopilot.core.verification.model.TestStrategy;
import com.aiburpcopilot.core.verification.technique.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Technique 层单元测试。
 * <p>
 * 覆盖：
 * <ol>
 *   <li>BOOLEAN_BASED strategy 生成</li>
 *   <li>ERROR_BASED strategy 生成</li>
 *   <li>TIME_BASED strategy 生成</li>
 *   <li>IDOR NUMERIC_INCREMENT strategy 生成</li>
 *   <li>AUTH REMOVE_TOKEN strategy 生成</li>
 *   <li>多 Technique 场景</li>
 *   <li>无 Technique 场景</li>
 *   <li>Registry 查找</li>
 *   <li>枚举 fromString</li>
 * </ol>
 */
class TechniqueLayerTest {

    private ITechniqueRegistry registry;
    private ITechniqueMapper mapper;

    @BeforeEach
    void setUp() {
        registry = TechniqueRegistry.createDefault();
        mapper = new DefaultTechniqueMapper(registry);
    }

    // ==================== 1. BOOLEAN_BASED ====================

    @Test
    @DisplayName("SQLI BOOLEAN_BASED → BOOLEAN_BASED_MINIMAL")
    void shouldMapSqlBooleanToBooleanBasedMinimal() {
        TechniqueRecommendation rec = new TechniqueRecommendation(
                "userId", AttackType.SQLI,
                VerificationTechnique.BOOLEAN_BASED, 0.92,
                "Parameter likely used in SQL query"
        );

        List<TestStrategy> strategies = mapper.mapToStrategies(List.of(rec));

        assertEquals(1, strategies.size());
        TestStrategy s = strategies.get(0);
        assertEquals(AttackType.SQLI, s.getAttackType());
        assertEquals("userId", s.getParameterName());
        assertEquals(VerificationTechnique.BOOLEAN_BASED, s.getTechnique());
        assertEquals(StrategyType.BOOLEAN_BASED_MINIMAL, s.getPrimaryStrategy());
        assertEquals(0.92, s.getConfidence(), 0.001);
    }

    // ==================== 2. ERROR_BASED ====================

    @Test
    @DisplayName("SQLI ERROR_BASED → ERROR_BASED")
    void shouldMapSqlErrorToErrorBased() {
        TechniqueRecommendation rec = new TechniqueRecommendation(
                "search", AttackType.SQLI,
                VerificationTechnique.ERROR_BASED, 0.81,
                "Error-based injection might reveal DB info"
        );

        List<TestStrategy> strategies = mapper.mapToStrategies(List.of(rec));

        assertEquals(1, strategies.size());
        TestStrategy s = strategies.get(0);
        assertEquals(VerificationTechnique.ERROR_BASED, s.getTechnique());
        assertEquals(StrategyType.ERROR_BASED, s.getPrimaryStrategy());
    }

    // ==================== 3. TIME_BASED ====================

    @Test
    @DisplayName("SQLI TIME_BASED → TIME_BASED")
    void shouldMapSqlTimeToTimeBased() {
        TechniqueRecommendation rec = new TechniqueRecommendation(
                "sort", AttackType.SQLI,
                VerificationTechnique.TIME_BASED, 0.77,
                "Time-based detection for blind SQLI"
        );

        List<TestStrategy> strategies = mapper.mapToStrategies(List.of(rec));

        assertEquals(1, strategies.size());
        TestStrategy s = strategies.get(0);
        assertEquals(VerificationTechnique.TIME_BASED, s.getTechnique());
        assertEquals(StrategyType.TIME_BASED, s.getPrimaryStrategy());
    }

    // ==================== 4. IDOR (NUMERIC_INCREMENT) ====================

    @Test
    @DisplayName("IDOR NUMERIC_INCREMENT → NUMERIC_INCREMENT")
    void shouldMapIdorNumericIncrement() {
        TechniqueRecommendation rec = new TechniqueRecommendation(
                "userId", AttackType.IDOR,
                VerificationTechnique.NUMERIC_INCREMENT, 0.88,
                "Numeric ID param, likely vulnerable to IDOR"
        );

        List<TestStrategy> strategies = mapper.mapToStrategies(List.of(rec));

        assertEquals(1, strategies.size());
        TestStrategy s = strategies.get(0);
        assertEquals(AttackType.IDOR, s.getAttackType());
        assertEquals(VerificationTechnique.NUMERIC_INCREMENT, s.getTechnique());
        assertEquals(StrategyType.NUMERIC_INCREMENT, s.getPrimaryStrategy());
    }

    // ==================== 5. AUTH (REMOVE_TOKEN) ====================

    @Test
    @DisplayName("AUTH REMOVE_TOKEN → REMOVE_TOKEN")
    void shouldMapAuthRemoveToken() {
        TechniqueRecommendation rec = new TechniqueRecommendation(
                "Authorization", AttackType.AUTH,
                VerificationTechnique.REMOVE_TOKEN, 0.90,
                "Remove token to test auth bypass"
        );

        List<TestStrategy> strategies = mapper.mapToStrategies(List.of(rec));

        assertEquals(1, strategies.size());
        TestStrategy s = strategies.get(0);
        assertEquals(VerificationTechnique.REMOVE_TOKEN, s.getTechnique());
        assertEquals(StrategyType.REMOVE_TOKEN, s.getPrimaryStrategy());
    }

    // ==================== 6. SSRF (LOCALHOST_PROBE) ====================

    @Test
    @DisplayName("SSRF LOCALHOST_PROBE → LOCALHOST_PROBE")
    void shouldMapSsrfLocalhostProbe() {
        TechniqueRecommendation rec = new TechniqueRecommendation(
                "callback", AttackType.SSRF,
                VerificationTechnique.LOCALHOST_PROBE, 0.85,
                "URL parameter may allow SSRF"
        );

        List<TestStrategy> strategies = mapper.mapToStrategies(List.of(rec));

        assertEquals(1, strategies.size());
        TestStrategy s = strategies.get(0);
        assertEquals(VerificationTechnique.LOCALHOST_PROBE, s.getTechnique());
        assertEquals(StrategyType.LOCALHOST_PROBE, s.getPrimaryStrategy());
    }

    // ==================== 7. 多 Technique 场景 ====================

    @Test
    @DisplayName("Multiple techniques for single parameter+attack type")
    void shouldMapMultipleTechniquesForSameParam() {
        List<TechniqueRecommendation> recs = List.of(
                new TechniqueRecommendation("id", AttackType.SQLI,
                        VerificationTechnique.BOOLEAN_BASED, 0.92, "Primary"),
                new TechniqueRecommendation("id", AttackType.SQLI,
                        VerificationTechnique.ERROR_BASED, 0.81, "Secondary"),
                new TechniqueRecommendation("id", AttackType.SQLI,
                        VerificationTechnique.TIME_BASED, 0.77, "Tertiary")
        );

        List<TestStrategy> strategies = mapper.mapToStrategies(recs);

        assertEquals(3, strategies.size());
        assertEquals(VerificationTechnique.BOOLEAN_BASED, strategies.get(0).getTechnique());
        assertEquals(VerificationTechnique.ERROR_BASED, strategies.get(1).getTechnique());
        assertEquals(VerificationTechnique.TIME_BASED, strategies.get(2).getTechnique());
        // All should have the same attack type and parameter
        strategies.forEach(s -> {
            assertEquals(AttackType.SQLI, s.getAttackType());
            assertEquals("id", s.getParameterName());
        });
    }

    // ==================== 8. 无 Technique 场景 ====================

    @Test
    @DisplayName("Empty recommendations → empty strategies")
    void shouldReturnEmptyForEmptyRecommendations() {
        List<TestStrategy> strategies = mapper.mapToStrategies(List.of());
        assertTrue(strategies.isEmpty());
    }

    @Test
    @DisplayName("Null recommendations → empty strategies")
    void shouldReturnEmptyForNullRecommendations() {
        List<TestStrategy> strategies = mapper.mapToStrategies(null);
        assertTrue(strategies.isEmpty());
    }

    // ==================== 9. Invalid Recommendation ====================

    @Test
    @DisplayName("Invalid recommendation is skipped")
    void shouldSkipInvalidRecommendation() {
        TechniqueRecommendation invalid = new TechniqueRecommendation(
                null, AttackType.SQLI,
                VerificationTechnique.BOOLEAN_BASED, 0.5, "Missing param name"
        );
        assertFalse(invalid.isValid());

        List<TestStrategy> strategies = mapper.mapToStrategies(List.of(invalid));
        assertTrue(strategies.isEmpty());
    }

    // ==================== 10. Registry 查找 ====================

    @Test
    @DisplayName("Registry finds matching rule")
    void registryShouldFindMatchingRule() {
        Optional<TechniqueRule> rule = registry.findRule(AttackType.SQLI, VerificationTechnique.BOOLEAN_BASED);
        assertTrue(rule.isPresent());
        assertEquals(StrategyType.BOOLEAN_BASED_MINIMAL, rule.get().getStrategyType());
    }

    @Test
    @DisplayName("Registry returns empty for unknown combination")
    void registryShouldReturnEmptyForUnknown() {
        Optional<TechniqueRule> rule = registry.findRule(AttackType.SQLI, VerificationTechnique.UUID_SWAP);
        assertTrue(rule.isEmpty());
    }

    @Test
    @DisplayName("Registry returns empty for null inputs")
    void registryShouldReturnEmptyForNullInputs() {
        assertTrue(registry.findRule(null, VerificationTechnique.BOOLEAN_BASED).isEmpty());
        assertTrue(registry.findRule(AttackType.SQLI, null).isEmpty());
    }

    @Test
    @DisplayName("Registry has correct rule count")
    void registryShouldHaveCorrectRuleCount() {
        assertEquals(11, registry.getRuleCount());
    }

    // ==================== 11. 枚举 fromString ====================

    @Test
    @DisplayName("VerificationTechnique.fromString handles various formats")
    void verificationTechniqueFromString() {
        assertEquals(VerificationTechnique.BOOLEAN_BASED, VerificationTechnique.fromString("BOOLEAN_BASED"));
        assertEquals(VerificationTechnique.BOOLEAN_BASED, VerificationTechnique.fromString("boolean based"));
        assertEquals(VerificationTechnique.BOOLEAN_BASED, VerificationTechnique.fromString("Boolean Based"));
        assertEquals(VerificationTechnique.NUMERIC_INCREMENT, VerificationTechnique.fromString("NUMERIC_INCREMENT"));
        assertEquals(VerificationTechnique.NUMERIC_INCREMENT, VerificationTechnique.fromString("numeric increment"));
        assertNull(VerificationTechnique.fromString(null));
        assertNull(VerificationTechnique.fromString("  "));
        assertNull(VerificationTechnique.fromString("INVALID_TECHNIQUE"));
    }

    @Test
    @DisplayName("StrategyType.fromString handles various formats")
    void strategyTypeFromString() {
        assertEquals(StrategyType.BOOLEAN_BASED_MINIMAL, StrategyType.fromString("BOOLEAN_BASED_MINIMAL"));
        assertEquals(StrategyType.BOOLEAN_BASED_MINIMAL, StrategyType.fromString("boolean based (minimal)"));
        assertEquals(StrategyType.NUMERIC_INCREMENT, StrategyType.fromString("NUMERIC_INCREMENT"));
        assertEquals(StrategyType.LOCALHOST_PROBE, StrategyType.fromString("localhost probe"));
        assertNull(StrategyType.fromString(null));
        assertNull(StrategyType.fromString("INVALID_STRATEGY"));
    }

    // ==================== 12. IDOR 规则补充 ====================

    @Test
    @DisplayName("Supplement IDOR for numeric uid parameter")
    void shouldSupplementIdorForNumericId() {
        List<TestStrategy> supplements = mapper.supplementStrategies(
                AttackType.IDOR, "userId", "1001");

        assertEquals(1, supplements.size());
        TestStrategy s = supplements.get(0);
        assertEquals(AttackType.IDOR, s.getAttackType());
        assertEquals("userId", s.getParameterName());
        assertEquals(VerificationTechnique.NUMERIC_INCREMENT, s.getTechnique());
    }

    @Test
    @DisplayName("Supplement IDOR for UUID parameter")
    void shouldSupplementIdorForUuid() {
        List<TestStrategy> supplements = mapper.supplementStrategies(
                AttackType.IDOR, "userUuid", "550e8400-e29b-41d4-a716-446655440000");

        assertEquals(1, supplements.size());
        assertEquals(VerificationTechnique.UUID_SWAP, supplements.get(0).getTechnique());
    }

    @Test
    @DisplayName("No supplement for non-matching parameter")
    void shouldNotSupplementForNonMatchingParam() {
        List<TestStrategy> supplements = mapper.supplementStrategies(
                AttackType.SQLI, "search", "test");
        assertTrue(supplements.isEmpty());
    }

    // ==================== 13. TestStrategy constructors ====================

    @Test
    @DisplayName("TestStrategy with technique has correct fields")
    void testStrategyWithTechniqueConstructor() {
        TestStrategy s = new TestStrategy(
                AttackType.SQLI, "id",
                VerificationTechnique.BOOLEAN_BASED,
                List.of(StrategyType.BOOLEAN_BASED_MINIMAL),
                0.85, "Reasoning text"
        );

        assertEquals(AttackType.SQLI, s.getAttackType());
        assertEquals("id", s.getParameterName());
        assertEquals(VerificationTechnique.BOOLEAN_BASED, s.getTechnique());
        assertEquals(StrategyType.BOOLEAN_BASED_MINIMAL, s.getPrimaryStrategy());
        assertEquals(0.85, s.getConfidence(), 0.001);
        assertEquals("Reasoning text", s.getReasoning());
    }

    @Test
    @DisplayName("TestStrategy without technique (backward compatible)")
    void testStrategyWithoutTechniqueConstructor() {
        TestStrategy s = new TestStrategy(
                AttackType.IDOR, "accountId",
                List.of(StrategyType.BOOLEAN_BASED_MINIMAL),
                0.70, "Old-style reasoning"
        );

        assertNull(s.getTechnique());
        assertEquals(StrategyType.BOOLEAN_BASED_MINIMAL, s.getPrimaryStrategy());
    }
}
