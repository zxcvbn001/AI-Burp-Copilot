package com.aiburpcopilot.core.verification.candidate.impl;

import com.aiburpcopilot.core.context.*;
import com.aiburpcopilot.core.verification.capability.RuleCapabilityCatalog;
import com.aiburpcopilot.core.verification.candidate.ICandidateExtractor;
import com.aiburpcopilot.core.verification.model.CandidateParameter;
import com.aiburpcopilot.core.verification.technique.TechniqueRecommendation;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Candidate 提取器实现。
 * 从 AI 分析结果中提取验证候选参数。
 */
public class CandidateExtractor implements ICandidateExtractor {

    private static final Logger log = LoggerFactory.getLogger(CandidateExtractor.class);
    private final PluginLogger pluginLog = PluginLogger.getInstance();
    private final RuleCapabilityCatalog capabilityCatalog;

    public CandidateExtractor() {
        this(null);
    }

    public CandidateExtractor(RuleCapabilityCatalog capabilityCatalog) {
        this.capabilityCatalog = capabilityCatalog;
    }

    @Override
    public List<CandidateParameter> extract(HTTPContext context) {
        List<CandidateParameter> candidates = new ArrayList<>();
        AnalysisResult result = context.getAnalysisResult();
        if (result == null || !result.isSuccess()) return candidates;

        // 1. 从 AI 推荐的 Technique 提取
        List<TechniqueRecommendation> recs = result.getRecommendedTechniques();
        if (recs != null && !recs.isEmpty()) {
            for (TechniqueRecommendation rec : recs) {
                String resolved = findMatchingParamName(context, rec.getParameterName());
                if (resolved != null && isSupported(rec.getAttackType(), rec.getTechnique())) {
                    List<VerificationTechnique> techniques = new ArrayList<>();
                    if (rec.getTechnique() != null) {
                        techniques.add(rec.getTechnique());
                    }
                    candidates.add(new CandidateParameter(
                            resolved,
                            getParamType(context, resolved),
                            rec.getAttackType(),
                            rec.getConfidence(),
                            "AI recommended: " + (rec.getTechnique() != null ? rec.getTechnique().name() : "none"),
                            "AI_RECOMMENDATION",
                            techniques
                    ));
                }
            }
        }

        // 2. 从高价值参数 + 漏洞类型提取（规则补充）
        Set<String> coveredParams = candidates.stream()
                .map(c -> c.getParameterName() + "|" + c.getAttackType().name())
                .collect(Collectors.toSet());

        if (result.getHighValueParams() != null && result.getPossibleVulnerabilities() != null) {
            Set<AttackType> attackTypes = mapVulnerabilityToAttackTypes(result.getPossibleVulnerabilities());
            for (AnalysisResult.HighValueParam param : result.getHighValueParams()) {
                String resolved = findMatchingParamName(context, param.getParamName());
                if (resolved == null) continue;
                for (AttackType at : attackTypes) {
                    String key = resolved + "|" + at.name();
                    if (!coveredParams.contains(key) && isSupported(at, null)) {
                        candidates.add(new CandidateParameter(
                                resolved,
                                getParamType(context, resolved),
                                at,
                                riskLevelToConfidence(param.getRiskLevel()),
                                param.getReason() != null ? param.getReason() : "Rule supplement",
                                "RULE_SUPPLEMENT",
                                List.of()
                        ));
                        coveredParams.add(key);
                    }
                }
            }
        }

        // 3. AI 可能只给出 "SQLI -> id" 这类漏洞建议，没有同步填充 highValueParams。
        // 被动验证不能因此断链：这里把规则内漏洞建议确定性转换为候选参数。
        for (VulnerabilityHint hint : parseVulnerabilityHints(result.getPossibleVulnerabilities())) {
            String resolved = findMatchingParamName(context, hint.parameterName());
            if (resolved == null) continue;
            String key = resolved + "|" + hint.attackType().name();
            if (!coveredParams.contains(key) && isSupported(hint.attackType(), null)) {
                candidates.add(new CandidateParameter(
                        resolved,
                        getParamType(context, resolved),
                        hint.attackType(),
                        0.70,
                        "AI vulnerability hint: " + hint.originalText(),
                        "AI_VULNERABILITY_HINT",
                        List.of()
                ));
                coveredParams.add(key);
            }
        }

        pluginLog.info("Candidate", "Extracted " + candidates.size() + " candidates from analysis");
        return candidates;
    }

    @Override
    public List<CandidateParameter> filterByConfidence(List<CandidateParameter> candidates, double minConfidence) {
        return candidates.stream()
                .filter(c -> c.getConfidence() >= minConfidence)
                .collect(Collectors.toList());
    }

    // --- Private helpers ---

    private String findMatchingParamName(HTTPContext context, String aiName) {
        if (aiName == null || aiName.isBlank()) return null;
        String cleaned = aiName.trim();
        if (context.getParameters() == null) return null;

        // Exact match
        for (ParameterContext p : context.getParameters()) {
            if (p.getName() != null && p.getName().equals(cleaned)) return p.getName();
        }
        // Case insensitive
        for (ParameterContext p : context.getParameters()) {
            if (p.getName() != null && p.getName().equalsIgnoreCase(cleaned)) return p.getName();
        }
        return null;
    }

    private String getParamType(HTTPContext context, String paramName) {
        if (context.getParameters() == null) return "UNKNOWN";
        for (ParameterContext p : context.getParameters()) {
            if (p.getName() != null && p.getName().equals(paramName)) {
                return p.getType() != null ? p.getType().name() : "UNKNOWN";
            }
        }
        return "UNKNOWN";
    }

    private double riskLevelToConfidence(RiskLevel level) {
        if (level == null) return 0.5;
        return switch (level) {
            case CRITICAL -> 0.95;
            case HIGH -> 0.85;
            case MEDIUM -> 0.70;
            case LOW -> 0.50;
            case INFO -> 0.30;
        };
    }

    private Set<AttackType> mapVulnerabilityToAttackTypes(List<String> vulnNames) {
        Set<AttackType> result = new LinkedHashSet<>();
        if (vulnNames == null) return result;
        for (String name : vulnNames) {
            String upper = normalizeText(name);
            addIfSupported(result, upper, "SQL", AttackType.SQLI);
            addIfSupported(result, upper, "IDOR", AttackType.IDOR);
            addIfSupported(result, upper, "SSRF", AttackType.SSRF);
            addIfSupported(result, upper, "AUTH", AttackType.AUTH);
            addIfSupported(result, upper, "XSS", AttackType.XSS);
            if ((upper.contains("PATH") || upper.contains("TRAVERSAL"))
                    && isSupported(AttackType.PATH_TRAVERSAL, null)) {
                result.add(AttackType.PATH_TRAVERSAL);
            }
        }
        return result;
    }

    private List<VulnerabilityHint> parseVulnerabilityHints(List<String> vulnNames) {
        if (vulnNames == null || vulnNames.isEmpty()) {
            return List.of();
        }
        List<VulnerabilityHint> hints = new ArrayList<>();
        for (String text : vulnNames) {
            AttackType attackType = parseAttackType(text);
            String parameterName = extractParameterName(text);
            if (attackType != null && parameterName != null && !parameterName.isBlank()) {
                hints.add(new VulnerabilityHint(attackType, parameterName, text));
            }
        }
        return hints;
    }

    private AttackType parseAttackType(String text) {
        String upper = normalizeText(text);
        if (upper.isBlank()) return null;
        if (upper.contains("SQL")) return AttackType.SQLI;
        if (upper.contains("IDOR")) return AttackType.IDOR;
        if (upper.contains("SSRF")) return AttackType.SSRF;
        if (upper.contains("AUTH")) return AttackType.AUTH;
        if (upper.contains("XSS")) return AttackType.XSS;
        if (upper.contains("PATH") || upper.contains("TRAVERSAL")) return AttackType.PATH_TRAVERSAL;
        return null;
    }

    private String extractParameterName(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String trimmed = text.trim();
        int arrow = trimmed.indexOf("->");
        if (arrow >= 0 && arrow + 2 < trimmed.length()) {
            return cleanupParameterName(trimmed.substring(arrow + 2));
        }

        String lower = trimmed.toLowerCase(Locale.ROOT);
        String[] markers = {"parameter", "param", "参数", ":"};
        for (String marker : markers) {
            int index = lower.lastIndexOf(marker.toLowerCase(Locale.ROOT));
            if (index >= 0 && index + marker.length() < trimmed.length()) {
                return cleanupParameterName(trimmed.substring(index + marker.length()));
            }
        }
        return null;
    }

    private String cleanupParameterName(String value) {
        if (value == null) {
            return null;
        }
        String cleaned = value.replaceAll("[`'\"，。；;：:()（）\\[\\]{}]", " ").trim();
        if (cleaned.isBlank()) {
            return null;
        }
        return cleaned.split("\\s+")[0];
    }

    private String normalizeText(String text) {
        return text == null
                ? ""
                : text.toUpperCase(Locale.ROOT).replace(" ", "_").replace("-", "_");
    }

    private void addIfSupported(Set<AttackType> result, String text, String token, AttackType attackType) {
        if (text.contains(token) && isSupported(attackType, null)) {
            result.add(attackType);
        }
    }

    private boolean isSupported(AttackType attackType, VerificationTechnique technique) {
        if (capabilityCatalog == null) {
            return attackType != null;
        }
        if (technique != null) {
            return capabilityCatalog.supportsTechnique(attackType, technique);
        }
        return capabilityCatalog.supportsAttackType(attackType);
    }

    private record VulnerabilityHint(AttackType attackType, String parameterName, String originalText) {}
}
