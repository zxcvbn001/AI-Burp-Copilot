package com.aiburpcopilot.core.verification.candidate.impl;

import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.verification.capability.RuleCapabilityCatalog;
import com.aiburpcopilot.core.verification.candidate.ICandidateExtractor;
import com.aiburpcopilot.core.verification.model.CandidateParameter;
import com.aiburpcopilot.core.verification.technique.TechniqueRecommendation;
import com.aiburpcopilot.core.verification.technique.VerificationTechnique;
import com.aiburpcopilot.utils.PluginLogger;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CandidateExtractor implements ICandidateExtractor {

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
        if (result == null || !result.isSuccess()) {
            return candidates;
        }

        for (TechniqueRecommendation rec : safeRecommendations(result.getRecommendedTechniques())) {
            String resolved = findMatchingParamName(context, rec.getParameterName());
            String attackTypeName = resolveAttackTypeName(rec.getAttackTypeName());
            if (resolved == null || attackTypeName == null || !isSupported(attackTypeName, rec.getTechniqueName())) {
                continue;
            }
            CandidateParameter candidate = newCandidate(
                    resolved,
                    getParamType(context, resolved),
                    attackTypeName,
                    rec.getConfidence(),
                    "AI recommended: " + (rec.getTechniqueName() != null ? rec.getTechniqueName() : "rule probes"),
                    "AI_RECOMMENDATION");
            if (rec.getTechnique() != null) {
                candidate.setRecommendedTechniques(List.of(rec.getTechnique()));
            }
            candidates.add(candidate);
        }

        Set<String> coveredParams = candidates.stream()
                .map(c -> c.getParameterName() + "|" + c.getAttackTypeName())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        List<VulnerabilityHint> hints = parseVulnerabilityHints(result.getPossibleVulnerabilities());
        if (result.getHighValueParams() != null && !hints.isEmpty()) {
            for (AnalysisResult.HighValueParam param : result.getHighValueParams()) {
                String resolved = findMatchingParamName(context, param.getParamName());
                if (resolved == null) {
                    continue;
                }
                for (VulnerabilityHint hint : hints) {
                    String key = resolved + "|" + hint.attackTypeName();
                    if (coveredParams.add(key)) {
                        candidates.add(newCandidate(
                                resolved,
                                getParamType(context, resolved),
                                hint.attackTypeName(),
                                riskLevelToConfidence(param.getRiskLevel()),
                                param.getReason() != null ? param.getReason() : "Rule supplement",
                                "RULE_SUPPLEMENT"));
                    }
                }
            }
        }

        for (VulnerabilityHint hint : hints) {
            String resolved = findMatchingParamName(context, hint.parameterName());
            if (resolved == null) {
                continue;
            }
            String key = resolved + "|" + hint.attackTypeName();
            if (coveredParams.add(key)) {
                candidates.add(newCandidate(
                        resolved,
                        getParamType(context, resolved),
                        hint.attackTypeName(),
                        0.70,
                        "AI vulnerability hint: " + hint.originalText(),
                        "AI_VULNERABILITY_HINT"));
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

    private CandidateParameter newCandidate(String parameterName,
                                            String parameterType,
                                            String attackTypeName,
                                            double confidence,
                                            String reasoning,
                                            String source) {
        CandidateParameter candidate = new CandidateParameter();
        candidate.setParameterName(parameterName);
        candidate.setParameterType(parameterType);
        candidate.setAttackTypeName(attackTypeName);
        candidate.setConfidence(confidence);
        candidate.setReasoning(reasoning);
        candidate.setSource(source);
        return candidate;
    }

    private List<TechniqueRecommendation> safeRecommendations(List<TechniqueRecommendation> recommendations) {
        return recommendations != null ? recommendations : List.of();
    }

    private List<VulnerabilityHint> parseVulnerabilityHints(List<String> vulnNames) {
        if (vulnNames == null || vulnNames.isEmpty()) {
            return List.of();
        }
        List<VulnerabilityHint> hints = new ArrayList<>();
        for (String text : vulnNames) {
            String attackTypeName = resolveAttackTypeName(text);
            String parameterName = extractParameterName(text);
            if (attackTypeName != null) {
                hints.add(new VulnerabilityHint(attackTypeName, parameterName, text));
            }
        }
        return hints;
    }

    private String resolveAttackTypeName(String text) {
        if (capabilityCatalog == null) {
            return text;
        }
        return capabilityCatalog.resolveAttackTypeName(text);
    }

    private boolean isSupported(String attackTypeName, String techniqueName) {
        if (capabilityCatalog == null) {
            return attackTypeName != null;
        }
        return techniqueName != null
                ? capabilityCatalog.supportsTechnique(attackTypeName, techniqueName)
                : capabilityCatalog.supportsAttackType(attackTypeName);
    }

    private String findMatchingParamName(HTTPContext context, String aiName) {
        if (aiName == null || aiName.isBlank()) {
            return null;
        }
        String cleaned = cleanupParameterName(aiName);
        if (cleaned == null || context.getParameters() == null) {
            return null;
        }
        for (ParameterContext p : context.getParameters()) {
            if (p.getName() != null && p.getName().equals(cleaned)) {
                return p.getName();
            }
        }
        for (ParameterContext p : context.getParameters()) {
            if (p.getName() != null && p.getName().equalsIgnoreCase(cleaned)) {
                return p.getName();
            }
        }
        return null;
    }

    private String getParamType(HTTPContext context, String paramName) {
        if (context.getParameters() == null) {
            return "UNKNOWN";
        }
        for (ParameterContext p : context.getParameters()) {
            if (p.getName() != null && p.getName().equals(paramName)) {
                return p.getType() != null ? p.getType().name() : "UNKNOWN";
            }
        }
        return "UNKNOWN";
    }

    private double riskLevelToConfidence(RiskLevel level) {
        if (level == null) {
            return 0.5;
        }
        return switch (level) {
            case CRITICAL -> 0.95;
            case HIGH -> 0.85;
            case MEDIUM -> 0.70;
            case LOW -> 0.50;
            case INFO -> 0.30;
        };
    }

    private String extractParameterName(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        int arrow = text.indexOf("->");
        if (arrow >= 0 && arrow + 2 < text.length()) {
            return cleanupParameterName(text.substring(arrow + 2));
        }
        String lower = text.toLowerCase();
        for (String marker : List.of("parameter", "param", "参数", ":")) {
            int index = lower.lastIndexOf(marker.toLowerCase());
            if (index >= 0 && index + marker.length() < text.length()) {
                return cleanupParameterName(text.substring(index + marker.length()));
            }
        }
        return null;
    }

    private String cleanupParameterName(String value) {
        if (value == null) {
            return null;
        }
        String cleaned = value.replaceAll("[`'\"，。；;:()（）\\[\\]{}]", " ").trim();
        if (cleaned.isBlank()) {
            return null;
        }
        return cleaned.split("\\s+")[0];
    }

    private record VulnerabilityHint(String attackTypeName, String parameterName, String originalText) {
    }
}
