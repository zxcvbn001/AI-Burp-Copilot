package com.aiburpcopilot.core.verification.capability;

import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.verification.technique.TechniqueRecommendation;
import com.aiburpcopilot.utils.PluginLogger;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Deterministically removes AI output outside locally registered rules.
 */
public class AnalysisResultCapabilityFilter {

    private final RuleCapabilityCatalog catalog;

    public AnalysisResultCapabilityFilter(RuleCapabilityCatalog catalog) {
        this.catalog = catalog;
    }

    public AnalysisResult filter(AnalysisResult result) {
        return filter(result, null);
    }

    public AnalysisResult filter(AnalysisResult result, HTTPContext context) {
        if (result == null || catalog == null) {
            return result;
        }
        result.setHighValueParams(filterHighValueParams(result.getHighValueParams(), context));
        result.setPossibleVulnerabilities(filterVulnerabilities(result.getPossibleVulnerabilities(), context));
        result.setRecommendedTechniques(filterRecommendations(result.getRecommendedTechniques(), context));
        return result;
    }

    private List<AnalysisResult.HighValueParam> filterHighValueParams(
            List<AnalysisResult.HighValueParam> highValueParams,
            HTTPContext context) {
        if (highValueParams == null || highValueParams.isEmpty()) {
            return List.of();
        }
        List<AnalysisResult.HighValueParam> filtered = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (AnalysisResult.HighValueParam highValueParam : highValueParams) {
            if (highValueParam == null) {
                continue;
            }
            String resolved = resolveParamName(context, highValueParam.getParamName());
            if (resolved == null) {
                PluginLogger.getInstance().warn("AI",
                        "Dropped high value param not present in request: " + highValueParam.getParamName());
                continue;
            }
            if (seen.add(resolved)) {
                highValueParam.setParamName(resolved);
                filtered.add(highValueParam);
            }
        }
        return filtered;
    }

    private List<String> filterVulnerabilities(List<String> vulnerabilities, HTTPContext context) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return List.of();
        }
        Set<String> filtered = new LinkedHashSet<>();
        for (String vulnerability : vulnerabilities) {
            AttackType attackType = parseAttackType(vulnerability);
            if (attackType == null || !catalog.supportsAttackType(attackType)) {
                PluginLogger.getInstance().warn("AI",
                        "Dropped unsupported vulnerability from AI output: " + vulnerability);
                continue;
            }
            String parameter = extractParameterName(vulnerability);
            String resolved = resolveParamName(context, parameter);
            if (parameter != null && resolved == null) {
                PluginLogger.getInstance().warn("AI",
                        "Dropped vulnerability with non-request parameter: " + vulnerability);
                continue;
            }
            filtered.add(toBroadVulnerability(attackType, resolved));
        }
        return new ArrayList<>(filtered);
    }

    private List<TechniqueRecommendation> filterRecommendations(
            List<TechniqueRecommendation> recommendations,
            HTTPContext context) {
        if (recommendations == null || recommendations.isEmpty()) {
            return List.of();
        }
        List<TechniqueRecommendation> filtered = new ArrayList<>();
        for (TechniqueRecommendation recommendation : recommendations) {
            String resolved = recommendation != null
                    ? resolveParamName(context, recommendation.getParameterName())
                    : null;
            if (recommendation != null
                    && resolved != null
                    && catalog.supportsTechnique(
                    recommendation.getAttackType(), recommendation.getTechnique())) {
                recommendation.setParameterName(resolved);
                filtered.add(recommendation);
            } else {
                PluginLogger.getInstance().warn("AI",
                        "Dropped unsupported technique recommendation: " + recommendation);
            }
        }
        return filtered;
    }

    private AttackType parseAttackType(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String upper = text.toUpperCase().replace("-", "_").replace(" ", "_");
        for (AttackType attackType : AttackType.values()) {
            if (upper.contains(attackType.name())) {
                return attackType;
            }
        }
        if (upper.contains("SQL")) return AttackType.SQLI;
        if (upper.contains("注入")) return AttackType.SQLI;
        if (upper.contains("IDOR")) return AttackType.IDOR;
        if (upper.contains("SSRF")) return AttackType.SSRF;
        if (upper.contains("AUTH") || upper.contains("认证") || upper.contains("鉴权") || upper.contains("授权")) return AttackType.AUTH;
        if (upper.contains("XSS") || upper.contains("跨站")) return AttackType.XSS;
        if (upper.contains("TRAVERSAL") || upper.contains("PATH") || upper.contains("路径遍历")) return AttackType.PATH_TRAVERSAL;
        return null;
    }

    private String toBroadVulnerability(AttackType attackType, String parameter) {
        return parameter == null || parameter.isBlank()
                ? attackType.name()
                : attackType.name() + " -> " + parameter;
    }

    private String resolveParamName(HTTPContext context, String aiName) {
        if (aiName == null || aiName.isBlank()) {
            return null;
        }
        if (context == null || context.getParameters() == null || context.getParameters().isEmpty()) {
            return aiName.trim();
        }

        String cleaned = cleanupParam(aiName);
        if (cleaned == null || cleaned.isBlank()) {
            return null;
        }
        for (ParameterContext param : context.getParameters()) {
            if (param.getName() != null && param.getName().equals(cleaned)) {
                return param.getName();
            }
        }
        for (ParameterContext param : context.getParameters()) {
            if (param.getName() != null && param.getName().equalsIgnoreCase(cleaned)) {
                return param.getName();
            }
        }
        List<ParameterContext> valueMatches = context.getParameters().stream()
                .filter(param -> param.getValue() != null && param.getValue().equals(cleaned))
                .toList();
        if (valueMatches.size() == 1) {
            PluginLogger.getInstance().warn("AI",
                    "AI used parameter value as name, corrected '" + cleaned
                            + "' to parameter '" + valueMatches.get(0).getName() + "'");
            return valueMatches.get(0).getName();
        }
        return null;
    }

    private String extractParameterName(String text) {
        if (text == null) {
            return null;
        }
        String normalized = text.trim();
        int arrow = normalized.indexOf("->");
        if (arrow >= 0 && arrow + 2 < normalized.length()) {
            return cleanupParam(normalized.substring(arrow + 2));
        }
        String[] separators = {"参数", "param", "parameter", ":"};
        String lower = normalized.toLowerCase();
        for (String separator : separators) {
            int index = lower.lastIndexOf(separator.toLowerCase());
            if (index >= 0 && index + separator.length() < normalized.length()) {
                return cleanupParam(normalized.substring(index + separator.length()));
            }
        }
        return null;
    }

    private String cleanupParam(String value) {
        if (value == null) {
            return null;
        }
        String cleaned = value.replaceAll("[`'\"，。；;：:()（）\\[\\]{}]", " ").trim();
        if (cleaned.isBlank()) {
            return null;
        }
        String[] tokens = cleaned.split("\\s+");
        return tokens.length > 0 ? tokens[0] : cleaned;
    }
}
