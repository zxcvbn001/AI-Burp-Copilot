package com.aiburpcopilot.core.verification.capability;

import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.verification.technique.TechniqueRecommendation;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;
import com.aiburpcopilot.utils.PluginLogger;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class AnalysisResultCapabilityFilter {

    private final RuleCapabilityCatalog catalog;
    private final Set<String> correctionWarnings = new LinkedHashSet<>();

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
            String resolved = highValueParam != null
                    ? resolveParamName(context, highValueParam.getParamName())
                    : null;
            if (resolved == null) {
                PluginLogger.getInstance().warn(PluginLogger.Category.LLM, "AI",
                        "Dropped high value param not present in request: "
                                + (highValueParam != null ? highValueParam.getParamName() : null));
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
            String attackTypeName = parseAttackTypeName(vulnerability);
            if (attackTypeName == null || !catalog.supportsAttackType(attackTypeName)) {
                PluginLogger.getInstance().warn(PluginLogger.Category.LLM, "AI",
                        "Dropped unsupported vulnerability from AI output: " + vulnerability);
                continue;
            }
            String parameter = extractParameterName(vulnerability);
            if (isEndpointLevelHint(parameter)) {
                filtered.add(attackTypeName);
                continue;
            }
            String resolved = resolveParamName(context, parameter);
            if (parameter != null && resolved == null) {
                PluginLogger.getInstance().warn(PluginLogger.Category.LLM, "AI",
                        "Dropped vulnerability with non-request parameter: " + vulnerability);
                continue;
            }
            filtered.add(resolved == null ? attackTypeName : attackTypeName + " -> " + resolved);
        }
        return new ArrayList<>(filtered);
    }

    private boolean isEndpointLevelHint(String parameter) {
        if (parameter == null || parameter.isBlank()) {
            return false;
        }
        String normalized = cleanupParam(parameter);
        if (normalized == null || normalized.isBlank()) {
            return false;
        }
        String lower = normalized.toLowerCase();
        return lower.contains("endpoint")
                || lower.contains("entire")
                || lower.contains("whole")
                || lower.contains("global")
                || lower.contains("端点")
                || lower.contains("整体")
                || lower.contains("全局");
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
            String attackTypeName = recommendation != null
                    ? catalog.resolveAttackTypeName(recommendation.getAttackTypeName())
                    : null;
            String techniqueName = recommendation != null ? recommendation.getTechniqueName() : null;
            if (recommendation != null
                    && resolved != null
                    && attackTypeName != null
                    && catalog.supportsTechnique(attackTypeName, techniqueName)) {
                recommendation.setParameterName(resolved);
                recommendation.setAttackTypeName(attackTypeName);
                filtered.add(recommendation);
            } else {
                PluginLogger.getInstance().warn(PluginLogger.Category.LLM, "AI",
                        "Dropped unsupported technique recommendation: " + recommendation);
            }
        }
        return filtered;
    }

    public String parseAttackTypeName(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String direct = catalog.resolveAttackTypeName(text);
        if (direct != null) {
            return direct;
        }
        String normalized = RuleKeyUtil.normalize(text);
        if (normalized == null) {
            return null;
        }
        for (String attackTypeName : catalog.getSupportedAttackTypeNames()) {
            if (normalized.contains(attackTypeName)) {
                return attackTypeName;
            }
        }
        return null;
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
            String correctionKey = cleaned + "->" + valueMatches.get(0).getName();
            if (correctionWarnings.add(correctionKey)) {
                PluginLogger.getInstance().warn(PluginLogger.Category.LLM, "AI",
                        "AI used parameter value as name, corrected '" + cleaned
                                + "' to parameter '" + valueMatches.get(0).getName() + "'");
            }
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
        String cleaned = value.replaceAll("[`'\"，。；;:()（）\\[\\]{}]", " ").trim();
        if (cleaned.isBlank()) {
            return null;
        }
        String[] tokens = cleaned.split("\\s+");
        return tokens.length > 0 ? tokens[0] : cleaned;
    }
}
