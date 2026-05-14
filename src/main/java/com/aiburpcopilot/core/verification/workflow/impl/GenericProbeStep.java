package com.aiburpcopilot.core.verification.workflow.impl;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;
import com.aiburpcopilot.core.verification.model.CandidateParameter;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import com.aiburpcopilot.core.verification.model.StepResult;
import com.aiburpcopilot.core.verification.policy.IPolicyEngine;
import com.aiburpcopilot.core.verification.probe.IProbeRuleEngine;
import com.aiburpcopilot.core.verification.probe.OracleResult;
import com.aiburpcopilot.core.verification.probe.ProbeDefinition;
import com.aiburpcopilot.core.verification.probe.ProbeExecution;
import com.aiburpcopilot.core.verification.probe.ProbeOracleEngine;
import com.aiburpcopilot.core.verification.probe.ProbePayload;
import com.aiburpcopilot.core.verification.probe.ProbePayloadPair;
import com.aiburpcopilot.core.verification.probe.ProbeRole;
import com.aiburpcopilot.core.verification.safety.DangerousPayloadFilter;
import com.aiburpcopilot.core.verification.util.RuleKeyUtil;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;
import com.aiburpcopilot.core.verification.workflow.WorkflowContext;
import com.aiburpcopilot.utils.PluginLogger;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class GenericProbeStep implements VerificationStep {

    public static final String SQLI_STEP = "SQLIProbes";
    public static final String XSS_STEP = "XSSProbes";
    public static final String IDOR_STEP = "IDORProbes";
    public static final String AUTH_STEP = "AUTHProbes";
    public static final String SSRF_STEP = "SSRFProbes";
    public static final String PATH_TRAVERSAL_STEP = "PathTraversalProbes";
    public static final String OPEN_REDIRECT_STEP = "OpenRedirectProbes";
    public static final String SSTI_STEP = "SSTIProbes";

    private final String name;
    private final AttackType attackType;
    private final String attackTypeName;
    private final IReplayEngine replayEngine;
    private final IProbeRuleEngine probeRuleEngine;
    private final ProbeOracleEngine oracleEngine;
    private final IPolicyEngine policyEngine;
    private final int defaultMaxPayloadLength;

    public GenericProbeStep(String name,
                            AttackType attackType,
                            IReplayEngine replayEngine,
                            IProbeRuleEngine probeRuleEngine,
                            ProbeOracleEngine oracleEngine,
                            IPolicyEngine policyEngine,
                            int defaultMaxPayloadLength) {
        this(name, RuleKeyUtil.attackTypeName(attackType), replayEngine, probeRuleEngine,
                oracleEngine, policyEngine, defaultMaxPayloadLength);
    }

    public GenericProbeStep(String name,
                            String attackTypeName,
                            IReplayEngine replayEngine,
                            IProbeRuleEngine probeRuleEngine,
                            ProbeOracleEngine oracleEngine,
                            IPolicyEngine policyEngine,
                            int defaultMaxPayloadLength) {
        this.name = name;
        this.attackTypeName = RuleKeyUtil.normalize(attackTypeName);
        this.attackType = RuleKeyUtil.toAttackType(this.attackTypeName).orElse(null);
        this.replayEngine = replayEngine;
        this.probeRuleEngine = probeRuleEngine;
        this.oracleEngine = oracleEngine;
        this.policyEngine = policyEngine;
        this.defaultMaxPayloadLength = defaultMaxPayloadLength > 0 ? defaultMaxPayloadLength : 128;
    }

    public GenericProbeStep(String name,
                            AttackType attackType,
                            IReplayEngine replayEngine,
                            IProbeRuleEngine probeRuleEngine,
                            ProbeOracleEngine oracleEngine,
                            int defaultMaxPayloadLength) {
        this(name, attackType, replayEngine, probeRuleEngine, oracleEngine, null, defaultMaxPayloadLength);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public StepResult execute(WorkflowContext context) {
        if (context == null || context.getCandidate() == null) {
            return StepResult.hardFail(name, "Context or candidate parameter is null");
        }
        if (probeRuleEngine == null || oracleEngine == null) {
            return StepResult.softFail(name, "Probe rule engine or oracle engine is unavailable");
        }

        IReplayEngine effectiveReplay = context.getReplayEngine() != null
                ? context.getReplayEngine()
                : replayEngine;
        if (effectiveReplay == null) {
            return StepResult.softFail(name, "No ReplayEngine available");
        }

        CandidateParameter candidate = context.getCandidate();
        HTTPContext httpContext = context.getHttpContext();
        IPolicyEngine effectivePolicy = context.getPolicyEngine() != null
                ? context.getPolicyEngine()
                : policyEngine;

        List<ProbeDefinition> probes = probeRuleEngine.getProbes(attackTypeName).stream()
                .filter(ProbeDefinition::isEnabledByDefault)
                .filter(probe -> isAllowedByPolicy(probe, effectivePolicy))
                .filter(probe -> isApplicableToParameter(probe, httpContext, candidate, context.getParameterProfile()))
                .sorted(Comparator.comparingInt(ProbeDefinition::getPriority))
                .toList();
        if (probes.isEmpty()) {
            return StepResult.softFail(name, "No applicable probe rules for " + attackTypeName);
        }

        byte[] baseline = context.getBaselineResponse();
        long baselineDuration = 0;
        if (baseline == null || baseline.length == 0) {
            baseline = effectiveReplay.replayOriginal(httpContext);
            baselineDuration = effectiveReplay.getLastReplayDurationMs();
            context.setBaselineResponse(baseline);
        }

        StepResult result = new StepResult();
        result.setStepName(name);
        result.setPhase("Payload Verification");
        result.setContinueWorkflow(true);

        int tested = 0;
        int matched = 0;
        int maxReplayRequests = effectivePolicy != null
                ? Math.max(1, effectivePolicy.getMaxReplayRequests())
                : Integer.MAX_VALUE;
        double combinedConfidence = 0.0;
        StringBuilder transcript = new StringBuilder();
        int exchangeIndex = 1;

        for (ProbeDefinition probe : probes) {
            if (tested >= maxReplayRequests) {
                result.setContinueWorkflow(false);
                break;
            }
            List<ProbeExecution> executions = executeProbe(
                    effectiveReplay,
                    httpContext,
                    candidate.getParameterName(),
                    probe,
                    maxReplayRequests - tested);
            tested += executions.size();
            if (executions.isEmpty()) {
                continue;
            }

            for (ProbeExecution execution : executions) {
                appendExchange(transcript, exchangeIndex++, probe, execution);
            }

            ProbeExecution last = executions.get(executions.size() - 1);
            result.setRequestBytes(last.getRequestBytes());
            result.setResponseBytes(last.getResponseBytes());
            result.setPayload(last.getValue());
            result.setResponseLength(last.getResponseBytes() != null ? last.getResponseBytes().length : 0);
            result.setStrategyName(probe.getStrategyName());
            if (probe.getStrategy() != null) {
                result.setStrategyType(probe.getStrategy());
            }

            OracleResult oracle = oracleEngine.evaluate(probe, baseline, baselineDuration, executions);
            if (probe.isRequiresLlmReview() && !oracle.isLlmAvailable()) {
                oracle.setMatched(false);
                oracle.setConfidence(0.0);
                oracle.setReasoning("该规则要求 LLM 二次研判，但当前 LLM 不可用或研判失败。");
            }
            if (oracle.getDiffResult() != null) {
                result.setDiffResult(oracle.getDiffResult());
            }
            if (oracle.getLlmReview() != null && !oracle.getLlmReview().isBlank()) {
                result.setLlmReview(oracle.getLlmReview());
            }
            if (oracle.isMatched()) {
                matched++;
                double weighted = oracle.getConfidence() * probe.getEvidenceWeight();
                combinedConfidence = combineConfidence(combinedConfidence, weighted);
                oracle.getEvidences().forEach(result::addEvidence);
                if (probe.isStopOnMatch() && isStrongEnoughToStop(probe, oracle)) {
                    break;
                }
            }
        }

        result.setSuccess(matched > 0);
        result.setConfidence(combinedConfidence);
        result.setExchangeTranscript(transcript.toString());
        result.setReasoning("漏洞类型聚合探测：" + attackTypeName
                + "，规则数=" + probes.size()
                + "，请求数=" + tested
                + "，命中证据=" + matched
                + "，置信度=" + String.format("%.2f", combinedConfidence));

        PluginLogger.getInstance().info(PluginLogger.Category.VERIFICATION, name,
                "Completed: attackType=" + attackTypeName
                        + " param='" + candidate.getParameterName()
                        + "' requests=" + tested
                        + " matched=" + matched
                        + " confidence=" + String.format("%.2f", combinedConfidence));
        return result;
    }

    private List<ProbeExecution> executeProbe(IReplayEngine replay,
                                              HTTPContext httpContext,
                                              String parameterName,
                                              ProbeDefinition probe,
                                              int remainingRequests) {
        List<ProbeExecution> executions = new ArrayList<>();
        int maxRequests = Math.min(Math.max(1, probe.getMaxRequests()), Math.max(0, remainingRequests));
        if (maxRequests <= 0) {
            return executions;
        }

        for (ProbePayload payload : probe.getPayloads()) {
            if (executions.size() >= maxRequests) {
                break;
            }
            executePayload(replay, httpContext, parameterName, payload.getValue(),
                    payload.getRole(), payload.getMutation(), probe, executions);
        }

        for (ProbePayloadPair pair : probe.getPayloadPairs()) {
            if (executions.size() + 2 > maxRequests) {
                break;
            }
            executePayload(replay, httpContext, parameterName, pair.getTrueValue(),
                    ProbeRole.TRUE_CASE, pair.getTrueMutation(), probe, executions);
            executePayload(replay, httpContext, parameterName, pair.getFalseValue(),
                    ProbeRole.FALSE_CASE, pair.getFalseMutation(), probe, executions);
        }
        return executions;
    }

    private void executePayload(IReplayEngine replay,
                                HTTPContext httpContext,
                                String parameterName,
                                String payload,
                                ProbeRole role,
                                String mutation,
                                ProbeDefinition probe,
                                List<ProbeExecution> executions) {
        int maxPayloadLength = probe.getMaxPayloadLength() > 0
                ? probe.getMaxPayloadLength()
                : defaultMaxPayloadLength;
        if (payload == null || DangerousPayloadFilter.isPayloadTooLong(payload, maxPayloadLength)) {
            return;
        }
        if (DangerousPayloadFilter.filter(List.of(payload)).isEmpty()) {
            return;
        }

        String mutationValue = resolveMutationValue(httpContext, parameterName, payload, mutation);
        if (mutationValue == null || DangerousPayloadFilter.isPayloadTooLong(mutationValue, maxPayloadLength)) {
            return;
        }

        byte[] response = shouldAppendMutation(mutation)
                ? replay.replayWithAppendedMutation(httpContext, parameterName, payload)
                : replay.replayWithMutation(httpContext, parameterName, mutationValue);
        executions.add(new ProbeExecution(
                mutationValue,
                role,
                replay.getLastRequestBytes(),
                response,
                replay.getLastReplayDurationMs()));
    }

    private boolean isAllowedByPolicy(ProbeDefinition probe, IPolicyEngine policy) {
        if (probe == null || policy == null || probe.getStrategyName() == null) {
            return true;
        }
        String strategy = RuleKeyUtil.normalize(probe.getStrategyName());
        if ("TIME_BASED".equals(strategy) && !policy.isTimeBasedAllowed()) {
            return false;
        }
        if ("UNION_BASED".equals(strategy) && !policy.isUnionBasedAllowed()) {
            return false;
        }
        return !"ERROR_BASED".equals(strategy) || policy.isErrorBasedAllowed();
    }

    private boolean isApplicableToParameter(ProbeDefinition probe,
                                            HTTPContext httpContext,
                                            CandidateParameter candidate,
                                            ParameterProfile profile) {
        if (probe == null || candidate == null) {
            return false;
        }
        if (!probe.getApplicableParamTypes().isEmpty()) {
            String paramType = candidate.getParameterType() != null
                    ? candidate.getParameterType().toUpperCase()
                    : findParameterType(httpContext, candidate.getParameterName());
            if (paramType == null || !probe.getApplicableParamTypes().contains(paramType)) {
                return false;
            }
        }
        if (!probe.getHttpMethods().isEmpty()) {
            String method = httpContext != null && httpContext.getMethod() != null
                    ? httpContext.getMethod().toUpperCase()
                    : "";
            if (!probe.getHttpMethods().contains(method)) {
                return false;
            }
        }
        if (!probe.getValueTypes().isEmpty()) {
            String valueType = profile != null && profile.getDetectedType() != null
                    ? profile.getDetectedType().toUpperCase()
                    : ParameterProfile.TYPE_UNKNOWN;
            return probe.getValueTypes().contains(valueType);
        }
        return true;
    }

    private boolean isStrongEnoughToStop(ProbeDefinition probe, OracleResult oracle) {
        if (probe == null || oracle == null) {
            return false;
        }
        String strength = probe.getStrength() != null ? probe.getStrength() : "MEDIUM";
        if ("WEAK".equalsIgnoreCase(strength)) {
            return false;
        }
        if ("MEDIUM".equalsIgnoreCase(strength)) {
            return oracle.getConfidence() >= 0.75;
        }
        return true;
    }

    private String findParameterType(HTTPContext httpContext, String parameterName) {
        if (httpContext == null || httpContext.getParameters() == null) {
            return null;
        }
        for (ParameterContext parameter : httpContext.getParameters()) {
            if (parameter.getName() != null && parameter.getName().equals(parameterName)
                    && parameter.getType() != null) {
                return parameter.getType().name();
            }
        }
        return null;
    }

    private String resolveMutationValue(HTTPContext httpContext,
                                        String parameterName,
                                        String payload,
                                        String mutation) {
        String normalized = mutation != null ? mutation.trim().toUpperCase() : "REPLACE";
        String originalValue = findOriginalValue(httpContext, parameterName);
        return switch (normalized) {
            case "APPEND" -> (originalValue != null ? originalValue : "") + payload;
            case "ADD", "INCREMENT" -> mutateNumeric(originalValue, payload, true);
            case "SUBTRACT", "DECREMENT" -> mutateNumeric(originalValue, payload, false);
            default -> payload;
        };
    }

    private boolean shouldAppendMutation(String mutation) {
        return "APPEND".equalsIgnoreCase(mutation);
    }

    private String mutateNumeric(String originalValue, String deltaValue, boolean add) {
        try {
            long original = Long.parseLong(originalValue != null ? originalValue.trim() : "");
            long delta = Long.parseLong(deltaValue != null ? deltaValue.trim() : "1");
            return String.valueOf(add ? original + delta : original - delta);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String findOriginalValue(HTTPContext httpContext, String parameterName) {
        if (httpContext == null || httpContext.getParameters() == null) {
            return null;
        }
        for (ParameterContext parameter : httpContext.getParameters()) {
            if (parameter.getName() != null && parameter.getName().equals(parameterName)) {
                return parameter.getValue();
            }
        }
        return null;
    }

    private double combineConfidence(double current, double evidence) {
        return Math.min(1.0, 1.0 - ((1.0 - current) * (1.0 - evidence)));
    }

    private void appendExchange(StringBuilder transcript,
                                int index,
                                ProbeDefinition probe,
                                ProbeExecution execution) {
        transcript.append("========== Request ").append(index).append(" ==========\n")
                .append("Probe: ").append(probe.getId()).append("\n")
                .append("Role: ").append(execution.getRole()).append("\n")
                .append("Payload: ").append(execution.getValue()).append("\n\n")
                .append(bytesToText(execution.getRequestBytes()))
                .append("\n\n========== Response ").append(index).append(" ==========\n")
                .append("Duration: ").append(execution.getDurationMs()).append(" ms\n\n")
                .append(bytesToText(execution.getResponseBytes()))
                .append("\n\n");
    }

    private String bytesToText(byte[] bytes) {
        return bytes == null || bytes.length == 0 ? "" : new String(bytes, StandardCharsets.UTF_8);
    }
}
