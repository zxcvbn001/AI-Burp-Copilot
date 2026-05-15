package com.aiburpcopilot.core.verification.workflow.impl;

import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.influence.IInfluenceDiffEngine;
import com.aiburpcopilot.core.verification.influence.IInfluenceLlmAnalyzer;
import com.aiburpcopilot.core.verification.influence.IInfluenceScorer;
import com.aiburpcopilot.core.verification.influence.IMinimalMutationEngine;
import com.aiburpcopilot.core.verification.influence.IParameterRoleAnalyzer;
import com.aiburpcopilot.core.verification.influence.IReplayEngine;
import com.aiburpcopilot.core.verification.influence.IStrategyApprovalEngine;
import com.aiburpcopilot.core.verification.influence.InfluenceLlmDecision;
import com.aiburpcopilot.core.verification.influence.ParameterRole;
import com.aiburpcopilot.core.verification.model.CandidateParameter;
import com.aiburpcopilot.core.verification.model.DiffResult;
import com.aiburpcopilot.core.verification.model.Evidence;
import com.aiburpcopilot.core.verification.model.InfluenceResult;
import com.aiburpcopilot.core.verification.model.InfluenceStatus;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import com.aiburpcopilot.core.verification.model.StepResult;
import com.aiburpcopilot.core.verification.workflow.VerificationStep;
import com.aiburpcopilot.core.verification.workflow.WorkflowContext;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class InfluenceValidationStep implements VerificationStep {

    private static final Logger log = LoggerFactory.getLogger(InfluenceValidationStep.class);

    public static final String STEP_NAME = "InfluenceValidation";
    private static final int DEFAULT_MAX_INFLUENCE_MUTATIONS = 1;
    private static final int AI_ROLE_MAX_INFLUENCE_MUTATIONS = 2;
    private static final double SEMANTIC_PRIOR_APPROVE_THRESHOLD = 0.60;
    private static final double SEMANTIC_PRIOR_UNCERTAIN_THRESHOLD = 0.45;
    private static final double AI_CANDIDATE_UNCERTAIN_THRESHOLD = 0.70;

    private final IReplayEngine replayEngine;
    private final IMinimalMutationEngine mutationEngine;
    private final IInfluenceDiffEngine diffEngine;
    private final IInfluenceScorer scorer;
    private final IInfluenceLlmAnalyzer llmAnalyzer;
    private final IParameterRoleAnalyzer roleAnalyzer;
    private final IStrategyApprovalEngine approvalEngine;
    private final double minInfluenceScore;

    public InfluenceValidationStep(IReplayEngine replayEngine,
                                   IMinimalMutationEngine mutationEngine,
                                   IInfluenceDiffEngine diffEngine,
                                   IInfluenceScorer scorer,
                                   IInfluenceLlmAnalyzer llmAnalyzer,
                                   IParameterRoleAnalyzer roleAnalyzer,
                                   IStrategyApprovalEngine approvalEngine,
                                   double minInfluenceScore) {
        this.replayEngine = replayEngine;
        this.mutationEngine = mutationEngine;
        this.diffEngine = diffEngine;
        this.scorer = scorer;
        this.llmAnalyzer = llmAnalyzer;
        this.roleAnalyzer = roleAnalyzer;
        this.approvalEngine = approvalEngine;
        this.minInfluenceScore = minInfluenceScore;
    }

    public InfluenceValidationStep(IReplayEngine replayEngine,
                                   IMinimalMutationEngine mutationEngine,
                                   IInfluenceDiffEngine diffEngine,
                                   IInfluenceScorer scorer,
                                   IStrategyApprovalEngine approvalEngine,
                                   double minInfluenceScore) {
        this(replayEngine, mutationEngine, diffEngine, scorer,
                null, null, approvalEngine, minInfluenceScore);
    }

    public InfluenceValidationStep(IReplayEngine replayEngine,
                                   IMinimalMutationEngine mutationEngine,
                                   IInfluenceDiffEngine diffEngine,
                                   IInfluenceScorer scorer,
                                   IStrategyApprovalEngine approvalEngine) {
        this(replayEngine, mutationEngine, diffEngine, scorer,
                null, null, approvalEngine, 0.1);
    }

    @Override
    public String getName() {
        return STEP_NAME;
    }

    @Override
    public StepResult execute(WorkflowContext context) {
        if (context == null || context.getCandidate() == null) {
            log.warn("InfluenceValidationStep: context or candidate is null");
            return StepResult.hardFail(STEP_NAME, "Context or candidate parameter is null");
        }

        CandidateParameter candidate = context.getCandidate();
        HTTPContext httpContext = context.getHttpContext();
        String paramName = candidate.getParameterName();

        PluginLogger.getInstance().info(PluginLogger.Category.VERIFICATION, STEP_NAME,
                "Validating influence for param='" + paramName + "' | attackType=" + candidate.getAttackTypeName());

        IReplayEngine effectiveReplay = getReplayEngine(context);
        if (effectiveReplay == null) {
            return StepResult.softFail(STEP_NAME, "No ReplayEngine available for influence validation");
        }

        StepResult stepResult = new StepResult();
        stepResult.setStepName(STEP_NAME);
        stepResult.setPhase("Influence Gate");

        try {
            byte[] baselineResponse = effectiveReplay.replayOriginal(httpContext);
            long originalDuration = effectiveReplay.getLastReplayDurationMs();
            context.setBaselineResponse(baselineResponse);

            if (baselineResponse == null || baselineResponse.length == 0) {
                stepResult.setSuccess(false);
                stepResult.setConfidence(0.0);
                stepResult.setContinueWorkflow(false);
                stepResult.setReasoning("Baseline response is empty - cannot validate influence");
                return stepResult;
            }

            ParameterProfile profile = context.getParameterProfile();
            if (profile == null && mutationEngine != null) {
                profile = new ParameterProfile();
                profile.setParameterName(paramName);
                profile.setOriginalValue("");
                profile.setMutable(true);
            }

            if (profile == null) {
                stepResult.setSuccess(false);
                stepResult.setConfidence(0.0);
                stepResult.setContinueWorkflow(true);
                stepResult.setReasoning("No ParameterProfile - cannot generate mutations, proceeding");
                return stepResult;
            }

            ParameterRole parameterRole = roleAnalyzer != null
                    ? roleAnalyzer.analyze(httpContext, candidate, profile)
                    : ParameterRole.unavailable();

            List<String> mutations = mutationEngine != null
                    ? mutationEngine.generateMutations(profile)
                    : List.of();
            mutations = prioritizeByRole(mutations, parameterRole, profile);
            int maxMutations = parameterRole.available()
                    ? AI_ROLE_MAX_INFLUENCE_MUTATIONS
                    : DEFAULT_MAX_INFLUENCE_MUTATIONS;
            if (mutations != null && mutations.size() > maxMutations) {
                mutations = mutations.subList(0, maxMutations);
            }
            if (mutations == null) {
                mutations = List.of();
            }

            double totalScore = 0.0;
            int mutationCount = 0;
            DiffResult bestDiff = null;
            InfluenceLlmDecision bestLlmDecision = InfluenceLlmDecision.unavailable();
            List<String> allMutationValues = new ArrayList<>();

            for (String mutationValue : mutations) {
                try {
                    byte[] mutatedResponse = effectiveReplay.replayWithMutation(
                            httpContext, paramName, mutationValue);
                    long mutatedDuration = effectiveReplay.getLastReplayDurationMs();
                    stepResult.setRequestBytes(effectiveReplay.getLastRequestBytes());
                    stepResult.setResponseBytes(mutatedResponse);
                    stepResult.setPayload(mutationValue);
                    stepResult.setResponseLength(mutatedResponse != null ? mutatedResponse.length : 0);
                    allMutationValues.add(mutationValue);

                    if (diffEngine != null && mutatedResponse != null) {
                        DiffResult diff = diffEngine.analyze(
                                baselineResponse, mutatedResponse,
                                originalDuration, mutatedDuration);

                        if (diff != null) {
                            context.setLastDiffResult(diff);
                            context.setLastMutationValue(mutationValue);
                            stepResult.setDiffResult(diff);

                            double deterministicScore = scorer != null ? scorer.score(diff) : 0.0;
                            InfluenceLlmDecision llmDecision = llmAnalyzer != null
                                    ? llmAnalyzer.analyze(candidate.getAttackTypeName(), paramName,
                                    mutationValue, profile, diff, deterministicScore)
                                    : InfluenceLlmDecision.unavailable();
                            double finalScore = mergeInfluenceScore(deterministicScore, llmDecision);
                            totalScore += finalScore;

                            if (llmDecision.available()) {
                                bestLlmDecision = chooseBetterDecision(bestLlmDecision, llmDecision);
                                stepResult.addEvidence(Evidence.general(
                                        "LLM 影响性分析：influential=" + llmDecision.influential()
                                                + " | confidence=" + String.format("%.2f", llmDecision.confidence())
                                                + " | reason=" + llmDecision.reasoning(),
                                        "INFLUENCE_LLM",
                                        llmDecision.confidence()));
                            }

                            if (bestDiff == null || (diff.isSignificant()
                                    && bestDiff.getSimilarity() > diff.getSimilarity())) {
                                bestDiff = diff;
                            }
                        }
                    }

                    mutationCount++;
                    if (mutationCount > 0
                            && (totalScore / mutationCount) >= getEffectiveMinScore(context)) {
                        break;
                    }
                } catch (Exception e) {
                    log.warn("InfluenceValidationStep: mutation '{}' failed for param='{}': {}",
                            mutationValue, paramName, e.getMessage());
                }
            }

            double avgScore = mutationCount > 0 ? totalScore / mutationCount : 0.0;
            double effectiveMinScore = getEffectiveMinScore(context);
            double semanticPrior = semanticBusinessPrior(httpContext, candidate, profile, parameterRole);
            double aiPrior = aiEndpointPrior(candidate, parameterRole);
            double combinedPrior = combinePrior(semanticPrior, aiPrior);

            InfluenceResult influenceResult = new InfluenceResult();
            influenceResult.setParameterName(paramName);
            influenceResult.setInfluenceScore(Math.max(avgScore, combinedPrior * 0.08));
            influenceResult.setReplaySuccess(true);
            influenceResult.setDiffResult(bestDiff);
            influenceResult.setParameterProfile(profile);
            influenceResult.setMutationValues(allMutationValues);
            influenceResult.getDetails().add("Tested " + mutationCount + " mutations");
            influenceResult.getDetails().add("Average influence score: " + String.format("%.3f", avgScore));
            influenceResult.getDetails().add("Business semantic prior: " + String.format("%.3f", semanticPrior));
            influenceResult.getDetails().add("AI endpoint prior: " + String.format("%.3f", aiPrior));
            influenceResult.getDetails().add("Combined prior: " + String.format("%.3f", combinedPrior));
            if (parameterRole.available()) {
                influenceResult.getDetails().add("Parameter role: " + parameterRole.role()
                        + " | businessRelevant=" + parameterRole.likelyBusinessRelevant()
                        + " | confidence=" + String.format("%.2f", parameterRole.confidence())
                        + " | reason=" + parameterRole.reasoning());
                stepResult.addEvidence(Evidence.general(
                        "AI 参数作用分析：" + parameterRole.role()
                                + " | businessRelevant=" + parameterRole.likelyBusinessRelevant()
                                + " | confidence=" + String.format("%.2f", parameterRole.confidence())
                                + " | reason=" + parameterRole.reasoning(),
                        "PARAMETER_ROLE",
                        parameterRole.confidence()));
            }
            if (bestLlmDecision.available()) {
                influenceResult.getDetails().add("LLM influence: " + bestLlmDecision.influential()
                        + " | confidence=" + String.format("%.2f", bestLlmDecision.confidence())
                        + " | reason=" + bestLlmDecision.reasoning());
            }

            if (approvalEngine != null) {
                influenceResult = approvalEngine.approve(influenceResult, profile, effectiveMinScore);
            } else {
                boolean approved = avgScore >= effectiveMinScore;
                influenceResult.setApproved(approved);
                influenceResult.setApprovalReason(approved
                        ? "Score " + String.format("%.3f", avgScore) + " >= threshold " + effectiveMinScore
                        : "Score " + String.format("%.3f", avgScore) + " < threshold " + effectiveMinScore);
            }
            applyPriorApproval(influenceResult, combinedPrior, semanticPrior, aiPrior,
                    avgScore, mutationCount, parameterRole, candidate);
            applyLlmApproval(influenceResult, bestLlmDecision, avgScore, effectiveMinScore, combinedPrior);
            assignInfluenceStatus(influenceResult, avgScore, combinedPrior, effectiveMinScore);

            context.setInfluenceResult(influenceResult);

            if (bestDiff != null) {
                stepResult.addEvidence(Evidence.general(
                        "Influence validated: score=" + String.format("%.3f", avgScore)
                                + " | mutations=" + mutationCount
                                + " | diff=" + bestDiff,
                        "INFLUENCE_CHECK", avgScore));
            } else {
                stepResult.addEvidence(Evidence.general(
                        "Influence test: score=" + String.format("%.3f", avgScore)
                                + " | mutations=" + mutationCount,
                        "INFLUENCE_CHECK", avgScore));
            }

            if (influenceResult.isApproved()) {
                stepResult.setSuccess(true);
                stepResult.setConfidence(influenceResult.isUncertain()
                        ? Math.max(0.30, influenceResult.getInfluenceScore())
                        : influenceResult.getInfluenceScore());
                stepResult.setContinueWorkflow(true);
                stepResult.setReasoning("Influence status=" + influenceResult.getStatus()
                        + " | " + influenceResult.getApprovalReason());
                PluginLogger.getInstance().info(PluginLogger.Category.VERIFICATION, STEP_NAME,
                        "APPROVED: param='" + paramName
                                + "' | status=" + influenceResult.getStatus()
                                + "' | score=" + String.format("%.3f", avgScore)
                                + " | combinedPrior=" + String.format("%.3f", combinedPrior)
                                + " | mutations=" + mutationCount);
            } else {
                stepResult.setSuccess(false);
                stepResult.setConfidence(avgScore);
                stepResult.setContinueWorkflow(false);
                stepResult.setReasoning("Influence status=" + influenceResult.getStatus()
                        + " | not approved: " + influenceResult.getApprovalReason());
                PluginLogger.getInstance().info(PluginLogger.Category.VERIFICATION, STEP_NAME,
                        "REJECTED: param='" + paramName
                                + "' | status=" + influenceResult.getStatus()
                                + "' | score=" + String.format("%.3f", avgScore)
                                + " | combinedPrior=" + String.format("%.3f", combinedPrior)
                                + " | reason=" + influenceResult.getApprovalReason());
            }
        } catch (Exception e) {
            log.error("InfluenceValidationStep: unhandled exception for param='{}'", paramName, e);
            PluginLogger.getInstance().error(PluginLogger.Category.VERIFICATION, STEP_NAME,
                    "Exception during influence validation for '" + paramName + "'", e);

            stepResult.setSuccess(false);
            stepResult.setConfidence(0.0);
            stepResult.setContinueWorkflow(false);
            stepResult.setReasoning("Exception during influence validation: " + e.getMessage());
        }

        return stepResult;
    }

    private IReplayEngine getReplayEngine(WorkflowContext context) {
        return context.getReplayEngine() != null ? context.getReplayEngine() : replayEngine;
    }

    private double getEffectiveMinScore(WorkflowContext context) {
        if (context.getPolicyEngine() != null) {
            return context.getPolicyEngine().getMinInfluenceScore();
        }
        return minInfluenceScore;
    }

    private double mergeInfluenceScore(double deterministicScore, InfluenceLlmDecision decision) {
        if (!decision.available()) {
            return deterministicScore;
        }
        if (decision.influential()) {
            return Math.max(deterministicScore, Math.min(1.0, decision.confidence()));
        }
        return Math.min(deterministicScore, Math.max(0.0, 1.0 - decision.confidence()) * 0.2);
    }

    private List<String> prioritizeByRole(List<String> mutations,
                                          ParameterRole role,
                                          ParameterProfile profile) {
        if (mutations == null || mutations.isEmpty() || role == null || !role.available()) {
            return mutations != null ? mutations : List.of();
        }
        List<String> unique = new ArrayList<>();
        for (String mutation : mutations) {
            if (!unique.contains(mutation)) {
                unique.add(mutation);
            }
        }
        List<String> prioritized = new ArrayList<>();
        for (String action : role.recommendedMutations()) {
            addMutationForAction(prioritized, unique, action, profile);
        }
        for (String mutation : unique) {
            if (!prioritized.contains(mutation)) {
                prioritized.add(mutation);
            }
        }
        return prioritized;
    }

    private void addMutationForAction(List<String> target,
                                      List<String> available,
                                      String action,
                                      ParameterProfile profile) {
        if (action == null) {
            return;
        }
        String normalized = action.trim().toUpperCase();
        switch (normalized) {
            case "EMPTY" -> addIfAvailable(target, available, "");
            case "NULL_LITERAL" -> addIfAvailable(target, available, "null");
            case "INCREMENT", "DECREMENT", "FLIP_BOOLEAN", "APPEND_MARKER", "CHANGE_TEXT" ->
                    addFirstNonOriginal(target, available,
                            profile != null ? profile.getOriginalValue() : null);
            default -> {
            }
        }
    }

    private void addIfAvailable(List<String> target, List<String> available, String value) {
        if (available.contains(value) && !target.contains(value)) {
            target.add(value);
        }
    }

    private void addFirstNonOriginal(List<String> target, List<String> available, String originalValue) {
        for (String value : available) {
            if ((originalValue == null || !originalValue.equals(value)) && !target.contains(value)) {
                target.add(value);
                return;
            }
        }
    }

    private void applyPriorApproval(InfluenceResult influenceResult,
                                    double combinedPrior,
                                    double semanticPrior,
                                    double aiPrior,
                                    double avgScore,
                                    int mutationCount,
                                    ParameterRole parameterRole,
                                    CandidateParameter candidate) {
        if (influenceResult == null || influenceResult.isApproved()) {
            return;
        }
        String reason = influenceResult.getApprovalReason() != null
                ? influenceResult.getApprovalReason().toLowerCase()
                : "";
        if (reason.contains("not mutable") || reason.contains("replay failed")) {
            return;
        }
        if (combinedPrior >= SEMANTIC_PRIOR_APPROVE_THRESHOLD) {
            influenceResult.setApproved(true);
            influenceResult.setStatus(InfluenceStatus.UNCERTAIN);
            influenceResult.setApprovalReason("参数具备较强综合业务先验，diff 不明显时不提前剪枝："
                    + "combinedPrior=" + String.format("%.2f", combinedPrior)
                    + ", semanticPrior=" + String.format("%.2f", semanticPrior)
                    + ", aiPrior=" + String.format("%.2f", aiPrior)
                    + ", score=" + String.format("%.3f", avgScore)
                    + ", mutations=" + mutationCount
                    + (candidate != null
                    ? ", aiCandidateConfidence=" + String.format("%.2f", candidate.getConfidence())
                    + ", source=" + candidate.getSource()
                    : "")
                    + (parameterRole != null && parameterRole.available()
                    ? ", role=" + parameterRole.role() + ", reason=" + parameterRole.reasoning()
                    : ""));
        }
    }

    private void assignInfluenceStatus(InfluenceResult influenceResult,
                                       double avgScore,
                                       double combinedPrior,
                                       double effectiveMinScore) {
        if (influenceResult == null) {
            return;
        }
        if (influenceResult.getStatus() == InfluenceStatus.UNCERTAIN) {
            return;
        }
        if (influenceResult.isApproved() && avgScore >= effectiveMinScore) {
            influenceResult.setStatus(InfluenceStatus.INFLUENTIAL);
            return;
        }
        if (influenceResult.isApproved() && combinedPrior >= SEMANTIC_PRIOR_UNCERTAIN_THRESHOLD) {
            influenceResult.setStatus(InfluenceStatus.UNCERTAIN);
            return;
        }
        influenceResult.setStatus(InfluenceStatus.NOT_INFLUENTIAL);
    }

    private InfluenceLlmDecision chooseBetterDecision(InfluenceLlmDecision current,
                                                     InfluenceLlmDecision next) {
        if (!current.available()) {
            return next;
        }
        return next.confidence() > current.confidence() ? next : current;
    }

    private void applyLlmApproval(InfluenceResult influenceResult,
                                  InfluenceLlmDecision decision,
                                  double avgScore,
                                  double effectiveMinScore,
                                  double combinedPrior) {
        if (!decision.available()) {
            return;
        }
        boolean llmApproved = decision.influential()
                && decision.confidence() >= 0.55
                && avgScore >= Math.min(0.05, effectiveMinScore);
        if (llmApproved && !influenceResult.isApproved()) {
            influenceResult.setApproved(true);
            influenceResult.setStatus(InfluenceStatus.INFLUENTIAL);
            influenceResult.setApprovalReason("LLM confirmed parameter influence: " + decision.reasoning());
            return;
        }
        boolean llmRejected = !decision.influential()
                && decision.confidence() >= 0.75
                && avgScore < effectiveMinScore
                && combinedPrior < SEMANTIC_PRIOR_UNCERTAIN_THRESHOLD;
        if (llmRejected) {
            influenceResult.setApproved(false);
            influenceResult.setStatus(InfluenceStatus.NOT_INFLUENTIAL);
            influenceResult.setApprovalReason("LLM rejected as noise/unrelated diff: " + decision.reasoning());
        }
    }

    private double aiEndpointPrior(CandidateParameter candidate, ParameterRole parameterRole) {
        double score = 0.0;
        if (candidate != null) {
            String source = candidate.getSource() != null ? candidate.getSource() : "";
            if (source.contains("AI")) {
                score = Math.max(score, candidate.getConfidence());
            } else {
                score = Math.max(score, candidate.getConfidence() * 0.55);
            }
        }
        if (parameterRole != null && parameterRole.available() && parameterRole.likelyBusinessRelevant()) {
            score = Math.max(score, parameterRole.confidence());
        }
        return Math.max(0.0, Math.min(1.0, score));
    }

    private double combinePrior(double semanticPrior, double aiPrior) {
        double combined = 1.0 - ((1.0 - Math.max(0.0, semanticPrior))
                * (1.0 - Math.max(0.0, aiPrior)));
        if (aiPrior >= AI_CANDIDATE_UNCERTAIN_THRESHOLD) {
            combined = Math.max(combined, aiPrior);
        }
        return Math.min(1.0, combined);
    }

    private double semanticBusinessPrior(HTTPContext httpContext,
                                         CandidateParameter candidate,
                                         ParameterProfile profile,
                                         ParameterRole parameterRole) {
        double score = 0.0;
        if (parameterRole != null && parameterRole.strongBusinessSignal()) {
            score = Math.max(score, Math.min(0.85, 0.45 + parameterRole.confidence() * 0.35));
        }
        String name = candidate != null && candidate.getParameterName() != null
                ? candidate.getParameterName().toLowerCase()
                : "";
        String valueType = profile != null && profile.getDetectedType() != null
                ? profile.getDetectedType()
                : ParameterProfile.TYPE_UNKNOWN;

        if (isObjectIdentifierName(name)) {
            score += 0.45;
        }
        if (ParameterProfile.TYPE_NUMERIC.equals(valueType)
                || ParameterProfile.TYPE_UUID.equals(valueType)) {
            score += 0.20;
        }
        if (isBusinessActionEndpoint(httpContext)) {
            score += 0.15;
        }
        if (isLookupOrDetailEndpoint(httpContext)) {
            score += 0.15;
        }
        if (candidate != null && candidate.getConfidence() >= 0.70) {
            score += 0.10;
        }
        return Math.min(1.0, score);
    }

    private boolean isObjectIdentifierName(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        return name.equals("id")
                || name.equals("uid")
                || name.equals("userid")
                || name.equals("user_id")
                || name.equals("accountid")
                || name.equals("account_id")
                || name.equals("orderid")
                || name.equals("order_id")
                || name.equals("fileid")
                || name.equals("file_id")
                || name.equals("projectid")
                || name.equals("project_id")
                || name.equals("tenantid")
                || name.equals("tenant_id")
                || name.endsWith("id")
                || name.endsWith("_id")
                || name.endsWith("-id");
    }

    private boolean isBusinessActionEndpoint(HTTPContext httpContext) {
        if (httpContext == null) {
            return false;
        }
        String method = httpContext.getMethod() != null ? httpContext.getMethod().toUpperCase() : "";
        String path = httpContext.getPath() != null ? httpContext.getPath().toLowerCase() : "";
        if ("POST".equals(method) || "PUT".equals(method)
                || "PATCH".equals(method) || "DELETE".equals(method)) {
            return true;
        }
        return path.contains("update")
                || path.contains("edit")
                || path.contains("delete")
                || path.contains("change")
                || path.contains("detail")
                || path.contains("view")
                || path.contains("show");
    }

    private boolean isLookupOrDetailEndpoint(HTTPContext httpContext) {
        if (httpContext == null) {
            return false;
        }
        String path = httpContext.getPath() != null ? httpContext.getPath().toLowerCase() : "";
        return path.contains("detail")
                || path.contains("view")
                || path.contains("show")
                || path.contains("profile")
                || path.contains("user")
                || path.contains("account")
                || path.contains("order")
                || path.contains("job")
                || path.contains("file");
    }

}
