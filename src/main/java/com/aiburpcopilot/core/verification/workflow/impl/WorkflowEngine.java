package com.aiburpcopilot.core.verification.workflow.impl;

import com.aiburpcopilot.core.verification.model.*;
import com.aiburpcopilot.core.verification.workflow.*;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Workflow 瀵洘鎼哥€圭偟骞囬妴?
 * <p>
 * 閺嶇绺惧銉ょ稊濞翠焦澧界悰灞界穿閹垮函绱濈拹鐔荤煑閿?
 * <ul>
 *   <li>閺嶈宓?WorkflowDefinition 缂傛牗甯撳銉╊€冩い鍝勭碍閹笛嗩攽</li>
 *   <li>濮濄儵顎冮梻銊﹀付閿涘湯tep Gate閿涘绱伴弽瑙勫祦 StepResult.continueWorkflow 閸愬啿鐣鹃弰顖氭儊缂佈呯敾</li>
 *   <li>閸嬫粍顒涢弶鈥叉閿涙碍鏁幐浣峰瘜閸?stop() 閸滃苯绱撶敮绋夸粻濮?/li>
 *   <li>鐠囦焦宓侀崥鍫濊嫙閿涙艾鐨㈤崥鍕劄妤犮倛鐦夐幑顔界湽閹鍩?WorkflowResult</li>
 *   <li>缂冾喕淇婃惔锕侇吀缁犳绱板Ч鍌氭倗濮濄儵顎冪純顔讳繆鎼达妇娈戦獮鍐叉綆閸?/li>
 * </ul>
 * <p>
 * 鐠佹崘顓搁崢鐔峰灟閿涙艾绱╅幙搴㈡Ц闁氨鏁ら惃鍕剁礉娑撳秹鎷＄€靛湱澹掔€规碍绱″ú鐐佃閸ㄥ鈧?
 * 閺傛澘顤冨蹇旂缁鐎烽崣顏堟付閺傛澘顤?WorkflowDefinition + VerificationStep閿涘奔绗夋穱顔芥暭瀵洘鎼搁妴?
 */
public class WorkflowEngine implements IWorkflowEngine {

    private static final Logger log = LoggerFactory.getLogger(WorkflowEngine.class);

    /** 濞夈劌鍞介惃?VerificationStep 鐎圭偟骞囬弰鐘茬殸閿涘牊顒炴銈呮倳 -> 濮濄儵顎冪€圭偟骞囬敍?*/
    private final Map<String, VerificationStep> steps = new ConcurrentHashMap<>();

    /** Workflow 濞夈劌鍞芥稉顓炵妇 */
    private final IWorkflowRegistry workflowRegistry;

    /**
     * 閺嬪嫰鈧?WorkflowEngine閵?
     *
     * @param workflowRegistry Workflow 濞夈劌鍞芥稉顓炵妇閿涘瞼鏁ゆ禍搴㈢叀閹?WorkflowDefinition
     */
    public WorkflowEngine(IWorkflowRegistry workflowRegistry) {
        this.workflowRegistry = workflowRegistry;
    }

    /**
     * 閺冪姴寮弸鍕偓鐙呯礄闂団偓鐟曚礁鎮楃紒顓☆啎缂?registry閿涘鈧?
     */
    public WorkflowEngine() {
        this(null);
    }

    @Override
    public WorkflowResult execute(WorkflowContext context) {
        long workflowStart = System.currentTimeMillis();
        WorkflowResult result = new WorkflowResult();

        if (context == null || context.getCandidate() == null) {
            log.warn("WorkflowEngine: execute called with null context or candidate");
            return buildErrorResult(result, "Context or candidate is null");
        }

        // 1. 閺屻儲澹?WorkflowDefinition
        Optional<WorkflowDefinition> defOpt = Optional.empty();
        if (workflowRegistry != null && context.getCandidate().getAttackType() != null) {
            defOpt = workflowRegistry.findWorkflow(context.getCandidate().getAttackType());
        }

        if (!defOpt.isPresent()) {
            String msg = "No workflow definition found for attackType="
                    + context.getCandidate().getAttackType();
            log.warn("WorkflowEngine: {}", msg);
            PluginLogger.getInstance().warn("WorkflowEngine", msg);
            return buildErrorResult(result, msg);
        }

        WorkflowDefinition def = defOpt.get();
        context.setWorkflowDefinition(def);

        log.info("WorkflowEngine: executing workflow '{}' for attackType={}, param={}, steps={}",
                def.getName(), def.getAttackType(),
                context.getCandidate().getParameterName(), def.getStepNames().size());

        PluginLogger.getInstance().info("WorkflowEngine",
                "Executing workflow: " + def.getName()
                        + " | param=" + context.getCandidate().getParameterName()
                        + " | steps=" + def.getStepNames());

        result.setAttackType(def.getAttackType());
        result.setWorkflowName(def.getName());
        result.setParameterName(context.getCandidate().getParameterName());

        List<StepResult> stepResults = new ArrayList<>();

        // 婵″倹鐏?requires Influence 鐎光剝澹掗敍灞藉帥濡偓閺屻儲妲搁崥锕€鍑￠張?InfluenceResult
        if (def.isRequiresInfluenceApproval() && context.getInfluenceResult() != null) {
            if (!context.getInfluenceResult().isApproved()) {
                String reason = context.getInfluenceResult().getApprovalReason();
                log.info("WorkflowEngine: Influence not approved, stopping workflow: {}", reason);
                PluginLogger.getInstance().info("WorkflowEngine", "Influence not approved: " + reason);
                result.setCompleted(false);
                result.setStopReason(reason);
                result.setStoppedAtStep(0);
                result.setDurationMs(System.currentTimeMillis() - workflowStart);
                return result;
            }
        }

        // 2. 閹稿銆庢惔蹇斿⒔鐞涘本鐦℃稉顏咁劄妤?
        int executedSteps = 0;
        for (int i = 0; i < def.getStepNames().size(); i++) {
            // 濡偓閺屻儲妲搁崥锕侇潶婢舵牠鍎撮崑婊勵剾
            if (context.isStopped()) {
                log.info("WorkflowEngine: workflow stopped externally: {}", context.getStopReason());
                PluginLogger.getInstance().info("WorkflowEngine",
                        "Workflow stopped: " + context.getStopReason());
                result.setCompleted(false);
                result.setStopReason(context.getStopReason());
                result.setStoppedAtStep(i);
                break;
            }

            String stepName = def.getStepNames().get(i);
            context.setCurrentStepIndex(i);
            if (!context.isPayloadVerificationAllowed()
                    && !InfluenceValidationStep.STEP_NAME.equals(stepName)) {
                String msg = "Payload verification blocked by endpoint action policy";
                log.info("WorkflowEngine: {}", msg);
                PluginLogger.getInstance().warn("WorkflowEngine", msg);
                result.setCompleted(false);
                result.setStopReason(msg);
                result.setStoppedAtStep(i);
                break;
            }
            if (InfluenceValidationStep.STEP_NAME.equals(stepName)
                    && context.getInfluenceResult() != null
                    && context.getInfluenceResult().isApproved()) {
                log.info("WorkflowEngine: skipping InfluenceValidation because influence is already approved");
                PluginLogger.getInstance().info("WorkflowEngine",
                        "Skipping InfluenceValidation: already approved");
                executedSteps++;
                continue;
            }

            // 閺屻儲澹樺銉╊€冪€圭偟骞?
            VerificationStep step = steps.get(stepName);
            if (step == null) {
                String msg = "Step implementation not found: " + stepName;
                log.warn("WorkflowEngine: {}", msg);
                PluginLogger.getInstance().warn("WorkflowEngine", msg);

                StepResult missingStep = StepResult.hardFail(stepName, msg);
                missingStep.setDurationMs(0);
                stepResults.add(missingStep);
                result.setCompleted(false);
                result.setStopReason(msg);
                result.setStoppedAtStep(i);
                break;
            }

            // 3. 閹笛嗩攽濮濄儵顎?
            try {
                context = executeStep(context, stepName, step);

                StepResult stepResult = context.getLastStepResult();
                if (stepResult != null) {
                    stepResults.add(stepResult);
                    executedSteps++;

                    // 4. 濮濄儵顎冮梻銊﹀付閿涙碍顥呴弻銉︽Ц閸氾妇鎴风紒?
                    if (!stepResult.isContinueWorkflow()) {
                        log.info("WorkflowEngine: step '{}' requested stop: {}",
                                stepName, stepResult.getReasoning());
                        PluginLogger.getInstance().info("WorkflowEngine",
                                "Workflow stopped at step: " + stepName
                                        + " | reason=" + stepResult.getReasoning());
                        result.setCompleted(false);
                        result.setStoppedAtStep(i);
                        result.setStopReason(stepResult.getReasoning());
                        break;
                    }
                }
            } catch (Exception e) {
                log.error("WorkflowEngine: unhandled exception in step '{}'", stepName, e);
                PluginLogger.getInstance().error("WorkflowEngine",
                        "Step execution exception: " + stepName, e);

                StepResult errorResult = new StepResult(false, 0.0, false,
                        stepName, "Unhandled exception: " + e.getMessage());
                errorResult.setDurationMs(0);
                stepResults.add(errorResult);

                result.setCompleted(false);
                result.setStoppedAtStep(i);
                result.setStopReason("Exception in step " + stepName + ": " + e.getMessage());
                break;
            }
        }

        // 5. 閸掋倖鏌囬弰顖氭儊鐎瑰本鍨氶幍鈧張澶嬵劄妤?
        if (!result.isCompleted() && result.getStopReason() == null) {
            result.setCompleted(true); // 閹碘偓閺堝顒炴銈嗗⒔鐞涘苯鐣В?
        }

        // 6. 閺€鍫曟肠閹碘偓閺堝鐦夐幑?
        result.setStepResults(stepResults);
        result.collectEvidence();

        // 7. 鐠侊紕鐣婚幀璁崇秼缂冾喕淇婃惔锔肩礄閸氬嫭顒炴銈囩枂娣団€冲閻ㄥ嫬濮為弶鍐ㄩ挬閸у浄绱?
        if (!stepResults.isEmpty()) {
            double totalConfidence = 0.0;
            int confidenceSteps = 0;
            for (StepResult sr : stepResults) {
                totalConfidence += sr.getConfidence();
                confidenceSteps++;
            }
            result.setOverallConfidence(confidenceSteps > 0 ? totalConfidence / confidenceSteps : 0.0);
        }

        result.setDurationMs(System.currentTimeMillis() - workflowStart);
        result.setCompleted(executedSteps == def.getStepNames().size()
                && !context.isStopped());

        log.info("WorkflowEngine: workflow '{}' completed={}, confidence={:.2f}, duration={}ms, evidence={}",
                def.getName(), result.isCompleted(), result.getOverallConfidence(),
                result.getDurationMs(), result.getEvidence().size());

        PluginLogger.getInstance().info("WorkflowEngine",
                "Workflow result: " + def.getName()
                        + " | completed=" + result.isCompleted()
                        + " | confidence=" + String.format("%.2f", result.getOverallConfidence())
                        + " | duration=" + result.getDurationMs() + "ms"
                        + " | evidence=" + result.getEvidence().size());

        return result;
    }

    @Override
    public WorkflowContext executeStep(WorkflowContext context, String stepName, VerificationStep step) {
        if (context == null || step == null) {
            log.warn("WorkflowEngine: executeStep called with null context or step");
            return context;
        }

        long stepStart = System.currentTimeMillis();
        StepResult result;

        try {
            // 閹笛嗩攽濮濄儵顎?
            result = step.execute(context);

            if (result == null) {
                log.warn("WorkflowEngine: step '{}' returned null StepResult", stepName);
                result = StepResult.hardFail(stepName, "Step returned null result");
                result.setDurationMs(0);
            }
        } catch (Exception e) {
            log.error("WorkflowEngine: exception executing step '{}'", stepName, e);
            PluginLogger.getInstance().error("WorkflowEngine",
                    "Exception in step: " + stepName, e);

            result = new StepResult(false, 0.0, false, stepName,
                    "Step exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // 鐠佸墽鐤嗗銉╊€冮懓妤佹
        long stepDuration = System.currentTimeMillis() - stepStart;
        result.setDurationMs(stepDuration);
        result.setStepName(stepName);

        context.setLastStepResult(result);

        if (result.getEvidences() != null) {
            for (Evidence evidence : result.getEvidences()) {
                if (evidence != null) {
                    evidence.setSourceStep(stepName);
                    context.addEvidence(evidence);
                }
            }
        }

        log.debug("WorkflowEngine: step '{}' completed | success={} | confidence={:.2f} | continue={} | duration={}ms",
                stepName, result.isSuccess(), result.getConfidence(),
                result.isContinueWorkflow(), stepDuration);

        return context;
    }

    @Override
    public void stop(WorkflowContext context) {
        if (context != null) {
            context.stop("Manually stopped by engine");
            log.info("WorkflowEngine: workflow context stopped");
            PluginLogger.getInstance().info("WorkflowEngine", "Workflow context manually stopped");
        }
    }

    @Override
    public void registerStep(String stepName, VerificationStep step) {
        if (stepName == null || stepName.isEmpty() || step == null) {
            log.warn("WorkflowEngine: refused to register step with null name or implementation");
            PluginLogger.getInstance().warn("WorkflowEngine",
                    "Refused to register step: name=" + stepName + " impl=" + step);
            return;
        }

        VerificationStep previous = steps.put(stepName, step);

        PluginLogger.getInstance().info("WorkflowEngine",
                "Registered step: " + stepName
                        + " | impl=" + step.getClass().getSimpleName()
                        + (previous != null ? " (replaced)" : "")
                        + " | total=" + steps.size());

        log.info("WorkflowEngine: registered step '{}' -> {} (total steps={})",
                stepName, step.getClass().getSimpleName(), steps.size());
    }

    @Override
    public VerificationStep findStep(String stepName) {
        if (stepName == null) {
            return null;
        }
        return steps.get(stepName);
    }

    // ---------- Private Helpers ----------

    /**
     * 閺嬪嫬缂撻柨娆掝嚖缂佹挻鐏夐惃鍕窡閸斺晜鏌熷▔鏇樷偓?
     */
    private WorkflowResult buildErrorResult(WorkflowResult result, String reason) {
        result.setCompleted(false);
        result.setStopReason(reason);
        result.setOverallConfidence(0.0);
        return result;
    }
}
