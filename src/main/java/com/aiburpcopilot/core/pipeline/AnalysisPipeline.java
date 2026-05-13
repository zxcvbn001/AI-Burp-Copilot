package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.utils.Constants;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * 分析流水线实现。
 * <p>
 * 按顺序执行注册的 IPipelineStage，异步处理 HTTPContext。
 * 使用独立线程池，不阻塞 Burp Proxy 主线程。
 * <p>
 * Verification replay is delegated to the unified execution engine. The
 * pipeline itself does not send active verification traffic.
 * <p>
 * 流水线生命周期：
 * <pre>
 * HTTPContext.submit() → [Stage1] → [Stage2] → ... → [StageN] → completed
 * </pre>
 * <p>
 * 每个 Stage 处理失败不影响后续 Stage 的执行。
 */
public class AnalysisPipeline implements IPipeline {

    private static final Logger log = LoggerFactory.getLogger(AnalysisPipeline.class);
    private final PluginLogger pluginLog = PluginLogger.getInstance();

    private final List<IPipelineStage> stages = new ArrayList<>();
    private final ExecutorService executor;
    private volatile boolean running = false;

    public AnalysisPipeline() {
        this.executor = new ThreadPoolExecutor(
                Constants.PIPELINE_WORKER_COUNT,
                Constants.PIPELINE_WORKER_COUNT,
                60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(Constants.PIPELINE_QUEUE_CAPACITY),
                new ThreadFactory() {
                    private int counter = 0;
                    @Override
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "pipeline-worker-" + counter++);
                        t.setDaemon(false);
                        return t;
                    }
                },
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
    }

    @Override
    public void submit(HTTPContext context) {
        if (!running) {
            log.warn("Pipeline is not running, rejecting context: {}", context.getPath());
            return;
        }

        pluginLog.debug("Pipeline", "Submit: " + context.getMethod() + " " + context.getPath());
        executor.submit(() -> processContext(context));
    }

    @Override
    public void registerStage(IPipelineStage stage) {
        stages.add(stage);
        log.info("Pipeline stage registered: {}", stage.getName());
        pluginLog.info("Pipeline", "Stage registered: " + stage.getName());
    }

    @Override
    public int getStageCount() {
        return stages.size();
    }

    @Override
    public void start() {
        running = true;
        log.info("Pipeline started with {} stages", stages.size());
    }

    @Override
    public void shutdown() {
        running = false;
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        log.info("Pipeline shutdown complete");
    }

    // ---------- Private ----------

    /**
     * 按顺序执行所有 Stage。
     * 每个 Stage 独立 try-catch，避免一个 Stage 失败影响后续。
     */
    private void processContext(HTTPContext context) {
        context.setAnalysisStatus(AnalysisStatus.ANALYZING);
        pluginLog.info("Pipeline", "Start: " + context.getMethod() + " " + context.getPath()
                + " [" + context.getParameters().size() + " params]");

        for (IPipelineStage stage : stages) {
            try {
                if (stage.shouldProcess(context)) {
                    long start = System.currentTimeMillis();
                    pluginLog.debug("Pipeline", "Stage '" + stage.getName() + "' starting...");
                    stage.process(context);
                    long elapsed = System.currentTimeMillis() - start;
                    log.debug("Stage '{}' completed in {}ms for: {}",
                            stage.getName(), elapsed, context.getPath());
                    pluginLog.info("Pipeline", "Stage '" + stage.getName()
                            + "' done (" + elapsed + "ms)");
                } else {
                    log.debug("Stage '{}' skipped for: {}", stage.getName(), context.getPath());
                    pluginLog.debug("Pipeline", "Stage '" + stage.getName() + "' skipped");
                }
            } catch (Exception e) {
                log.error("Pipeline stage '{}' failed for: {}",
                        stage.getName(), context.getPath(), e);
                pluginLog.error("Pipeline", "Stage '" + stage.getName()
                        + "' FAILED: " + e.getMessage(), e);
            }
        }

        String resultInfo = buildResultInfo(context);
        pluginLog.info("Pipeline", "Done: " + context.getMethod() + " " + context.getPath()
                + " -> " + context.getEndpointType() + " [" + context.getRiskLevel() + "]");
        if (resultInfo != null) {
            pluginLog.info("Pipeline", "  " + resultInfo);
        }
        log.debug("Pipeline completed for: {} {}", context.getMethod(), context.getPath());
    }

    private String buildResultInfo(HTTPContext context) {
        if (context.getAnalysisResult() == null) return null;
        var ar = context.getAnalysisResult();
        StringBuilder sb = new StringBuilder();
        if (ar.getAttackSurface() != null && !ar.getAttackSurface().isEmpty()) {
            sb.append("AttackSurface=").append(ar.getAttackSurface().size());
        }
        if (ar.getHighValueParams() != null && !ar.getHighValueParams().isEmpty()) {
            if (!sb.isEmpty()) sb.append(", ");
            sb.append("HighValueParams=").append(ar.getHighValueParams().size());
        }
        if (ar.getErrorMessage() != null) {
            if (!sb.isEmpty()) sb.append(", ");
            sb.append("Error=").append(ar.getErrorMessage());
        }
        if (ar.getAiCallDurationMs() > 0) {
            if (!sb.isEmpty()) sb.append(", ");
            sb.append("AICost=").append(ar.getAiCallDurationMs()).append("ms");
        }
        return sb.isEmpty() ? null : sb.toString();
    }
}
