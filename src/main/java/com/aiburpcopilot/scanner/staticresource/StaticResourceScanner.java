package com.aiburpcopilot.scanner.staticresource;

import burp.api.montoya.MontoyaApi;
import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.EndpointActionClassifier;
import com.aiburpcopilot.core.context.EndpointActionType;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterContext;
import com.aiburpcopilot.core.context.ParameterType;
import com.aiburpcopilot.core.context.RiskLevel;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.core.pipeline.HistoryEventBus;
import com.aiburpcopilot.prompts.IPromptService;
import com.aiburpcopilot.scanner.endpoint.IEndpointClassifier;
import com.aiburpcopilot.scanner.staticresource.js.JsAnalysisApiClient;
import com.aiburpcopilot.scanner.staticresource.js.JsAnalysisResponse;
import com.aiburpcopilot.utils.HttpUtil;
import com.aiburpcopilot.utils.InternalTrafficMarker;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Semaphore;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class StaticResourceScanner implements IStaticScanner {

    private static final Logger log = LoggerFactory.getLogger(StaticResourceScanner.class);

    private final IAIProvider aiProvider;
    private final IPromptService promptService;
    private final ICacheService cacheService;
    private final IConfigService configService;
    private final RegexRuleEngine ruleEngine;
    private final IHistoryService historyService;
    private final IEndpointClassifier endpointClassifier;
    private final JsAnalysisApiClient jsAnalysisClient;
    private final MontoyaApi api;
    private final com.aiburpcopilot.core.pipeline.AIAnalysisStage recoveredEndpointAnalysisStage;
    private final Semaphore jsAnalysisPermits;
    private final ConcurrentMap<String, Long> lastStaticProgressPublishAt = new ConcurrentHashMap<>();

    public StaticResourceScanner(IAIProvider aiProvider,
                                 IPromptService promptService,
                                 ICacheService cacheService,
                                 IConfigService configService,
                                 IHistoryService historyService,
                                 IEndpointClassifier endpointClassifier,
                                 MontoyaApi api) {
        this.aiProvider = aiProvider;
        this.promptService = promptService;
        this.cacheService = cacheService;
        this.configService = configService;
        this.ruleEngine = new RegexRuleEngine();
        this.historyService = historyService;
        this.endpointClassifier = endpointClassifier;
        AppConfig.JsAnalysisConfig jsConfig = configService.getConfig().getJsAnalysis();
        this.jsAnalysisClient = new JsAnalysisApiClient(jsConfig);
        this.jsAnalysisPermits = new Semaphore(Math.max(1, jsConfig.getMaxConcurrentAnalyses()));
        this.api = api;
        this.recoveredEndpointAnalysisStage = new com.aiburpcopilot.core.pipeline.AIAnalysisStage(
                aiProvider, promptService, cacheService, configService);
    }

    @Override
    public boolean shouldScan(HTTPContext context) {
        if (context.getResponseBody() == null || context.getResponseBody().length == 0) {
            context.setStaticScanResult("静态文件扫描已跳过：响应体为空。");
            return false;
        }

        AppConfig.ScanConfig scanConfig = configService.getConfig().getScan();
        String path = context.getPath() != null ? context.getPath() : context.getUrl();
        if (HttpUtil.hasExtension(path, scanConfig.getSkipExtensions())) {
            context.setStaticScanResult("静态文件扫描已跳过：命中扩展名黑名单。Path=" + path);
            return false;
        }
        if (HttpUtil.shouldSkipByKeyword(path, scanConfig.getSkipKeywords())) {
            context.setStaticScanResult("静态文件扫描已跳过：命中路径关键字黑名单。Path=" + path);
            return false;
        }
        int maxSizeKb = Math.max(1, scanConfig.getStaticScanMaxSize());
        int maxSizeBytes = maxSizeKb * 1024;
        if (context.getResponseBody().length > maxSizeBytes) {
            context.setStaticScanResult("静态文件扫描已跳过：响应体过大。大小="
                    + context.getResponseBody().length + " bytes，限制=" + maxSizeKb + " KB");
            return false;
        }
        if (!scanConfig.getResponseBodyScan().isEnabled()) {
            context.setStaticScanResult("静态文件扫描已跳过：responseBodyScan.enabled=false。");
            return false;
        }
        if (!looksLikeJavaScript(context)) {
            context.setStaticScanResult("静态文件扫描已跳过：当前仅扫描 JavaScript 资源。");
            return false;
        }
        return true;
    }

    @Override
    public StaticScanResult scan(HTTPContext context) {
        StaticScanResult result = new StaticScanResult();
        if (!shouldScan(context)) {
            result.setHasFindings(false);
            return result;
        }

        try {
            byte[] scanBody = resolveBodyForStaticAnalysis(context);
            String content = new String(scanBody, StandardCharsets.UTF_8);
            result.setFindings(new ArrayList<>());
            result.setHasFindings(false);

            if (looksLikeJavaScript(context)) {
                enrichWithJsAnalysis(context, content, result, 0, new LinkedHashSet<>());
            }

            context.setStaticScanResult(buildSummary(context, result));
            clearProgressThrottle(context);
            return result;
        } catch (Exception e) {
            log.error("Static scan failed for: {}", context.getPath(), e);
            String detail = e.getClass().getSimpleName()
                    + (e.getMessage() != null && !e.getMessage().isBlank() ? ": " + e.getMessage() : "");
            context.setStaticScanResult("静态分析失败: " + detail);
            result.setHasFindings(false);
            clearProgressThrottle(context);
            return result;
        }
    }

    private byte[] resolveBodyForStaticAnalysis(HTTPContext context) {
        byte[] rawResponse = context.getRawResponse();
        if (rawResponse != null && rawResponse.length > 0) {
            byte[] rawBody = extractResponseBody(rawResponse);
            if (rawBody != null && rawBody.length > 0) {
                return rawBody;
            }
        }
        return context.getResponseBody() != null ? context.getResponseBody() : new byte[0];
    }

    public void reloadRules() {
        log.info("Static scan local regex rules are disabled; using cloud JS analysis results only");
    }

    private void enrichWithJsAnalysis(HTTPContext context,
                                      String content,
                                      StaticScanResult result,
                                      int depth,
                                      Set<String> visitedScripts) {
        AppConfig.JsAnalysisConfig jsConfig = configService.getConfig().getJsAnalysis();
        String jsMode = normalizeJsMode(jsConfig);
        if (!jsConfig.isEnabled()) {
            appendScriptResult(result, buildScriptSummary(context.getUrl(), false, -1, "JS AST 分析已关闭", null));
            publishStaticProgress(context, result, true);
            return;
        }

        if (!jsAnalysisClient.isHealthy()) {
            appendScriptResult(result, buildScriptSummary(context.getUrl(), false, -1,
                    "JS AST 服务不可用: " + jsAnalysisClient.getLastHealthMessage(), null));
            publishStaticProgress(context, result, true);
            return;
        }

        String scriptUrl = normalizeAbsoluteUrl(context.getUrl(), context.getUrl());
        if (scriptUrl == null || !visitedScripts.add(scriptUrl)) {
            return;
        }

        PluginLogger.getInstance().info(
                PluginLogger.Category.SYSTEM,
                "JS-AST",
                "script=" + safe(scriptUrl)
                        + ", mode=" + jsMode
                        + ", async=" + jsConfig.isSubmitAsync()
                        + ", depth=" + depth);

        probeSourceMap(scriptUrl, result);
        publishStaticProgress(context, result);

        JsAnalysisResponse analysis = analyzeScriptWithLimit(scriptUrl, content, context.getUrl(),
                progress -> recordJsAstProgress(context, result, progress));
        if (analysis == null || !analysis.isSuccess()) {
            appendScriptResult(result, buildScriptSummary(scriptUrl, true, 200,
                    "JS AST 分析失败: " + (analysis != null ? analysis.errorMessage() : "empty response"), analysis));
            publishStaticProgress(context, result, true);
            return;
        }

        appendScriptResult(result, buildScriptSummary(scriptUrl, true, 200, "JS AST 分析完成", analysis));
        mergeCloudAnalysis(scriptUrl, context.getUrl(), analysis, result);
        recordJsAstFinished(context, result, scriptUrl, analysis, "completed", "JS AST 分析完成");
        handleRecoveredEndpoints(context, scriptUrl, analysis, result);
        publishStaticProgress(context, result, true);

        if (depth >= jsConfig.getMaxRecursiveDepth()) {
            return;
        }

        List<String> referencedScripts = collectReferencedScripts(content, context.getUrl(), analysis);
        int limit = Math.min(referencedScripts.size(), jsConfig.getMaxReferencedScripts());
        boolean autoFetchReferencedScripts = jsConfig.isAutoFetchReferencedScripts();
        for (int index = 0; index < limit; index++) {
            String childUrl = referencedScripts.get(index);
            if (!autoFetchReferencedScripts) {
                appendScriptResult(result, buildScriptSummary(
                        childUrl,
                        false,
                        -1,
                        "引用 JS 已发现，但自动抓取已关闭，未发包抓取",
                        null));
                publishStaticProgress(context, result, true);
                continue;
            }
            var validation = validateStaticChild(childUrl);
            appendScriptResult(result, validation.summary);
            publishStaticProgress(context, result);
            if (!validation.exists || visitedScripts.contains(childUrl)) {
                continue;
            }
            probeSourceMap(childUrl, result);
            publishStaticProgress(context, result);
            JsAnalysisResponse childAnalysis = analyzeScriptWithLimit(childUrl,
                    new String(validation.responseBody, StandardCharsets.UTF_8),
                    context.getUrl(),
                    progress -> recordJsAstProgress(context, result, progress));
            if (childAnalysis == null || !childAnalysis.isSuccess()) {
                appendScriptResult(result, buildScriptSummary(childUrl, true, validation.statusCode,
                        "引用 JS AST 分析失败: " + (childAnalysis != null ? childAnalysis.errorMessage() : "empty response"),
                        childAnalysis));
                publishStaticProgress(context, result, true);
                continue;
            }
            appendScriptResult(result, buildScriptSummary(childUrl, true, validation.statusCode, "引用 JS AST 分析完成", childAnalysis));
            mergeCloudAnalysis(childUrl, context.getUrl(), childAnalysis, result);
            recordJsAstFinished(context, result, childUrl, childAnalysis, "completed", "引用 JS AST 分析完成");
            handleRecoveredEndpoints(context, childUrl, childAnalysis, result);
            publishStaticProgress(context, result, true);
            enrichWithJsAnalysis(context,
                    new String(validation.responseBody, StandardCharsets.UTF_8),
                    result,
                    depth + 1,
                    visitedScripts);
        }
    }

    private void handleRecoveredEndpoints(HTTPContext context,
                                          String sourceScriptUrl,
                                          JsAnalysisResponse analysis,
                                          StaticScanResult result) {
        List<StaticScanResult.RecoveredEndpoint> recoveredEndpoints = verifyRecoveredEndpoints(context, sourceScriptUrl, analysis);
        if (recoveredEndpoints.isEmpty()) {
            return;
        }
        if (result.getRecoveredEndpoints() == null) {
            result.setRecoveredEndpoints(new ArrayList<>());
        }
        result.getRecoveredEndpoints().addAll(recoveredEndpoints);
        for (StaticScanResult.RecoveredEndpoint recovered : recoveredEndpoints) {
            if (recovered.isValidated()) {
                registerRecoveredEndpointHistory(context, analysis, recovered);
            }
        }
    }

    private List<String> collectReferencedScripts(String content, String baseUrl, JsAnalysisResponse analysis) {
        List<String> referencedScripts = extractReferencedScripts(content, baseUrl);
        for (JsAnalysisResponse.AssetResult asset : scriptAssets(analysis)) {
            String normalized = normalizeAbsoluteUrl(baseUrl, asset.getUrl());
            if (normalized != null && !referencedScripts.contains(normalized)) {
                referencedScripts.add(normalized);
            }
        }
        return referencedScripts;
    }

    private List<StaticScanResult.RecoveredEndpoint> verifyRecoveredEndpoints(HTTPContext context,
                                                                              String sourceScriptUrl,
                                                                              JsAnalysisResponse analysis) {
        List<StaticScanResult.RecoveredEndpoint> recovered = new ArrayList<>();
        List<JsAnalysisResponse.ApiResult> apis = endpointApis(analysis);
        if (apis.isEmpty()) {
            return recovered;
        }

        URI baseUri = safeUri(sourceScriptUrl != null && !sourceScriptUrl.isBlank() ? sourceScriptUrl : context.getUrl());
        if (baseUri == null) {
            return recovered;
        }

        int max = Math.max(1, configService.getConfig().getJsAnalysis().getMaxVerifiedEndpointsPerScript());
        boolean autoVerify = configService.getConfig().getJsAnalysis().isAutoVerifyRecoveredApis();
        apis.stream()
                .sorted(Comparator.comparing(api -> api.getUrl() != null ? api.getUrl().length() : Integer.MAX_VALUE))
                .limit(max)
                .forEach(api -> recovered.add(autoVerify
                        ? validateEndpointCandidate(baseUri, sourceScriptUrl, api)
                        : buildUnverifiedEndpoint(baseUri, sourceScriptUrl, api)));
        return recovered;
    }

    private StaticScanResult.RecoveredEndpoint buildUnverifiedEndpoint(URI baseUri,
                                                                       String sourceScriptUrl,
                                                                       JsAnalysisResponse.ApiResult api) {
        StaticScanResult.RecoveredEndpoint recovered = new StaticScanResult.RecoveredEndpoint();
        recovered.setSourceScriptUrl(sourceScriptUrl);
        recovered.setMethod(normalizeHttpMethod(api.getMethod()));
        recovered.setParams(api.getParams());
        recovered.setRawUrl(api.getUrl());

        String absoluteUrl = resolveApiAbsoluteUrl(baseUri, api);
        recovered.setUrl(absoluteUrl != null ? absoluteUrl : api.getUrl());
        recovered.setValidated(false);
        recovered.setStatusCode(-1);
        recovered.setReason(buildRecoveredReason("已从 JS AST 恢复，自动发包验证已关闭", api));
        return recovered;
    }

    private StaticScanResult.RecoveredEndpoint validateEndpointCandidate(URI baseUri,
                                                                         String sourceScriptUrl,
                                                                         JsAnalysisResponse.ApiResult api) {
        StaticScanResult.RecoveredEndpoint recovered = new StaticScanResult.RecoveredEndpoint();
        recovered.setSourceScriptUrl(sourceScriptUrl);
        recovered.setMethod(normalizeHttpMethod(api.getMethod()));
        recovered.setParams(api.getParams());
        recovered.setRawUrl(api.getUrl());

        String absoluteUrl = resolveApiAbsoluteUrl(baseUri, api);
        recovered.setUrl(absoluteUrl != null ? absoluteUrl : api.getUrl());

        if (absoluteUrl == null) {
            recovered.setValidated(false);
            recovered.setReason(buildRecoveredReason("无法解析相对接口地址", api));
            recovered.setStatusCode(-1);
            return recovered;
        }

        ValidationReplay replay = replayRequest(absoluteUrl, recovered.getMethod(), false, api);
        recovered.setValidated(replay.exists);
        recovered.setStatusCode(replay.statusCode);
        recovered.setReason(buildRecoveredReason(replay.reason, api));
        recovered.setRequestBytes(replay.requestBytes);
        recovered.setResponseBytes(replay.responseBytes);
        return recovered;
    }

    private String resolveApiAbsoluteUrl(URI baseUri, JsAnalysisResponse.ApiResult api) {
        if (api == null) {
            return null;
        }
        String resolvedUrl = api.getResolvedUrl();
        if (resolvedUrl != null && !resolvedUrl.isBlank()) {
            String normalizedResolved = normalizeAbsoluteUrl(baseUri != null ? baseUri.toString() : null, resolvedUrl);
            if (normalizedResolved != null) {
                return normalizedResolved;
            }
        }
        return normalizeAbsoluteUrl(baseUri != null ? baseUri.toString() : null, api.getUrl());
    }

    private String buildRecoveredReason(String baseReason, JsAnalysisResponse.ApiResult api) {
        StringBuilder reason = new StringBuilder(baseReason != null ? baseReason : "");
        if (api != null) {
            if (api.getConfidence() != null && !api.getConfidence().isBlank()) {
                reason.append(" | confidence=").append(api.getConfidence());
            }
            if (api.getBaseUrl() != null && !api.getBaseUrl().isBlank()) {
                reason.append(" | baseUrl=").append(api.getBaseUrl());
            }
            if (api.getNotes() != null && !api.getNotes().isEmpty()) {
                reason.append(" | notes=").append(String.join(",", api.getNotes()));
            }
        }
        return reason.toString();
    }

    private StaticScanResult.AnalyzedScript buildScriptSummary(String url,
                                                               boolean validated,
                                                               int statusCode,
                                                               String reason,
                                                               JsAnalysisResponse analysis) {
        StaticScanResult.AnalyzedScript script = new StaticScanResult.AnalyzedScript();
        script.setUrl(url);
        script.setValidated(validated);
        script.setStatusCode(statusCode);
        script.setReason(reason);
        script.setApiCount(analysis != null && analysis.getApis() != null ? analysis.getApis().size() : 0);
        script.setSecretCount(analysis != null && analysis.getSecrets() != null ? analysis.getSecrets().size() : 0);
        script.setRiskCount(analysis != null && analysis.getRisk() != null ? analysis.getRisk().size() : 0);
        if (analysis != null && analysis.getAssets() != null && !analysis.getAssets().isEmpty()) {
            script.setReason(reason + " | assets=" + analysis.getAssets().size());
        }
        return script;
    }

    private void appendScriptResult(StaticScanResult result, StaticScanResult.AnalyzedScript script) {
        if (script == null) {
            PluginLogger.getInstance().warn(
                    PluginLogger.Category.SYSTEM,
                    "JS-AST",
                    "Skipped null analyzed script result");
            return;
        }
        if (result.getAnalyzedScripts() == null) {
            result.setAnalyzedScripts(new ArrayList<>());
        }
        result.getAnalyzedScripts().add(script);
    }

    private JsAnalysisResponse analyzeScriptWithLimit(String scriptUrl,
                                                       String content,
                                                       String baseUrl,
                                                       Consumer<JsAnalysisApiClient.TaskProgress> progressConsumer) {
        boolean acquired = false;
        try {
            jsAnalysisPermits.acquire();
            acquired = true;
            return jsAnalysisClient.analyze(scriptUrl, content, baseUrl, progressConsumer);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            JsAnalysisResponse response = new JsAnalysisResponse();
            response.setSuccess(false);
            JsAnalysisResponse.Error error = new JsAnalysisResponse.Error();
            error.setMessage("JS AST 分析等待并发许可时被中断");
            response.setError(error);
            return response;
        } finally {
            if (acquired) {
                jsAnalysisPermits.release();
            }
        }
    }

    private void recordJsAstFinished(HTTPContext context,
                                     StaticScanResult result,
                                     String scriptUrl,
                                     JsAnalysisResponse analysis,
                                     String status,
                                     String prefix) {
        if (result == null || analysis == null) {
            return;
        }
        if (result.getJsAstTasks() == null) {
            result.setJsAstTasks(new ArrayList<>());
        }
        StaticScanResult.JsAstTaskStatus finished = new StaticScanResult.JsAstTaskStatus();
        finished.setScriptUrl(firstNonBlank(analysis.getUrl(), scriptUrl));
        finished.setTaskId(analysis.getTaskId());
        finished.setPhase("COMPLETED");
        finished.setStatus(status);
        finished.setMessage(prefix + " | findings=" + totalFindingCount(analysis)
                + " | endpoints=" + endpointApis(analysis).size()
                + " | secrets=" + exposureSecrets(analysis).size()
                + " | scripts=" + scriptAssets(analysis).size());
        result.getJsAstTasks().add(finished);
        publishStaticProgress(context, result, true);
    }

    private void probeSourceMap(String scriptUrl, StaticScanResult result) {
        if (scriptUrl == null || scriptUrl.isBlank() || scriptUrl.endsWith(".map")) {
            return;
        }
        String sourceMapUrl = scriptUrl + ".map";
        ValidationReplay replay = validateStaticChild(sourceMapUrl);
        if (!replay.exists) {
            return;
        }
        String reason = "默认探测同名 source map：存在";
        if (replay.reason != null && !replay.reason.isBlank()) {
            reason += " | " + replay.reason;
        }
        appendScriptResult(result, buildScriptSummary(
                sourceMapUrl,
                true,
                replay.statusCode,
                reason,
                null));
    }

    private void recordJsAstProgress(HTTPContext context,
                                     StaticScanResult result,
                                     JsAnalysisApiClient.TaskProgress progress) {
        if (progress == null) {
            return;
        }
        if (result.getJsAstTasks() == null) {
            result.setJsAstTasks(new ArrayList<>());
        }
        if (isDuplicateTaskProgress(result, progress)) {
            publishStaticProgress(context, result);
            return;
        }
        StaticScanResult.JsAstTaskStatus status = new StaticScanResult.JsAstTaskStatus();
        status.setScriptUrl(progress.scriptUrl());
        status.setTaskId(progress.taskId());
        status.setPhase(progress.phase());
        status.setStatus(progress.status());
        status.setMessage(progress.message());
        result.getJsAstTasks().add(status);

        PluginLogger.getInstance().info(
                PluginLogger.Category.SYSTEM,
                "JS-AST",
                "phase=" + safe(progress.phase())
                        + ", status=" + safe(progress.status())
                        + ", taskId=" + safe(progress.taskId())
                        + ", script=" + safe(progress.scriptUrl())
                        + ", message=" + safe(progress.message()));
        publishStaticProgress(context, result);
    }

    private boolean isDuplicateTaskProgress(StaticScanResult result, JsAnalysisApiClient.TaskProgress progress) {
        List<StaticScanResult.JsAstTaskStatus> tasks = result.getJsAstTasks();
        if (tasks == null || tasks.isEmpty() || progress == null) {
            return false;
        }
        StaticScanResult.JsAstTaskStatus latest = tasks.get(tasks.size() - 1);
        return safeEquals(latest.getTaskId(), progress.taskId())
                && safeEquals(latest.getPhase(), progress.phase())
                && safeEquals(latest.getStatus(), progress.status())
                && safeEquals(latest.getMessage(), progress.message());
    }

    private void publishStaticProgress(HTTPContext context, StaticScanResult result) {
        publishStaticProgress(context, result, false);
    }

    private void publishStaticProgress(HTTPContext context, StaticScanResult result, boolean force) {
        if (context == null || result == null || historyService == null || context.getRequestId() == null) {
            return;
        }
        if (!force && !shouldPublishProgress(context.getRequestId())) {
            return;
        }
        try {
            context.setStaticScanDetails(result);
            context.setStaticScanResult(buildSummary(context, result));
            HistoryEntry existing = historyService.getById(context.getRequestId());
            HistoryEntry entry = existing != null ? existing : HistoryEntry.fromStaticScan(context);
            entry.setStaticScanDetails(result);
            entry.setAiSummary(context.getStaticScanResult());
            historyService.update(entry);
            HistoryEventBus.getInstance().fireRefreshNeeded();
        } catch (Exception e) {
            log.debug("Failed to publish static analysis progress for: {}", context.getPath(), e);
        }
    }

    private boolean shouldPublishProgress(String requestId) {
        long now = System.currentTimeMillis();
        long interval = Math.max(500, configService.getConfig().getJsAnalysis().getProgressPublishIntervalMs());
        Long previous = lastStaticProgressPublishAt.putIfAbsent(requestId, now);
        if (previous == null) {
            return true;
        }
        if (now - previous < interval) {
            return false;
        }
        return lastStaticProgressPublishAt.replace(requestId, previous, now);
    }

    private String normalizeJsMode(AppConfig.JsAnalysisConfig jsConfig) {
        if (jsConfig == null) {
            return "full";
        }
        String mode = jsConfig.getMode();
        if (mode != null) {
            String normalized = mode.trim().toLowerCase(Locale.ROOT);
            if ("fast".equals(normalized) || "full".equals(normalized)) {
                return normalized;
            }
        }
        return jsConfig.isFastMode() ? "fast" : "full";
    }

    private void clearProgressThrottle(HTTPContext context) {
        if (context != null && context.getRequestId() != null) {
            lastStaticProgressPublishAt.remove(context.getRequestId());
        }
    }

    private List<JsAnalysisResponse.ApiResult> endpointApis(JsAnalysisResponse analysis) {
        if (analysis == null) {
            return List.of();
        }
        if (analysis.getGroups() != null
                && analysis.getGroups().getEndpoints() != null
                && analysis.getGroups().getEndpoints().getApis() != null
                && !analysis.getGroups().getEndpoints().getApis().isEmpty()) {
            return analysis.getGroups().getEndpoints().getApis();
        }
        return analysis.getApis() != null ? analysis.getApis() : List.of();
    }

    private List<JsAnalysisResponse.FindingResult> endpointFindings(JsAnalysisResponse analysis) {
        if (analysis == null) {
            return List.of();
        }
        if (analysis.getGroups() != null
                && analysis.getGroups().getEndpoints() != null
                && analysis.getGroups().getEndpoints().getFindings() != null) {
            return analysis.getGroups().getEndpoints().getFindings();
        }
        return filterFindingsByGroup(analysis.getFindings(), "api");
    }

    private List<JsAnalysisResponse.AssetResult> scriptAssets(JsAnalysisResponse analysis) {
        if (analysis == null) {
            return List.of();
        }
        List<JsAnalysisResponse.AssetResult> assets;
        if (analysis.getGroups() != null
                && analysis.getGroups().getScripts() != null
                && analysis.getGroups().getScripts().getAssets() != null
                && !analysis.getGroups().getScripts().getAssets().isEmpty()) {
            assets = analysis.getGroups().getScripts().getAssets();
        } else {
            assets = analysis.getAssets();
        }
        if (assets == null || assets.isEmpty()) {
            return List.of();
        }
        List<JsAnalysisResponse.AssetResult> scripts = new ArrayList<>();
        for (JsAnalysisResponse.AssetResult asset : assets) {
            if (asset == null || asset.getUrl() == null || asset.getUrl().isBlank()) {
                continue;
            }
            String type = asset.getType() != null ? asset.getType().trim().toLowerCase(Locale.ROOT) : "";
            if ("script".equals(type) || asset.getUrl().toLowerCase(Locale.ROOT).contains(".js")) {
                scripts.add(asset);
            }
        }
        return scripts;
    }

    private List<JsAnalysisResponse.FindingResult> scriptFindings(JsAnalysisResponse analysis) {
        if (analysis == null) {
            return List.of();
        }
        if (analysis.getGroups() != null
                && analysis.getGroups().getScripts() != null
                && analysis.getGroups().getScripts().getFindings() != null) {
            return analysis.getGroups().getScripts().getFindings();
        }
        return filterFindingsByGroup(analysis.getFindings(), "asset", "webpack");
    }

    private List<JsAnalysisResponse.SecretResult> exposureSecrets(JsAnalysisResponse analysis) {
        if (analysis == null) {
            return List.of();
        }
        if (analysis.getGroups() != null
                && analysis.getGroups().getExposures() != null
                && analysis.getGroups().getExposures().getSecrets() != null
                && !analysis.getGroups().getExposures().getSecrets().isEmpty()) {
            return analysis.getGroups().getExposures().getSecrets();
        }
        return analysis.getSecrets() != null ? analysis.getSecrets() : List.of();
    }

    private List<JsAnalysisResponse.FindingResult> exposureFindings(JsAnalysisResponse analysis) {
        if (analysis == null) {
            return List.of();
        }
        if (analysis.getGroups() != null
                && analysis.getGroups().getExposures() != null
                && analysis.getGroups().getExposures().getFindings() != null) {
            return analysis.getGroups().getExposures().getFindings();
        }
        return filterFindingsByGroup(analysis.getFindings(), "secret", "risk", "string", "identifier", "call");
    }

    private List<JsAnalysisResponse.FindingResult> filterFindingsByGroup(List<JsAnalysisResponse.FindingResult> findings,
                                                                         String... sources) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        Set<String> allowedSources = new LinkedHashSet<>();
        for (String source : sources) {
            if (source != null) {
                allowedSources.add(source.toLowerCase(Locale.ROOT));
            }
        }
        List<JsAnalysisResponse.FindingResult> filtered = new ArrayList<>();
        for (JsAnalysisResponse.FindingResult finding : findings) {
            if (finding == null) {
                continue;
            }
            String source = finding.getSource() != null
                    ? finding.getSource().trim().toLowerCase(Locale.ROOT)
                    : "";
            String category = finding.getCategory() != null
                    ? finding.getCategory().trim().toLowerCase(Locale.ROOT)
                    : "";
            if (allowedSources.contains(source)
                    || ("webpack".equals(source) && allowedSources.contains("webpack"))
                    || (category.contains("webpack") && allowedSources.contains("webpack"))) {
                filtered.add(finding);
            }
        }
        return filtered;
    }

    private void mergeCloudAnalysis(String sourceScriptUrl,
                                    String baseUrl,
                                    JsAnalysisResponse analysis,
                                    StaticScanResult result) {
        if (analysis == null) {
            return;
        }
        mergeCloudApis(sourceScriptUrl, baseUrl, analysis, result);
        mergeCloudAssets(sourceScriptUrl, baseUrl, analysis, result);
        mergeCloudParams(sourceScriptUrl, analysis, result);
        mergeCloudAuthSignals(analysis, result);
        mergeCloudSecrets(sourceScriptUrl, analysis, result);
        mergeCloudRisks(sourceScriptUrl, analysis, result);
        mergeGroupedFindings(sourceScriptUrl, analysis, result);
        mergeCloudFindings(sourceScriptUrl, analysis, result);
        result.setHasFindings(hasCloudAnalysis(result));
    }

    private void mergeCloudApis(String sourceScriptUrl,
                                String baseUrl,
                                JsAnalysisResponse analysis,
                                StaticScanResult result) {
        List<JsAnalysisResponse.ApiResult> apis = endpointApis(analysis);
        if (apis.isEmpty()) {
            return;
        }
        if (result.getCloudApis() == null) {
            result.setCloudApis(new ArrayList<>());
        }
        URI baseUri = safeUri(baseUrl);
        for (JsAnalysisResponse.ApiResult api : apis) {
            if (api == null) {
                continue;
            }
            StaticScanResult.CloudApi cloudApi = new StaticScanResult.CloudApi();
            cloudApi.setSourceScriptUrl(sourceScriptUrl);
            cloudApi.setRawUrl(api.getUrl());
            cloudApi.setResolvedUrl(resolveApiAbsoluteUrl(baseUri, api));
            cloudApi.setBaseUrl(api.getBaseUrl());
            cloudApi.setMethod(normalizeHttpMethod(api.getMethod()));
            cloudApi.setParams(copyList(api.getParams()));
            cloudApi.setHeaders(copyList(api.getHeaders()));
            cloudApi.setAuth(api.getAuth());
            cloudApi.setSource(api.getSource());
            cloudApi.setConfidence(api.getConfidence());
            cloudApi.setNotes(copyList(api.getNotes()));
            result.getCloudApis().add(cloudApi);
        }
    }

    private void mergeCloudAssets(String sourceScriptUrl,
                                  String baseUrl,
                                  JsAnalysisResponse analysis,
                                  StaticScanResult result) {
        List<JsAnalysisResponse.AssetResult> assets = scriptAssets(analysis);
        if (assets.isEmpty()) {
            return;
        }
        if (result.getCloudAssets() == null) {
            result.setCloudAssets(new ArrayList<>());
        }
        for (JsAnalysisResponse.AssetResult asset : assets) {
            if (asset == null) {
                continue;
            }
            StaticScanResult.CloudAsset cloudAsset = new StaticScanResult.CloudAsset();
            cloudAsset.setSourceScriptUrl(sourceScriptUrl);
            cloudAsset.setUrl(asset.getUrl());
            cloudAsset.setResolvedUrl(normalizeAbsoluteUrl(baseUrl, asset.getUrl()));
            cloudAsset.setType(asset.getType());
            cloudAsset.setChunkName(asset.getChunkName());
            cloudAsset.setSource(asset.getSource());
            result.getCloudAssets().add(cloudAsset);
        }
    }

    private void mergeCloudParams(String sourceScriptUrl,
                                  JsAnalysisResponse analysis,
                                  StaticScanResult result) {
        if (analysis.getParams() == null || analysis.getParams().isEmpty()) {
            return;
        }
        if (result.getCloudParams() == null) {
            result.setCloudParams(new ArrayList<>());
        }
        for (JsAnalysisResponse.ParamResult param : analysis.getParams()) {
            if (param == null) {
                continue;
            }
            StaticScanResult.CloudParam cloudParam = new StaticScanResult.CloudParam();
            cloudParam.setSourceScriptUrl(sourceScriptUrl);
            cloudParam.setName(param.getName());
            cloudParam.setLocation(param.getLocation());
            cloudParam.setApi(param.getApi());
            cloudParam.setSource(param.getSource());
            result.getCloudParams().add(cloudParam);
        }
    }

    private void mergeCloudAuthSignals(JsAnalysisResponse analysis, StaticScanResult result) {
        if (analysis.getAuth() == null || analysis.getAuth().isEmpty()) {
            return;
        }
        if (result.getCloudAuthSignals() == null) {
            result.setCloudAuthSignals(new ArrayList<>());
        }
        for (String signal : analysis.getAuth()) {
            if (signal != null && !signal.isBlank() && !result.getCloudAuthSignals().contains(signal)) {
                result.getCloudAuthSignals().add(signal);
            }
        }
    }

    private void mergeCloudSecrets(String sourceScriptUrl,
                                   JsAnalysisResponse analysis,
                                   StaticScanResult result) {
        List<JsAnalysisResponse.SecretResult> secrets = exposureSecrets(analysis);
        if (secrets.isEmpty()) {
            return;
        }
        if (result.getCloudSecrets() == null) {
            result.setCloudSecrets(new ArrayList<>());
        }
        for (JsAnalysisResponse.SecretResult secret : secrets) {
            if (secret == null) {
                continue;
            }
            StaticScanResult.CloudSecret cloudSecret = new StaticScanResult.CloudSecret();
            cloudSecret.setSourceScriptUrl(sourceScriptUrl);
            cloudSecret.setType(secret.getType());
            cloudSecret.setValue(secret.getValue());
            cloudSecret.setSeverity(normalizeSeverity(secret.getSeverity()));
            cloudSecret.setConfidence(secret.getConfidence());
            cloudSecret.setSource(secret.getSource());
            cloudSecret.setEvidence(secret.getEvidence());
            result.getCloudSecrets().add(cloudSecret);
        }
    }

    private void mergeCloudRisks(String sourceScriptUrl,
                                 JsAnalysisResponse analysis,
                                 StaticScanResult result) {
        if (analysis.getRisk() == null || analysis.getRisk().isEmpty()) {
            return;
        }
        if (result.getCloudRisks() == null) {
            result.setCloudRisks(new ArrayList<>());
        }
        for (JsAnalysisResponse.RiskResult risk : analysis.getRisk()) {
            if (risk == null) {
                continue;
            }
            StaticScanResult.CloudRisk cloudRisk = new StaticScanResult.CloudRisk();
            cloudRisk.setSourceScriptUrl(sourceScriptUrl);
            cloudRisk.setType(risk.getType());
            cloudRisk.setSeverity(normalizeSeverity(risk.getSeverity()));
            cloudRisk.setEvidence(risk.getEvidence());
            result.getCloudRisks().add(cloudRisk);
        }
    }

    private void mergeCloudFindings(String sourceScriptUrl,
                                    JsAnalysisResponse analysis,
                                    StaticScanResult result) {
        if (analysis.getFindings() != null && !analysis.getFindings().isEmpty()) {
            if (result.getCloudFindings() == null) {
                result.setCloudFindings(new ArrayList<>());
            }
            for (JsAnalysisResponse.FindingResult finding : analysis.getFindings()) {
                if (finding == null) {
                    continue;
                }
                StaticScanResult.CloudFinding cloudFinding = new StaticScanResult.CloudFinding();
                cloudFinding.setSourceScriptUrl(sourceScriptUrl);
                cloudFinding.setCategory(finding.getCategory());
                cloudFinding.setType(finding.getType());
                cloudFinding.setValue(finding.getValue());
                cloudFinding.setSeverity(normalizeSeverity(finding.getSeverity()));
                cloudFinding.setConfidence(finding.getConfidence());
                cloudFinding.setSource(finding.getSource());
                cloudFinding.setEvidence(finding.getEvidence());
                result.getCloudFindings().add(cloudFinding);
                if (isSecretFinding(finding)) {
                    appendSecretFinding(sourceScriptUrl, finding, result);
                }
            }
        }
    }

    private void mergeGroupedFindings(String sourceScriptUrl,
                                      JsAnalysisResponse analysis,
                                      StaticScanResult result) {
        appendGroupedFindings(result, "endpoint", sourceScriptUrl, endpointFindings(analysis));
        appendGroupedFindings(result, "exposure", sourceScriptUrl, exposureFindings(analysis));
        appendGroupedFindings(result, "script", sourceScriptUrl, scriptFindings(analysis));
    }

    private void appendGroupedFindings(StaticScanResult result,
                                       String group,
                                       String sourceScriptUrl,
                                       List<JsAnalysisResponse.FindingResult> findings) {
        if (findings == null || findings.isEmpty()) {
            return;
        }
        List<StaticScanResult.CloudFinding> target;
        if ("endpoint".equals(group)) {
            if (result.getEndpointFindings() == null) {
                result.setEndpointFindings(new ArrayList<>());
            }
            target = result.getEndpointFindings();
        } else if ("script".equals(group)) {
            if (result.getScriptFindings() == null) {
                result.setScriptFindings(new ArrayList<>());
            }
            target = result.getScriptFindings();
        } else {
            if (result.getExposureFindings() == null) {
                result.setExposureFindings(new ArrayList<>());
            }
            target = result.getExposureFindings();
        }

        for (JsAnalysisResponse.FindingResult finding : findings) {
            StaticScanResult.CloudFinding cloudFinding = toCloudFinding(sourceScriptUrl, finding);
            if (cloudFinding != null) {
                target.add(cloudFinding);
            }
        }
    }

    private StaticScanResult.CloudFinding toCloudFinding(String sourceScriptUrl,
                                                         JsAnalysisResponse.FindingResult finding) {
        if (finding == null) {
            return null;
        }
        StaticScanResult.CloudFinding cloudFinding = new StaticScanResult.CloudFinding();
        cloudFinding.setSourceScriptUrl(sourceScriptUrl);
        cloudFinding.setCategory(finding.getCategory());
        cloudFinding.setType(finding.getType());
        cloudFinding.setValue(finding.getValue());
        cloudFinding.setSeverity(normalizeSeverity(finding.getSeverity()));
        cloudFinding.setConfidence(finding.getConfidence());
        cloudFinding.setSource(finding.getSource());
        cloudFinding.setEvidence(finding.getEvidence());
        return cloudFinding;
    }

    private boolean isSecretFinding(JsAnalysisResponse.FindingResult finding) {
        if (finding == null) {
            return false;
        }
        String combined = (safe(finding.getCategory()) + " " + safe(finding.getType()) + " " + safe(finding.getSource()))
                .toLowerCase(Locale.ROOT);
        return combined.contains("secret")
                || combined.contains("token")
                || combined.contains("password")
                || combined.contains("credential")
                || combined.contains("凭据")
                || combined.contains("密钥")
                || combined.contains("敏感凭据")
                || combined.contains("ak/sk")
                || combined.contains("access-key");
    }

    private void appendSecretFinding(String sourceScriptUrl,
                                     JsAnalysisResponse.FindingResult finding,
                                     StaticScanResult result) {
        if (result.getCloudSecrets() == null) {
            result.setCloudSecrets(new ArrayList<>());
        }
        StaticScanResult.CloudSecret secret = new StaticScanResult.CloudSecret();
        secret.setSourceScriptUrl(sourceScriptUrl);
        secret.setType(finding.getType());
        secret.setValue(finding.getValue());
        secret.setSeverity(normalizeSeverity(finding.getSeverity()));
        secret.setConfidence(finding.getConfidence());
        secret.setSource(finding.getSource());
        secret.setEvidence(finding.getEvidence());
        result.getCloudSecrets().add(secret);
    }

    private boolean hasCloudAnalysis(StaticScanResult result) {
        return notEmpty(result.getCloudFindings())
                || notEmpty(result.getCloudApis())
                || notEmpty(result.getCloudAssets())
                || notEmpty(result.getCloudParams())
                || notEmpty(result.getCloudAuthSignals())
                || notEmpty(result.getCloudSecrets())
                || notEmpty(result.getCloudRisks());
    }

    private boolean notEmpty(List<?> values) {
        return values != null && !values.isEmpty();
    }

    private List<String> copyList(List<String> values) {
        return values != null ? new ArrayList<>(values) : List.of();
    }

    private String normalizeSeverity(String severity) {
        return severity != null && !severity.isBlank()
                ? severity.trim().toUpperCase(Locale.ROOT)
                : "MEDIUM";
    }

    private void registerRecoveredEndpointHistory(HTTPContext sourceContext,
                                                  JsAnalysisResponse analysis,
                                                  StaticScanResult.RecoveredEndpoint recovered) {
        if (recovered.getUrl() == null || recovered.getUrl().isBlank()) {
            return;
        }

        String requestId = "js-" + UUID.nameUUIDFromBytes((recovered.getSourceScriptUrl() + "|" + recovered.getUrl()
                + "|" + recovered.getMethod()).getBytes(StandardCharsets.UTF_8));
        if (historyService.getById(requestId) != null) {
            return;
        }

        HTTPContext endpointContext = new HTTPContext();
        endpointContext.setRequestId(requestId);
        endpointContext.setTimestamp(System.currentTimeMillis());
        endpointContext.setMethod(recovered.getMethod());
        endpointContext.setUrl(recovered.getUrl());
        URI uri = safeUri(recovered.getUrl());
        endpointContext.setPath(uri != null && uri.getPath() != null ? uri.getPath() : recovered.getUrl());
        endpointContext.setQuery(uri != null ? uri.getRawQuery() : null);
        endpointContext.setEndpointType(EndpointType.ENDPOINT);
        endpointContext.setAnalysisStatus(AnalysisStatus.COMPLETED);
        byte[] requestBytes = recovered.getRequestBytes();
        byte[] responseBytes = recovered.getResponseBytes();
        int statusCode = recovered.getStatusCode();
        if (requestBytes == null || requestBytes.length == 0 || responseBytes == null || responseBytes.length == 0) {
            ValidationReplay replay = replayRequest(recovered.getUrl(), recovered.getMethod(), false, null);
            requestBytes = replay.requestBytes;
            responseBytes = replay.responseBytes;
            statusCode = replay.statusCode;
        }
        endpointContext.setRawRequest(requestBytes);
        endpointContext.setRawResponse(responseBytes);
        endpointContext.setResponseBody(extractResponseBody(responseBytes));
        endpointContext.setStatusCode(statusCode);
        endpointContext.setResponseContentType(extractContentType(responseBytes));

        if (recovered.getParams() != null) {
            for (String param : recovered.getParams()) {
                endpointContext.addParameter(new ParameterContext(param, "", ParameterType.QUERY));
            }
        }

        AnalysisResult analysisResult = buildRecoveredEndpointAnalysis(sourceContext, analysis, recovered);
        endpointContext.setAnalysisResult(analysisResult);
        endpointContext.setEndpointActionType(EndpointActionClassifier.classify(endpointContext, analysisResult));
        endpointContext.setRiskLevel(calculateRecoveredRisk(analysisResult));
        if (configService.getConfig().getJsAnalysis().isAutoAnalyzeVerifiedApis()) {
            try {
                recoveredEndpointAnalysisStage.process(endpointContext);
                AnalysisResult aiResult = endpointContext.getAnalysisResult();
                if (aiResult != null && aiResult.isSuccess()) {
                    endpointContext.setEndpointActionType(EndpointActionClassifier.classify(endpointContext, aiResult));
                    endpointContext.setRiskLevel(calculateRecoveredRisk(aiResult));
                } else {
                    endpointContext.setAnalysisResult(analysisResult);
                }
            } catch (Exception e) {
                endpointContext.setAnalysisResult(analysisResult);
                PluginLogger.getInstance().warn(
                        PluginLogger.Category.LLM,
                        "JS-AST",
                        "Recovered endpoint AI analysis failed: " + safe(recovered.getUrl()) + " | " + e.getMessage());
            }
        } else {
            PluginLogger.getInstance().info(
                    PluginLogger.Category.LLM,
                    "JS-AST",
                    "Recovered endpoint AI analysis skipped by config: " + safe(recovered.getUrl()));
        }

        HistoryEntry entry = HistoryEntry.fromHTTPContext(endpointContext);
        historyService.update(entry);
        HistoryEventBus.getInstance().fireRefreshNeeded();
    }

    private AnalysisResult buildRecoveredEndpointAnalysis(HTTPContext sourceContext,
                                                          JsAnalysisResponse jsAnalysis,
                                                          StaticScanResult.RecoveredEndpoint recovered) {
        AnalysisResult result = new AnalysisResult();
        result.setSummary("来源 JS: " + recovered.getSourceScriptUrl()
                + "\n已验证接口存在: " + recovered.getUrl()
                + "\n返回状态码: " + recovered.getStatusCode()
                + "\n接口发现来源: AST 接口恢复 + 存在性验证");

        List<String> attackSurface = new ArrayList<>();
        attackSurface.add("JS 恢复接口");
        if (jsAnalysis.getAuth() != null && !jsAnalysis.getAuth().isEmpty()) {
            attackSurface.add("认证头信号: " + String.join(", ", jsAnalysis.getAuth()));
        }
        result.setAttackSurface(attackSurface);

        List<String> possibleVulns = new ArrayList<>();
        if (jsAnalysis.getRisk() != null) {
            for (JsAnalysisResponse.RiskResult risk : jsAnalysis.getRisk()) {
                if (risk.getType() != null && !risk.getType().isBlank()) {
                    possibleVulns.add(risk.getType());
                }
            }
        }
        result.setPossibleVulnerabilities(possibleVulns);

        List<AnalysisResult.HighValueParam> highValueParams = new ArrayList<>();
        if (recovered.getParams() != null) {
            for (String param : recovered.getParams()) {
                highValueParams.add(new AnalysisResult.HighValueParam(
                        param,
                        "参数来自 JS AST 恢复并已确认接口存在",
                        RiskLevel.MEDIUM));
            }
        }
        result.setHighValueParams(highValueParams);

        List<String> recommendedTests = new ArrayList<>();
        recommendedTests.add("优先验证恢复接口的鉴权、越权与参数注入风险");
        if (recovered.getMethod() != null && !"GET".equalsIgnoreCase(recovered.getMethod())) {
            recommendedTests.add("关注 " + recovered.getMethod() + " 语义对应的写操作风险");
        }
        result.setRecommendedTests(recommendedTests);
        result.setEndpointActionType(EndpointActionClassifier.classifyByHttp(sourceContext).name());
        return result;
    }

    private RiskLevel calculateRecoveredRisk(AnalysisResult result) {
        if (result == null || result.getHighValueParams() == null || result.getHighValueParams().isEmpty()) {
            return RiskLevel.INFO;
        }
        RiskLevel max = RiskLevel.INFO;
        for (AnalysisResult.HighValueParam param : result.getHighValueParams()) {
            if (param.getRiskLevel() != null && param.getRiskLevel().ordinal() > max.ordinal()) {
                max = param.getRiskLevel();
            }
        }
        return max;
    }

    private ValidationReplay validateStaticChild(String url) {
        return replayRequest(url, "GET", true, null);
    }

    private ValidationReplay replayRequest(String absoluteUrl,
                                           String method,
                                           boolean staticFile,
                                           JsAnalysisResponse.ApiResult apiResult) {
        ValidationReplay replay = new ValidationReplay();
        replay.requestBytes = buildRawRequest(absoluteUrl, method, apiResult);
        replay.responseBytes = null;
        replay.statusCode = -1;
        replay.exists = false;
        replay.reason = "No response";

        try {
            URI uri = safeUri(absoluteUrl);
            if (uri == null) {
                replay.reason = "Invalid URL";
                replay.summary = buildScriptSummary(absoluteUrl, false, replay.statusCode, replay.reason, null);
                return replay;
            }
            if (staticFile && "HEAD".equalsIgnoreCase(method)) {
                replay.requestBytes = buildRawRequest(absoluteUrl, "HEAD", null);
            }
            byte[] markedRequest = InternalTrafficMarker.ensureMarked(replay.requestBytes);
            replay.requestBytes = markedRequest;

            burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(
                    uri.getHost(),
                    uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80),
                    "https".equalsIgnoreCase(uri.getScheme()));
            var request = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    service, burp.api.montoya.core.ByteArray.byteArray(markedRequest));
            var response = api != null ? api.http().sendRequest(request) : null;
            if (response == null || !response.hasResponse()) {
                replay.reason = "No response";
                replay.summary = buildScriptSummary(absoluteUrl, false, replay.statusCode, replay.reason, null);
                return replay;
            }
            if (response.response() == null || response.response().toByteArray() == null) {
                replay.reason = "Response bytes unavailable";
                replay.summary = buildScriptSummary(absoluteUrl, false, replay.statusCode, replay.reason, null);
                return replay;
            }
            replay.responseBytes = response.response().toByteArray().getBytes();
            if (replay.responseBytes == null || replay.responseBytes.length == 0) {
                replay.reason = "Response bytes empty";
                replay.summary = buildScriptSummary(absoluteUrl, false, replay.statusCode, replay.reason, null);
                return replay;
            }
            replay.statusCode = parseStatusCode(replay.responseBytes);
            replay.exists = judgeExistence(replay.statusCode, replay.responseBytes, absoluteUrl, staticFile);
            replay.reason = buildReplayReason(replay.statusCode, replay.responseBytes, staticFile);
            replay.summary = buildScriptSummary(absoluteUrl, replay.exists, replay.statusCode, replay.reason, null);
            return replay;
        } catch (Exception e) {
            replay.reason = e.getClass().getSimpleName() + ": " + e.getMessage();
            replay.summary = buildScriptSummary(absoluteUrl, false, replay.statusCode, replay.reason, null);
            return replay;
        }
    }

    private boolean judgeExistence(int statusCode, byte[] responseBytes, String url, boolean staticFile) {
        if (statusCode == 404 || statusCode == 410 || statusCode <= 0) {
            return false;
        }
        String contentType = extractContentType(responseBytes).toLowerCase(Locale.ROOT);
        String body = new String(extractResponseBody(responseBytes), StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        boolean htmlLike = contentType.contains("text/html") || body.contains("<html") || body.contains("<!doctype");
        boolean routeMissing = body.contains("not found") || body.contains("cannot get")
                || body.contains("resource not found") || body.contains("404");

        if (staticFile) {
            if (statusCode >= 200 && statusCode < 300) {
                if (url.endsWith(".map")) {
                    return body.contains("\"version\"") && (body.contains("\"sources\"") || body.contains("\"mappings\""));
                }
                if (url.endsWith(".js")) {
                    return !htmlLike || body.contains("function") || body.contains("=>") || body.contains("webpack");
                }
                return !routeMissing;
            }
            return statusCode == 401 || statusCode == 403;
        }

        if (statusCode == 401 || statusCode == 403 || statusCode == 405 || statusCode == 415 || statusCode == 422) {
            return true;
        }
        if (statusCode >= 200 && statusCode < 300) {
            return !(htmlLike && routeMissing);
        }
        return false;
    }

    private String buildReplayReason(int statusCode, byte[] responseBytes, boolean staticFile) {
        String contentType = extractContentType(responseBytes);
        String body = new String(extractResponseBody(responseBytes), StandardCharsets.UTF_8);
        if (statusCode == 404 || statusCode == 410) {
            return "响应为 " + statusCode + "，不存在信号明确";
        }
        if (staticFile && statusCode >= 200 && statusCode < 300 && contentType.toLowerCase(Locale.ROOT).contains("javascript")) {
            return "返回 2xx 且 Content-Type 为 JavaScript";
        }
        if (!staticFile && (statusCode == 401 || statusCode == 403 || statusCode == 405 || statusCode == 415 || statusCode == 422)) {
            return "返回 " + statusCode + "，接口路由大概率存在";
        }
        if (statusCode >= 200 && statusCode < 300) {
            if (body.toLowerCase(Locale.ROOT).contains("not found")) {
                return "返回 2xx 但正文存在 not found 痕迹，需谨慎";
            }
            return "返回 2xx，存在性信号较强";
        }
        return "响应状态码=" + statusCode;
    }

    private String buildSummary(HTTPContext context, StaticScanResult result) {
        StringBuilder summary = new StringBuilder();
        AppConfig.JsAnalysisConfig jsConfig = configService.getConfig().getJsAnalysis();
        summary.append("Static scan for ").append(context.getPath()).append("\n");
        summary.append("JS AST config: mode=").append(normalizeJsMode(jsConfig))
                .append(" | async=").append(jsConfig.isSubmitAsync())
                .append(" | enabled=").append(jsConfig.isEnabled())
                .append("\n");

        int endpointFindings = size(result.getEndpointFindings());
        int sensitiveFindings = size(result.getExposureFindings());
        int scriptFindings = size(result.getScriptFindings());
        int rawFindings = size(result.getCloudFindings());
        int totalFindings = endpointFindings + sensitiveFindings + scriptFindings;
        if (totalFindings == 0) {
            totalFindings = rawFindings + size(result.getCloudSecrets()) + size(result.getCloudRisks());
        }
        summary.append("JS AST summary: findings=").append(totalFindings)
                .append(" | endpointFindings=").append(endpointFindings)
                .append(" | sensitiveFindings=").append(sensitiveFindings)
                .append(" | scriptFindings=").append(scriptFindings)
                .append(" | rawFindings=").append(rawFindings)
                .append("\n");
        summary.append("Recovered: endpoints=").append(size(result.getCloudApis()))
                .append(" | verifiedEndpoints=").append(validRecoveredEndpointCount(result))
                .append(" | scripts=").append(size(result.getCloudAssets()))
                .append(" | params=").append(size(result.getCloudParams()))
                .append(" | authSignals=").append(size(result.getCloudAuthSignals()))
                .append(" | secrets=").append(size(result.getCloudSecrets()))
                .append(" | risks=").append(size(result.getCloudRisks()))
                .append("\n");

        summary.append("Details: 请在 Endpoints / Sensitive / Scripts / Tasks 表格中查看明细。\n");

        if (result.getAnalyzedScripts() != null && !result.getAnalyzedScripts().isEmpty()) {
            summary.append("JS scripts analyzed: ").append(result.getAnalyzedScripts().size()).append("\n");
            for (StaticScanResult.AnalyzedScript script : result.getAnalyzedScripts()) {
                if (script == null) {
                    continue;
                }
                summary.append("  - ").append(script.getUrl())
                        .append(" | validated=").append(script.isValidated())
                        .append(" | status=").append(script.getStatusCode())
                        .append(" | apis=").append(script.getApiCount())
                        .append(" | ").append(script.getReason())
                        .append("\n");
            }
        }

        if (result.getJsAstTasks() != null && !result.getJsAstTasks().isEmpty()) {
            StaticScanResult.JsAstTaskStatus latest = result.getJsAstTasks().get(result.getJsAstTasks().size() - 1);
            summary.append("JS AST progress: [").append(safe(latest.getPhase())).append("] ")
                    .append(safe(latest.getStatus()))
                    .append(" | taskId=").append(safe(latest.getTaskId()))
                    .append(" | ").append(safe(latest.getMessage()))
                    .append("\n");
        }

        if (result.getRecoveredEndpoints() != null && !result.getRecoveredEndpoints().isEmpty()) {
            long validCount = result.getRecoveredEndpoints().stream().filter(StaticScanResult.RecoveredEndpoint::isValidated).count();
            summary.append("Recovered endpoints: ").append(result.getRecoveredEndpoints().size())
                    .append(" (validated=").append(validCount).append(")\n");
        }

        if (result.getAiReview() != null && !result.getAiReview().isBlank()) {
            summary.append("AI Review: ").append(result.getAiReview());
        }
        return summary.toString();
    }

    private int validRecoveredEndpointCount(StaticScanResult result) {
        if (result == null || result.getRecoveredEndpoints() == null) {
            return 0;
        }
        return (int) result.getRecoveredEndpoints().stream()
                .filter(StaticScanResult.RecoveredEndpoint::isValidated)
                .count();
    }

    private int totalFindingCount(JsAnalysisResponse analysis) {
        if (analysis == null) {
            return 0;
        }
        int grouped = endpointFindings(analysis).size()
                + exposureFindings(analysis).size()
                + scriptFindings(analysis).size();
        if (grouped > 0) {
            return grouped;
        }
        return (analysis.getFindings() != null ? analysis.getFindings().size() : 0)
                + exposureSecrets(analysis).size()
                + (analysis.getRisk() != null ? analysis.getRisk().size() : 0);
    }

    private int size(List<?> values) {
        return values != null ? values.size() : 0;
    }

    private boolean safeEquals(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private String formatConfidence(Double confidence) {
        return confidence != null ? String.format(Locale.ROOT, "%.2f", confidence) : "-";
    }

    private String joinList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "-";
        }
        return String.join(", ", values);
    }

    private String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }

    private String shortUrl(String url) {
        if (url == null || url.isBlank()) {
            return "-";
        }
        URI uri = safeUri(url);
        if (uri == null || uri.getPath() == null) {
            return url;
        }
        String path = uri.getPath();
        return path.isBlank() ? url : path;
    }

    private boolean looksLikeJavaScript(HTTPContext context) {
        String path = context.getPath() != null ? context.getPath().toLowerCase(Locale.ROOT) : "";
        String contentType = context.getResponseContentType() != null
                ? context.getResponseContentType().toLowerCase(Locale.ROOT) : "";
        return path.endsWith(".js")
                || contentType.contains("javascript")
                || contentType.contains("ecmascript")
                || contentType.contains("application/x-javascript");
    }

    private List<String> extractReferencedScripts(String content, String baseUrl) {
        Set<String> scripts = new LinkedHashSet<>();
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("(?i)(?:src\\s*=\\s*[\"']([^\"']+\\.js(?:\\?[^\"']*)?)[\"'])|([\"']([^\"']+\\.js(?:\\?[^\"']*)?)[\"'])")
                .matcher(content);
        while (matcher.find()) {
            String raw = matcher.group(1) != null ? matcher.group(1) : matcher.group(3);
            String normalized = normalizeAbsoluteUrl(baseUrl, raw);
            if (normalized != null) {
                scripts.add(normalized);
            }
        }
        return new ArrayList<>(scripts);
    }

    private String normalizeAbsoluteUrl(String base, String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return null;
        }
        try {
            URI baseUri = safeUri(base);
            if (candidate.startsWith("http://") || candidate.startsWith("https://")) {
                return URI.create(candidate).toString();
            }
            if (candidate.startsWith("//") && baseUri != null && baseUri.getScheme() != null) {
                return baseUri.getScheme() + ":" + candidate;
            }
            if (baseUri != null) {
                return baseUri.resolve(candidate).toString();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private URI safeUri(String url) {
        try {
            return url != null ? URI.create(url) : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String normalizeHttpMethod(String method) {
        if (method == null || method.isBlank()) {
            return "GET";
        }
        String normalized = method.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" -> normalized;
            default -> "GET";
        };
    }

    private byte[] buildRawRequest(String absoluteUrl, String method) {
        return buildRawRequest(absoluteUrl, method, null);
    }

    private byte[] buildRawRequest(String absoluteUrl, String method, JsAnalysisResponse.ApiResult apiResult) {
        URI uri = safeUri(absoluteUrl);
        if (uri == null || uri.getHost() == null) {
            return new byte[0];
        }
        AppConfig.RecoveredRequestBuilderConfig builderConfig = requestBuilderConfig();
        String normalizedMethod = normalizeHttpMethod(method);
        String path = buildRequestTarget(uri, normalizedMethod, apiResult, builderConfig);
        List<String> headerLines = buildRequestHeaders(uri, normalizedMethod, apiResult, builderConfig);
        String body = buildRequestBody(normalizedMethod, apiResult, builderConfig);
        if (body != null && !body.isEmpty()) {
            headerLines.add("Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length);
        }
        String raw = normalizedMethod + " " + path + " HTTP/1.1\r\n"
                + String.join("\r\n", headerLines)
                + "\r\n\r\n"
                + (body != null ? body : "");
        return raw.getBytes(StandardCharsets.UTF_8);
    }

    private AppConfig.RecoveredRequestBuilderConfig requestBuilderConfig() {
        try {
            AppConfig.JsAnalysisConfig jsConfig = configService.getConfig().getJsAnalysis();
            if (jsConfig != null && jsConfig.getRequestBuilder() != null) {
                return jsConfig.getRequestBuilder();
            }
        } catch (Exception ignored) {
        }
        return new AppConfig.RecoveredRequestBuilderConfig();
    }

    private String buildRequestTarget(URI uri,
                                      String method,
                                      JsAnalysisResponse.ApiResult apiResult,
                                      AppConfig.RecoveredRequestBuilderConfig builderConfig) {
        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
        List<String> queryParts = new ArrayList<>();
        if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) {
            queryParts.add(uri.getRawQuery());
        }
        if (builderConfig != null
                && builderConfig.isEnabled()
                && builderConfig.isAppendParamsToQuery()
                && isQueryLikeMethod(method)
                && apiResult != null
                && apiResult.getParams() != null
                && !apiResult.getParams().isEmpty()) {
            Set<String> existingParams = queryParts.stream()
                    .flatMap(part -> List.of(part.split("&")).stream())
                    .map(part -> {
                        int idx = part.indexOf('=');
                        return idx >= 0 ? part.substring(0, idx) : part;
                    })
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            int maxParams = Math.max(0, builderConfig.getMaxParams());
            for (String param : apiResult.getParams()) {
                if (maxParams-- <= 0) {
                    break;
                }
                String normalizedParam = sanitizeParamName(param);
                if (normalizedParam.isBlank() || existingParams.contains(normalizedParam)) {
                    continue;
                }
                existingParams.add(normalizedParam);
                queryParts.add(normalizedParam + "=" + urlEncode(builderConfig.getPlaceholderValue()));
            }
        }
        if (!queryParts.isEmpty()) {
            path += "?" + String.join("&", queryParts);
        }
        return path;
    }

    private List<String> buildRequestHeaders(URI uri,
                                             String method,
                                             JsAnalysisResponse.ApiResult apiResult,
                                             AppConfig.RecoveredRequestBuilderConfig builderConfig) {
        List<String> headers = new ArrayList<>();
        Set<String> headerNames = new LinkedHashSet<>();
        addHeader(headers, headerNames, "Host", uri.getAuthority());
        addHeader(headers, headerNames, "User-Agent", "AI-Burp-Copilot-Static/1.0");
        addHeader(headers, headerNames, "Accept", "*/*");

        if (builderConfig != null && builderConfig.isEnabled() && builderConfig.isCopyJsHeaders() && apiResult != null) {
            int maxHeaders = Math.max(0, builderConfig.getMaxHeaders());
            for (String header : apiResult.getHeaders() != null ? apiResult.getHeaders() : List.<String>of()) {
                if (maxHeaders-- <= 0) {
                    break;
                }
                addJsHeader(headers, headerNames, header);
            }
        }

        if (builderConfig != null
                && builderConfig.isEnabled()
                && builderConfig.isCopyAuthSignalHeaders()
                && apiResult != null
                && apiResult.getAuth() != null
                && !apiResult.getAuth().isBlank()) {
            addJsHeader(headers, headerNames, apiResult.getAuth());
        }

        String body = buildRequestBody(method, apiResult, builderConfig);
        if (body != null && !body.isEmpty() && !headerNames.contains("content-type")) {
            String format = normalizedBodyFormat(builderConfig);
            addHeader(headers, headerNames, "Content-Type",
                    "form".equals(format)
                            ? "application/x-www-form-urlencoded"
                            : "application/json");
        }
        addHeader(headers, headerNames, "Connection", "close");
        return headers;
    }

    private void addJsHeader(List<String> headers, Set<String> headerNames, String rawHeader) {
        if (rawHeader == null || rawHeader.isBlank()) {
            return;
        }
        String header = rawHeader.trim();
        int idx = header.indexOf(':');
        if (idx > 0) {
            String name = header.substring(0, idx).trim();
            if (!isUnsafeJsHeader(name)) {
                addHeader(headers, headerNames, name, header.substring(idx + 1).trim());
            }
            return;
        }
        if (header.matches("(?i)^[A-Z0-9-]+$") && !isUnsafeJsHeader(header)) {
            addHeader(headers, headerNames, header, "");
        }
    }

    private void addHeader(List<String> headers, Set<String> headerNames, String name, String value) {
        if (name == null || name.isBlank()) {
            return;
        }
        String normalized = name.trim();
        if (normalized.contains("\r") || normalized.contains("\n")) {
            return;
        }
        String key = normalized.toLowerCase(Locale.ROOT);
        if (headerNames.contains(key)) {
            return;
        }
        headerNames.add(key);
        headers.add(normalized + ": " + (value != null ? value : ""));
    }

    private boolean isUnsafeJsHeader(String name) {
        String normalized = name != null ? name.trim().toLowerCase(Locale.ROOT) : "";
        return normalized.isBlank()
                || normalized.equals("host")
                || normalized.equals("content-length")
                || normalized.equals("connection")
                || normalized.equals("cookie")
                || normalized.equals("authorization")
                || normalized.equals("proxy-authorization");
    }

    private String buildRequestBody(String method,
                                    JsAnalysisResponse.ApiResult apiResult,
                                    AppConfig.RecoveredRequestBuilderConfig builderConfig) {
        if (builderConfig == null
                || !builderConfig.isEnabled()
                || !builderConfig.isBuildBodyForUnsafeMethods()
                || isQueryLikeMethod(method)
                || apiResult == null
                || apiResult.getParams() == null
                || apiResult.getParams().isEmpty()) {
            return "";
        }
        String format = normalizedBodyFormat(builderConfig);
        int maxParams = Math.max(0, builderConfig.getMaxParams());
        List<String> params = new ArrayList<>();
        for (String param : apiResult.getParams()) {
            if (maxParams-- <= 0) {
                break;
            }
            String normalizedParam = sanitizeParamName(param);
            if (!normalizedParam.isBlank()) {
                params.add(normalizedParam);
            }
        }
        if (params.isEmpty()) {
            return "";
        }
        String placeholder = builderConfig.getPlaceholderValue() != null
                ? builderConfig.getPlaceholderValue()
                : "";
        if ("form".equals(format)) {
            return params.stream()
                    .map(param -> param + "=" + urlEncode(placeholder))
                    .collect(Collectors.joining("&"));
        }
        return params.stream()
                .map(param -> "\"" + jsonEscape(param) + "\":\"" + jsonEscape(placeholder) + "\"")
                .collect(Collectors.joining(",", "{", "}"));
    }

    private String normalizedBodyFormat(AppConfig.RecoveredRequestBuilderConfig builderConfig) {
        String format = builderConfig != null ? builderConfig.getDefaultBodyFormat() : null;
        if (format != null && "form".equalsIgnoreCase(format.trim())) {
            return "form";
        }
        return "json";
    }

    private boolean isQueryLikeMethod(String method) {
        return method == null
                || method.isBlank()
                || "GET".equalsIgnoreCase(method)
                || "HEAD".equalsIgnoreCase(method)
                || "DELETE".equalsIgnoreCase(method)
                || "OPTIONS".equalsIgnoreCase(method);
    }

    private String sanitizeParamName(String param) {
        if (param == null) {
            return "";
        }
        String normalized = param.trim();
        int equalIdx = normalized.indexOf('=');
        if (equalIdx >= 0) {
            normalized = normalized.substring(0, equalIdx);
        }
        return normalized.replaceAll("[\\r\\n&?#\\s]+", "");
    }

    private String urlEncode(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private int parseStatusCode(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) {
            return -1;
        }
        String text = new String(responseBytes, StandardCharsets.UTF_8);
        String firstLine = text.split("\r\n|\n", 2)[0];
        String[] parts = firstLine.split(" ");
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1]);
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return -1;
    }

    private String extractContentType(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) {
            return "";
        }
        String text = new String(responseBytes, StandardCharsets.UTF_8);
        int split = text.indexOf("\r\n\r\n");
        if (split < 0) {
            split = text.indexOf("\n\n");
        }
        String headerText = split >= 0 ? text.substring(0, split) : text;
        for (String line : headerText.split("\r\n|\n")) {
            int idx = line.indexOf(':');
            if (idx > 0 && "content-type".equalsIgnoreCase(line.substring(0, idx).trim())) {
                return line.substring(idx + 1).trim();
            }
        }
        return "";
    }

    private byte[] extractResponseBody(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) {
            return new byte[0];
        }
        String text = new String(responseBytes, StandardCharsets.UTF_8);
        int split = text.indexOf("\r\n\r\n");
        int offset = 4;
        if (split < 0) {
            split = text.indexOf("\n\n");
            offset = 2;
        }
        if (split < 0) {
            return responseBytes;
        }
        int bodyStart = split + offset;
        if (bodyStart >= responseBytes.length) {
            return new byte[0];
        }
        byte[] body = new byte[responseBytes.length - bodyStart];
        System.arraycopy(responseBytes, bodyStart, body, 0, body.length);
        return body;
    }

    private static final class ValidationReplay {
        private boolean exists;
        private int statusCode;
        private String reason;
        private byte[] requestBytes;
        private byte[] responseBytes;
        private byte[] responseBody;
        private StaticScanResult.AnalyzedScript summary;
    }

    private String safe(String value) {
        return value != null && !value.isBlank() ? value : "-";
    }

    private String oneLine(String value) {
        if (value == null) {
            return "-";
        }
        return value.replace("\r", " ").replace("\n", " ").trim();
    }
}
