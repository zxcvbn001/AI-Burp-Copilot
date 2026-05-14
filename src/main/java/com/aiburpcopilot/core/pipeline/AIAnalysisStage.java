package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.context.AnalysisResult;
import com.aiburpcopilot.core.context.EndpointActionClassifier;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.verification.capability.AnalysisResultCapabilityFilter;
import com.aiburpcopilot.core.verification.capability.RuleCapabilityCatalog;
import com.aiburpcopilot.prompts.IPromptService;
import com.aiburpcopilot.utils.Constants;
import com.aiburpcopilot.utils.JsonUtil;
import com.aiburpcopilot.utils.PluginLogger;
import com.aiburpcopilot.utils.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.concurrent.*;

/**
 * AI 攻击面分析 Pipeline Stage。
 * <p>
 * 仅对 ENDPOINT 类型的请求执行。
 * 调用 AI 分析接口的攻击面、参数语义和高价值参数。
 * <p>
 * AI 分析输入：HTTP 上下文摘要（不含完整请求/响应体）
 * AI 分析输出：JSON 格式的攻击面分析结果（不直接生成漏洞结论）
 */
public class AIAnalysisStage implements IPipelineStage {

    private static final Logger log = LoggerFactory.getLogger(AIAnalysisStage.class);
    private static final String ANALYSIS_CACHE_PREFIX = "analysis:broad-attack-v3:";
    private final PluginLogger pluginLog = PluginLogger.getInstance();

    // 速率限制（每秒最多 N 次 AI 调用，从配置读取）
    private final Semaphore rateLimiter;
    private static final ScheduledExecutorService rateResetScheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "ai-rate-reset");
                t.setDaemon(true);
                return t;
            });

    // ========== Service Dependencies ==========

    private final IAIProvider aiProvider;
    private final IPromptService promptService;
    private final ICacheService cacheService;
    private IConfigService configService;
    private final RuleCapabilityCatalog capabilityCatalog;
    private final AnalysisResultCapabilityFilter capabilityFilter;

    public AIAnalysisStage(IAIProvider aiProvider,
                           IPromptService promptService,
                           ICacheService cacheService,
                           IConfigService configService) {
        this(aiProvider, promptService, cacheService, configService, null);
    }

    public AIAnalysisStage(IAIProvider aiProvider,
                           IPromptService promptService,
                           ICacheService cacheService,
                           IConfigService configService,
                           RuleCapabilityCatalog capabilityCatalog) {
        this.aiProvider = aiProvider;
        this.promptService = promptService;
        this.cacheService = cacheService;
        this.configService = configService;
        this.capabilityCatalog = capabilityCatalog;
        this.capabilityFilter = capabilityCatalog != null
                ? new AnalysisResultCapabilityFilter(capabilityCatalog)
                : null;
        int configRateLimit = configService.getConfig().getAi().getRateLimitPerSecond();
        if (configRateLimit <= 0) configRateLimit = 5;
        final int rateLimit = configRateLimit;
        this.rateLimiter = new Semaphore(rateLimit);
        // 每秒重置速率限制：drainPermits耗尽剩余许可后release新许可
        rateResetScheduler.scheduleAtFixedRate(
                () -> {
                    rateLimiter.drainPermits();
                    rateLimiter.release(rateLimit);
                },
                1, 1, TimeUnit.SECONDS);
    }

    @Override
    public String getName() {
        return "AI Attack Surface Analysis";
    }

    @Override
    public void process(HTTPContext context) {
        long startTime = System.currentTimeMillis();

        try {
            if (!aiProvider.isAvailable()) {
                log.warn("AI provider not available, skipping analysis for: {}", context.getPath());
                pluginLog.warn(PluginLogger.Category.LLM, "AI", "Provider unavailable, skip: " + context.getPath());
                AnalysisResult result = new AnalysisResult();
                result.setErrorMessage("AI provider not configured");
                context.setAnalysisResult(result);
                return;
            }

            // 检查缓存
            String cacheKey = ANALYSIS_CACHE_PREFIX + context.generateCacheKey();
            Optional<String> cached = cacheService.get(cacheKey);
            if (cached.isPresent()) {
                log.debug("Cache hit for analysis: {}", context.getPath());
                pluginLog.debug(PluginLogger.Category.LLM, "AI", "Cache hit: " + context.getPath());
                AnalysisResult cachedResult = JsonUtil.fromJsonSafe(cached.get(), AnalysisResult.class);
                if (cachedResult != null) {
                    if (capabilityFilter != null) {
                        cachedResult = capabilityFilter.filter(cachedResult, context);
                    }
                    context.setEndpointActionType(EndpointActionClassifier.classify(context, cachedResult));
                    context.setAnalysisResult(cachedResult);
                    context.getAnalysisResult().setAiCallDurationMs(System.currentTimeMillis() - startTime);
                    return;
                }
            }

            // 构建摘要并清洗（防 Prompt Injection）
            String aiSummary = SecurityUtil.sanitizeForPrompt(context.toAISummary());

            // 加载 Prompt
            Optional<String> systemPrompt = promptService.loadSystemPrompt(Constants.PROMPT_ENDPOINT_ANALYSIS);
            Optional<String> userPrompt = promptService.loadTemplate(Constants.PROMPT_ENDPOINT_ANALYSIS);

            if (userPrompt.isEmpty()) {
                log.warn("Analysis prompt not found: {}", Constants.PROMPT_ENDPOINT_ANALYSIS);
                pluginLog.warn(PluginLogger.Category.LLM, "AI", "Prompt not found: " + Constants.PROMPT_ENDPOINT_ANALYSIS);
                AnalysisResult result = new AnalysisResult();
                result.setErrorMessage("Prompt template not found");
                context.setAnalysisResult(result);
                return;
            }

            // 构造最终 Prompt 并限制长度
            String fullPrompt = buildRuleBoundPrompt(userPrompt.get(), aiSummary, context);
            int maxPromptLen = configService.getConfig().getAi().getMaxPromptLength();
            if (maxPromptLen > 0) {
                fullPrompt = SecurityUtil.truncatePrompt(fullPrompt, maxPromptLen);
            }

            // 速率限制：阻塞等待直到获取许可（不丢弃分析请求）
            rateLimiter.acquire();

            // 调用 AI。Provider 本身返回异步 Future；Pipeline worker 在这里等待结果或超时。
            pluginLog.info(PluginLogger.Category.LLM, "AI", "Calling AI for: " + context.getMethod() + " " + context.getPath()
                    + " [prompt=" + fullPrompt.length() + " chars]");
            CompletableFuture<String> future = aiProvider.analyzeAttackSurface(
                    context,
                    systemPrompt.orElse(""),
                    fullPrompt);

            long waitTimeoutMs = effectiveAiWaitTimeoutMs();
            String aiResponse = future.get(waitTimeoutMs, TimeUnit.MILLISECONDS);

            // 解析结果
            AnalysisResult result = parseAIResponse(aiResponse);
            if (capabilityFilter != null) {
                result = capabilityFilter.filter(result, context);
            }
            context.setEndpointActionType(EndpointActionClassifier.classify(context, result));
            result.setAiCallDurationMs(System.currentTimeMillis() - startTime);
            result.setRawResponse(aiResponse);
            context.setAnalysisResult(result);

            // 缓存结果
            cacheService.put(cacheKey, JsonUtil.toJson(result),
                    configService.getConfig().getStorage().getCacheTtlSeconds());

            log.info("AI analysis completed in {}ms for: {}",
                    result.getAiCallDurationMs(), context.getPath());
            pluginLog.info(PluginLogger.Category.LLM, "AI", "Response received (" + result.getAiCallDurationMs() + "ms): "
                    + context.getPath());

        } catch (java.util.concurrent.TimeoutException e) {
            log.error("AI analysis timeout for: {}", context.getPath());
            pluginLog.error(PluginLogger.Category.LLM, "AI", "TIMEOUT for: " + context.getPath()
                    + " [timeout=" + effectiveAiWaitTimeoutMs() + "ms]");
            AnalysisResult result = new AnalysisResult();
            result.setErrorMessage("AI analysis timeout");
            result.setAiCallDurationMs(System.currentTimeMillis() - startTime);
            context.setAnalysisResult(result);
        } catch (Exception e) {
            log.error("AI analysis failed for: {}", context.getPath(), e);
            pluginLog.error(PluginLogger.Category.LLM, "AI", "Failed for " + context.getPath() + ": " + e.getMessage());
            AnalysisResult result = new AnalysisResult();
            result.setErrorMessage("AI analysis failed: " + e.getMessage());
            result.setAiCallDurationMs(System.currentTimeMillis() - startTime);
            context.setAnalysisResult(result);
        }
    }

    @Override
    public boolean shouldProcess(HTTPContext context) {
        if (context.getAnalysisStatus() == com.aiburpcopilot.core.context.AnalysisStatus.SKIPPED) {
            return false;
        }
        if (context.getEndpointType() != EndpointType.ENDPOINT) {
            return false;
        }
        // 无参数请求（无 Query String 且无请求体）跳过 AI 分析
        // 除非用户手动 send 到插件，否则静默资源、HTML 页面等不消耗 AI 配额
        boolean hasQuery = context.getQuery() != null && !context.getQuery().isEmpty();
        boolean hasBody = context.getRequestBody() != null && context.getRequestBody().length > 0;
        if (!hasQuery && !hasBody) {
            log.debug("Skipping AI analysis for parameterless request: {} {}", context.getMethod(), context.getPath());
            return false;
        }
        return true;
    }

    private long effectiveAiWaitTimeoutMs() {
        int configured = configService.getConfig().getAi().getTimeoutMs();
        int readTimeout = configService.getConfig().getLlm().getReadTimeoutMs();
        int connectTimeout = configService.getConfig().getLlm().getConnectTimeoutMs();
        return Math.max(configured, (long) readTimeout + connectTimeout + 5000L);
    }

    public void shutdown() {
        rateResetScheduler.shutdown();
        log.info("AI rate scheduler shutdown");
    }

    // ---------- Private ----------

    /**
     * 解析 AI 返回的 JSON 格式结果。
     * 如果解析失败，返回包含原始文本的 AnalysisResult。
     */
    private AnalysisResult parseAIResponse(String response) {
        try {
            // 尝试提取 JSON 部分（AI 可能包含 Markdown 代码块）
            String jsonStr = extractJsonFromResponse(response);
            if (jsonStr != null) {
                AnalysisResult result = JsonUtil.fromJsonSafe(jsonStr, AnalysisResult.class);
                if (result != null) {
                    return result;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse AI response as JSON, using raw text", e);
        }

        // 解析失败时，将原始文本作为 summary
        AnalysisResult fallback = new AnalysisResult();
        fallback.setSummary(response);
        return fallback;
    }

    private String buildRuleBoundPrompt(String template, String aiSummary, HTTPContext context) {
        StringBuilder prompt = new StringBuilder();
        prompt.append(template);
        if (capabilityCatalog != null) {
            prompt.append("\n\n[本地规则能力边界]\n")
                    .append(capabilityCatalog.toPromptConstraint());
        }
        prompt.append("\n\n[AUTHORITATIVE PARAMETER CONTRACT]\n")
                .append(buildParameterContract(context));
        prompt.append("\n\n").append(aiSummary);
        return prompt.toString();
    }

    private String buildParameterContract(HTTPContext context) {
        if (context == null || context.getParameters() == null || context.getParameters().isEmpty()) {
            return "No request parameters are available. Return empty parameter-based findings.\n";
        }
        StringBuilder contract = new StringBuilder();
        contract.append("AllowedParameterNames: [");
        for (int index = 0; index < context.getParameters().size(); index++) {
            if (index > 0) {
                contract.append(", ");
            }
            contract.append(context.getParameters().get(index).getName());
        }
        contract.append("]\nParameterSamples(name=sampleValue): ");
        for (var parameter : context.getParameters()) {
            String value = parameter.getValue();
            if (value != null && value.length() > 40) {
                value = value.substring(0, 40) + "...";
            }
            contract.append(parameter.getName())
                    .append("(").append(parameter.getType()).append(")=")
                    .append(value != null ? SecurityUtil.sanitizeForPrompt(value) : "")
                    .append("; ");
        }
        contract.append("\n");
        return contract.toString();
    }

    /**
     * 从 AI 响应中提取 JSON 字符串。
     * 处理 Markdown 代码块包裹的情况。
     */
    private String extractJsonFromResponse(String response) {
        if (response == null) return null;

        // 尝试提取 ```json ... ``` 中的内容
        int jsonStart = response.indexOf("```json");
        if (jsonStart >= 0) {
            jsonStart += 7; // skip ```json
            int jsonEnd = response.indexOf("```", jsonStart);
            if (jsonEnd > jsonStart) {
                return response.substring(jsonStart, jsonEnd).trim();
            }
        }

        // 尝试直接解析（AI 直接返回 JSON）
        String trimmed = response.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            return trimmed;
        }

        return null;
    }
}
