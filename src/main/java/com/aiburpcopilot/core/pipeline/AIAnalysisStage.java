package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.config.Timeouts;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * AI 鏀诲嚮闈㈠垎鏋?Pipeline Stage銆?
 * <p>
 * 浠呭 ENDPOINT 绫诲瀷鐨勮姹傛墽琛屻€?
 * 璋冪敤 AI 鍒嗘瀽鎺ュ彛鐨勬敾鍑婚潰銆佸弬鏁拌涔夊拰楂樹环鍊煎弬鏁般€?
 * <p>
 * AI 鍒嗘瀽杈撳叆锛欻TTP 涓婁笅鏂囨憳瑕侊紙涓嶅惈瀹屾暣璇锋眰/鍝嶅簲浣擄級
 * AI 鍒嗘瀽杈撳嚭锛欽SON 鏍煎紡鐨勬敾鍑婚潰鍒嗘瀽缁撴灉锛堜笉鐩存帴鐢熸垚婕忔礊缁撹锛?
 */
public class AIAnalysisStage implements IPipelineStage {

    private static final Logger log = LoggerFactory.getLogger(AIAnalysisStage.class);
    private static final String ANALYSIS_CACHE_PREFIX = "analysis:broad-attack-v3:";
    private final PluginLogger pluginLog = PluginLogger.getInstance();
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

            // 妫€鏌ョ紦瀛?
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

            // 鏋勫缓鎽樿骞舵竻娲楋紙闃?Prompt Injection锛?
            String aiSummary = SecurityUtil.sanitizeForPrompt(context.toAISummary());

            // 鍔犺浇 Prompt
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

            // 鏋勯€犳渶缁?Prompt 骞堕檺鍒堕暱搴?
            String fullPrompt = buildRuleBoundPrompt(userPrompt.get(), aiSummary, context);
            int maxPromptLen = configService.getConfig().getAi().getMaxPromptLength();
            if (maxPromptLen > 0) {
                fullPrompt = SecurityUtil.truncatePrompt(fullPrompt, maxPromptLen);
            }


            // 璋冪敤 AI銆侾rovider 鏈韩杩斿洖寮傛 Future锛汸ipeline worker 鍦ㄨ繖閲岀瓑寰呯粨鏋滄垨瓒呮椂銆?
            pluginLog.info(PluginLogger.Category.LLM, "AI", "Calling AI for: " + context.getMethod() + " " + context.getPath()
                    + " [prompt=" + fullPrompt.length() + " chars]");
            CompletableFuture<String> future = aiProvider.analyzeAttackSurface(
                    context,
                    systemPrompt.orElse(""),
                    fullPrompt);

            long waitTimeoutMs = effectiveAiWaitTimeoutMs();
            String aiResponse = future.get(waitTimeoutMs, TimeUnit.MILLISECONDS);

            // 瑙ｆ瀽缁撴灉
            AnalysisResult result = parseAIResponse(aiResponse);
            if (capabilityFilter != null) {
                result = capabilityFilter.filter(result, context);
            }
            context.setEndpointActionType(EndpointActionClassifier.classify(context, result));
            result.setAiCallDurationMs(System.currentTimeMillis() - startTime);
            result.setRawResponse(aiResponse);
            context.setAnalysisResult(result);

            // 缂撳瓨缁撴灉
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
        // 鏃犲弬鏁拌姹傦紙鏃?Query String 涓旀棤璇锋眰浣擄級璺宠繃 AI 鍒嗘瀽
        // 闄ら潪鐢ㄦ埛鎵嬪姩 send 鍒版彃浠讹紝鍚﹀垯闈欓粯璧勬簮銆丠TML 椤甸潰绛変笉娑堣€?AI 閰嶉
        boolean hasQuery = context.getQuery() != null && !context.getQuery().isEmpty();
        boolean hasBody = context.getRequestBody() != null && context.getRequestBody().length > 0;
        if (!hasQuery && !hasBody) {
            log.debug("Skipping AI analysis for parameterless request: {} {}", context.getMethod(), context.getPath());
            return false;
        }
        return true;
    }

    private long effectiveAiWaitTimeoutMs() {
        return Timeouts.effectiveLlmWaitMs(configService);
    }

    public void shutdown() {
    }

    // ---------- Private ----------

    /**
     * 瑙ｆ瀽 AI 杩斿洖鐨?JSON 鏍煎紡缁撴灉銆?
     * 濡傛灉瑙ｆ瀽澶辫触锛岃繑鍥炲寘鍚師濮嬫枃鏈殑 AnalysisResult銆?
     */
    private AnalysisResult parseAIResponse(String response) {
        try {
            // 灏濊瘯鎻愬彇 JSON 閮ㄥ垎锛圓I 鍙兘鍖呭惈 Markdown 浠ｇ爜鍧楋級
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

        // 瑙ｆ瀽澶辫触鏃讹紝灏嗗師濮嬫枃鏈綔涓?summary
        AnalysisResult fallback = new AnalysisResult();
        fallback.setSummary(response);
        return fallback;
    }

    private String buildRuleBoundPrompt(String template, String aiSummary, HTTPContext context) {
        StringBuilder prompt = new StringBuilder();
        prompt.append(template);
        if (capabilityCatalog != null) {
            prompt.append("\n\n[鏈湴瑙勫垯鑳藉姏杈圭晫]\n")
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
     * 浠?AI 鍝嶅簲涓彁鍙?JSON 瀛楃涓层€?
     * 澶勭悊 Markdown 浠ｇ爜鍧楀寘瑁圭殑鎯呭喌銆?
     */
    private String extractJsonFromResponse(String response) {
        if (response == null) return null;

        // 灏濊瘯鎻愬彇 ```json ... ``` 涓殑鍐呭
        int jsonStart = response.indexOf("```json");
        if (jsonStart >= 0) {
            jsonStart += 7; // skip ```json
            int jsonEnd = response.indexOf("```", jsonStart);
            if (jsonEnd > jsonStart) {
                return response.substring(jsonStart, jsonEnd).trim();
            }
        }

        // 灏濊瘯鐩存帴瑙ｆ瀽锛圓I 鐩存帴杩斿洖 JSON锛?
        String trimmed = response.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            return trimmed;
        }

        return null;
    }
}


