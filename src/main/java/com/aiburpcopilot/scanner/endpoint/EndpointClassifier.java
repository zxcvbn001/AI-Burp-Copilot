package com.aiburpcopilot.scanner.endpoint;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.core.context.ParameterType;
import com.aiburpcopilot.prompts.IPromptService;
import com.aiburpcopilot.utils.Constants;
import com.aiburpcopilot.utils.HttpUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * 端点分类器实现（评分制）。
 * <p>
 * 两层分类机制：
 * <ol>
 *   <li><b>规则评分引擎</b> - 基于 Method、后缀、路径关键字、Content-Type 等特征加权评分</li>
 *   <li><b>AI 辅助</b> - 评分结果不明确时调用 LLM 判断</li>
 * </ol>
 * <p>
 * 评分规则（可配置权重）：
 * <pre>
 *   Endpoint 特征加分：
 *     POST/PUT/PATCH         +3
 *     DELETE                  +2
 *     JSON/XML/GraphQL CT     +2
 *     API 路径关键字          +2
 *     查询参数                +1
 *     Body 参数               +1
 *
 *   Static 特征减分：
 *     静态文件后缀 (.js 等)    -3
 *     跳过关键字              -3
 *     静态目录路径            -2
 *     GET 无特征              -1
 *
 *   阈值：
 *     score >= 2  → ENDPOINT
 *     score <= -2 → STATIC_RESOURCE
 *     其余         → AI 辅助判断
 * </pre>
 * <p>
 * Phase 2 扩展点：
 * 评分权重可通过配置系统动态调整，无需修改代码。
 */
public class EndpointClassifier implements IEndpointClassifier {

    private static final Logger log = LoggerFactory.getLogger(EndpointClassifier.class);

    // ========== 评分常量（后续可提取到配置） ==========
    private static final int SCORE_ENDPOINT_METHOD = 3;
    private static final int SCORE_ENDPOINT_DELETE = 2;
    private static final int SCORE_ENDPOINT_CT = 2;
    private static final int SCORE_ENDPOINT_API_PATH = 2;
    private static final int SCORE_ENDPOINT_QUERY = 1;
    private static final int SCORE_ENDPOINT_BODY_PARAM = 1;
    private static final int SCORE_DYNAMIC_PAGE_QUERY = 2;

    private static final int SCORE_STATIC_EXTENSION = -3;
    private static final int SCORE_STATIC_SKIP_KEYWORD = -3;
    private static final int SCORE_STATIC_DIR = -2;
    private static final int SCORE_STATIC_GET_NO_FEATURE = -1;

    private static final int THRESHOLD_ENDPOINT = 2;
    private static final int THRESHOLD_STATIC = -2;

    private final IAIProvider aiProvider;
    private final IPromptService promptService;
    private final ICacheService cacheService;
    private final IConfigService configService;

    public EndpointClassifier(IAIProvider aiProvider,
                              IPromptService promptService,
                              ICacheService cacheService,
                              IConfigService configService) {
        this.aiProvider = aiProvider;
        this.promptService = promptService;
        this.cacheService = cacheService;
        this.configService = configService;
    }

    @Override
    public RuleResult classifyByRules(HTTPContext context) {
        String path = context.getPath() != null ? context.getPath() : "";
        String method = context.getMethod() != null ? context.getMethod().toUpperCase() : "";
        String contentType = context.getContentType() != null ? context.getContentType() : "";
        String lowerPath = path.toLowerCase();

        int score = 0;

        AppConfig.ScanConfig scanConfig = configService.getConfig().getScan();

        // ========== 1. 静态文件后缀检查（最高优先级，直接判定） ==========
        if (HttpUtil.hasExtension(path, scanConfig.getSkipExtensions())
                || HttpUtil.isStaticExtension(path)) {
            return RuleResult.CONFIDENT_STATIC;
        }

        // ========== 2. 跳过关键字检查（直接判定） ==========
        if (HttpUtil.shouldSkipByKeyword(path, scanConfig.getSkipKeywords())) {
            return RuleResult.CONFIDENT_STATIC;
        }

        // ========== 3. HTTP Method 评分 ==========
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            score += SCORE_ENDPOINT_METHOD;
            log.debug("Score {}: POST/PUT/PATCH method", score);
        } else if ("DELETE".equals(method)) {
            score += SCORE_ENDPOINT_DELETE;
            log.debug("Score {}: DELETE method", score);
        }

        // ========== 4. Content-Type 评分 ==========
        if (contentType.contains("json") || contentType.contains("xml") || contentType.contains("graphql")) {
            score += SCORE_ENDPOINT_CT;
            log.debug("Score {}: JSON/XML/GraphQL Content-Type", score);
        }

        // ========== 5. API 路径关键字评分 ==========
        boolean hasApiKeyword = false;
        for (String keyword : Constants.ENDPOINT_PATH_KEYWORDS) {
            if (lowerPath.contains("/" + keyword + "/") || lowerPath.endsWith("/" + keyword)) {
                score += SCORE_ENDPOINT_API_PATH;
                hasApiKeyword = true;
                log.debug("Score {}: API path keyword '{}'", score, keyword);
                break;
            }
        }

        // ========== 6. 查询参数评分 ==========
        if (context.getQuery() != null && !context.getQuery().isEmpty()) {
            score += SCORE_ENDPOINT_QUERY;
            log.debug("Score {}: has query parameters", score);
        }

        if ("GET".equals(method)
                && context.getQuery() != null && !context.getQuery().isEmpty()
                && looksLikeDynamicPage(lowerPath)) {
            score += SCORE_DYNAMIC_PAGE_QUERY;
            log.debug("Score {}: GET dynamic page with query parameters", score);
        }

        // ========== 7. Body 参数评分 ==========
        if (context.getParameters() != null && !context.getParameters().isEmpty()) {
            boolean hasBodyParam = context.getParameters().stream()
                    .anyMatch(p -> p.getType() == ParameterType.BODY);
            if (hasBodyParam) {
                score += SCORE_ENDPOINT_BODY_PARAM;
                log.debug("Score {}: has body parameters", score);
            }
        }

        // ========== 8. 静态目录路径减分（仅对无 API 关键字的请求） ==========
        if ("GET".equals(method) && !hasApiKeyword) {
            if (lowerPath.contains("/static/") || lowerPath.contains("/assets/")
                    || lowerPath.contains("/public/") || lowerPath.contains("/dist/")
                    || lowerPath.contains("/build/")) {
                score += SCORE_STATIC_DIR;
                log.debug("Score {}: static directory path", score);
            }
        }

        // ========== 9. GET 无任何特征 → 倾向静态 ==========
        if ("GET".equals(method) && score == 0) {
            score += SCORE_STATIC_GET_NO_FEATURE;
            log.debug("Score {}: GET with no features", score);
        }

        // ========== 10. 根据阈值判定 ==========
        log.debug("Final score {} for {} {}", score, method, path);

        if (score >= THRESHOLD_ENDPOINT) {
            return RuleResult.CONFIDENT_ENDPOINT;
        } else if (score <= THRESHOLD_STATIC) {
            return RuleResult.CONFIDENT_STATIC;
        } else {
            return RuleResult.UNCERTAIN;
        }
    }

    @Override
    public EndpointType classifyByAI(HTTPContext context) {
        if (!aiProvider.isAvailable()) {
            log.warn("AI provider not available, skipping AI classification");
            return EndpointType.UNKNOWN;
        }

        try {
            // 检查缓存
            String cacheKey = "classify:" + context.generateCacheKey();
            Optional<String> cached = cacheService.get(cacheKey);
            if (cached.isPresent()) {
                String value = cached.get();
                return parseEndpointType(value);
            }

            // 构建 AI 摘要（仅传递最小信息）
            String aiSummary = buildAISummary(context);

            // 加载分类 Prompt
            Optional<String> promptOpt = promptService.loadTemplate(Constants.PROMPT_ENDPOINT_CLASSIFIER);
            if (promptOpt.isEmpty()) {
                log.warn("Classifier prompt not found: {}", Constants.PROMPT_ENDPOINT_CLASSIFIER);
                return EndpointType.UNKNOWN;
            }

            // 调用 AI
            CompletableFuture<String> future = aiProvider.classifyEndpoint(aiSummary, promptOpt.get());
            long waitTimeoutMs = Math.max(
                    configService.getConfig().getAi().getTimeoutMs(),
                    (long) configService.getConfig().getLlm().getConnectTimeoutMs()
                            + configService.getConfig().getLlm().getReadTimeoutMs()
                            + 5000L);
            String result = future.get(waitTimeoutMs, TimeUnit.MILLISECONDS);

            // 缓存结果（30 min TTL）
            cacheService.put(cacheKey, result, 1800);

            return parseEndpointType(result.trim());
        } catch (java.util.concurrent.TimeoutException e) {
            log.warn("AI classification timed out for {} {}", context.getMethod(), context.getPath());
            return fallbackForAiClassificationFailure(context, "timeout");
        } catch (Exception e) {
            log.warn("AI classification failed: {}", e.getMessage());
            return fallbackForAiClassificationFailure(context, e.getClass().getSimpleName());
        }
    }

    @Override
    public void classify(HTTPContext context) {
        // 第一层：规则评分判断
        RuleResult ruleResult = classifyByRules(context);

        switch (ruleResult) {
            case CONFIDENT_ENDPOINT -> {
                context.setEndpointType(EndpointType.ENDPOINT);
                log.debug("Rule scored as ENDPOINT: {}", context.getPath());
            }
            case CONFIDENT_STATIC -> {
                context.setEndpointType(EndpointType.STATIC_RESOURCE);
                log.debug("Rule scored as STATIC: {}", context.getPath());
            }
            case UNCERTAIN -> {
                // 第二层：AI 辅助判断
                EndpointType aiResult = classifyByAI(context);
                context.setEndpointType(aiResult);
                log.debug("AI classified as {}: {}", aiResult, context.getPath());
            }
        }
    }

    // ---------- Private Helpers ----------

    /**
     * 构建 AI 分类用的最小信息摘要。
     */
    private String buildAISummary(HTTPContext context) {
        StringBuilder sb = new StringBuilder();
        sb.append("Method: ").append(context.getMethod()).append("\n");
        sb.append("Path: ").append(context.getPath()).append("\n");
        sb.append("Content-Type: ").append(context.getContentType()).append("\n");

        // 仅传递 body 前 512 字节
        if (context.getRequestBody() != null && context.getRequestBody().length > 0) {
            int len = Math.min(context.getRequestBody().length, Constants.AI_MAX_BODY_PREVIEW_SIZE);
            String bodyPreview = new String(context.getRequestBody(), 0, len, StandardCharsets.UTF_8);
            sb.append("Body Preview: ").append(bodyPreview).append("\n");
        }

        sb.append("Response Content-Type: ").append(context.getResponseContentType()).append("\n");
        return sb.toString();
    }

    private EndpointType parseEndpointType(String text) {
        if (text == null) return EndpointType.UNKNOWN;
        String upper = text.trim().toUpperCase();
        if (upper.contains("ENDPOINT")) return EndpointType.ENDPOINT;
        if (upper.contains("STATIC")) return EndpointType.STATIC_RESOURCE;
        return EndpointType.UNKNOWN;
    }

    private EndpointType fallbackForAiClassificationFailure(HTTPContext context, String reason) {
        String path = context.getPath() != null ? context.getPath().toLowerCase() : "";
        boolean hasQuery = context.getQuery() != null && !context.getQuery().isEmpty();
        boolean hasBody = context.getRequestBody() != null && context.getRequestBody().length > 0;
        if ((hasQuery || hasBody) && looksLikeDynamicPage(path)) {
            log.info("Fallback endpoint classification applied for {} {} due to AI {}", 
                    context.getMethod(), context.getPath(), reason);
            return EndpointType.ENDPOINT;
        }
        return EndpointType.UNKNOWN;
    }

    private boolean looksLikeDynamicPage(String lowerPath) {
        if (lowerPath == null || lowerPath.isBlank()) {
            return false;
        }
        return lowerPath.endsWith(".php")
                || lowerPath.endsWith(".jsp")
                || lowerPath.endsWith(".asp")
                || lowerPath.endsWith(".aspx")
                || lowerPath.contains("/vulnerabilities/")
                || lowerPath.contains("authbypass")
                || lowerPath.contains("sqli")
                || lowerPath.contains("xss")
                || lowerPath.contains("upload");
    }
}
