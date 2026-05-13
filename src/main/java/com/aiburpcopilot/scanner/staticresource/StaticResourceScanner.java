package com.aiburpcopilot.scanner.staticresource;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.context.HTTPContext;
import com.aiburpcopilot.prompts.IPromptService;
import com.aiburpcopilot.utils.Constants;
import com.aiburpcopilot.utils.HttpUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * 静态资源扫描器实现。
 * <p>
 * 两层扫描机制：
 * <ol>
 *   <li><b>RegexRuleEngine</b> - 从 YAML 配置文件加载规则，正则匹配响应体</li>
 *   <li><b>AI 复核</b> - 规则命中后调用 AI 判断是否为真实风险</li>
 * </ol>
 * <p>
 * 规则加载优先级：YAML 配置 > 内置硬编码降级。
 * 仅在规则命中后才消耗 Token 调用 AI，避免不必要的开销。
 * <p>
 * Phase 2 扩展点：
 * <ul>
 *   <li>通过修改 rules/static-resource-rules.yaml 添加自定义规则</li>
 *   <li>通过 reloadRules() 热加载规则变更</li>
 * </ul>
 */
public class StaticResourceScanner implements IStaticScanner {

    private static final Logger log = LoggerFactory.getLogger(StaticResourceScanner.class);

    private final IAIProvider aiProvider;
    private final IPromptService promptService;
    private final ICacheService cacheService;
    private final IConfigService configService;
    private final RegexRuleEngine ruleEngine;

    public StaticResourceScanner(IAIProvider aiProvider,
                                  IPromptService promptService,
                                  ICacheService cacheService,
                                  IConfigService configService) {
        this.aiProvider = aiProvider;
        this.promptService = promptService;
        this.cacheService = cacheService;
        this.configService = configService;
        this.ruleEngine = new RegexRuleEngine();
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
            context.setStaticScanResult("静态文件扫描已跳过：命中扩展名黑名单。Path=" + path
                    + "，黑名单=" + scanConfig.getSkipExtensions());
            log.debug("Static scan skipped by extension blacklist: {}", path);
            return false;
        }
        if (HttpUtil.shouldSkipByKeyword(path, scanConfig.getSkipKeywords())) {
            context.setStaticScanResult("静态文件扫描已跳过：命中路径关键字黑名单。Path=" + path
                    + "，黑名单=" + scanConfig.getSkipKeywords());
            log.debug("Static scan skipped by keyword blacklist: {}", path);
            return false;
        }

        // 检查响应体大小限制
        int maxSize = scanConfig.getStaticScanMaxSize();
        if (context.getResponseBody().length > maxSize) {
            context.setStaticScanResult("静态文件扫描已跳过：响应体过大。大小="
                    + context.getResponseBody().length + " bytes，限制=" + maxSize + " bytes");
            log.debug("Response body too large for static scan: {} bytes (max: {})",
                    context.getResponseBody().length, maxSize);
            return false;
        }

        // 响应体扫描开关
        if (!scanConfig.getResponseBodyScan().isEnabled()) {
            context.setStaticScanResult("静态文件扫描已跳过：responseBodyScan.enabled=false。");
            return false;
        }

        return true;
    }

    @Override
    public StaticScanResult scan(HTTPContext context) {
        if (!shouldScan(context)) {
            StaticScanResult result = new StaticScanResult();
            result.setHasFindings(false);
            return result;
        }

        try {
            String content = new String(context.getResponseBody(), StandardCharsets.UTF_8);

            // 第一层：RegexRuleEngine 规则匹配
            List<StaticScanResult.Finding> findings = ruleEngine.matchAll(content);
            StaticScanResult result = new StaticScanResult();

            if (findings.isEmpty()) {
                result.setHasFindings(false);
                return result;
            }

            result.setHasFindings(true);
            result.setFindings(findings);

            // 第二层：AI 复核（仅在规则命中后）
            String aiReview = aiReview(context, findings, content);
            result.setAiReview(aiReview);

            // 设置扫描结果摘要到 context
            StringBuilder summary = new StringBuilder();
            summary.append("Found ").append(findings.size()).append(" potential secrets:\n");
            for (StaticScanResult.Finding f : findings) {
                summary.append("  - [").append(f.getSeverity()).append("] ")
                        .append(f.getRuleName()).append(" at line ")
                        .append(f.getLineNumber()).append("\n");
            }
            if (aiReview != null) {
                summary.append("AI Review: ").append(aiReview);
            }
            context.setStaticScanResult(summary.toString());

            log.info("Static scan found {} findings for: {}", findings.size(), context.getPath());
            return result;

        } catch (Exception e) {
            log.error("Static scan failed for: {}", context.getPath(), e);
            StaticScanResult result = new StaticScanResult();
            result.setHasFindings(false);
            return result;
        }
    }

    /**
     * 重新加载规则（支持热更新）。
     * 可由 UI 配置面板或配置变更监听触发。
     */
    public void reloadRules() {
        ruleEngine.reload();
        log.info("Static scan rules reloaded, {} rules active", ruleEngine.getRuleCount());
    }

    // ---------- Private ----------

    /**
     * AI 复核规则命中的内容。
     */
    private String aiReview(HTTPContext context, List<StaticScanResult.Finding> findings, String content) {
        if (!aiProvider.isAvailable()) {
            log.debug("AI provider not available, skipping AI review");
            return "AI review skipped (provider not available)";
        }

        try {
            // 检查缓存
            String cacheKey = "static-review:" + context.generateCacheKey();
            Optional<String> cached = cacheService.get(cacheKey);
            if (cached.isPresent()) {
                return cached.get();
            }

            // 提取命中的代码片段（上下文行）
            StringBuilder snippet = new StringBuilder();
            String[] lines = content.split("\n");
            for (StaticScanResult.Finding f : findings) {
                int lineIdx = f.getLineNumber() - 1;
                int start = Math.max(0, lineIdx - 2);
                int end = Math.min(lines.length, lineIdx + 3);
                snippet.append("--- Finding: ").append(f.getRuleName()).append(" ---\n");
                for (int i = start; i < end; i++) {
                    String prefix = (i == lineIdx) ? ">>> " : "    ";
                    snippet.append(prefix).append(i + 1).append(": ").append(lines[i]).append("\n");
                }
                snippet.append("\n");
            }

            // 加载 Prompt
            Optional<String> promptOpt = promptService.loadTemplate(Constants.PROMPT_STATIC_REVIEW);
            if (promptOpt.isEmpty()) {
                log.warn("Static review prompt not found: {}", Constants.PROMPT_STATIC_REVIEW);
                return "No review prompt available";
            }

            // 调用 AI 复核
            CompletableFuture<String> future = aiProvider.reviewStaticResource(
                    snippet.toString(), promptOpt.get());
            String review = future.get(20, TimeUnit.SECONDS);

            // 缓存结果（1 hour TTL）
            cacheService.put(cacheKey, review, 3600);

            return review;
        } catch (Exception e) {
            log.warn("AI review failed: {}", e.getMessage());
            return "AI review failed: " + e.getMessage();
        }
    }
}
