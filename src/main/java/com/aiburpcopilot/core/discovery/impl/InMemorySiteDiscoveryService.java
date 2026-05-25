package com.aiburpcopilot.core.discovery.impl;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.config.Timeouts;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.discovery.DiscoveryAssetType;
import com.aiburpcopilot.core.discovery.DiscoveryAttempt;
import com.aiburpcopilot.core.discovery.DiscoveryCandidate;
import com.aiburpcopilot.core.discovery.DiscoveryJudgment;
import com.aiburpcopilot.core.discovery.DiscoveryValidation;
import com.aiburpcopilot.core.discovery.DiscoveryValidationStatus;
import com.aiburpcopilot.core.discovery.ISiteDiscoveryService;
import com.aiburpcopilot.core.history.HistoryEntry;
import com.aiburpcopilot.core.history.IHistoryService;
import com.aiburpcopilot.prompts.IPromptService;
import com.aiburpcopilot.utils.HttpUtil;
import com.aiburpcopilot.utils.Constants;
import com.aiburpcopilot.utils.JsonUtil;
import com.aiburpcopilot.utils.PluginLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class InMemorySiteDiscoveryService implements ISiteDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(InMemorySiteDiscoveryService.class);

    private static final List<String> CRUD_ACTIONS = List.of(
            "list", "detail", "get", "info", "query", "search", "page",
            "create", "add", "save", "update", "edit", "delete", "remove",
            "export", "import");
    private static final Set<Integer> POSITIVE_ENDPOINT_CODES = Set.of(
            200, 201, 202, 204, 301, 302, 303, 307, 308,
            401, 403, 405, 406, 409, 415, 422, 429);
    private static final Set<Integer> NEGATIVE_CODES = Set.of(404, 410);

    private final IHistoryService historyService;
    private final MontoyaApi api;
    private final IAIProvider aiProvider;
    private final IPromptService promptService;
    private final IConfigService configService;
    private final Map<String, DiscoveryValidation> validationCache = new ConcurrentHashMap<>();
    private final Map<String, CachedInference> inferenceCache = new ConcurrentHashMap<>();

    public InMemorySiteDiscoveryService(IHistoryService historyService, MontoyaApi api) {
        this(historyService, api, null, null, null);
    }

    public InMemorySiteDiscoveryService(IHistoryService historyService,
                                        MontoyaApi api,
                                        IAIProvider aiProvider,
                                        IPromptService promptService,
                                        IConfigService configService) {
        this.historyService = historyService;
        this.api = api;
        this.aiProvider = aiProvider;
        this.promptService = promptService;
        this.configService = configService;
    }

    @Override
    public List<String> listHosts() {
        return historyService.getAll().stream()
                .map(HistoryEntry::getUrl)
                .map(this::parseUri)
                .filter(uri -> uri != null && uri.getScheme() != null && uri.getAuthority() != null)
                .map(uri -> uri.getScheme() + "://" + uri.getAuthority())
                .distinct()
                .sorted()
                .toList();
    }

    @Override
    public List<DiscoveryCandidate> getCandidates(String hostFilter) {
        List<DiscoveryCandidate> persisted = historyService.listDiscoveryCandidates(hostFilter);
        return persisted.stream()
                .map(this::cloneCandidate)
                .peek(candidate -> {
                    DiscoveryValidation cachedValidation = validationCache.get(candidate.getKey());
                    if (cachedValidation != null) {
                        candidate.setValidation(cloneValidation(cachedValidation));
                    }
                })
                .sorted(Comparator.comparingDouble(DiscoveryCandidate::getScore).reversed()
                        .thenComparing(DiscoveryCandidate::getPath))
                .toList();
    }

    @Override
    public List<DiscoveryCandidate> inferCandidates(String hostFilter) {
        Map<String, HostObservation> grouped = groupObservations(hostFilter);
        Map<String, DiscoveryCandidate> candidates = new LinkedHashMap<>();
        for (HostObservation observation : grouped.values()) {
            inferEndpointCandidatesWithLlm(observation, candidates);
        }
        return candidates.values().stream()
                .peek(candidate -> {
                    DiscoveryValidation cachedValidation = validationCache.get(candidate.getKey());
                    if (cachedValidation != null) {
                        candidate.setValidation(cloneValidation(cachedValidation));
                    }
                    historyService.saveDiscoveryCandidate(candidate.getHost(), candidate);
                })
                .sorted(Comparator.comparingDouble(DiscoveryCandidate::getScore).reversed()
                        .thenComparing(DiscoveryCandidate::getPath))
                .toList();
    }

    @Override
    public String describeEndpointStructure(String hostFilter) {
        Map<String, HostObservation> grouped = groupObservations(hostFilter);
        if (grouped.isEmpty()) {
            return "暂无可用于结构分析的历史 Endpoint。\n\n说明：静态文件、404/410、未验证的 JS AST 恢复接口不会进入这里。";
        }

        StringBuilder text = new StringBuilder();
        for (HostObservation observation : grouped.values()) {
            text.append(observation.host)
                    .append(" | 已验证/历史 Endpoint: ")
                    .append(observation.endpointPaths.size())
                    .append("\n");
            Map<String, List<PathObservation>> modules = observation.endpointPaths.values().stream()
                    .sorted(Comparator.comparing(path -> path.path))
                    .collect(Collectors.groupingBy(
                            path -> modulePrefix(path.path),
                            LinkedHashMap::new,
                            Collectors.toList()));
            for (Map.Entry<String, List<PathObservation>> module : modules.entrySet()) {
                text.append("├─ ").append(module.getKey()).append("\n");
                for (PathObservation path : module.getValue()) {
                    text.append("│  ├─ ")
                            .append(path.methods.isEmpty() ? "GET" : String.join(",", path.methods))
                            .append(" ")
                            .append(path.path);
                    if (!path.statusCodes.isEmpty()) {
                        text.append(" | status=").append(String.join(",", path.statusCodes));
                    }
                    if (!path.parameters.isEmpty()) {
                        text.append(" | params=").append(String.join(",", path.parameters));
                    }
                    if (path.fromJsRecovered) {
                        text.append(" | source=validated-js-ast");
                    }
                    text.append("\n");
                }
            }
            text.append("\n");
        }
        return text.toString();
    }

    @Override
    public DiscoveryCandidate validateCandidate(DiscoveryCandidate candidate) {
        if (candidate == null) {
            return null;
        }
        DiscoveryValidation validation = new DiscoveryValidation();
        validation.setStatus(DiscoveryValidationStatus.RUNNING);
        candidate.setValidation(validation);
        validationCache.put(candidate.getKey(), cloneValidation(validation));
        historyService.saveDiscoveryCandidate(candidate.getHost(), candidate);

        try {
            DiscoveryValidation completed = doValidate(candidate);
            candidate.setValidation(completed);
            validationCache.put(candidate.getKey(), cloneValidation(completed));
            historyService.saveDiscoveryCandidate(candidate.getHost(), candidate);
            return candidate;
        } catch (Exception e) {
            log.warn("Discovery validation failed for {}: {}", candidate.getUrl(), e.getMessage());
            DiscoveryValidation failed = new DiscoveryValidation();
            failed.setStatus(DiscoveryValidationStatus.COMPLETED);
            failed.setJudgment(DiscoveryJudgment.ERROR);
            failed.setReasoning("验证失败: " + e.getMessage());
            failed.setValidatedAt(Instant.now().toEpochMilli());
            candidate.setValidation(failed);
            validationCache.put(candidate.getKey(), cloneValidation(failed));
            historyService.saveDiscoveryCandidate(candidate.getHost(), candidate);
            return candidate;
        }
    }

    private DiscoveryValidation doValidate(DiscoveryCandidate candidate) {
        DiscoveryValidation validation = new DiscoveryValidation();
        validation.setStatus(DiscoveryValidationStatus.RUNNING);
        List<DiscoveryAttempt> attempts = new ArrayList<>();

        attempts.add(executeAttempt(candidate, normalizeMethod(candidate.getMethodHint()), 1));

        ValidationAssessment assessment = assess(candidate, attempts);
        validation.setStatus(DiscoveryValidationStatus.COMPLETED);
        validation.setJudgment(assessment.judgment());
        validation.setReasoning(assessment.reasoning());
        validation.setAttempts(attempts);
        validation.setFinalStatusCode(assessment.finalStatusCode());
        validation.setContentType(assessment.contentType());
        validation.setValidatedAt(Instant.now().toEpochMilli());
        return validation;
    }

    private DiscoveryAttempt executeAttempt(DiscoveryCandidate candidate, String method, int sequence) {
        DiscoveryAttempt attempt = new DiscoveryAttempt();
        attempt.setSequence(sequence);
        attempt.setMethod(method);
        byte[] requestBytes = buildRawRequest(candidate.getUrl(), method);
        attempt.setRequestBytes(requestBytes);
        if (requestBytes == null || requestBytes.length == 0) {
            attempt.setStatusCode(-1);
            attempt.setSummary("Request bytes unavailable");
            return attempt;
        }

        if (api == null) {
            attempt.setStatusCode(-1);
            attempt.setSummary("Montoya API unavailable");
            return attempt;
        }

        URI uri = parseUri(candidate.getUrl());
        if (uri == null || uri.getHost() == null) {
            attempt.setStatusCode(-1);
            attempt.setSummary("Invalid target URL");
            return attempt;
        }

        try {
            HttpService service = HttpService.httpService(
                    uri.getHost(),
                    uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80),
                    "https".equalsIgnoreCase(uri.getScheme()));
            var request = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    service,
                    ByteArray.byteArray(requestBytes));
            HttpRequestResponse result = api.http().sendRequest(request);
            if (result == null || !result.hasResponse()) {
                attempt.setStatusCode(-1);
                attempt.setSummary("No response");
                return attempt;
            }

            byte[] responseBytes = safeBytes(result.response().toByteArray());
            attempt.setResponseBytes(responseBytes);
            ParsedResponse parsed = parseResponse(responseBytes);
            attempt.setStatusCode(parsed.statusCode);
            attempt.setContentType(parsed.headers.getOrDefault("content-type", ""));
            attempt.setSummary("HTTP " + parsed.statusCode + " | " + summarizeResponse(parsed));
            attempt.setSignalMatched(parsed.statusCode > 0 && parsed.statusCode != 404 && parsed.statusCode != 410);
            return attempt;
        } catch (Exception e) {
            attempt.setStatusCode(-1);
            attempt.setSummary("Request failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return attempt;
        }
    }

    private byte[] safeBytes(ByteArray bytes) {
        if (bytes == null) {
            return new byte[0];
        }
        byte[] raw = bytes.getBytes();
        return raw != null ? raw : new byte[0];
    }

    private ValidationAssessment assess(DiscoveryCandidate candidate, List<DiscoveryAttempt> attempts) {
        DiscoveryAttempt decisive = attempts.isEmpty() ? null : attempts.get(attempts.size() - 1);
        ParsedResponse parsed = decisive != null ? parseResponse(decisive.getResponseBytes()) : new ParsedResponse();
        int statusCode = decisive != null ? decisive.getStatusCode() : -1;
        String contentType = decisive != null ? decisive.getContentType() : "";
        String bodyText = parsed.bodyText;
        boolean htmlLike = safeLower(contentType).contains("text/html")
                || bodyText.contains("<html")
                || bodyText.contains("<!doctype");
        boolean routeMissingText = containsAny(bodyText,
                "not found", "404", "cannot get", "no resource found",
                "resource not found", "whitelabel error");

        if (NEGATIVE_CODES.contains(statusCode)) {
            return new ValidationAssessment(DiscoveryJudgment.NOT_FOUND, statusCode, contentType,
                    "响应为 " + statusCode + "，目标大概率不存在。");
        }

        if (POSITIVE_ENDPOINT_CODES.contains(statusCode)) {
            if (statusCode == 200 && htmlLike && candidate.getPath().contains("/api/")) {
                return new ValidationAssessment(DiscoveryJudgment.INCONCLUSIVE, statusCode, contentType,
                        "返回 200，但内容更像 HTML 页面，对 API 路径不够可信，建议人工复核。");
            }
            if (routeMissingText && statusCode == 200) {
                return new ValidationAssessment(DiscoveryJudgment.INCONCLUSIVE, statusCode, contentType,
                        "返回 200，但正文出现疑似不存在文案，不直接认定接口存在。");
            }
            if (statusCode == 401 || statusCode == 403 || statusCode == 405 || statusCode == 415 || statusCode == 422) {
                return new ValidationAssessment(DiscoveryJudgment.LIKELY_EXISTS, statusCode, contentType,
                        "返回 " + statusCode + "，说明路由或鉴权链路大概率存在。");
            }
            return new ValidationAssessment(DiscoveryJudgment.EXISTS, statusCode, contentType,
                    "返回 " + statusCode + "，接口存在性信号明确。");
        }

        if (statusCode <= 0) {
            String reason = decisive != null && decisive.getSummary() != null ? decisive.getSummary() : "请求失败";
            return new ValidationAssessment(DiscoveryJudgment.ERROR, statusCode, contentType, reason);
        }

        if (routeMissingText) {
            return new ValidationAssessment(DiscoveryJudgment.NOT_FOUND, statusCode, contentType,
                    "响应正文包含明显不存在特征，未认定目标存在。");
        }

        return new ValidationAssessment(DiscoveryJudgment.INCONCLUSIVE, statusCode, contentType,
                "当前响应不足以准确判断是否存在，建议结合业务上下文人工复核。");
    }

    private void inferEndpointCandidates(HostObservation observation, Map<String, DiscoveryCandidate> candidates) {
        Map<String, EndpointFamily> families = new LinkedHashMap<>();
        for (PathObservation pathObservation : observation.endpointPaths.values()) {
            List<String> segments = splitSegments(pathObservation.path);
            if (segments.size() < 2) {
                continue;
            }
            String action = safeLower(segments.get(segments.size() - 1));
            if (!CRUD_ACTIONS.contains(action)) {
                continue;
            }
            String prefix = "/" + String.join("/", segments.subList(0, segments.size() - 1));
            EndpointFamily family = families.computeIfAbsent(prefix, ignored -> new EndpointFamily(prefix));
            family.actions.add(action);
            family.supportingPaths.add(pathObservation.path);
            family.supportingParameters.addAll(pathObservation.parameters);
            family.observationCount += pathObservation.observationCount;
        }

        for (EndpointFamily family : families.values()) {
            if (family.actions.size() < 2) {
                continue;
            }
            int created = 0;
            for (String action : prioritizedMissingActions(family.actions)) {
                if (created >= 4) {
                    break;
                }
                String candidatePath = family.prefix + "/" + action;
                if (observation.allPaths.contains(candidatePath)) {
                    continue;
                }
                DiscoveryCandidate candidate = createCandidate(
                        observation.host,
                        candidatePath,
                        DiscoveryAssetType.ENDPOINT,
                        clamp(0.46 + Math.min(0.28, family.actions.size() * 0.07) + Math.min(0.1, family.observationCount * 0.01)),
                        "同模块接口动作补全：已观察到 " + String.join(", ", family.actions) + "，推测存在 " + action,
                        family.supportingPaths,
                        family.supportingParameters,
                        family.observationCount);
                mergeCandidate(candidates, candidate);
                created++;
            }
        }
    }

    private void inferEndpointCandidatesWithLlm(HostObservation observation, Map<String, DiscoveryCandidate> candidates) {
        if (observation == null || observation.endpointPaths.isEmpty()) {
            return;
        }
        if (aiProvider == null || !aiProvider.isAvailable() || promptService == null) {
            log.debug("LLM site discovery unavailable, falling back to local inference for {}", observation != null ? observation.host : "-");
            inferEndpointCandidates(observation, candidates);
            return;
        }

        String fingerprint = observationFingerprint(observation);
        CachedInference cached = inferenceCache.get(observation.host);
        if (cached != null && Objects.equals(cached.fingerprint(), fingerprint)) {
            for (DiscoveryCandidate candidate : cached.candidates()) {
                mergeCandidate(candidates, candidate);
            }
            return;
        }

        Optional<String> promptTemplate = promptService.loadTemplate(Constants.PROMPT_SITE_DISCOVERY);
        if (promptTemplate.isEmpty()) {
            log.warn("Site discovery prompt not found: {}", Constants.PROMPT_SITE_DISCOVERY);
            inferEndpointCandidates(observation, candidates);
            return;
        }

        try {
            String prompt = buildLlmDiscoveryPrompt(promptTemplate.get(), observation);
            PluginLogger.getInstance().info(
                    PluginLogger.Category.LLM,
                    "SiteDiscovery",
                    "Calling LLM for site endpoint inference: " + observation.host
                            + " [validatedEndpoints=" + observation.endpointPaths.size() + "]");
            String response = aiProvider.analyzeDiff(prompt)
                    .get(siteDiscoveryWaitMs(), TimeUnit.MILLISECONDS);
            List<DiscoveryCandidate> inferred = parseLlmCandidates(observation, response);
            if (inferred.isEmpty()) {
                PluginLogger.getInstance().info(
                        PluginLogger.Category.LLM,
                        "SiteDiscovery",
                        "LLM returned no site endpoint candidates for: " + observation.host);
            }
            inferenceCache.put(observation.host, new CachedInference(fingerprint, cloneCandidates(inferred)));
            for (DiscoveryCandidate candidate : inferred) {
                mergeCandidate(candidates, candidate);
            }
        } catch (Exception e) {
            log.warn("LLM site discovery failed for {}: {}", observation.host, e.getMessage());
            PluginLogger.getInstance().warn(
                    PluginLogger.Category.LLM,
                    "SiteDiscovery",
                    "LLM site endpoint inference failed: " + observation.host + " | " + e.getMessage());
            inferEndpointCandidates(observation, candidates);
        }
    }

    private String buildLlmDiscoveryPrompt(String template, HostObservation observation) {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("host", observation.host);
        input.put("observedEndpoints", observation.endpointPaths.values().stream()
                .sorted(Comparator.comparing(path -> path.path))
                .limit(120)
                .map(path -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("method", path.methods.isEmpty() ? "GET" : String.join(",", path.methods));
                    item.put("path", path.path);
                    item.put("params", new ArrayList<>(path.parameters));
                    item.put("statusCodes", new ArrayList<>(path.statusCodes));
                    item.put("source", path.fromJsRecovered ? "validated-js-ast" : "history");
                    item.put("observations", path.observationCount);
                    return item;
                })
                .toList());
        input.put("negativeExamples", validationCache.values().stream()
                .filter(validation -> validation != null && validation.getJudgment() == DiscoveryJudgment.NOT_FOUND)
                .map(DiscoveryValidation::getReasoning)
                .filter(reason -> reason != null && !reason.isBlank())
                .limit(30)
                .toList());

        return template + "\n\n[INPUT_JSON]\n" + JsonUtil.toPrettyJson(input);
    }

    @SuppressWarnings("unchecked")
    private List<DiscoveryCandidate> parseLlmCandidates(HostObservation observation, String response) {
        String json = extractJson(response);
        if (json == null || json.isBlank()) {
            return List.of();
        }
        Map<String, Object> root = JsonUtil.fromJsonSafe(json, Map.class);
        if (root == null) {
            return List.of();
        }
        Object rawCandidates = root.get("candidates");
        if (!(rawCandidates instanceof List<?> items)) {
            return List.of();
        }

        List<DiscoveryCandidate> result = new ArrayList<>();
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> rawMap)) {
                continue;
            }
            Map<String, Object> candidateMap = rawMap.entrySet().stream()
                    .collect(Collectors.toMap(
                            entry -> String.valueOf(entry.getKey()),
                            Map.Entry::getValue,
                            (first, second) -> first,
                            LinkedHashMap::new));
            DiscoveryCandidate candidate = toCandidate(observation, candidateMap);
            if (candidate != null) {
                result.add(candidate);
            }
        }
        return result;
    }

    private DiscoveryCandidate toCandidate(HostObservation observation, Map<String, Object> values) {
        String rawPath = stringValue(values.get("path"));
        String normalizedPath = normalizePath(rawPath);
        if (normalizedPath == null || normalizedPath.isBlank() || "/".equals(normalizedPath)) {
            return null;
        }
        if (observation.allPaths.contains(normalizedPath) || HttpUtil.isStaticExtension(normalizedPath)) {
            return null;
        }

        List<String> evidence = stringList(values.get("evidence"));
        if (evidence.isEmpty()) {
            evidence = stringList(values.get("evidencePaths"));
        }
        List<String> supportingPaths = evidence.stream()
                .map(this::normalizePath)
                .filter(path -> path != null && observation.allPaths.contains(path))
                .distinct()
                .limit(10)
                .toList();
        if (supportingPaths.isEmpty()) {
            return null;
        }

        List<String> params = extractCandidateParams(values.get("params"));
        double confidence = clamp(doubleValue(values.get("confidence"), 0.55));
        String method = normalizeMethod(stringValue(values.get("method")));
        String reason = stringValue(values.get("reason"));
        if (reason.isBlank()) {
            reason = "LLM 基于已验证历史接口和已验证 JS AST 恢复接口推理";
        }

        DiscoveryCandidate candidate = createCandidate(
                observation.host,
                normalizedPath,
                DiscoveryAssetType.ENDPOINT,
                confidence,
                "LLM 接口规律推理：" + reason,
                supportingPaths,
                params,
                supportingPaths.size());
        candidate.setMethodHint(method);
        candidate.setSupportingMethods(List.of(method));
        candidate.setKey(candidate.getKey() + "|" + method);
        return candidate;
    }

    private List<String> extractCandidateParams(Object rawParams) {
        if (!(rawParams instanceof List<?> items)) {
            return List.of();
        }
        List<String> params = new ArrayList<>();
        for (Object item : items) {
            if (item instanceof Map<?, ?> map) {
                String name = stringValue(map.get("name"));
                if (!name.isBlank()) {
                    params.add(name);
                }
            } else {
                String value = stringValue(item);
                if (!value.isBlank()) {
                    params.add(value);
                }
            }
        }
        return params.stream().distinct().limit(20).toList();
    }

    private String observationFingerprint(HostObservation observation) {
        return observation.endpointPaths.values().stream()
                .sorted(Comparator.comparing(path -> path.path))
                .map(path -> path.path + "|" + String.join(",", path.methods) + "|" + String.join(",", path.parameters))
                .collect(Collectors.joining("\n"));
    }

    private List<DiscoveryCandidate> cloneCandidates(List<DiscoveryCandidate> source) {
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        List<DiscoveryCandidate> copies = new ArrayList<>();
        for (DiscoveryCandidate candidate : source) {
            copies.add(cloneCandidate(candidate));
        }
        return copies;
    }

    private DiscoveryCandidate cloneCandidate(DiscoveryCandidate candidate) {
        return candidate != null ? candidate.copy() : null;
    }

    private boolean matchesHost(DiscoveryCandidate candidate, String hostFilter) {
        if (candidate == null) {
            return false;
        }
        return hostFilter == null
                || hostFilter.isBlank()
                || "ALL".equalsIgnoreCase(hostFilter)
                || hostFilter.equals(candidate.getHost());
    }

    private Map<String, HostObservation> groupObservations(String hostFilter) {
        Map<String, HostObservation> grouped = new LinkedHashMap<>();
        for (HistoryEntry entry : historyService.getAll()) {
            URI uri = parseUri(entry.getUrl());
            if (uri == null || uri.getScheme() == null || uri.getAuthority() == null) {
                continue;
            }
            String host = uri.getScheme() + "://" + uri.getAuthority();
            if (hostFilter != null && !hostFilter.isBlank() && !"ALL".equalsIgnoreCase(hostFilter) && !host.equals(hostFilter)) {
                continue;
            }

            String normalizedPath = normalizePath(uri.getPath());
            if (normalizedPath == null || normalizedPath.isBlank()) {
                continue;
            }
            HostObservation observation = grouped.computeIfAbsent(host, HostObservation::new);
            observation.allPaths.add(normalizedPath);
            Set<String> parameters = extractParameterNames(entry);
            if (HttpUtil.isStaticExtension(normalizedPath)) {
                continue;
            }
            if (!isUsableObservedEndpoint(entry, normalizedPath)) {
                continue;
            }
            PathObservation pathObservation = observation.endpointPaths.computeIfAbsent(normalizedPath, PathObservation::new);
            pathObservation.observationCount++;
            pathObservation.parameters.addAll(parameters);
            pathObservation.methods.add(normalizeMethod(entry.getMethod()));
            if (entry.getStatusCode() > 0) {
                pathObservation.statusCodes.add(String.valueOf(entry.getStatusCode()));
            }
            pathObservation.fromJsRecovered = pathObservation.fromJsRecovered
                    || (entry.getRequestId() != null && entry.getRequestId().startsWith("js-"));
        }
        return grouped;
    }

    private boolean isUsableObservedEndpoint(HistoryEntry entry, String normalizedPath) {
        if (entry == null || normalizedPath == null || HttpUtil.isStaticExtension(normalizedPath)) {
            return false;
        }
        EndpointType endpointType = entry.getEndpointType();
        if (endpointType != null && endpointType != EndpointType.ENDPOINT && endpointType != EndpointType.UNKNOWN) {
            return false;
        }
        int status = entry.getStatusCode();
        if (NEGATIVE_CODES.contains(status)) {
            return false;
        }
        if (entry.getRequestId() != null && entry.getRequestId().startsWith("js-")) {
            return POSITIVE_ENDPOINT_CODES.contains(status);
        }
        return true;
    }

    private Set<String> extractParameterNames(HistoryEntry entry) {
        Set<String> names = new LinkedHashSet<>();
        URI uri = parseUri(entry.getUrl());
        if (uri != null && uri.getRawQuery() != null) {
            HttpUtil.parseQueryParams(uri.getRawQuery()).stream()
                    .map(param -> param.getName())
                    .filter(name -> name != null && !name.isBlank())
                    .forEach(names::add);
        }

        String body = entry.getRequestBody();
        String contentType = entry.getContentType();
        if (body != null && !body.isBlank()) {
            if (HttpUtil.isJsonContent(contentType)) {
                HttpUtil.parseJsonBodyParams(body).stream()
                        .map(param -> param.getName())
                        .filter(name -> name != null && !name.isBlank())
                        .forEach(names::add);
            } else if (HttpUtil.isFormContent(contentType)) {
                HttpUtil.parseFormBodyParams(body).stream()
                        .map(param -> param.getName())
                        .filter(name -> name != null && !name.isBlank())
                        .forEach(names::add);
            } else if (HttpUtil.isMultipartContent(contentType)) {
                HttpUtil.parseMultipartBodyParams(body).stream()
                        .map(param -> param.getName())
                        .filter(name -> name != null && !name.isBlank())
                        .forEach(names::add);
            }
        }
        if (entry.getHighValueParams() != null) {
            names.addAll(entry.getHighValueParams());
        }
        return names;
    }

    private DiscoveryCandidate createCandidate(String host,
                                               String path,
                                               DiscoveryAssetType assetType,
                                               double score,
                                               String reason,
                                               Collection<String> supportingPaths,
                                               Collection<String> supportingParameters,
                                               int supportingObservationCount) {
        DiscoveryCandidate candidate = new DiscoveryCandidate();
        candidate.setHost(host);
        candidate.setPath(path);
        candidate.setUrl(host + path);
        candidate.setAssetType(assetType);
        candidate.setScore(score);
        candidate.setSourceReason(reason);
        candidate.setSupportingPaths(new ArrayList<>(new LinkedHashSet<>(supportingPaths)));
        candidate.setSupportingParameters(new ArrayList<>(new LinkedHashSet<>(supportingParameters)));
        candidate.setSupportingObservationCount(supportingObservationCount);
        candidate.setKey(assetType.name() + "|" + host + "|" + path);
        return candidate;
    }

    private void mergeCandidate(Map<String, DiscoveryCandidate> candidates, DiscoveryCandidate incoming) {
        DiscoveryCandidate existing = candidates.get(incoming.getKey());
        if (existing == null) {
            candidates.put(incoming.getKey(), incoming);
            return;
        }
        existing.setScore(Math.max(existing.getScore(), incoming.getScore()));
        existing.setSupportingObservationCount(Math.max(existing.getSupportingObservationCount(),
                incoming.getSupportingObservationCount()));
        existing.setSupportingPaths(mergeOrdered(existing.getSupportingPaths(), incoming.getSupportingPaths()));
        existing.setSupportingParameters(mergeOrdered(existing.getSupportingParameters(), incoming.getSupportingParameters()));
        if (incoming.getSourceReason() != null && !incoming.getSourceReason().isBlank()
                && (existing.getSourceReason() == null || !existing.getSourceReason().contains(incoming.getSourceReason()))) {
            String mergedReason = existing.getSourceReason() == null || existing.getSourceReason().isBlank()
                    ? incoming.getSourceReason()
                    : existing.getSourceReason() + "；" + incoming.getSourceReason();
            existing.setSourceReason(mergedReason);
        }
    }

    private List<String> mergeOrdered(List<String> first, List<String> second) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        if (first != null) {
            merged.addAll(first);
        }
        if (second != null) {
            merged.addAll(second);
        }
        return new ArrayList<>(merged);
    }

    private List<String> prioritizedMissingActions(Set<String> observed) {
        List<String> order = Arrays.asList("list", "detail", "create", "update", "delete", "export", "import", "search");
        List<String> result = new ArrayList<>();
        for (String action : order) {
            if (!observed.contains(action)) {
                result.add(action);
            }
        }
        for (String action : CRUD_ACTIONS) {
            if (!observed.contains(action) && !result.contains(action)) {
                result.add(action);
            }
        }
        return result;
    }

    private byte[] buildRawRequest(String url, String method) {
        URI uri = parseUri(url);
        if (uri == null || uri.getHost() == null) {
            return new byte[0];
        }
        String target = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) {
            target += "?" + uri.getRawQuery();
        }
        String hostHeader = uri.getAuthority();
        String request = method + " " + target + " HTTP/1.1\r\n"
                + "Host: " + hostHeader + "\r\n"
                + "User-Agent: AI-Burp-Copilot-Discovery/1.0\r\n"
                + "Accept: */*\r\n"
                + "Connection: close\r\n"
                + "\r\n";
        return request.getBytes(StandardCharsets.UTF_8);
    }

    private ParsedResponse parseResponse(byte[] responseBytes) {
        ParsedResponse parsed = new ParsedResponse();
        if (responseBytes == null || responseBytes.length == 0) {
            return parsed;
        }
        String text = new String(responseBytes, StandardCharsets.UTF_8);
        int sep = text.indexOf("\r\n\r\n");
        int headerEnd = sep >= 0 ? sep : text.indexOf("\n\n");
        String headersText = headerEnd >= 0 ? text.substring(0, headerEnd) : text;
        String[] lines = headersText.split("\r\n|\n");
        if (lines.length > 0) {
            String[] parts = lines[0].split(" ", 3);
            if (parts.length >= 2) {
                try {
                    parsed.statusCode = Integer.parseInt(parts[1]);
                } catch (NumberFormatException ignored) {
                    parsed.statusCode = -1;
                }
            }
        }
        for (int i = 1; i < lines.length; i++) {
            int idx = lines[i].indexOf(':');
            if (idx > 0) {
                parsed.headers.put(lines[i].substring(0, idx).trim().toLowerCase(Locale.ROOT),
                        lines[i].substring(idx + 1).trim());
            }
        }
        if (headerEnd >= 0) {
            int bodyOffset = text.startsWith("\r\n\r\n", headerEnd) ? headerEnd + 4 : headerEnd + 2;
            if (bodyOffset < text.length()) {
                parsed.bodyText = text.substring(bodyOffset).toLowerCase(Locale.ROOT);
            }
        } else {
            parsed.bodyText = text.toLowerCase(Locale.ROOT);
        }
        return parsed;
    }

    private String summarizeResponse(ParsedResponse parsed) {
        if (parsed == null) {
            return "No response";
        }
        String contentType = parsed.headers.getOrDefault("content-type", "");
        if (contentType != null && !contentType.isBlank()) {
            return contentType;
        }
        if (parsed.bodyText.contains("<html") || parsed.bodyText.contains("<!doctype")) {
            return "HTML body";
        }
        if (looksLikeJson(parsed.bodyText)) {
            return "JSON body";
        }
        return "body available";
    }

    private DiscoveryValidation cloneValidation(DiscoveryValidation original) {
        return original != null ? original.copy() : new DiscoveryValidation();
    }

    private boolean looksLikeJson(String bodyText) {
        String trimmed = bodyText == null ? "" : bodyText.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    private boolean looksLikeSourceMap(String bodyText) {
        String trimmed = bodyText == null ? "" : bodyText.trim();
        return trimmed.startsWith("{")
                && trimmed.contains("\"version\"")
                && (trimmed.contains("\"mappings\"") || trimmed.contains("\"sources\""));
    }

    private boolean containsAny(String text, String... values) {
        if (text == null || text.isBlank()) {
            return false;
        }
        for (String value : values) {
            if (text.contains(value)) {
                return true;
            }
        }
        return false;
    }

    private String normalizePath(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return "/";
        }
        String normalized = rawPath.trim();
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        if (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String normalizeMethod(String method) {
        if (method == null || method.isBlank()) {
            return "GET";
        }
        String normalized = method.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" -> normalized;
            default -> "GET";
        };
    }

    private String extractJson(String response) {
        if (response == null || response.isBlank()) {
            return null;
        }
        int fencedStart = response.indexOf("```json");
        if (fencedStart >= 0) {
            int contentStart = response.indexOf('\n', fencedStart);
            int fencedEnd = response.indexOf("```", contentStart + 1);
            if (contentStart >= 0 && fencedEnd > contentStart) {
                return response.substring(contentStart + 1, fencedEnd).trim();
            }
        }
        int objectStart = response.indexOf('{');
        int objectEnd = response.lastIndexOf('}');
        if (objectStart >= 0 && objectEnd > objectStart) {
            return response.substring(objectStart, objectEnd + 1).trim();
        }
        return null;
    }

    private List<String> stringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream()
                    .map(this::stringValue)
                    .filter(item -> !item.isBlank())
                    .toList();
        }
        String single = stringValue(value);
        return single.isBlank() ? List.of() : List.of(single);
    }

    private String stringValue(Object value) {
        return value != null ? String.valueOf(value).trim() : "";
    }

    private double doubleValue(Object value, double fallback) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return value != null ? Double.parseDouble(String.valueOf(value)) : fallback;
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private long siteDiscoveryWaitMs() {
        return Math.max(20000L, Timeouts.effectiveLlmWaitMs(configService));
    }

    private List<String> splitSegments(String path) {
        return Arrays.stream(path.split("/"))
                .filter(part -> part != null && !part.isBlank())
                .toList();
    }

    private String modulePrefix(String path) {
        List<String> segments = splitSegments(path);
        if (segments.isEmpty()) {
            return "/";
        }
        int end = Math.min(segments.size(), 3);
        return "/" + String.join("/", segments.subList(0, end));
    }

    private URI parseUri(String url) {
        try {
            return url == null || url.isBlank() ? null : URI.create(url);
        } catch (Exception ignored) {
            return null;
        }
    }

    private double clamp(double value) {
        return Math.max(0.0, Math.min(0.99, value));
    }

    private String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private static final class HostObservation {
        private final String host;
        private final Map<String, PathObservation> endpointPaths = new LinkedHashMap<>();
        private final Set<String> allPaths = new LinkedHashSet<>();

        private HostObservation(String host) {
            this.host = host;
        }
    }

    private static final class PathObservation {
        private final String path;
        private final Set<String> parameters = new LinkedHashSet<>();
        private final Set<String> methods = new LinkedHashSet<>();
        private final Set<String> statusCodes = new LinkedHashSet<>();
        private int observationCount;
        private boolean fromJsRecovered;

        private PathObservation(String path) {
            this.path = path;
        }
    }

    private static final class EndpointFamily {
        private final String prefix;
        private final Set<String> actions = new LinkedHashSet<>();
        private final Set<String> supportingPaths = new LinkedHashSet<>();
        private final Set<String> supportingParameters = new LinkedHashSet<>();
        private int observationCount;

        private EndpointFamily(String prefix) {
            this.prefix = prefix;
        }
    }

    private static final class ParsedResponse {
        private int statusCode = -1;
        private String bodyText = "";
        private final Map<String, String> headers = new LinkedHashMap<>();
    }

    private record ValidationAssessment(DiscoveryJudgment judgment,
                                        int finalStatusCode,
                                        String contentType,
                                        String reasoning) {
    }

    private record CachedInference(String fingerprint, List<DiscoveryCandidate> candidates) {
        private CachedInference {
            candidates = candidates != null ? List.copyOf(candidates) : List.of();
        }
    }
}
