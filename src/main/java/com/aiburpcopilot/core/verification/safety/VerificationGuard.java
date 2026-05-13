package com.aiburpcopilot.core.verification.safety;

import com.aiburpcopilot.core.config.AppConfig;
import com.aiburpcopilot.core.context.EndpointActionClassifier;
import com.aiburpcopilot.core.context.EndpointActionType;
import com.aiburpcopilot.core.context.HTTPContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.List;

/**
 * 验证安全守卫。
 * <p>
 * 负责验证模式开关控制、Host 白名单检查、
 * 请求数量限制等安全策略。
 */
public class VerificationGuard {

    private static final Logger log = LoggerFactory.getLogger(VerificationGuard.class);

    private volatile AppConfig.VerificationConfig config;

    public VerificationGuard(AppConfig.VerificationConfig config) {
        this.config = config;
    }

    public void updateConfig(AppConfig.VerificationConfig config) {
        this.config = config;
    }

    /**
     * 检查验证功能是否启用。
     */
    public boolean isVerificationEnabled() {
        return config != null && config.isEnabled();
    }

    /**
     * 检查目标 Host 是否在白名单中。
     * 如果白名单为空，则允许所有 Host。
     *
     * @param url 目标 URL
     * @return true 如果允许
     */
    public boolean isHostAllowed(String url) {
        List<String> whitelist = config.getWhitelist();
        if (whitelist == null || whitelist.isEmpty()) {
            return true;
        }

        try {
            String host = new URL(url).getHost();
            for (String allowed : whitelist) {
                if (host.equalsIgnoreCase(allowed.trim()) || host.endsWith("." + allowed.trim())) {
                    return true;
                }
            }
            log.warn("Host '{}' not in verification whitelist", host);
            return false;
        } catch (Exception e) {
            log.warn("Failed to parse URL for host check: {}", url, e);
            return false;
        }
    }

    public List<String> getWhitelist() {
        return config != null && config.getWhitelist() != null
                ? List.copyOf(config.getWhitelist())
                : List.of();
    }

    /**
     * 获取每个端点最大验证请求数。
     */
    public int getMaxRequestsPerEndpoint() {
        return config != null ? config.getMaxRequestsPerEndpoint() : 5;
    }

    /**
     * 获取最大 payload 长度。
     */
    public int getMaxPayloadLength() {
        return config != null ? config.getMaxPayloadLength() : 128;
    }

    /**
     * 获取请求超时秒数。
     */
    public int getRequestTimeoutSeconds() {
        return config != null ? config.getRequestTimeoutSeconds() : 5;
    }

    public boolean isInfluenceActionAllowed(HTTPContext context) {
        return isActionAllowed(context, config != null ? config.getAllowedInfluenceActions() : List.of("READ"));
    }

    public boolean isVerificationActionAllowed(HTTPContext context) {
        return isActionAllowed(context, config != null ? config.getAllowedVerificationActions() : List.of("READ"));
    }

    public String describeActionPolicy(HTTPContext context, boolean influence) {
        EndpointActionType actionType = resolveActionType(context);
        List<String> allowed = influence
                ? (config != null ? config.getAllowedInfluenceActions() : List.of("READ"))
                : (config != null ? config.getAllowedVerificationActions() : List.of("READ"));
        return "endpointAction=" + actionType + ", allowed=" + allowed;
    }

    /**
     * 检查是否应该跳过该端点的验证。
     *
     * @param context            HTTP 上下文
     * @param requestCountSoFar  已发送的验证请求数
     * @return true 如果应该跳过
     */
    public boolean shouldSkipEndpoint(HTTPContext context, int requestCountSoFar) {
        if (!isVerificationEnabled()) return true;
        if (!isHostAllowed(context.getUrl())) return true;
        if (requestCountSoFar >= getMaxRequestsPerEndpoint()) {
            log.debug("Max requests ({}) reached for endpoint: {}", getMaxRequestsPerEndpoint(), context.getPath());
            return true;
        }
        return false;
    }

    private boolean isActionAllowed(HTTPContext context, List<String> allowedActions) {
        if (allowedActions == null || allowedActions.isEmpty()) {
            return false;
        }
        EndpointActionType actionType = resolveActionType(context);
        for (String allowed : allowedActions) {
            if ("ALL".equalsIgnoreCase(allowed)
                    || actionType.name().equalsIgnoreCase(String.valueOf(allowed).trim())) {
                return true;
            }
        }
        return false;
    }

    private EndpointActionType resolveActionType(HTTPContext context) {
        if (context == null) {
            return EndpointActionType.UNKNOWN;
        }
        EndpointActionType actionType = context.getEndpointActionType();
        if (actionType == null || actionType == EndpointActionType.UNKNOWN) {
            actionType = EndpointActionClassifier.classifyByHttp(context);
            context.setEndpointActionType(actionType);
        }
        return actionType;
    }
}
