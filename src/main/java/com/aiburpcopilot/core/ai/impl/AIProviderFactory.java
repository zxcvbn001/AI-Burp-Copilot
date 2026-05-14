package com.aiburpcopilot.core.ai.impl;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.config.IConfigService;

public final class AIProviderFactory {

    private AIProviderFactory() {
    }

    public static IAIProvider create(IConfigService configService) {
        return new DynamicAIProvider(configService);
    }

    public static IAIProvider createConcrete(IConfigService configService) {
        String provider = configService.getConfig().getLlm().getProvider();
        String normalized = provider != null ? provider.trim().toLowerCase() : "";
        return switch (normalized) {
            case "qwen", "dashscope", "aliyun", "alibaba" -> new QwenProvider(configService);
            case "openai", "openai-compatible", "custom" -> new OpenAIProvider(configService);
            case "deepseek", "" -> new DeepSeekProvider(configService);
            default -> new DeepSeekProvider(configService);
        };
    }
}
