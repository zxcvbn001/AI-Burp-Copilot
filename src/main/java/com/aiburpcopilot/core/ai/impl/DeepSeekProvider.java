package com.aiburpcopilot.core.ai.impl;

import com.aiburpcopilot.core.config.IConfigService;

public class DeepSeekProvider extends OpenAICompatibleProvider {

    public DeepSeekProvider(IConfigService configService) {
        super(configService);
    }

    @Override
    public String getProviderName() {
        return "DeepSeek";
    }

    @Override
    protected String defaultModel() {
        return "deepseek-chat";
    }

    @Override
    protected String defaultApiUrl() {
        return "https://api.deepseek.com/v1/chat/completions";
    }
}
