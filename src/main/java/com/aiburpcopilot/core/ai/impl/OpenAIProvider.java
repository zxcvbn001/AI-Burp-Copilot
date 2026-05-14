package com.aiburpcopilot.core.ai.impl;

import com.aiburpcopilot.core.config.IConfigService;

public class OpenAIProvider extends OpenAICompatibleProvider {

    public OpenAIProvider(IConfigService configService) {
        super(configService);
    }

    @Override
    public String getProviderName() {
        return "OpenAI";
    }

    @Override
    protected String defaultModel() {
        return "gpt-4o-mini";
    }

    @Override
    protected String defaultApiUrl() {
        return "https://api.openai.com/v1/chat/completions";
    }
}
