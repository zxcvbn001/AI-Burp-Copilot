package com.aiburpcopilot.core.ai.impl;

import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.config.AppConfig;

public class QwenProvider extends OpenAICompatibleProvider {

    public QwenProvider(IConfigService configService) {
        super(configService);
    }

    @Override
    public String getProviderName() {
        return "Qwen";
    }

    @Override
    protected String defaultModel() {
        return "qwen-plus";
    }

    @Override
    protected String defaultApiUrl() {
        return "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions";
    }

    @Override
    protected boolean omitOptionalRequestFieldsForCustomEndpoint(AppConfig.LLMConfig llmConfig) {
        String apiUrl = llmConfig.getApiUrl();
        return apiUrl != null
                && !apiUrl.isBlank()
                && !apiUrl.equals(defaultApiUrl());
    }
}
