package com.aiburpcopilot.core.ai.impl;

import com.aiburpcopilot.core.ai.IAIProvider;
import com.aiburpcopilot.core.config.IConfigService;
import com.aiburpcopilot.core.context.HTTPContext;

import java.util.concurrent.CompletableFuture;

public class DynamicAIProvider implements IAIProvider {

    private final IConfigService configService;

    public DynamicAIProvider(IConfigService configService) {
        this.configService = configService;
    }

    @Override
    public String getProviderName() {
        return delegate().getProviderName();
    }

    @Override
    public CompletableFuture<String> analyzeAttackSurface(HTTPContext context, String systemPrompt, String userPrompt) {
        return delegate().analyzeAttackSurface(context, systemPrompt, userPrompt);
    }

    @Override
    public CompletableFuture<String> classifyEndpoint(String aiSummary, String classifierPrompt) {
        return delegate().classifyEndpoint(aiSummary, classifierPrompt);
    }

    @Override
    public CompletableFuture<String> reviewStaticResource(String content, String reviewPrompt) {
        return delegate().reviewStaticResource(content, reviewPrompt);
    }

    @Override
    public CompletableFuture<String> analyzeDiff(String diffPrompt) {
        return delegate().analyzeDiff(diffPrompt);
    }

    @Override
    public boolean isAvailable() {
        return delegate().isAvailable();
    }

    private IAIProvider delegate() {
        return AIProviderFactory.createConcrete(configService);
    }
}
