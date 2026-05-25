package com.aiburpcopilot.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PluginLoggerTest {

    @Test
    void categoryVersionShouldAdvanceAfterClearAndNewLog() {
        PluginLogger logger = PluginLogger.getInstance();
        logger.clear();

        logger.llmRequest("AI", "request", "prompt");
        long beforeClear = logger.getVersion(PluginLogger.Category.LLM);
        assertEquals(1, logger.getSize(PluginLogger.Category.LLM));

        logger.clear(PluginLogger.Category.LLM);
        long afterClear = logger.getVersion(PluginLogger.Category.LLM);
        assertEquals(0, logger.getSize(PluginLogger.Category.LLM));
        assertTrue(afterClear > beforeClear);

        logger.llmResponse("AI", "response", "answer");
        long afterAppend = logger.getVersion(PluginLogger.Category.LLM);
        assertEquals(1, logger.getSize(PluginLogger.Category.LLM));
        assertTrue(afterAppend > afterClear);
    }
}
