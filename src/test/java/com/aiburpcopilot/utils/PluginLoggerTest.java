package com.aiburpcopilot.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.concurrent.atomic.AtomicInteger;

class PluginLoggerTest {

    @Test
    void categoryVersionShouldAdvanceAfterClearAndNewLog() {
        PluginLogger logger = PluginLogger.getInstance();
        logger.clear();
        AtomicInteger llmEvents = new AtomicInteger();
        PluginLogger.Listener listener = category -> {
            if (category == PluginLogger.Category.LLM) {
                llmEvents.incrementAndGet();
            }
        };
        logger.addListener(listener);

        try {
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
            assertTrue(llmEvents.get() >= 3);
        } finally {
            logger.removeListener(listener);
        }
    }
}
