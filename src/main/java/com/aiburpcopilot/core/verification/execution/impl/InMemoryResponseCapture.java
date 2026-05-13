package com.aiburpcopilot.core.verification.execution.impl;

import com.aiburpcopilot.core.verification.execution.ResponseCapture;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 基于内存的响应捕获实现。
 * <p>
 * 使用 ConcurrentHashMap 存储原始响应和修改后响应。
 * Phase 2 使用内存存储，后续可扩展为数据库存储。
 */
public class InMemoryResponseCapture implements ResponseCapture {

    private final ConcurrentHashMap<String, byte[]> originalResponses = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, byte[]> mutatedResponses = new ConcurrentHashMap<>();

    @Override
    public byte[] getOriginalResponse(String requestId) {
        return originalResponses.get(requestId);
    }

    @Override
    public void storeOriginalResponse(String requestId, byte[] response) {
        if (requestId != null && response != null) {
            originalResponses.put(requestId, response);
        }
    }

    @Override
    public void captureMutatedResponse(String taskId, byte[] response) {
        if (taskId != null && response != null) {
            mutatedResponses.put(taskId, response);
        }
    }

    @Override
    public byte[] getMutatedResponse(String taskId) {
        return mutatedResponses.get(taskId);
    }

    /**
     * 清理指定请求的所有响应缓存。
     */
    public void remove(String requestId) {
        originalResponses.remove(requestId);
    }

    /**
     * 清空所有缓存。
     */
    public void clear() {
        originalResponses.clear();
        mutatedResponses.clear();
    }

    /**
     * 获取缓存的原始响应数量。
     */
    public int getOriginalCount() {
        return originalResponses.size();
    }

    /**
     * 获取缓存的修改后响应数量。
     */
    public int getMutatedCount() {
        return mutatedResponses.size();
    }
}
