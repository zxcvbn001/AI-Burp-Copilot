package com.aiburpcopilot.core.cache.impl;

import com.aiburpcopilot.core.cache.ICacheService;
import com.aiburpcopilot.utils.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存缓存服务实现。
 * <p>
 * 基于 ConcurrentHashMap，支持 TTL 过期和最大条目限制。
 * Phase 1 使用内存缓存，Phase 2 可扩展磁盘缓存。
 * <p>
 * 线程安全，适合在多线程 Burp 环境中使用。
 */
public class MemoryCacheService implements ICacheService {

    private static final Logger log = LoggerFactory.getLogger(MemoryCacheService.class);

    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final int maxEntries;
    private final long defaultTtlMs;

    public MemoryCacheService() {
        this(Constants.CACHE_MAX_ENTRIES, Constants.CACHE_DEFAULT_TTL_SECONDS * 1000L);
    }

    public MemoryCacheService(int maxEntries, long defaultTtlMs) {
        this.maxEntries = maxEntries;
        this.defaultTtlMs = defaultTtlMs;
    }

    @Override
    public Optional<String> get(String key) {
        CacheEntry entry = cache.get(key);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.isExpired()) {
            cache.remove(key);
            log.debug("Cache entry expired: {}", key);
            return Optional.empty();
        }
        entry.updateLastAccess();
        return Optional.of(entry.value);
    }

    @Override
    public void put(String key, String value) {
        put(key, value, defaultTtlMs / 1000);
    }

    @Override
    public void put(String key, String value, long ttlSeconds) {
        // 如果缓存已满，执行清理
        if (cache.size() >= maxEntries && !cache.containsKey(key)) {
            evictOldest();
        }
        cache.put(key, new CacheEntry(value, ttlSeconds * 1000));
        log.debug("Cache put: {}", key);
    }

    @Override
    public boolean contains(String key) {
        CacheEntry entry = cache.get(key);
        if (entry == null) return false;
        if (entry.isExpired()) {
            cache.remove(key);
            return false;
        }
        return true;
    }

    @Override
    public void remove(String key) {
        cache.remove(key);
    }

    @Override
    public void clear() {
        cache.clear();
        log.info("Cache cleared");
    }

    @Override
    public int size() {
        // 清理过期条目
        cache.entrySet().removeIf(e -> e.getValue().isExpired());
        return cache.size();
    }

    // ---------- Private ----------

    /**
     * 移除最久未访问的条目（LRU 近似）。
     */
    private void evictOldest() {
        cache.entrySet()
                .stream()
                .min((a, b) -> Long.compare(a.getValue().lastAccess, b.getValue().lastAccess))
                .ifPresent(entry -> {
                    cache.remove(entry.getKey());
                    log.debug("Evicted oldest cache entry: {}", entry.getKey());
                });
    }

    /**
     * 缓存条目（内部类）。
     */
    private static class CacheEntry {
        final String value;
        final long expiryTime;
        volatile long lastAccess;

        CacheEntry(String value, long ttlMs) {
            this.value = value;
            this.expiryTime = System.currentTimeMillis() + ttlMs;
            this.lastAccess = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }

        void updateLastAccess() {
            this.lastAccess = System.currentTimeMillis();
        }
    }
}
