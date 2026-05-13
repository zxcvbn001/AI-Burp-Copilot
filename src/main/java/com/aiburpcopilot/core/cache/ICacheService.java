package com.aiburpcopilot.core.cache;

import java.util.Optional;

/**
 * 缓存服务接口。
 * <p>
 * 用于缓存 AI 分析结果，避免对相同请求重复调用 LLM，降低 Token 消耗。
 * <p>
 * Phase 1 实现内存缓存（MemoryCacheService）。
 * Phase 2 可扩展磁盘缓存（DiskCacheService）。
 * <p>
 * 缓存 Key 生成规则：METHOD + PATH + 参数名哈希（由 HTTPContext.generateCacheKey() 提供）
 */
public interface ICacheService {

    /**
     * 从缓存中获取数据。
     *
     * @param key 缓存 Key
     * @return Optional 包含缓存值，或空 Optional
     */
    Optional<String> get(String key);

    /**
     * 将数据放入缓存。
     *
     * @param key   缓存 Key
     * @param value 缓存值
     */
    void put(String key, String value);

    /**
     * 将数据放入缓存并指定 TTL（秒）。
     *
     * @param key   缓存 Key
     * @param value 缓存值
     * @param ttlSeconds 过期时间（秒）
     */
    void put(String key, String value, long ttlSeconds);

    /**
     * 判断缓存中是否包含指定 Key。
     *
     * @param key 缓存 Key
     * @return true 如果存在且未过期
     */
    boolean contains(String key);

    /**
     * 从缓存中移除指定 Key。
     *
     * @param key 缓存 Key
     */
    void remove(String key);

    /**
     * 清空所有缓存。
     */
    void clear();

    /**
     * 获取当前缓存条目数。
     *
     * @return 缓存条目数量
     */
    int size();

    /**
     * 获取缓存 Key 对应的唯一标识。
     * 用于统一生成缓存 Key。
     *
     * @param method HTTP 方法
     * @param path   URL 路径
     * @param paramSchemaHash 参数模式哈希
     * @return 缓存 Key 字符串
     */
    static String buildKey(String method, String path, String paramSchemaHash) {
        return method + "|" + path + "|" + paramSchemaHash;
    }
}
