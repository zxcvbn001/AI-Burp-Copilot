package com.aiburpcopilot.core.verification.rate_limit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

/**
 * Host 级限流器。
 * <p>
 * 基于 ConcurrentHashMap + Semaphore 实现按 Host 的并发控制。
 * 每个 Host 最多允许指定数量的并发验证请求。
 */
public class HostRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(HostRateLimiter.class);

    /** Host → 并发控制信号量 */
    private final ConcurrentHashMap<String, Semaphore> hostSemaphores = new ConcurrentHashMap<>();

    /** 每个 Host 的最大并发数 */
    private final int maxConcurrentPerHost;

    /**
     * @param maxConcurrentPerHost 每个 Host 的最大并发验证请求数
     */
    public HostRateLimiter(int maxConcurrentPerHost) {
        this.maxConcurrentPerHost = Math.max(1, maxConcurrentPerHost);
    }

    /**
     * 获取指定 Host 的执行许可（阻塞直到有可用许可）。
     *
     * @param hostUrl 目标 URL
     * @throws InterruptedException 如果线程被中断
     */
    public void acquire(String hostUrl) throws InterruptedException {
        String host = extractHost(hostUrl);
        Semaphore semaphore = hostSemaphores.computeIfAbsent(
                host, h -> new Semaphore(maxConcurrentPerHost, true));
        semaphore.acquire();
        log.debug("Rate limiter acquired for host: {} (permits: {})",
                host, semaphore.availablePermits());
    }

    /**
     * 释放指定 Host 的执行许可。
     *
     * @param hostUrl 目标 URL
     */
    public void release(String hostUrl) {
        String host = extractHost(hostUrl);
        Semaphore semaphore = hostSemaphores.get(host);
        if (semaphore != null) {
            semaphore.release();
            log.debug("Rate limiter released for host: {} (permits: {})",
                    host, semaphore.availablePermits());
        }
    }

    /**
     * 尝试获取许可（非阻塞）。
     *
     * @param hostUrl 目标 URL
     * @return true 如果成功获取
     */
    public boolean tryAcquire(String hostUrl) {
        String host = extractHost(hostUrl);
        Semaphore semaphore = hostSemaphores.computeIfAbsent(
                host, h -> new Semaphore(maxConcurrentPerHost, true));
        boolean acquired = semaphore.tryAcquire();
        if (!acquired) {
            log.debug("Rate limiter busy for host: {}", host);
        }
        return acquired;
    }

    /**
     * 清理长期无活动的 Host 条目（可周期性调用）。
     */
    public void cleanup() {
        hostSemaphores.entrySet().removeIf(entry -> {
            Semaphore s = entry.getValue();
            // 如果所有许可都可用（无等待线程），移除条目
            if (s.availablePermits() == maxConcurrentPerHost) {
                log.debug("Rate limiter cleanup: removing idle host '{}'", entry.getKey());
                return true;
            }
            return false;
        });
    }

    /**
     * 获取当前跟踪的 Host 数量。
     */
    public int getTrackedHostCount() {
        return hostSemaphores.size();
    }

    // ---------- Private ----------

    private String extractHost(String url) {
        try {
            return new URL(url).getHost().toLowerCase();
        } catch (Exception e) {
            // 无法解析的 URL，使用原始字符串
            return url != null ? url.toLowerCase() : "unknown";
        }
    }
}
