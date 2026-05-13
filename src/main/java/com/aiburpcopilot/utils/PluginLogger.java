package com.aiburpcopilot.utils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * 插件运行时诊断日志（内存环形缓冲区）。
 * <p>
 * 为 UI Debug 面板提供结构化日志记录，与 SLF4J 互补：
 * <ul>
 *   <li>SLF4J → 控制台 / 文件（供开发者排查）</li>
 *   <li>PluginLogger → UI 面板（供用户实时诊断）</li>
 * </ul>
 * <p>
 * 线程安全：使用 ReadWriteLock，读取不阻塞写入。
 * <p>
 * 环形缓冲区：超过最大条目数时自动丢弃最旧记录。
 */
public class PluginLogger {

    public enum Level {
        DEBUG, INFO, WARN, ERROR
    }

    /**
     * 单条日志记录。
     */
    public record LogEntry(
            Instant timestamp,
            Level level,
            String source,
            String message
    ) {
        public String formatTimestamp() {
            return DateTimeFormatter.ofPattern("HH:mm:ss")
                    .withZone(ZoneId.systemDefault())
                    .format(timestamp);
        }
    }

    // ========== Singleton ==========

    private static final PluginLogger INSTANCE = new PluginLogger();

    public static PluginLogger getInstance() {
        return INSTANCE;
    }

    // ========== 配置 ==========

    private static final int DEFAULT_MAX_ENTRIES = 2000;

    // ========== 存储 ==========

    private final LogEntry[] buffer;
    private final int maxEntries;
    private int writeIndex = 0;
    private int size = 0;
    private boolean overflow = false;

    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    private PluginLogger() {
        this.maxEntries = DEFAULT_MAX_ENTRIES;
        this.buffer = new LogEntry[maxEntries];
    }

    // ========== 日志写入 ==========

    public void debug(String source, String message) {
        append(new LogEntry(Instant.now(), Level.DEBUG, source, message));
    }

    public void info(String source, String message) {
        append(new LogEntry(Instant.now(), Level.INFO, source, message));
    }

    public void warn(String source, String message) {
        append(new LogEntry(Instant.now(), Level.WARN, source, message));
    }

    public void error(String source, String message) {
        append(new LogEntry(Instant.now(), Level.ERROR, source, message));
    }

    public void error(String source, String message, Throwable t) {
        String msg = message + " - " + t.getClass().getSimpleName() + ": " + t.getMessage();
        append(new LogEntry(Instant.now(), Level.ERROR, source, msg));
    }

    // ========== 读取 ==========

    /**
     * 返回所有日志条目（倒序：最新在前）。
     */
    public List<LogEntry> getEntries() {
        return getEntries(EnumSet.allOf(Level.class));
    }

    /**
     * 返回指定级别的日志条目（倒序：最新在前）。
     */
    public List<LogEntry> getEntries(Set<Level> levelFilter) {
        lock.readLock().lock();
        try {
            List<LogEntry> result = new ArrayList<>(size);
            if (overflow) {
                // 环形缓冲区已满，从 writeIndex 开始读取
                for (int i = 0; i < size; i++) {
                    int idx = (writeIndex + i) % maxEntries;
                    LogEntry entry = buffer[idx];
                    if (entry != null && levelFilter.contains(entry.level())) {
                        result.add(entry);
                    }
                }
            } else {
                for (int i = 0; i < size; i++) {
                    LogEntry entry = buffer[i];
                    if (entry != null && levelFilter.contains(entry.level())) {
                        result.add(entry);
                    }
                }
            }
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 返回最新 N 条日志。
     */
    public List<LogEntry> getRecentEntries(int count) {
        lock.readLock().lock();
        try {
            List<LogEntry> result = new ArrayList<>();
            int actualCount = Math.min(count, size);
            for (int i = size - actualCount; i < size; i++) {
                int idx;
                if (overflow) {
                    idx = (writeIndex + i) % maxEntries;
                } else {
                    idx = i;
                }
                if (buffer[idx] != null) {
                    result.add(buffer[idx]);
                }
            }
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 清除所有日志。
     */
    public void clear() {
        lock.writeLock().lock();
        try {
            writeIndex = 0;
            size = 0;
            overflow = false;
            for (int i = 0; i < maxEntries; i++) {
                buffer[i] = null;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public int getSize() {
        lock.readLock().lock();
        try {
            return size;
        } finally {
            lock.readLock().unlock();
        }
    }

    // ========== Private ==========

    private void append(LogEntry entry) {
        lock.writeLock().lock();
        try {
            buffer[writeIndex] = entry;
            writeIndex = (writeIndex + 1) % maxEntries;
            if (size < maxEntries) {
                size++;
            } else {
                overflow = true;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
}
