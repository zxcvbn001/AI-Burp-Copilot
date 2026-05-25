package com.aiburpcopilot.utils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class PluginLogger {

    public enum Level {
        DEBUG, INFO, WARN, ERROR
    }

    public enum Category {
        SYSTEM,
        LLM,
        VERIFICATION
    }

    public enum EntryKind {
        TEXT,
        LLM_REQUEST,
        LLM_RESPONSE
    }

    public interface Listener {
        void onLogsChanged(Category category);
    }

    public record LogEntry(
            Instant timestamp,
            Level level,
            Category category,
            EntryKind kind,
            String source,
            String title,
            String message
    ) {
        public String formatTimestamp() {
            return DateTimeFormatter.ofPattern("HH:mm:ss")
                    .withZone(ZoneId.systemDefault())
                    .format(timestamp);
        }
    }

    private static final PluginLogger INSTANCE = new PluginLogger();
    private static final int DEFAULT_MAX_ENTRIES = 3000;

    public static PluginLogger getInstance() {
        return INSTANCE;
    }

    private final LogEntry[] buffer;
    private final int maxEntries;
    private int writeIndex = 0;
    private int size = 0;
    private boolean overflow = false;
    private long version = 0;
    private final long[] categoryVersions = new long[Category.values().length];
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    private PluginLogger() {
        this.maxEntries = DEFAULT_MAX_ENTRIES;
        this.buffer = new LogEntry[maxEntries];
    }

    public void debug(String source, String message) {
        append(Level.DEBUG, detectCategory(source), source, message);
    }

    public void info(String source, String message) {
        append(Level.INFO, detectCategory(source), source, message);
    }

    public void warn(String source, String message) {
        append(Level.WARN, detectCategory(source), source, message);
    }

    public void error(String source, String message) {
        append(Level.ERROR, detectCategory(source), source, message);
    }

    public void error(String source, String message, Throwable t) {
        String suffix = t == null ? "" : " - " + t.getClass().getSimpleName() + ": " + t.getMessage();
        append(Level.ERROR, detectCategory(source), source, message + suffix);
    }

    public void debug(Category category, String source, String message) {
        append(Level.DEBUG, category, source, message);
    }

    public void info(Category category, String source, String message) {
        append(Level.INFO, category, source, message);
    }

    public void warn(Category category, String source, String message) {
        append(Level.WARN, category, source, message);
    }

    public void error(Category category, String source, String message) {
        append(Level.ERROR, category, source, message);
    }

    public void error(Category category, String source, String message, Throwable t) {
        String suffix = t == null ? "" : " - " + t.getClass().getSimpleName() + ": " + t.getMessage();
        append(Level.ERROR, category, source, message + suffix);
    }

    public List<LogEntry> getEntries() {
        return getEntries(EnumSet.allOf(Level.class), null);
    }

    public List<LogEntry> getEntries(Set<Level> levelFilter) {
        return getEntries(levelFilter, null);
    }

    public List<LogEntry> getEntries(Set<Level> levelFilter, Category categoryFilter) {
        lock.readLock().lock();
        try {
            List<LogEntry> result = new ArrayList<>(size);
            if (overflow) {
                for (int i = 0; i < size; i++) {
                    int idx = (writeIndex + i) % maxEntries;
                    appendIfMatch(result, buffer[idx], levelFilter, categoryFilter);
                }
            } else {
                for (int i = 0; i < size; i++) {
                    appendIfMatch(result, buffer[i], levelFilter, categoryFilter);
                }
            }
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<LogEntry> getRecentEntries(int count) {
        return getRecentEntries(count, null);
    }

    public List<LogEntry> getRecentEntries(int count, Category categoryFilter) {
        lock.readLock().lock();
        try {
            List<LogEntry> result = new ArrayList<>();
            int actualCount = Math.min(count, size);
            for (int i = size - actualCount; i < size; i++) {
                int idx = overflow ? (writeIndex + i) % maxEntries : i;
                LogEntry entry = buffer[idx];
                if (entry != null && (categoryFilter == null || entry.category() == categoryFilter)) {
                    result.add(entry);
                }
            }
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void clear() {
        clear(null);
    }

    public void clear(Category category) {
        Category changedCategory = category;
        lock.writeLock().lock();
        try {
            if (category == null) {
                writeIndex = 0;
                size = 0;
                overflow = false;
                for (int i = 0; i < maxEntries; i++) {
                    buffer[i] = null;
                }
                version++;
                for (int i = 0; i < categoryVersions.length; i++) {
                    categoryVersions[i]++;
                }
            } else {
                List<LogEntry> kept = new ArrayList<>();
                if (overflow) {
                    for (int i = 0; i < size; i++) {
                        LogEntry entry = buffer[(writeIndex + i) % maxEntries];
                        if (entry != null && entry.category() != category) {
                            kept.add(entry);
                        }
                    }
                } else {
                    for (int i = 0; i < size; i++) {
                        LogEntry entry = buffer[i];
                        if (entry != null && entry.category() != category) {
                            kept.add(entry);
                        }
                    }
                }
                writeIndex = 0;
                size = 0;
                overflow = false;
                for (int i = 0; i < maxEntries; i++) {
                    buffer[i] = null;
                }
                for (LogEntry entry : kept) {
                    appendUnsafe(entry, false);
                }
                version++;
                categoryVersions[category.ordinal()]++;
            }
        } finally {
            lock.writeLock().unlock();
        }
        notifyListeners(changedCategory);
    }

    public void addListener(Listener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(Listener listener) {
        listeners.remove(listener);
    }

    public long getVersion(Category category) {
        lock.readLock().lock();
        try {
            if (category == null) {
                return version;
            }
            return categoryVersions[category.ordinal()];
        } finally {
            lock.readLock().unlock();
        }
    }

    public int getSize() {
        return getSize(null);
    }

    public int getSize(Category category) {
        lock.readLock().lock();
        try {
            if (category == null) {
                return size;
            }
            int count = 0;
            if (overflow) {
                for (int i = 0; i < size; i++) {
                    int idx = (writeIndex + i) % maxEntries;
                    if (buffer[idx] != null && buffer[idx].category() == category) {
                        count++;
                    }
                }
            } else {
                for (int i = 0; i < size; i++) {
                    if (buffer[i] != null && buffer[i].category() == category) {
                        count++;
                    }
                }
            }
            return count;
        } finally {
            lock.readLock().unlock();
        }
    }

    public Category detectCategory(String source) {
        String normalized = source == null ? "" : source.trim().toUpperCase(Locale.ROOT);
        if (normalized.isBlank()) {
            return Category.SYSTEM;
        }
        if (normalized.equals("AI")
                || normalized.equals("CANDIDATE")
                || normalized.equals("DIFF")
                || normalized.contains("LLM")) {
            return Category.LLM;
        }
        if (normalized.equals("VERIFICATION")
                || normalized.equals("WORKFLOWENGINE")
                || normalized.equals("WORKFLOWSTEPFACTORY")
                || normalized.equals("WORKFLOWREGISTRY")
                || normalized.equals("WORKFLOWVERIFICATION")
                || normalized.equals("REPLAY")
                || normalized.equals("INFLUENCEVALIDATION")
                || normalized.equals("SAFETY")
                || normalized.endsWith("PROBES")) {
            return Category.VERIFICATION;
        }
        return Category.SYSTEM;
    }

    private void append(Level level, Category category, String source, String message) {
        Category actualCategory = category != null ? category : Category.SYSTEM;
        lock.writeLock().lock();
        try {
            appendUnsafe(new LogEntry(Instant.now(), level,
                    actualCategory,
                    EntryKind.TEXT, source, null, message));
        } finally {
            lock.writeLock().unlock();
        }
        notifyListeners(actualCategory);
    }

    public void llmRequest(String source, String title, String message) {
        appendStructured(Level.DEBUG, Category.LLM, EntryKind.LLM_REQUEST, source, title, message);
    }

    public void llmResponse(String source, String title, String message) {
        appendStructured(Level.DEBUG, Category.LLM, EntryKind.LLM_RESPONSE, source, title, message);
    }

    private void appendStructured(Level level, Category category, EntryKind kind,
                                  String source, String title, String message) {
        Category actualCategory = category != null ? category : Category.SYSTEM;
        lock.writeLock().lock();
        try {
            appendUnsafe(new LogEntry(Instant.now(), level, actualCategory, kind, source, title, message));
        } finally {
            lock.writeLock().unlock();
        }
        notifyListeners(actualCategory);
    }

    private void notifyListeners(Category category) {
        for (Listener listener : listeners) {
            try {
                listener.onLogsChanged(category);
            } catch (Exception ignored) {
            }
        }
    }

    private void appendUnsafe(LogEntry entry) {
        appendUnsafe(entry, true);
    }

    private void appendUnsafe(LogEntry entry, boolean bumpVersion) {
        buffer[writeIndex] = entry;
        writeIndex = (writeIndex + 1) % maxEntries;
        if (size < maxEntries) {
            size++;
        } else {
            overflow = true;
        }
        if (bumpVersion) {
            version++;
            if (entry != null && entry.category() != null) {
                categoryVersions[entry.category().ordinal()]++;
            }
        }
    }

    private void appendIfMatch(List<LogEntry> result,
                               LogEntry entry,
                               Set<Level> levelFilter,
                               Category categoryFilter) {
        if (entry == null) {
            return;
        }
        if (levelFilter != null && !levelFilter.contains(entry.level())) {
            return;
        }
        if (categoryFilter != null && entry.category() != categoryFilter) {
            return;
        }
        result.add(entry);
    }
}
