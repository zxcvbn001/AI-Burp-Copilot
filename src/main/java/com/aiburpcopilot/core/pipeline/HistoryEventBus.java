package com.aiburpcopilot.core.pipeline;

import com.aiburpcopilot.core.history.HistoryEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 历史事件总线。
 * <p>
 * 当 Pipeline 完成分析并记录到历史时，通过此总线通知 UI 刷新。
 * 采用观察者模式，订阅者在 Swing EDT 线程上接收通知。
 * <p>
 * 相比轮询方式（每 2 秒刷新），事件驱动方式更高效：
 * <ul>
 *   <li>只在新数据产生时刷新</li>
 *   <li>避免无数据时空刷新浪费资源</li>
 *   <li>不干扰用户选中状态</li>
 * </ul>
 * <p>
 * 线程模型：
 * <ul>
 *   <li>fireXxx() 方法可从任何线程调用</li>
 *   <li>监听器回调保证在 Swing EDT 线程执行</li>
 * </ul>
 */
public class HistoryEventBus {

    private static final Logger log = LoggerFactory.getLogger(HistoryEventBus.class);

    /**
     * 历史更新监听器接口。
     */
    public interface Listener {
        /** 新的分析结果已添加到历史记录 */
        void onHistoryAdded(HistoryEntry entry);

        /** 历史记录被清空 */
        void onHistoryCleared();

        /** 通用刷新（用于批量操作后） */
        void onRefreshNeeded();
    }

    private static final HistoryEventBus INSTANCE = new HistoryEventBus();

    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    private HistoryEventBus() {}

    public static HistoryEventBus getInstance() {
        return INSTANCE;
    }

    /**
     * 订阅事件。
     */
    public void subscribe(Listener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
            log.debug("Listener registered: {}", listener.getClass().getSimpleName());
        }
    }

    /**
     * 取消订阅。
     */
    public void unsubscribe(Listener listener) {
        listeners.remove(listener);
    }

    /**
     * 触发历史添加事件。
     * 从 Pipeline 线程调用，将回调分发到 EDT。
     */
    public void fireHistoryAdded(HistoryEntry entry) {
        if (SwingUtilities.isEventDispatchThread()) {
            notifyHistoryAdded(entry);
        } else {
            SwingUtilities.invokeLater(() -> notifyHistoryAdded(entry));
        }
    }

    /**
     * 触发清空事件。
     */
    public void fireHistoryCleared() {
        if (SwingUtilities.isEventDispatchThread()) {
            notifyHistoryCleared();
        } else {
            SwingUtilities.invokeLater(this::notifyHistoryCleared);
        }
    }

    /**
     * 触发通用刷新事件。
     */
    public void fireRefreshNeeded() {
        if (SwingUtilities.isEventDispatchThread()) {
            notifyRefreshNeeded();
        } else {
            SwingUtilities.invokeLater(this::notifyRefreshNeeded);
        }
    }

    // ---------- Private ----------

    private void notifyHistoryAdded(HistoryEntry entry) {
        for (Listener listener : listeners) {
            try {
                listener.onHistoryAdded(entry);
            } catch (Exception e) {
                log.warn("Listener error on history added: {}", e.getMessage());
            }
        }
    }

    private void notifyHistoryCleared() {
        for (Listener listener : listeners) {
            try {
                listener.onHistoryCleared();
            } catch (Exception e) {
                log.warn("Listener error on history cleared: {}", e.getMessage());
            }
        }
    }

    private void notifyRefreshNeeded() {
        for (Listener listener : listeners) {
            try {
                listener.onRefreshNeeded();
            } catch (Exception e) {
                log.warn("Listener error on refresh: {}", e.getMessage());
            }
        }
    }
}
