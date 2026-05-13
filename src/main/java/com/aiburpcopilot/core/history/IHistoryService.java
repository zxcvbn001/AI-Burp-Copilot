package com.aiburpcopilot.core.history;

import com.aiburpcopilot.core.context.AnalysisStatus;
import com.aiburpcopilot.core.context.EndpointType;
import com.aiburpcopilot.core.context.RiskLevel;

import java.util.List;

/**
 * 历史记录服务接口。
 * <p>
 * 记录每次 HTTP 分析的结果，支持搜索、过滤和清空。
 * Phase 1 实现 InMemoryHistoryService。
 * Phase 2 可扩展数据库持久化。
 */
public interface IHistoryService {

    /**
     * 添加一条历史记录。
     *
     * @param entry 历史记录条目
     */
    void add(HistoryEntry entry);

    void update(HistoryEntry entry);

    /**
     * 获取所有历史记录。
     *
     * @return 历史记录列表（按时间倒序）
     */
    List<HistoryEntry> getAll();

    /**
     * 根据条件搜索历史记录。
     *
     * @param keyword   搜索关键词（匹配 URL、路径等）
     * @param endpointType 过滤端点类型（null 表示不限制）
     * @param riskLevel    过滤风险等级（null 表示不限制）
     * @param status       过滤分析状态（null 表示不限制）
     * @param offset    分页偏移
     * @param limit     每页数量
     * @return 符合条件的记录列表
     */
    List<HistoryEntry> search(String keyword,
                              EndpointType endpointType,
                              RiskLevel riskLevel,
                              AnalysisStatus status,
                              int offset,
                              int limit);

    /**
     * 根据请求 ID 获取单条记录。
     *
     * @param requestId 请求 ID
     * @return 历史记录（可能为 null）
     */
    HistoryEntry getById(String requestId);

    /**
     * 清空所有历史记录。
     */
    void clear();

    /**
     * 获取历史记录总数。
     *
     * @return 总数
     */
    int size();

    /**
     * 获取符合条件的记录数量。
     *
     * @param keyword   搜索关键词
     * @param endpointType 过滤端点类型
     * @param riskLevel    过滤风险等级
     * @param status       过滤分析状态
     * @return 符合条件的记录数量
     */
    int count(String keyword,
              EndpointType endpointType,
              RiskLevel riskLevel,
              AnalysisStatus status);
}
