package com.aiburpcopilot.core.context;

/**
 * 分析状态枚举。
 * <p>
 * 标识 HTTPContext 或 HistoryEntry 的分析处理进度。
 * 用于 UI 展示分析进度和状态过滤。
 */
public enum AnalysisStatus {

    /** 等待分析（刚采集到，尚未处理） */
    PENDING,

    /** 分析中（正在调用 AI 或规则引擎） */
    ANALYZING,

    /** 分析完成 */
    COMPLETED,

    /** 分析失败（如 AI 调用超时） */
    FAILED,

    /** 已跳过（符合跳过规则，无需分析） */
    SKIPPED
}
