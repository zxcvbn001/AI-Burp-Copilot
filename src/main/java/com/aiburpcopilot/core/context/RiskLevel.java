package com.aiburpcopilot.core.context;

/**
 * 风险等级枚举。
 * <p>
 * 用于标记参数、端点或分析结果的风险严重程度。
 * 风险等级代表"值得人工深入验证的概率"，而非"已确认存在漏洞"。
 * <p>
 * 等级说明：
 * <ul>
 *   <li>CRITICAL - 极可能存在问题，应立即人工验证</li>
 *   <li>HIGH - 高价值攻击面，优先验证</li>
 *   <li>MEDIUM - 值得关注，常规验证</li>
 *   <li>LOW - 低风险，可忽略或延后处理</li>
 *   <li>INFO - 信息性提示，非风险</li>
 * </ul>
 */
public enum RiskLevel {

    /** 极高风险，需立即关注 */
    CRITICAL,

    /** 高风险，优先验证 */
    HIGH,

    /** 中风险，常规关注 */
    MEDIUM,

    /** 低风险，可延后 */
    LOW,

    /** 信息性，非风险 */
    INFO
}
