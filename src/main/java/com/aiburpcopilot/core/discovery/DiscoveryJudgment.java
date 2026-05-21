package com.aiburpcopilot.core.discovery;

public enum DiscoveryJudgment {
    UNVALIDATED("未验证"),
    EXISTS("存在"),
    LIKELY_EXISTS("大概率存在"),
    INCONCLUSIVE("待人工研判"),
    NOT_FOUND("不存在"),
    ERROR("验证失败");

    private final String displayName;

    DiscoveryJudgment(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
