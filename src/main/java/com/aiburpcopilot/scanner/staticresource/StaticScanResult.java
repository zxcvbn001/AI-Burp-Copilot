package com.aiburpcopilot.scanner.staticresource;

import java.util.List;

/**
 * 静态资源扫描结果。
 * <p>
 * 记录在静态资源中发现的所有敏感信息条目。
 */
public class StaticScanResult {

    /** 是否命中任何规则 */
    private boolean hasFindings;

    /** 命中的规则列表 */
    private List<Finding> findings;

    /** AI 复核结论 */
    private String aiReview;

    public StaticScanResult() {
        this.hasFindings = false;
    }

    public boolean isHasFindings() { return hasFindings; }
    public void setHasFindings(boolean hasFindings) { this.hasFindings = hasFindings; }
    public List<Finding> getFindings() { return findings; }
    public void setFindings(List<Finding> findings) { this.findings = findings; }
    public String getAiReview() { return aiReview; }
    public void setAiReview(String aiReview) { this.aiReview = aiReview; }

    /**
     * 单条发现记录。
     */
    public static class Finding {
        /** 规则名称 */
        private String ruleName;

        /** 匹配的文本片段（脱敏） */
        private String matchedContent;

        /** 在内容中的行号 */
        private int lineNumber;

        /** 严重程度 */
        private String severity;

        public Finding() {}

        public Finding(String ruleName, String matchedContent, int lineNumber, String severity) {
            this.ruleName = ruleName;
            this.matchedContent = matchedContent;
            this.lineNumber = lineNumber;
            this.severity = severity;
        }

        public String getRuleName() { return ruleName; }
        public void setRuleName(String ruleName) { this.ruleName = ruleName; }
        public String getMatchedContent() { return matchedContent; }
        public void setMatchedContent(String matchedContent) { this.matchedContent = matchedContent; }
        public int getLineNumber() { return lineNumber; }
        public void setLineNumber(int lineNumber) { this.lineNumber = lineNumber; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }

        @Override
        public String toString() {
            return "Finding{" +
                    "rule='" + ruleName + '\'' +
                    ", line=" + lineNumber +
                    ", severity='" + severity + '\'' +
                    '}';
        }
    }
}
