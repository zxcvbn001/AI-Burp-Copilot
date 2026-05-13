package com.aiburpcopilot.core.verification.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 响应差异分析结果。
 * <p>
 * Response difference model produced by the generic diff engines.
 * 支持状态码、长度、关键词、JSON 结构、相似度等多维度对比。
 */
public class DiffResult {

    /** HTTP 状态码是否发生变化 */
    private boolean statusChanged;

    /** 响应体长度是否发生变化（>10%） */
    private boolean lengthChanged;

    /** 响应体是否出现安全相关关键词（如 sql syntax, error 等） */
    private boolean keywordChanged;

    /** JSON 结构是否发生变化 */
    private boolean structureChanged;

    /** 文本相似度 (0.0 ~ 1.0，1.0 表示完全相同) */
    private double similarity;

    /** 匹配到的关键词列表 */
    private List<String> matchedKeywords;

    /** 响应时间差异（毫秒） */
    private long responseTimeDiff;

    /** 原始响应状态码 */
    private String originalStatus;

    /** 修改后响应状态码 */
    private String mutatedStatus;

    /** 原始响应体长度 */
    private int originalLength;

    /** 修改后响应体长度 */
    private int mutatedLength;

    private int stableChangeCount;
    private int noiseChangeCount;
    private List<String> changedPaths;
    private List<String> noisePaths;
    private List<String> diffSummary;
    private List<String> diffSnippets;

    public DiffResult() {
        this.similarity = 1.0;
        this.matchedKeywords = new ArrayList<>();
        this.changedPaths = new ArrayList<>();
        this.noisePaths = new ArrayList<>();
        this.diffSummary = new ArrayList<>();
        this.diffSnippets = new ArrayList<>();
    }

    /**
     * 判断是否存在有意义的差异。
     * <p>
     * 满足以下任一条件即视为有意义的差异：
     * <ul>
     *   <li>状态码发生变化</li>
     *   <li>长度变化超过 10%</li>
     *   <li>出现安全相关关键词</li>
     *   <li>JSON 结构发生变化</li>
     *   <li>相似度低于 0.85</li>
     * </ul>
     *
     * @return true 如果存在有意义的差异
     */
    public boolean isSignificant() {
        return statusChanged
                || lengthChanged
                || keywordChanged
                || structureChanged
                || stableChangeCount > 0
                || similarity < 0.85;
    }

    // ---------- Getters & Setters ----------

    public boolean isStatusChanged() { return statusChanged; }
    public void setStatusChanged(boolean statusChanged) { this.statusChanged = statusChanged; }

    public boolean isLengthChanged() { return lengthChanged; }
    public void setLengthChanged(boolean lengthChanged) { this.lengthChanged = lengthChanged; }

    public boolean isKeywordChanged() { return keywordChanged; }
    public void setKeywordChanged(boolean keywordChanged) { this.keywordChanged = keywordChanged; }

    public boolean isStructureChanged() { return structureChanged; }
    public void setStructureChanged(boolean structureChanged) { this.structureChanged = structureChanged; }

    public double getSimilarity() { return similarity; }
    public void setSimilarity(double similarity) { this.similarity = Math.max(0.0, Math.min(1.0, similarity)); }

    public List<String> getMatchedKeywords() { return matchedKeywords; }
    public void setMatchedKeywords(List<String> matchedKeywords) { this.matchedKeywords = matchedKeywords; }

    public long getResponseTimeDiff() { return responseTimeDiff; }
    public void setResponseTimeDiff(long responseTimeDiff) { this.responseTimeDiff = responseTimeDiff; }

    public String getOriginalStatus() { return originalStatus; }
    public void setOriginalStatus(String originalStatus) { this.originalStatus = originalStatus; }

    public String getMutatedStatus() { return mutatedStatus; }
    public void setMutatedStatus(String mutatedStatus) { this.mutatedStatus = mutatedStatus; }

    public int getOriginalLength() { return originalLength; }
    public void setOriginalLength(int originalLength) { this.originalLength = originalLength; }

    public int getMutatedLength() { return mutatedLength; }
    public void setMutatedLength(int mutatedLength) { this.mutatedLength = mutatedLength; }

    public int getStableChangeCount() { return stableChangeCount; }
    public void setStableChangeCount(int stableChangeCount) { this.stableChangeCount = stableChangeCount; }

    public int getNoiseChangeCount() { return noiseChangeCount; }
    public void setNoiseChangeCount(int noiseChangeCount) { this.noiseChangeCount = noiseChangeCount; }

    public List<String> getChangedPaths() { return changedPaths; }
    public void setChangedPaths(List<String> changedPaths) {
        this.changedPaths = changedPaths != null ? changedPaths : new ArrayList<>();
    }

    public List<String> getNoisePaths() { return noisePaths; }
    public void setNoisePaths(List<String> noisePaths) {
        this.noisePaths = noisePaths != null ? noisePaths : new ArrayList<>();
    }

    public List<String> getDiffSummary() { return diffSummary; }
    public void setDiffSummary(List<String> diffSummary) {
        this.diffSummary = diffSummary != null ? diffSummary : new ArrayList<>();
    }

    public List<String> getDiffSnippets() { return diffSnippets; }
    public void setDiffSnippets(List<String> diffSnippets) {
        this.diffSnippets = diffSnippets != null ? diffSnippets : new ArrayList<>();
    }

    @Override
    public String toString() {
        return "DiffResult{" +
                "statusChanged=" + statusChanged +
                ", lengthChanged=" + lengthChanged +
                ", keywordChanged=" + keywordChanged +
                ", structureChanged=" + structureChanged +
                ", similarity=" + similarity +
                ", stableChangeCount=" + stableChangeCount +
                ", noiseChangeCount=" + noiseChangeCount +
                ", changedPaths=" + changedPaths +
                ", matchedKeywords=" + matchedKeywords +
                '}';
    }
}
