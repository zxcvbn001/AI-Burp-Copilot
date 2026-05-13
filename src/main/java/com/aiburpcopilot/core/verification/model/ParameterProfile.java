package com.aiburpcopilot.core.verification.model;

/**
 * 参数特征分析结果。
 * <p>
 * 由 IParameterProfiler 识别参数的类型特征，
 * 为 MinimalMutationEngine 提供最小差异变异的依据。
 */
public class ParameterProfile {

    /** 参数名 */
    private String parameterName;

    /** 检测到的参数类型 */
    private String detectedType;

    /** 检测置信度 (0.0 ~ 1.0) */
    private double confidence;

    /** 是否可变异（某些参数如签名类不适合变异） */
    private boolean mutable;

    /** 检测推理说明 */
    private String reasoning;

    /** 原始参数值 */
    private String originalValue;

    // ---- 支持的 detectedType 常量 ----

    public static final String TYPE_NUMERIC = "NUMERIC";
    public static final String TYPE_UUID = "UUID";
    public static final String TYPE_JWT = "JWT";
    public static final String TYPE_BASE64 = "BASE64";
    public static final String TYPE_BOOLEAN = "BOOLEAN";
    public static final String TYPE_JSON = "JSON";
    public static final String TYPE_EMAIL = "EMAIL";
    public static final String TYPE_URL = "URL";
    public static final String TYPE_STRING = "STRING";
    public static final String TYPE_UNKNOWN = "UNKNOWN";

    public ParameterProfile() {
        this.confidence = 0.0;
        this.mutable = true;
    }

    public ParameterProfile(String parameterName, String detectedType, double confidence,
                            boolean mutable, String reasoning, String originalValue) {
        this.parameterName = parameterName;
        this.detectedType = detectedType;
        this.confidence = confidence;
        this.mutable = mutable;
        this.reasoning = reasoning;
        this.originalValue = originalValue;
    }

    // ---------- Getters & Setters ----------

    public String getParameterName() { return parameterName; }
    public void setParameterName(String parameterName) { this.parameterName = parameterName; }

    public String getDetectedType() { return detectedType; }
    public void setDetectedType(String detectedType) { this.detectedType = detectedType; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = Math.max(0.0, Math.min(1.0, confidence)); }

    public boolean isMutable() { return mutable; }
    public void setMutable(boolean mutable) { this.mutable = mutable; }

    public String getReasoning() { return reasoning; }
    public void setReasoning(String reasoning) { this.reasoning = reasoning; }

    public String getOriginalValue() { return originalValue; }
    public void setOriginalValue(String originalValue) { this.originalValue = originalValue; }

    @Override
    public String toString() {
        return "ParameterProfile{" +
                "parameterName='" + parameterName + '\'' +
                ", detectedType='" + detectedType + '\'' +
                ", confidence=" + confidence +
                ", mutable=" + mutable +
                '}';
    }
}
