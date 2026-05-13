package com.aiburpcopilot.core.verification.probe;

public class ProbePayloadPair {

    private String trueValue;
    private String falseValue;
    private String trueMutation = "REPLACE";
    private String falseMutation = "REPLACE";

    public String getTrueValue() {
        return trueValue;
    }

    public void setTrueValue(String trueValue) {
        this.trueValue = trueValue;
    }

    public String getFalseValue() {
        return falseValue;
    }

    public void setFalseValue(String falseValue) {
        this.falseValue = falseValue;
    }

    public String getTrueMutation() {
        return trueMutation;
    }

    public void setTrueMutation(String trueMutation) {
        this.trueMutation = normalizeMutation(trueMutation);
    }

    public String getFalseMutation() {
        return falseMutation;
    }

    public void setFalseMutation(String falseMutation) {
        this.falseMutation = normalizeMutation(falseMutation);
    }

    private String normalizeMutation(String mutation) {
        return mutation != null && !mutation.isBlank()
                ? mutation.trim().toUpperCase()
                : "REPLACE";
    }
}
