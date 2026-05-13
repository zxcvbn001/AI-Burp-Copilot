package com.aiburpcopilot.core.verification.probe;

import com.aiburpcopilot.core.context.AttackType;
import com.aiburpcopilot.core.verification.model.StrategyType;

import java.util.ArrayList;
import java.util.List;

public class ProbeDefinition {

    private AttackType attackType;
    private String id;
    private String technique;
    private StrategyType strategy;
    private boolean enabledByDefault = true;
    private int priority = 100;
    private boolean stopOnMatch = true;
    private int maxRequests = 1;
    private int maxPayloadLength = 128;
    private double evidenceWeight = 0.5;
    private List<String> applicableParamTypes = new ArrayList<>();
    private List<String> valueTypes = new ArrayList<>();
    private boolean requiresLlmReview;
    private List<ProbePayload> payloads = new ArrayList<>();
    private List<ProbePayloadPair> payloadPairs = new ArrayList<>();
    private OracleDefinition oracle = new OracleDefinition();

    public AttackType getAttackType() {
        return attackType;
    }

    public void setAttackType(AttackType attackType) {
        this.attackType = attackType;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTechnique() {
        return technique;
    }

    public void setTechnique(String technique) {
        this.technique = technique;
    }

    public StrategyType getStrategy() {
        return strategy;
    }

    public void setStrategy(StrategyType strategy) {
        this.strategy = strategy;
    }

    public boolean isEnabledByDefault() {
        return enabledByDefault;
    }

    public void setEnabledByDefault(boolean enabledByDefault) {
        this.enabledByDefault = enabledByDefault;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public boolean isStopOnMatch() {
        return stopOnMatch;
    }

    public void setStopOnMatch(boolean stopOnMatch) {
        this.stopOnMatch = stopOnMatch;
    }

    public int getMaxRequests() {
        return maxRequests;
    }

    public void setMaxRequests(int maxRequests) {
        this.maxRequests = Math.max(1, maxRequests);
    }

    public int getMaxPayloadLength() {
        return maxPayloadLength;
    }

    public void setMaxPayloadLength(int maxPayloadLength) {
        this.maxPayloadLength = Math.max(1, maxPayloadLength);
    }

    public double getEvidenceWeight() {
        return evidenceWeight;
    }

    public void setEvidenceWeight(double evidenceWeight) {
        this.evidenceWeight = Math.max(0.0, Math.min(1.0, evidenceWeight));
    }

    public List<String> getApplicableParamTypes() {
        return applicableParamTypes;
    }

    public void setApplicableParamTypes(List<String> applicableParamTypes) {
        this.applicableParamTypes = normalizeUpperList(applicableParamTypes);
    }

    public List<String> getValueTypes() {
        return valueTypes;
    }

    public void setValueTypes(List<String> valueTypes) {
        this.valueTypes = normalizeUpperList(valueTypes);
    }

    public boolean isRequiresLlmReview() {
        return requiresLlmReview;
    }

    public void setRequiresLlmReview(boolean requiresLlmReview) {
        this.requiresLlmReview = requiresLlmReview;
    }

    public List<ProbePayload> getPayloads() {
        return payloads;
    }

    public void setPayloads(List<ProbePayload> payloads) {
        this.payloads = payloads != null ? payloads : new ArrayList<>();
    }

    public List<ProbePayloadPair> getPayloadPairs() {
        return payloadPairs;
    }

    public void setPayloadPairs(List<ProbePayloadPair> payloadPairs) {
        this.payloadPairs = payloadPairs != null ? payloadPairs : new ArrayList<>();
    }

    public OracleDefinition getOracle() {
        return oracle;
    }

    public void setOracle(OracleDefinition oracle) {
        this.oracle = oracle != null ? oracle : new OracleDefinition();
    }

    private List<String> normalizeUpperList(List<String> values) {
        if (values == null) {
            return new ArrayList<>();
        }
        return values.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(value -> value.trim().toUpperCase())
                .toList();
    }
}
