package com.aiburpcopilot.core.discovery;

import java.util.ArrayList;
import java.util.List;

public class DiscoveryCandidate {

    private String key;
    private String host;
    private String path;
    private String url;
    private DiscoveryAssetType assetType;
    private double score;
    private String methodHint;
    private String sourceReason;
    private int supportingObservationCount;
    private List<String> supportingPaths = new ArrayList<>();
    private List<String> supportingParameters = new ArrayList<>();
    private List<String> supportingMethods = new ArrayList<>();
    private DiscoveryValidation validation = new DiscoveryValidation();

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public DiscoveryAssetType getAssetType() {
        return assetType;
    }

    public void setAssetType(DiscoveryAssetType assetType) {
        this.assetType = assetType;
    }

    public double getScore() {
        return score;
    }

    public void setScore(double score) {
        this.score = score;
    }

    public String getMethodHint() {
        return methodHint;
    }

    public void setMethodHint(String methodHint) {
        this.methodHint = methodHint;
    }

    public String getSourceReason() {
        return sourceReason;
    }

    public void setSourceReason(String sourceReason) {
        this.sourceReason = sourceReason;
    }

    public int getSupportingObservationCount() {
        return supportingObservationCount;
    }

    public void setSupportingObservationCount(int supportingObservationCount) {
        this.supportingObservationCount = supportingObservationCount;
    }

    public List<String> getSupportingPaths() {
        return supportingPaths;
    }

    public void setSupportingPaths(List<String> supportingPaths) {
        this.supportingPaths = supportingPaths != null ? new ArrayList<>(supportingPaths) : new ArrayList<>();
    }

    public List<String> getSupportingParameters() {
        return supportingParameters;
    }

    public void setSupportingParameters(List<String> supportingParameters) {
        this.supportingParameters = supportingParameters != null ? new ArrayList<>(supportingParameters) : new ArrayList<>();
    }

    public List<String> getSupportingMethods() {
        return supportingMethods;
    }

    public void setSupportingMethods(List<String> supportingMethods) {
        this.supportingMethods = supportingMethods != null ? new ArrayList<>(supportingMethods) : new ArrayList<>();
    }

    public DiscoveryValidation getValidation() {
        return validation;
    }

    public void setValidation(DiscoveryValidation validation) {
        this.validation = validation != null ? validation : new DiscoveryValidation();
    }

    public DiscoveryCandidate copy() {
        DiscoveryCandidate copy = new DiscoveryCandidate();
        copy.setKey(key);
        copy.setHost(host);
        copy.setPath(path);
        copy.setUrl(url);
        copy.setAssetType(assetType);
        copy.setScore(score);
        copy.setMethodHint(methodHint);
        copy.setSourceReason(sourceReason);
        copy.setSupportingObservationCount(supportingObservationCount);
        copy.setSupportingPaths(supportingPaths);
        copy.setSupportingParameters(supportingParameters);
        copy.setSupportingMethods(supportingMethods);
        copy.setValidation(validation != null ? validation.copy() : new DiscoveryValidation());
        return copy;
    }
}
