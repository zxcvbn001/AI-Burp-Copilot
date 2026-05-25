package com.aiburpcopilot.core.discovery;

public class DiscoveryAttempt {

    private int sequence;
    private String method;
    private int statusCode;
    private byte[] requestBytes;
    private byte[] responseBytes;
    private boolean signalMatched;
    private String summary;
    private String contentType;

    public int getSequence() {
        return sequence;
    }

    public void setSequence(int sequence) {
        this.sequence = sequence;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public byte[] getRequestBytes() {
        return requestBytes;
    }

    public void setRequestBytes(byte[] requestBytes) {
        this.requestBytes = requestBytes;
    }

    public byte[] getResponseBytes() {
        return responseBytes;
    }

    public void setResponseBytes(byte[] responseBytes) {
        this.responseBytes = responseBytes;
    }

    public boolean isSignalMatched() {
        return signalMatched;
    }

    public void setSignalMatched(boolean signalMatched) {
        this.signalMatched = signalMatched;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public DiscoveryAttempt copy() {
        DiscoveryAttempt copy = new DiscoveryAttempt();
        copy.setSequence(sequence);
        copy.setMethod(method);
        copy.setStatusCode(statusCode);
        copy.setRequestBytes(requestBytes != null ? requestBytes.clone() : null);
        copy.setResponseBytes(responseBytes != null ? responseBytes.clone() : null);
        copy.setSignalMatched(signalMatched);
        copy.setSummary(summary);
        copy.setContentType(contentType);
        return copy;
    }
}
