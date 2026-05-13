package com.aiburpcopilot.core.verification.probe;

public class ProbeExecution {

    private final String value;
    private final ProbeRole role;
    private final byte[] requestBytes;
    private final byte[] responseBytes;
    private final long durationMs;

    public ProbeExecution(String value, ProbeRole role, byte[] requestBytes, byte[] responseBytes, long durationMs) {
        this.value = value;
        this.role = role != null ? role : ProbeRole.SINGLE;
        this.requestBytes = requestBytes;
        this.responseBytes = responseBytes;
        this.durationMs = durationMs;
    }

    public String getValue() {
        return value;
    }

    public ProbeRole getRole() {
        return role;
    }

    public byte[] getRequestBytes() {
        return requestBytes;
    }

    public byte[] getResponseBytes() {
        return responseBytes;
    }

    public long getDurationMs() {
        return durationMs;
    }
}
