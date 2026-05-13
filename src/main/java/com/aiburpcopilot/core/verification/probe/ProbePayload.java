package com.aiburpcopilot.core.verification.probe;

import java.util.ArrayList;
import java.util.List;

public class ProbePayload {

    private String value;
    private ProbeRole role = ProbeRole.SINGLE;
    private List<String> markers = new ArrayList<>();
    private String mutation = "REPLACE";

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public ProbeRole getRole() {
        return role;
    }

    public void setRole(ProbeRole role) {
        this.role = role != null ? role : ProbeRole.SINGLE;
    }

    public List<String> getMarkers() {
        return markers;
    }

    public void setMarkers(List<String> markers) {
        this.markers = markers != null ? markers : new ArrayList<>();
    }

    public String getMutation() {
        return mutation;
    }

    public void setMutation(String mutation) {
        this.mutation = mutation != null && !mutation.isBlank()
                ? mutation.trim().toUpperCase()
                : "REPLACE";
    }
}
