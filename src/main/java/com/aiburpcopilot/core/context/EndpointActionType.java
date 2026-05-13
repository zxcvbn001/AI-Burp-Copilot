package com.aiburpcopilot.core.context;

public enum EndpointActionType {
    READ,
    CREATE,
    UPDATE,
    DELETE,
    AUTH,
    UNKNOWN;

    public static EndpointActionType fromString(String value) {
        if (value == null || value.isBlank()) {
            return UNKNOWN;
        }
        String normalized = value.trim().toUpperCase().replace("-", "_").replace(" ", "_");
        for (EndpointActionType type : values()) {
            if (type.name().equals(normalized)) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
