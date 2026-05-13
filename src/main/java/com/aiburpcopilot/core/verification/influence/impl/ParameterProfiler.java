package com.aiburpcopilot.core.verification.influence.impl;

import com.aiburpcopilot.core.verification.influence.IParameterProfiler;
import com.aiburpcopilot.core.verification.model.ParameterProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;

public class ParameterProfiler implements IParameterProfiler {

    private static final Logger log = LoggerFactory.getLogger(ParameterProfiler.class);

    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "^eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$");
    private static final Pattern NUMERIC_PATTERN = Pattern.compile("^-?\\d+(\\.\\d+)?$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^@]+@[^@]+\\.[^@]+$");
    private static final Pattern BASE64_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+/]+=*$");

    @Override
    public ParameterProfile profile(String paramName, String paramValue) {
        ParameterProfile profile = new ParameterProfile();
        profile.setParameterName(paramName);

        if (paramValue == null || paramValue.isBlank()) {
            profile.setDetectedType(ParameterProfile.TYPE_UNKNOWN);
            profile.setConfidence(0.0);
            profile.setMutable(true);
            profile.setReasoning("Empty or null value");
            profile.setOriginalValue(paramValue);
            return profile;
        }

        profile.setOriginalValue(paramValue.trim());

        // Detect type by value pattern
        String detected = ParameterProfile.TYPE_STRING;
        double confidence = 0.5;
        boolean mutable = true;

        if (NUMERIC_PATTERN.matcher(paramValue.trim()).matches()) {
            detected = ParameterProfile.TYPE_NUMERIC;
            confidence = 0.95;
        } else if (UUID_PATTERN.matcher(paramValue.trim()).matches()) {
            detected = ParameterProfile.TYPE_UUID;
            confidence = 0.95;
        } else if (JWT_PATTERN.matcher(paramValue.trim()).matches()) {
            detected = ParameterProfile.TYPE_JWT;
            confidence = 0.9;
            mutable = false; // JWT shouldn't be mutated
        } else if (EMAIL_PATTERN.matcher(paramValue.trim()).matches()) {
            detected = ParameterProfile.TYPE_EMAIL;
            confidence = 0.85;
        } else if (paramValue.trim().startsWith("http://") || paramValue.trim().startsWith("https://")) {
            detected = ParameterProfile.TYPE_URL;
            confidence = 0.9;
        } else if ("true".equalsIgnoreCase(paramValue.trim()) || "false".equalsIgnoreCase(paramValue.trim())) {
            detected = ParameterProfile.TYPE_BOOLEAN;
            confidence = 0.95;
        } else if (paramValue.trim().startsWith("{") || paramValue.trim().startsWith("[")) {
            detected = ParameterProfile.TYPE_JSON;
            confidence = 0.8;
            mutable = false;
        } else if (BASE64_PATTERN.matcher(paramValue.trim()).matches() && paramValue.trim().length() > 20) {
            detected = ParameterProfile.TYPE_BASE64;
            confidence = 0.6;
        }

        // Refine by parameter name hints
        if (paramName != null) {
            String lower = paramName.toLowerCase();
            if (lower.contains("uuid")) {
                if (detected.equals(ParameterProfile.TYPE_STRING)) {
                    detected = ParameterProfile.TYPE_UUID;
                    confidence = 0.7;
                }
            }
            if (lower.contains("token") || lower.contains("jwt") || lower.contains("auth")) {
                mutable = false;
            }
            if (lower.contains("email") || lower.contains("mail")) {
                if (detected.equals(ParameterProfile.TYPE_STRING)) {
                    detected = ParameterProfile.TYPE_EMAIL;
                    confidence = 0.7;
                }
            }
            if ((lower.contains("id") || lower.contains("count") || lower.contains("page") || lower.contains("size") || lower.contains("limit"))
                    && detected.equals(ParameterProfile.TYPE_STRING)) {
                try {
                    Integer.parseInt(paramValue.trim());
                    detected = ParameterProfile.TYPE_NUMERIC;
                    confidence = 0.8;
                } catch (NumberFormatException ignored) {}
            }
        }

        profile.setDetectedType(detected);
        profile.setConfidence(confidence);
        profile.setMutable(mutable);
        profile.setReasoning("Detected type=" + detected + " (confidence=" + String.format("%.2f", confidence) + ")");

        return profile;
    }
}
