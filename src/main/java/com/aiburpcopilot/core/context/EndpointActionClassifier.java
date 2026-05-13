package com.aiburpcopilot.core.context;

public final class EndpointActionClassifier {

    private EndpointActionClassifier() {
    }

    public static EndpointActionType classify(HTTPContext context, AnalysisResult analysisResult) {
        EndpointActionType aiType = analysisResult != null
                ? EndpointActionType.fromString(analysisResult.getEndpointActionType())
                : EndpointActionType.UNKNOWN;
        EndpointActionType heuristicType = classifyByHttp(context);
        if (heuristicType == EndpointActionType.DELETE) {
            return EndpointActionType.DELETE;
        }
        if (heuristicType == EndpointActionType.UPDATE
                && (aiType == EndpointActionType.READ || aiType == EndpointActionType.UNKNOWN)) {
            return EndpointActionType.UPDATE;
        }
        if (heuristicType == EndpointActionType.CREATE
                && (aiType == EndpointActionType.READ || aiType == EndpointActionType.UNKNOWN)) {
            return EndpointActionType.CREATE;
        }
        return aiType != EndpointActionType.UNKNOWN ? aiType : heuristicType;
    }

    public static EndpointActionType classifyByHttp(HTTPContext context) {
        if (context == null) {
            return EndpointActionType.UNKNOWN;
        }
        String method = context.getMethod() != null ? context.getMethod().toUpperCase() : "";
        String path = context.getPath() != null ? context.getPath().toLowerCase() : "";

        if ("DELETE".equals(method)
                || containsAny(path, "delete", "remove", "destroy", "del")) {
            return EndpointActionType.DELETE;
        }
        if ("PUT".equals(method) || "PATCH".equals(method)
                || containsAny(path, "update", "edit", "modify", "change", "set", "reset")) {
            return EndpointActionType.UPDATE;
        }
        if ("POST".equals(method)) {
            if (containsAny(path, "login", "logout", "auth", "token", "session", "signin", "signout")) {
                return EndpointActionType.AUTH;
            }
            if (containsAny(path, "create", "add", "new", "insert", "register", "upload", "submit")) {
                return EndpointActionType.CREATE;
            }
            return EndpointActionType.UPDATE;
        }
        if ("GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method)) {
            return EndpointActionType.READ;
        }
        return EndpointActionType.UNKNOWN;
    }

    private static boolean containsAny(String value, String... tokens) {
        if (value == null || value.isBlank()) {
            return false;
        }
        for (String token : tokens) {
            if (value.contains(token)) {
                return true;
            }
        }
        return false;
    }
}
