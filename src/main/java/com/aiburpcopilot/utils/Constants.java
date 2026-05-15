package com.aiburpcopilot.utils;

/**
 * 全局常量定义。
 * <p>
 * 所有魔法字符串集中管理，避免散落在各模块代码中。
 * 后续阶段扩展时在此添加新常量。
 */
public final class Constants {

    private Constants() {}

    // ========== 插件信息 ==========

    public static final String EXTENSION_NAME = "AI Burp Copilot";
    public static final String EXTENSION_VERSION = "2.0.0";
    public static final String TAB_TITLE = "AI Burp Copilot";

    // ========== 配置相关 ==========

    public static final String CONFIG_FILE_NAME = "application.yml";
    public static final String CONFIG_DIR_NAME = "ai-burp-copilot";
    public static final String CONFIG_TEMPLATE_DIR_NAME = "ai-burp-copilot-templates";

    // ========== Prompt 模板名称 ==========

    /** 端点分类 Prompt */
    public static final String PROMPT_ENDPOINT_CLASSIFIER = "endpoint-classifier-v1";

    /** 攻击面分析 Prompt */
    public static final String PROMPT_ENDPOINT_ANALYSIS = "endpoint-analysis-v1";

    /** 静态资源审查 Prompt */
    public static final String PROMPT_STATIC_REVIEW = "static-review-v1";

    // ========== HTTP 相关 ==========

    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_COOKIE = "Cookie";
    public static final String HEADER_SET_COOKIE = "Set-Cookie";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_X_API_KEY = "X-Api-Key";
    public static final String HEADER_API_KEY = "Api-Key";

    /** 需要从历史记录中排除的敏感 Header */
    public static final java.util.Set<String> SENSITIVE_HEADERS = java.util.Set.of(
            HEADER_AUTHORIZATION.toLowerCase(),
            HEADER_COOKIE.toLowerCase(),
            HEADER_SET_COOKIE.toLowerCase(),
            HEADER_X_API_KEY.toLowerCase(),
            HEADER_API_KEY.toLowerCase()
    );

    // ========== Content-Type ==========

    public static final String CT_JSON = "application/json";
    public static final String CT_FORM = "application/x-www-form-urlencoded";
    public static final String CT_MULTIPART = "multipart/form-data";
    public static final String CT_XML = "application/xml";
    public static final String CT_GRAPHQL = "application/graphql-response+json";

    // ========== Endpoint 特征路径关键字 ==========

    public static final java.util.Set<String> ENDPOINT_PATH_KEYWORDS = java.util.Set.of(
            "api", "auth", "login", "graphql", "v1", "v2", "v3",
            "rest", "service", "rpc", "soap", "swagger", "openapi",
            "admin", "manage", "user", "account", "order", "payment"
    );

    // ========== 静态资源后缀 ==========

    public static final java.util.Set<String> STATIC_EXTENSIONS = java.util.Set.of(
            "js", "css", "png", "jpg", "jpeg", "gif", "svg", "webp",
            "woff", "woff2", "ttf", "eot", "ico", "map",
            "mp4", "webm", "ogg", "mp3", "wav",
            "pdf", "doc", "docx", "xls", "xlsx",
            "zip", "tar", "gz", "rar"
    );

    // ========== 静态资源敏感信息规则 ==========

    /** 正则：AWS Access Key */
    public static final String REGEX_AWS_KEY = "AKIA[0-9A-Z]{16}";

    /** 正则：Google API Key */
    public static final String REGEX_GOOGLE_KEY = "AIza[0-9A-Za-z_-]{35}";

    /** 正则：通用 secret */
    public static final String REGEX_SECRET = "(?i)(secret|password|passwd|pwd)\\s*[:=]\\s*['\"][^'\"]+['\"]";

    /** 正则：通用 token */
    public static final String REGEX_TOKEN = "(?i)(token|access_token|refresh_token|api_key|apikey)\\s*[:=]\\s*['\"][^'\"]+['\"]";

    /** 正则：SourceMappingURL */
    public static final String REGEX_SOURCE_MAP = "//# sourceMappingURL=.*";

    /** 正则：内网地址 */
    public static final String REGEX_INTERNAL_IP = "(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|127\\.0\\.0\\.1|localhost)";

    /** 正则：内网域名 */
    public static final String REGEX_INTERNAL_DOMAIN = "(?i)\\.internal\\.|\\bstaging\\b|\\bdev\\b|\\.test\\.|\\bdebug\\b";

    // ========== Pipeline 相关 ==========

    public static final int PIPELINE_QUEUE_CAPACITY = 1000;
    public static final int PIPELINE_WORKER_COUNT = 2;

    // ========== AI 限流 ==========

    public static final int AI_RATE_LIMIT_PER_MINUTE = 20;
    public static final int AI_MAX_BODY_PREVIEW_SIZE = 512;

    // ========== 缓存 ==========

    public static final int CACHE_DEFAULT_TTL_SECONDS = 3600;
    public static final int CACHE_MAX_ENTRIES = 5000;

    // ========== 历史记录 ==========

    public static final int HISTORY_DEFAULT_MAX = 10000;
    public static final int HISTORY_PAGE_SIZE = 50;

    // ========== 验证框架 (Phase 2) ==========

    public static final int VERIFICATION_QUEUE_CAPACITY = 200;
    public static final int VERIFICATION_WORKER_COUNT = 4;
    public static final int VERIFICATION_DEFAULT_TIMEOUT_MS = 5000;
    public static final int VERIFICATION_MAX_PAYLOAD_LENGTH = 128;
    public static final int VERIFICATION_MAX_REQUESTS_PER_ENDPOINT = 5;
    public static final int VERIFICATION_HOST_MAX_CONCURRENCY = 2;
}
