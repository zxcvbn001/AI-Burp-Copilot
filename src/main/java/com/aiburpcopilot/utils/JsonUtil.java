package com.aiburpcopilot.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * JSON 工具类。
 * <p>
 * 基于 Jackson 的简单封装，统一序列化/反序列化配置。
 * 线程安全，可直接在多个模块间共享。
 */
public final class JsonUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
            .configure(SerializationFeature.INDENT_OUTPUT, false);

    private JsonUtil() {}

    /**
     * 将对象序列化为 JSON 字符串。
     */
    public static String toJson(Object obj) {
        try {
            return MAPPER.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            return "{}";
        }
    }

    /**
     * 将对象序列化为格式化 JSON 字符串。
     */
    public static String toPrettyJson(Object obj) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            return "{}";
        }
    }

    /**
     * 将 JSON 字符串反序列化为指定类型。
     */
    public static <T> T fromJson(String json, Class<T> clazz) {
        try {
            return MAPPER.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to parse JSON: " + e.getMessage(), e);
        }
    }

    /**
     * 将 JSON 字符串反序列化为指定类型（可能为 null）。
     */
    public static <T> T fromJsonSafe(String json, Class<T> clazz) {
        try {
            return MAPPER.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /**
     * 获取 ObjectMapper 实例（供高级用法）。
     */
    public static ObjectMapper getMapper() {
        return MAPPER;
    }
}
