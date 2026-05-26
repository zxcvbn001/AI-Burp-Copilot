package com.aiburpcopilot.scanner.staticresource.js;

import com.aiburpcopilot.utils.JsonUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JsAnalysisResponseTest {

    @Test
    void shouldParseSnakeCaseAsyncTaskFields() {
        JsAnalysisResponse response = JsonUtil.fromJson("""
                {
                  "success": true,
                  "task_id": "task-1",
                  "status": "queued",
                  "status_url": "/analyze/tasks/task-1"
                }
                """, JsAnalysisResponse.class);

        assertEquals("task-1", response.getTaskId());
        assertEquals("queued", response.getStatus());
        assertEquals("/analyze/tasks/task-1", response.getStatusUrl());
    }

    @Test
    void shouldFallbackToNestedTaskFields() {
        JsAnalysisResponse response = JsonUtil.fromJson("""
                {
                  "success": true,
                  "task": {
                    "id": "task-2",
                    "status": "running"
                  }
                }
                """, JsAnalysisResponse.class);

        assertEquals("task-2", response.getTaskId());
        assertEquals("running", response.getStatus());
    }

    @Test
    void shouldParseCompactAnalysisResult() {
        JsAnalysisResponse response = JsonUtil.fromJson("""
                {
                  "success": true,
                  "url": "https://target.example/static/app.js",
                  "summary": {
                    "endpointCount": 1,
                    "leakCount": 1,
                    "jsFileCount": 1
                  },
                  "leaks": [
                    {
                      "category": "敏感凭据",
                      "type": "bearer-token",
                      "value": "Bearer abc",
                      "severity": "high",
                      "confidence": 0.9,
                      "source": "regex",
                      "evidence": "const token = 'Bearer abc'"
                    }
                  ],
                  "endpoints": [
                    {
                      "url": "/api/user",
                      "resolvedUrl": "https://target.example/api/user",
                      "baseUrl": "https://target.example",
                      "kind": "api",
                      "method": "POST",
                      "params": ["uid"],
                      "headers": ["Authorization"],
                      "auth": "Authorization",
                      "source": "axios.post",
                      "confidence": "high",
                      "notes": ["resolved-from-static-base-url"],
                      "evidence": "axios.post('/api/user')"
                    }
                  ],
                  "jsFiles": [
                    {
                      "url": "assets/js/chunk.js",
                      "type": "script",
                      "chunkName": "chunk",
                      "source": "webpack-runtime-return",
                      "confidence": 0.85,
                      "evidence": "webpack-runtime-return"
                    }
                  ]
                }
                """, JsAnalysisResponse.class);

        assertEquals(1, response.getSummary().getEndpointCount());
        assertEquals(1, response.getSummary().getLeakCount());
        assertEquals(1, response.getSummary().getJsFileCount());
        assertEquals("敏感凭据", response.getLeaks().getFirst().getCategory());
        assertEquals("bearer-token", response.getLeaks().getFirst().getType());
        assertEquals("https://target.example/api/user", response.getEndpoints().getFirst().getResolvedUrl());
        assertEquals("api", response.getEndpoints().getFirst().getKind());
        assertEquals("axios.post('/api/user')", response.getEndpoints().getFirst().getEvidence());
        assertEquals("chunk", response.getJsFiles().getFirst().getChunkName());
        assertEquals(0.85, response.getJsFiles().getFirst().getConfidence());
    }
}
