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
}
