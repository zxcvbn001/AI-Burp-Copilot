package com.aiburpcopilot.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import java.awt.*;

final class BurpMessageViewer {

    private BurpMessageViewer() {
    }

    static final class RequestView extends JPanel {
        private final HttpRequestEditor editor;
        private final JTextArea fallback;
        private byte[] lastBytes;

        RequestView(MontoyaApi api) {
            super(new BorderLayout());
            HttpRequestEditor created = null;
            JTextArea fallbackArea = null;
            if (api != null) {
                try {
                    created = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
                    add(created.uiComponent(), BorderLayout.CENTER);
                } catch (Exception ignored) {
                    created = null;
                }
            }
            if (created == null) {
                fallbackArea = UiUtil.createMessageArea();
                add(UiUtil.searchableTextPanel(fallbackArea), BorderLayout.CENTER);
            }
            this.editor = created;
            this.fallback = fallbackArea;
        }

        void setBytes(byte[] bytes) {
            boolean sameBytes = java.util.Arrays.equals(lastBytes, bytes);
            if (editor != null) {
                if (!sameBytes) {
                    editor.setRequest(bytes != null && bytes.length > 0
                            ? HttpRequest.httpRequest(ByteArray.byteArray(bytes))
                            : HttpRequest.httpRequest());
                }
            } else {
                UiUtil.setTextPreservingView(fallback, UiUtil.bytesToText(bytes), sameBytes);
            }
            lastBytes = bytes != null ? java.util.Arrays.copyOf(bytes, bytes.length) : null;
        }
    }

    static final class ResponseView extends JPanel {
        private final HttpResponseEditor editor;
        private final JTextArea fallback;
        private byte[] lastBytes;

        ResponseView(MontoyaApi api) {
            super(new BorderLayout());
            HttpResponseEditor created = null;
            JTextArea fallbackArea = null;
            if (api != null) {
                try {
                    created = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
                    add(created.uiComponent(), BorderLayout.CENTER);
                } catch (Exception ignored) {
                    created = null;
                }
            }
            if (created == null) {
                fallbackArea = UiUtil.createMessageArea();
                add(UiUtil.searchableTextPanel(fallbackArea), BorderLayout.CENTER);
            }
            this.editor = created;
            this.fallback = fallbackArea;
        }

        void setBytes(byte[] bytes) {
            boolean sameBytes = java.util.Arrays.equals(lastBytes, bytes);
            if (editor != null) {
                if (!sameBytes) {
                    editor.setResponse(bytes != null && bytes.length > 0
                            ? HttpResponse.httpResponse(ByteArray.byteArray(bytes))
                            : HttpResponse.httpResponse());
                }
            } else {
                UiUtil.setTextPreservingView(fallback, UiUtil.bytesToText(bytes), sameBytes);
            }
            lastBytes = bytes != null ? java.util.Arrays.copyOf(bytes, bytes.length) : null;
        }
    }
}
