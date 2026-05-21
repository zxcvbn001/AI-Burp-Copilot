package com.aiburpcopilot.core.history;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class HistoryExportService {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public void exportCsv(List<HistoryEntry> entries, Path output) throws IOException {
        StringBuilder csv = new StringBuilder();
        csv.append('\uFEFF');
        csv.append("time,method,url,path,statusCode,endpointType,endpointActionType,riskLevel,analysisStatus,summary\n");
        if (entries != null) {
            for (HistoryEntry entry : entries) {
                csv.append(cell(DATE_FORMAT.format(new Date(entry.getTimestamp())))).append(',')
                        .append(cell(entry.getMethod())).append(',')
                        .append(cell(entry.getUrl())).append(',')
                        .append(cell(entry.getPath())).append(',')
                        .append(cell(String.valueOf(entry.getStatusCode()))).append(',')
                        .append(cell(String.valueOf(entry.getEndpointType()))).append(',')
                        .append(cell(String.valueOf(entry.getEndpointActionType()))).append(',')
                        .append(cell(String.valueOf(entry.getRiskLevel()))).append(',')
                        .append(cell(String.valueOf(entry.getAnalysisStatus()))).append(',')
                        .append(cell(entry.getAiSummary()))
                        .append("\n");
            }
        }
        Files.writeString(output, csv.toString(), StandardCharsets.UTF_8);
    }

    private String cell(String value) {
        String normalized = value != null ? value.replace("\r", " ").replace("\n", " ") : "";
        normalized = normalized.replace("\"", "\"\"");
        return "\"" + normalized + "\"";
    }
}
