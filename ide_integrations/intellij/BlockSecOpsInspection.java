package com.blocksecops.intellij;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.ProcessOutput;
import com.intellij.lang.annotation.AnnotationHolder;
import com.intellij.lang.annotation.ExternalAnnotator;
import com.intellij.lang.annotation.HighlightSeverity;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.util.TextRange;
import com.intellij.psi.PsiDocumentManager;
import com.intellij.psi.PsiFile;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * External annotator that runs blocksecops-cli and displays results as editor annotations.
 */
public class BlockSecOpsExternalAnnotator extends ExternalAnnotator<PsiFile, List<BlockSecOpsExternalAnnotator.Finding>> {

    private static final Gson GSON = new Gson();

    @Override
    public @Nullable PsiFile collectInformation(@NotNull PsiFile file, @NotNull Editor editor, boolean hasErrors) {
        if (!file.getName().endsWith(".sol")) {
            return null;
        }
        return file;
    }

    @Override
    public @Nullable List<Finding> doAnnotate(PsiFile file) {
        if (file == null || file.getVirtualFile() == null) {
            return null;
        }

        String filePath = file.getVirtualFile().getPath();
        BlockSecOpsSettings settings = BlockSecOpsSettings.getInstance();
        String cliPath = settings.getCliPath();

        GeneralCommandLine commandLine = new GeneralCommandLine()
                .withExePath(cliPath)
                .withParameters("scan", "run", filePath, "--output", "sarif")
                .withCharset(StandardCharsets.UTF_8);

        try {
            CapturingProcessHandler handler = new CapturingProcessHandler(commandLine);
            ProcessOutput output = handler.runProcess(60000); // 60 second timeout

            if (output.getExitCode() == 0 || output.getExitCode() == 1) {
                return parseFindings(output.getStdout(), filePath);
            }
        } catch (Exception e) {
            // Log but don't crash - annotation failures shouldn't block the user
        }

        return null;
    }

    @Override
    public void apply(@NotNull PsiFile file, List<Finding> findings, @NotNull AnnotationHolder holder) {
        if (findings == null || findings.isEmpty()) {
            return;
        }

        Document document = PsiDocumentManager.getInstance(file.getProject()).getDocument(file);
        if (document == null) {
            return;
        }

        for (Finding finding : findings) {
            int startLine = Math.max(0, finding.startLine - 1);
            int endLine = Math.max(startLine, finding.endLine - 1);

            if (startLine >= document.getLineCount()) {
                continue;
            }

            int startOffset = document.getLineStartOffset(startLine);
            int endOffset = endLine < document.getLineCount()
                    ? document.getLineEndOffset(endLine)
                    : document.getTextLength();

            if (finding.startColumn > 0) {
                startOffset = Math.min(startOffset + finding.startColumn - 1, endOffset);
            }

            TextRange range = new TextRange(startOffset, endOffset);
            HighlightSeverity severity = mapSeverity(finding.level);

            holder.newAnnotation(severity, finding.message)
                    .range(range)
                    .tooltip(formatTooltip(finding))
                    .create();
        }
    }

    private List<Finding> parseFindings(String sarifJson, String filePath) {
        List<Finding> findings = new ArrayList<>();

        try {
            JsonObject sarif = GSON.fromJson(sarifJson, JsonObject.class);
            JsonArray runs = sarif.getAsJsonArray("runs");

            if (runs == null || runs.isEmpty()) {
                return findings;
            }

            JsonObject run = runs.get(0).getAsJsonObject();
            JsonArray results = run.getAsJsonArray("results");

            if (results == null) {
                return findings;
            }

            for (JsonElement resultElement : results) {
                JsonObject result = resultElement.getAsJsonObject();
                Finding finding = parseFinding(result, filePath);
                if (finding != null) {
                    findings.add(finding);
                }
            }
        } catch (Exception e) {
            // Parsing failed, return empty list
        }

        return findings;
    }

    private Finding parseFinding(JsonObject result, String expectedFilePath) {
        String ruleId = result.has("ruleId") ? result.get("ruleId").getAsString() : "unknown";
        String level = result.has("level") ? result.get("level").getAsString() : "warning";
        String message = "";

        if (result.has("message") && result.getAsJsonObject("message").has("text")) {
            message = result.getAsJsonObject("message").get("text").getAsString();
        }

        JsonArray locations = result.getAsJsonArray("locations");
        if (locations == null || locations.isEmpty()) {
            return null;
        }

        JsonObject location = locations.get(0).getAsJsonObject();
        JsonObject physicalLocation = location.getAsJsonObject("physicalLocation");

        if (physicalLocation == null) {
            return null;
        }

        // Check if this finding is for the current file
        if (physicalLocation.has("artifactLocation")) {
            String uri = physicalLocation.getAsJsonObject("artifactLocation").get("uri").getAsString();
            uri = uri.replace("file://", "");
            if (!uri.equals(expectedFilePath) && !expectedFilePath.endsWith(uri)) {
                return null;
            }
        }

        int startLine = 1, endLine = 1, startColumn = 0;

        if (physicalLocation.has("region")) {
            JsonObject region = physicalLocation.getAsJsonObject("region");
            startLine = region.has("startLine") ? region.get("startLine").getAsInt() : 1;
            endLine = region.has("endLine") ? region.get("endLine").getAsInt() : startLine;
            startColumn = region.has("startColumn") ? region.get("startColumn").getAsInt() : 0;
        }

        return new Finding(ruleId, level, message, startLine, endLine, startColumn);
    }

    private HighlightSeverity mapSeverity(String level) {
        switch (level.toLowerCase()) {
            case "error":
                return HighlightSeverity.ERROR;
            case "warning":
                return HighlightSeverity.WARNING;
            case "note":
                return HighlightSeverity.WEAK_WARNING;
            default:
                return HighlightSeverity.INFORMATION;
        }
    }

    private String formatTooltip(Finding finding) {
        return String.format("<b>%s</b><br>%s<br><i>Rule: %s</i>",
                finding.level.toUpperCase(),
                finding.message,
                finding.ruleId);
    }

    static class Finding {
        final String ruleId;
        final String level;
        final String message;
        final int startLine;
        final int endLine;
        final int startColumn;

        Finding(String ruleId, String level, String message, int startLine, int endLine, int startColumn) {
            this.ruleId = ruleId;
            this.level = level;
            this.message = message;
            this.startLine = startLine;
            this.endLine = endLine;
            this.startColumn = startColumn;
        }
    }
}
