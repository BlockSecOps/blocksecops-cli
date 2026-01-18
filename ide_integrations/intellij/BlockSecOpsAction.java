package com.blocksecops.intellij;

import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.OSProcessHandler;
import com.intellij.execution.process.ProcessAdapter;
import com.intellij.execution.process.ProcessEvent;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Key;
import com.intellij.openapi.vfs.VirtualFile;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;

/**
 * Action to scan the current file using blocksecops-cli.
 */
public class BlockSecOpsScanFileAction extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent event) {
        Project project = event.getProject();
        VirtualFile file = event.getData(CommonDataKeys.VIRTUAL_FILE);

        if (project == null || file == null) {
            return;
        }

        if (!file.getName().endsWith(".sol")) {
            showNotification(project, "BlockSecOps only scans Solidity (.sol) files", NotificationType.WARNING);
            return;
        }

        scanFile(project, file.getPath());
    }

    @Override
    public void update(@NotNull AnActionEvent event) {
        VirtualFile file = event.getData(CommonDataKeys.VIRTUAL_FILE);
        boolean enabled = file != null && file.getName().endsWith(".sol");
        event.getPresentation().setEnabledAndVisible(enabled);
    }

    private void scanFile(Project project, String filePath) {
        BlockSecOpsSettings settings = BlockSecOpsSettings.getInstance();
        String cliPath = settings.getCliPath();

        GeneralCommandLine commandLine = new GeneralCommandLine()
                .withExePath(cliPath)
                .withParameters("scan", "run", filePath, "--output", "sarif")
                .withCharset(StandardCharsets.UTF_8);

        if (project.getBasePath() != null) {
            commandLine.withWorkDirectory(project.getBasePath());
        }

        try {
            OSProcessHandler processHandler = new OSProcessHandler(commandLine);
            StringBuilder output = new StringBuilder();

            processHandler.addProcessListener(new ProcessAdapter() {
                @Override
                public void onTextAvailable(@NotNull ProcessEvent event, @NotNull Key outputType) {
                    output.append(event.getText());
                }

                @Override
                public void processTerminated(@NotNull ProcessEvent event) {
                    int exitCode = event.getExitCode();
                    ApplicationManager.getApplication().invokeLater(() -> {
                        handleScanResult(project, output.toString(), exitCode);
                    });
                }
            });

            processHandler.startNotify();
            showNotification(project, "Scanning " + filePath + "...", NotificationType.INFORMATION);

        } catch (Exception e) {
            showNotification(project,
                    "Failed to run blocksecops-cli: " + e.getMessage() +
                            "\nMake sure blocksecops is installed and in your PATH.",
                    NotificationType.ERROR);
        }
    }

    private void handleScanResult(Project project, String output, int exitCode) {
        if (exitCode == 0) {
            showNotification(project, "Scan complete: No issues found", NotificationType.INFORMATION);
        } else if (exitCode == 1) {
            // Parse SARIF output and count findings
            int count = countFindings(output);
            showNotification(project,
                    "Scan complete: " + count + " issue" + (count != 1 ? "s" : "") + " found",
                    NotificationType.WARNING);

            // Update tool window with results
            BlockSecOpsResultsService resultsService = project.getService(BlockSecOpsResultsService.class);
            if (resultsService != null) {
                resultsService.updateResults(output);
            }
        } else {
            showNotification(project, "Scan failed with exit code: " + exitCode, NotificationType.ERROR);
        }
    }

    private int countFindings(String sarifOutput) {
        // Simple count of "ruleId" occurrences in SARIF output
        int count = 0;
        int index = 0;
        while ((index = sarifOutput.indexOf("\"ruleId\"", index)) != -1) {
            count++;
            index++;
        }
        return count;
    }

    private void showNotification(Project project, String message, NotificationType type) {
        NotificationGroupManager.getInstance()
                .getNotificationGroup("BlockSecOps Notifications")
                .createNotification(message, type)
                .notify(project);
    }
}
