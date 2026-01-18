import * as vscode from 'vscode';
import { ScanService } from './scanService';
import { DiagnosticsManager } from './diagnostics';
import { getConfiguration, onConfigurationChange } from './configuration';

let scanService: ScanService;
let diagnosticsManager: DiagnosticsManager;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext): void {
    outputChannel = vscode.window.createOutputChannel('BlockSecOps');
    scanService = new ScanService(outputChannel);
    diagnosticsManager = new DiagnosticsManager();

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = '$(shield) BlockSecOps';
    statusBarItem.tooltip = 'BlockSecOps Security Scanner';
    statusBarItem.command = 'blocksecops.showOutput';
    statusBarItem.show();

    const scanFileCommand = vscode.commands.registerCommand('blocksecops.scanFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active file to scan');
            return;
        }

        await scanCurrentFile(editor.document);
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('blocksecops.scanWorkspace', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            vscode.window.showWarningMessage('No workspace folder open');
            return;
        }

        await scanWorkspace(workspaceFolders[0].uri.fsPath);
    });

    const showOutputCommand = vscode.commands.registerCommand('blocksecops.showOutput', () => {
        outputChannel.show();
    });

    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = getConfiguration();
        if (config.scanOnSave && isSolidityFile(document)) {
            await scanCurrentFile(document);
        }
    });

    const configChangeDisposable = onConfigurationChange(() => {
        outputChannel.appendLine('Configuration changed');
    });

    context.subscriptions.push(
        scanFileCommand,
        scanWorkspaceCommand,
        showOutputCommand,
        onSaveDisposable,
        configChangeDisposable,
        outputChannel,
        statusBarItem,
        diagnosticsManager
    );

    outputChannel.appendLine('BlockSecOps extension activated');
}

async function scanCurrentFile(document: vscode.TextDocument): Promise<void> {
    if (!isSolidityFile(document)) {
        return;
    }

    statusBarItem.text = '$(sync~spin) Scanning...';

    try {
        const result = await scanService.scanFile(document.uri.fsPath);

        if (result) {
            diagnosticsManager.updateDiagnostics(result);
            const count = result.runs?.[0]?.results?.length || 0;
            statusBarItem.text = count > 0
                ? `$(warning) BlockSecOps: ${count} issue${count !== 1 ? 's' : ''}`
                : '$(check) BlockSecOps';
        } else {
            statusBarItem.text = '$(error) BlockSecOps';
        }
    } catch (error) {
        statusBarItem.text = '$(error) BlockSecOps';
        outputChannel.appendLine(`Scan error: ${error}`);
    }
}

async function scanWorkspace(workspacePath: string): Promise<void> {
    statusBarItem.text = '$(sync~spin) Scanning workspace...';

    try {
        const result = await scanService.scanWorkspace(workspacePath);

        if (result) {
            diagnosticsManager.updateDiagnostics(result);
            const count = result.runs?.[0]?.results?.length || 0;
            vscode.window.showInformationMessage(
                `BlockSecOps scan complete: ${count} issue${count !== 1 ? 's' : ''} found`
            );
            statusBarItem.text = count > 0
                ? `$(warning) BlockSecOps: ${count} issue${count !== 1 ? 's' : ''}`
                : '$(check) BlockSecOps';
        } else {
            statusBarItem.text = '$(error) BlockSecOps';
        }
    } catch (error) {
        statusBarItem.text = '$(error) BlockSecOps';
        outputChannel.appendLine(`Workspace scan error: ${error}`);
    }
}

function isSolidityFile(document: vscode.TextDocument): boolean {
    return document.languageId === 'solidity' || document.fileName.endsWith('.sol');
}

export function deactivate(): void {
    diagnosticsManager?.dispose();
}
