import * as vscode from 'vscode';

export interface BlockSecOpsConfig {
    cliPath: string;
    scanOnSave: boolean;
    outputFormat: 'sarif' | 'json' | 'table';
    severityThreshold: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

export function getConfiguration(): BlockSecOpsConfig {
    const config = vscode.workspace.getConfiguration('blocksecops');

    return {
        cliPath: config.get<string>('cliPath', 'blocksecops'),
        scanOnSave: config.get<boolean>('scanOnSave', true),
        outputFormat: config.get<'sarif' | 'json' | 'table'>('outputFormat', 'sarif'),
        severityThreshold: config.get<'info' | 'low' | 'medium' | 'high' | 'critical'>('severityThreshold', 'low'),
    };
}

export function onConfigurationChange(callback: () => void): vscode.Disposable {
    return vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration('blocksecops')) {
            callback();
        }
    });
}
