import * as vscode from 'vscode';
import { spawn } from 'child_process';
import { getConfiguration } from './configuration';

export interface SarifResult {
    $schema?: string;
    version: string;
    runs: SarifRun[];
}

export interface SarifRun {
    tool: {
        driver: {
            name: string;
            version?: string;
            rules?: SarifRule[];
        };
    };
    results: SarifResultItem[];
}

export interface SarifRule {
    id: string;
    name?: string;
    shortDescription?: { text: string };
    fullDescription?: { text: string };
    defaultConfiguration?: { level: string };
}

export interface SarifResultItem {
    ruleId: string;
    level: 'none' | 'note' | 'warning' | 'error';
    message: { text: string };
    locations?: SarifLocation[];
}

export interface SarifLocation {
    physicalLocation: {
        artifactLocation: { uri: string };
        region?: {
            startLine: number;
            startColumn?: number;
            endLine?: number;
            endColumn?: number;
        };
    };
}

export class ScanService {
    private outputChannel: vscode.OutputChannel;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
    }

    async scanFile(filePath: string): Promise<SarifResult | null> {
        const config = getConfiguration();
        return this.runScan([filePath], config.cliPath);
    }

    async scanWorkspace(workspacePath: string): Promise<SarifResult | null> {
        const config = getConfiguration();
        return this.runScan([workspacePath], config.cliPath);
    }

    private async runScan(targets: string[], cliPath: string): Promise<SarifResult | null> {
        return new Promise((resolve) => {
            const args = ['scan', 'run', ...targets, '--output', 'sarif'];

            this.outputChannel.appendLine(`Running: ${cliPath} ${args.join(' ')}`);

            const process = spawn(cliPath, args, {
                cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
            });

            let stdout = '';
            let stderr = '';

            process.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            process.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            process.on('close', (code) => {
                if (stderr) {
                    this.outputChannel.appendLine(`stderr: ${stderr}`);
                }

                if (code === 0 || code === 1) {
                    try {
                        const result = JSON.parse(stdout) as SarifResult;
                        this.outputChannel.appendLine(`Scan completed: ${result.runs?.[0]?.results?.length || 0} findings`);
                        resolve(result);
                    } catch (e) {
                        this.outputChannel.appendLine(`Failed to parse scan results: ${e}`);
                        resolve(null);
                    }
                } else {
                    this.outputChannel.appendLine(`Scan failed with exit code: ${code}`);
                    resolve(null);
                }
            });

            process.on('error', (err) => {
                this.outputChannel.appendLine(`Failed to run blocksecops: ${err.message}`);
                vscode.window.showErrorMessage(
                    `Failed to run blocksecops-cli. Make sure it is installed and in your PATH.`
                );
                resolve(null);
            });
        });
    }
}
