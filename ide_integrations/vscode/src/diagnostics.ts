import * as vscode from 'vscode';
import { SarifResult, SarifResultItem } from './scanService';

export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('blocksecops');
    }

    updateDiagnostics(result: SarifResult): void {
        this.diagnosticCollection.clear();

        const diagnosticsByUri = new Map<string, vscode.Diagnostic[]>();

        for (const run of result.runs || []) {
            const rules = new Map(
                (run.tool?.driver?.rules || []).map((r) => [r.id, r])
            );

            for (const item of run.results || []) {
                const diagnostics = this.createDiagnosticsForResult(item, rules);

                for (const { uri, diagnostic } of diagnostics) {
                    const existing = diagnosticsByUri.get(uri) || [];
                    existing.push(diagnostic);
                    diagnosticsByUri.set(uri, existing);
                }
            }
        }

        for (const [uriString, diagnostics] of diagnosticsByUri) {
            const uri = vscode.Uri.file(uriString);
            this.diagnosticCollection.set(uri, diagnostics);
        }
    }

    private createDiagnosticsForResult(
        item: SarifResultItem,
        rules: Map<string, { shortDescription?: { text: string }; fullDescription?: { text: string } }>
    ): Array<{ uri: string; diagnostic: vscode.Diagnostic }> {
        const results: Array<{ uri: string; diagnostic: vscode.Diagnostic }> = [];

        for (const location of item.locations || []) {
            const physLoc = location.physicalLocation;
            if (!physLoc?.artifactLocation?.uri) {
                continue;
            }

            const uri = physLoc.artifactLocation.uri.replace('file://', '');
            const region = physLoc.region;

            const range = new vscode.Range(
                (region?.startLine || 1) - 1,
                (region?.startColumn || 1) - 1,
                (region?.endLine || region?.startLine || 1) - 1,
                (region?.endColumn || 999) - 1
            );

            const severity = this.mapSeverity(item.level);
            const rule = rules.get(item.ruleId);

            const message = item.message.text || rule?.shortDescription?.text || item.ruleId;

            const diagnostic = new vscode.Diagnostic(range, message, severity);
            diagnostic.source = 'blocksecops';
            diagnostic.code = item.ruleId;

            results.push({ uri, diagnostic });
        }

        return results;
    }

    private mapSeverity(level: string): vscode.DiagnosticSeverity {
        switch (level) {
            case 'error':
                return vscode.DiagnosticSeverity.Error;
            case 'warning':
                return vscode.DiagnosticSeverity.Warning;
            case 'note':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    clear(): void {
        this.diagnosticCollection.clear();
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
