"""
BlockSecOps - Sublime Text plugin for smart contract security scanning.

This plugin integrates blocksecops-cli with Sublime Text to provide
security scanning for Solidity files.
"""

import sublime
import sublime_plugin
import subprocess
import json
import os
import threading
from typing import List, Dict, Any, Optional


class BlockSecOpsScanCommand(sublime_plugin.TextCommand):
    """Command to scan the current file for security issues."""

    def run(self, edit: sublime.Edit) -> None:
        file_path = self.view.file_name()
        if not file_path:
            sublime.status_message("BlockSecOps: No file to scan")
            return

        if not file_path.endswith('.sol'):
            sublime.status_message("BlockSecOps: Only .sol files can be scanned")
            return

        # Run scan in background thread
        thread = threading.Thread(target=self._run_scan, args=(file_path,))
        thread.start()

    def _run_scan(self, file_path: str) -> None:
        sublime.status_message("BlockSecOps: Scanning...")

        settings = sublime.load_settings("BlockSecOps.sublime-settings")
        cli_path = settings.get("cli_path", "blocksecops")

        try:
            result = subprocess.run(
                [cli_path, "scan", "run", file_path, "--output", "sarif"],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode in (0, 1):
                findings = self._parse_sarif(result.stdout)
                sublime.set_timeout(
                    lambda: self._show_results(findings, file_path),
                    0
                )
            else:
                sublime.set_timeout(
                    lambda: sublime.status_message(
                        f"BlockSecOps: Scan failed with code {result.returncode}"
                    ),
                    0
                )

        except FileNotFoundError:
            sublime.set_timeout(
                lambda: sublime.error_message(
                    "BlockSecOps: blocksecops-cli not found.\n"
                    "Please install it and ensure it's in your PATH."
                ),
                0
            )
        except subprocess.TimeoutExpired:
            sublime.set_timeout(
                lambda: sublime.status_message("BlockSecOps: Scan timed out"),
                0
            )
        except Exception as e:
            sublime.set_timeout(
                lambda: sublime.status_message(f"BlockSecOps: Error - {str(e)}"),
                0
            )

    def _parse_sarif(self, sarif_json: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            sarif = json.loads(sarif_json)
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    finding = self._parse_finding(result)
                    if finding:
                        findings.append(finding)
        except json.JSONDecodeError:
            pass
        return findings

    def _parse_finding(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        locations = result.get("locations", [])
        if not locations:
            return None

        location = locations[0].get("physicalLocation", {})
        region = location.get("region", {})

        return {
            "rule_id": result.get("ruleId", "unknown"),
            "level": result.get("level", "warning"),
            "message": result.get("message", {}).get("text", ""),
            "line": region.get("startLine", 1),
            "column": region.get("startColumn", 1),
            "end_line": region.get("endLine", region.get("startLine", 1)),
        }

    def _show_results(self, findings: List[Dict[str, Any]], file_path: str) -> None:
        if not findings:
            sublime.status_message("BlockSecOps: No issues found")
            return

        # Add gutter marks
        self._add_gutter_marks(findings)

        # Show quick panel with results
        items = []
        for f in findings:
            level = f["level"].upper()
            line = f["line"]
            items.append([
                f"[{level}] {f['rule_id']}",
                f"Line {line}: {f['message']}"
            ])

        def on_select(index: int) -> None:
            if index >= 0:
                finding = findings[index]
                self._goto_finding(finding)

        sublime.status_message(f"BlockSecOps: {len(findings)} issue(s) found")
        self.view.window().show_quick_panel(items, on_select)

    def _add_gutter_marks(self, findings: List[Dict[str, Any]]) -> None:
        regions_error = []
        regions_warning = []
        regions_info = []

        for finding in findings:
            line = finding["line"] - 1
            region = self.view.line(self.view.text_point(line, 0))

            if finding["level"] == "error":
                regions_error.append(region)
            elif finding["level"] == "warning":
                regions_warning.append(region)
            else:
                regions_info.append(region)

        self.view.add_regions(
            "blocksecops_error",
            regions_error,
            "region.redish",
            "dot",
            sublime.DRAW_NO_FILL | sublime.DRAW_NO_OUTLINE
        )
        self.view.add_regions(
            "blocksecops_warning",
            regions_warning,
            "region.orangish",
            "dot",
            sublime.DRAW_NO_FILL | sublime.DRAW_NO_OUTLINE
        )
        self.view.add_regions(
            "blocksecops_info",
            regions_info,
            "region.bluish",
            "dot",
            sublime.DRAW_NO_FILL | sublime.DRAW_NO_OUTLINE
        )

    def _goto_finding(self, finding: Dict[str, Any]) -> None:
        line = finding["line"]
        column = finding.get("column", 1)
        point = self.view.text_point(line - 1, column - 1)
        self.view.sel().clear()
        self.view.sel().add(sublime.Region(point))
        self.view.show_at_center(point)


class BlockSecOpsScanWorkspaceCommand(sublime_plugin.WindowCommand):
    """Command to scan all Solidity files in the workspace."""

    def run(self) -> None:
        folders = self.window.folders()
        if not folders:
            sublime.status_message("BlockSecOps: No folder open")
            return

        # Find all .sol files
        sol_files = []
        for folder in folders:
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith('.sol'):
                        sol_files.append(os.path.join(root, file))

        if not sol_files:
            sublime.status_message("BlockSecOps: No Solidity files found")
            return

        # Run scan in background
        thread = threading.Thread(
            target=self._run_workspace_scan,
            args=(folders[0], sol_files)
        )
        thread.start()

    def _run_workspace_scan(self, folder: str, files: List[str]) -> None:
        sublime.status_message(f"BlockSecOps: Scanning {len(files)} files...")

        settings = sublime.load_settings("BlockSecOps.sublime-settings")
        cli_path = settings.get("cli_path", "blocksecops")

        try:
            result = subprocess.run(
                [cli_path, "scan", "run", folder, "--output", "sarif"],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode in (0, 1):
                findings_count = result.stdout.count('"ruleId"')
                sublime.set_timeout(
                    lambda: sublime.status_message(
                        f"BlockSecOps: Scan complete - {findings_count} issue(s) found"
                    ),
                    0
                )
            else:
                sublime.set_timeout(
                    lambda: sublime.status_message(
                        f"BlockSecOps: Scan failed with code {result.returncode}"
                    ),
                    0
                )

        except Exception as e:
            sublime.set_timeout(
                lambda: sublime.status_message(f"BlockSecOps: Error - {str(e)}"),
                0
            )


class BlockSecOpsClearMarkersCommand(sublime_plugin.TextCommand):
    """Command to clear all BlockSecOps gutter markers."""

    def run(self, edit: sublime.Edit) -> None:
        self.view.erase_regions("blocksecops_error")
        self.view.erase_regions("blocksecops_warning")
        self.view.erase_regions("blocksecops_info")
        sublime.status_message("BlockSecOps: Markers cleared")


class BlockSecOpsEventListener(sublime_plugin.EventListener):
    """Event listener for automatic scanning on save."""

    def on_post_save_async(self, view: sublime.View) -> None:
        settings = sublime.load_settings("BlockSecOps.sublime-settings")
        if not settings.get("scan_on_save", False):
            return

        file_path = view.file_name()
        if file_path and file_path.endswith('.sol'):
            view.run_command("block_sec_ops_scan")
