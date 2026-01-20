"""Scan commands."""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional
from uuid import UUID

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..api.client import APIError, AuthenticationError, BlockSecOpsClient
from ..config import get_api_key
from ..formatters import OutputFormat, get_formatter
from ..scanner import SolidityDefendScanner
from ..scanner.downloader import DownloadError

app = typer.Typer(help="Scan commands")
console = Console()

# Valid scan sources
VALID_SCAN_SOURCES = {"cli", "vscode", "jetbrains", "neovim", "vim", "github_actions", "web"}


def require_auth():
    """Check that user is authenticated."""
    if not get_api_key():
        console.print("[red]Not authenticated. Run 'blocksecops auth login' first.[/red]")
        raise typer.Exit(1)


@app.command("run")
def scan_run(
    path: Path = typer.Argument(
        ...,
        help="Path to contract file or directory",
        exists=True,
    ),
    local: bool = typer.Option(
        False,
        "--local",
        "-l",
        help="Run SolidityDefend locally (downloads latest from GitHub if needed)",
    ),
    scan_source: str = typer.Option(
        "cli",
        "--scan-source",
        help="Source identifier for tracking (cli, vscode, jetbrains, neovim, github_actions)",
    ),
    wait: bool = typer.Option(
        True,
        "--wait/--no-wait",
        "-w/-W",
        help="Wait for scan to complete",
    ),
    output: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--output",
        "-o",
        help="Output format",
    ),
    scanners: Optional[List[str]] = typer.Option(
        None,
        "--scanner",
        "-s",
        help="Specific scanners to use (can be repeated, ignored with --local)",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with error if vulnerabilities at this severity or higher (critical, high, medium, low)",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-f",
        help="Write output to file",
    ),
):
    """Scan a smart contract file or directory."""
    require_auth()

    if not path.exists():
        console.print(f"[red]Error: Path not found: {path}[/red]")
        raise typer.Exit(1)

    # Validate scan source
    if scan_source not in VALID_SCAN_SOURCES:
        console.print(
            f"[yellow]Warning: Unknown scan source '{scan_source}'. "
            f"Valid sources: {', '.join(sorted(VALID_SCAN_SOURCES))}[/yellow]"
        )

    if local:
        # Local scan workflow
        asyncio.run(_run_local_scan(path, scan_source, output, output_file, fail_on))
    else:
        # Remote scan workflow (existing behavior)
        asyncio.run(_run_remote_scan(path, scan_source, wait, output, scanners, output_file, fail_on))


async def _run_local_scan(
    path: Path,
    scan_source: str,
    output: OutputFormat,
    output_file: Optional[Path],
    fail_on: Optional[str],
):
    """Run SolidityDefend locally and submit results to API."""
    client = BlockSecOpsClient()
    scanner = SolidityDefendScanner()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        try:
            # Step 1: Check/download SolidityDefend
            task = progress.add_task("Checking SolidityDefend installation...", total=None)
            await scanner.downloader.ensure_latest()
            version = scanner.get_version()
            progress.update(task, description=f"SolidityDefend {version} ready")

            # Step 2: Upload contract to create contract record
            progress.update(task, description="Uploading contract...")
            upload = await client.upload_file(path)

            # Step 3: Create scan record with source
            progress.update(task, description="Creating scan record...")
            scan = await client.create_scan(
                upload.contract_id,
                scanners=["soliditydefend"],
                scan_source=scan_source,
            )

            # Step 4: Run local scan
            progress.update(task, description="Running SolidityDefend locally...")
            raw_results = await scanner.scan(path)

            # Step 5: Transform results
            progress.update(task, description="Processing results...")
            vulnerabilities = scanner.transform_results(raw_results)

            # Step 6: Submit results to API
            progress.update(task, description="Submitting results to API...")
            result = await client.submit_local_results(scan.id, vulnerabilities)

            # Step 7: Get final scan state
            progress.update(task, description="Finalizing...")
            scan = await client.get_scan(scan.id)

            progress.update(task, description="Scan complete!")

        except DownloadError as e:
            console.print(f"[red]Download error: {e}[/red]")
            raise typer.Exit(1)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    if scan.status == "failed":
        console.print(f"[red]Scan failed: {scan.error_message or 'Unknown error'}[/red]")
        raise typer.Exit(1)

    # Format output
    formatter = get_formatter(output)
    formatted = formatter.format_scan(scan, result)

    if output_file:
        output_file.write_text(formatted)
        console.print(f"[green]Results written to: {output_file}[/green]")
    else:
        console.print(formatted)

    # Check fail-on threshold
    if fail_on:
        exit_code = _check_fail_threshold(result, fail_on)
        if exit_code:
            raise typer.Exit(exit_code)


async def _run_remote_scan(
    path: Path,
    scan_source: str,
    wait: bool,
    output: OutputFormat,
    scanners: Optional[List[str]],
    output_file: Optional[Path],
    fail_on: Optional[str],
):
    """Run scan remotely via API (existing behavior with scan_source support)."""
    client = BlockSecOpsClient()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        # Upload
        task = progress.add_task("Uploading contract...", total=None)

        scan, result = await client.scan_file(
            path,
            wait=wait,
            scanners=scanners,
            scan_source=scan_source,
            progress_callback=lambda s: progress.update(
                task, description=f"Scan status: {s.status}"
            ),
        )

        progress.update(task, description="Scan complete!")

    if not wait:
        console.print(f"[green]Scan started: {scan.id}[/green]")
        console.print(f"[dim]Check status with: blocksecops scan status {scan.id}[/dim]")
        return

    if scan.status == "failed":
        console.print(f"[red]Scan failed: {scan.error_message or 'Unknown error'}[/red]")
        raise typer.Exit(1)

    if result is None:
        console.print("[yellow]Scan completed but no results available[/yellow]")
        return

    # Format output
    formatter = get_formatter(output)
    formatted = formatter.format_scan(scan, result)

    if output_file:
        output_file.write_text(formatted)
        console.print(f"[green]Results written to: {output_file}[/green]")
    else:
        console.print(formatted)

    # Check fail-on threshold
    if fail_on:
        exit_code = _check_fail_threshold(result, fail_on)
        if exit_code:
            raise typer.Exit(exit_code)


@app.command("status")
def scan_status(
    scan_id: str = typer.Argument(..., help="Scan ID to check"),
):
    """Check the status of a scan."""
    require_auth()

    try:
        uuid = UUID(scan_id)
    except ValueError:
        console.print(f"[red]Invalid scan ID: {scan_id}[/red]")
        raise typer.Exit(1)

    async def get_status():
        client = BlockSecOpsClient()
        return await client.get_scan(uuid)

    try:
        scan = asyncio.run(get_status())
    except AuthenticationError as e:
        console.print(f"[red]Authentication error: {e}[/red]")
        raise typer.Exit(1)
    except APIError as e:
        console.print(f"[red]API error: {e}[/red]")
        raise typer.Exit(1)

    status_colors = {
        "pending": "yellow",
        "running": "blue",
        "completed": "green",
        "failed": "red",
        "cancelled": "dim",
    }

    color = status_colors.get(scan.status, "white")
    console.print(f"[bold]Scan ID:[/bold] {scan.id}")
    console.print(f"[bold]Status:[/bold] [{color}]{scan.status.upper()}[/{color}]")

    if scan.started_at:
        console.print(f"[bold]Started:[/bold] {scan.started_at}")
    if scan.completed_at:
        console.print(f"[bold]Completed:[/bold] {scan.completed_at}")
    if scan.error_message:
        console.print(f"[bold]Error:[/bold] [red]{scan.error_message}[/red]")


@app.command("results")
def scan_results(
    scan_id: str = typer.Argument(..., help="Scan ID to get results for"),
    output: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--output",
        "-o",
        help="Output format",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-f",
        help="Write output to file",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with error if vulnerabilities at this severity or higher",
    ),
):
    """Get results for a completed scan."""
    require_auth()

    try:
        uuid = UUID(scan_id)
    except ValueError:
        console.print(f"[red]Invalid scan ID: {scan_id}[/red]")
        raise typer.Exit(1)

    async def get_results():
        client = BlockSecOpsClient()
        scan = await client.get_scan(uuid)
        result = await client.get_scan_results(uuid)
        return scan, result

    try:
        scan, result = asyncio.run(get_results())
    except AuthenticationError as e:
        console.print(f"[red]Authentication error: {e}[/red]")
        raise typer.Exit(1)
    except APIError as e:
        console.print(f"[red]API error: {e}[/red]")
        raise typer.Exit(1)

    if scan.status != "completed":
        console.print(f"[yellow]Scan status: {scan.status}. Results may not be available.[/yellow]")

    # Format output
    formatter = get_formatter(output)
    formatted = formatter.format_scan(scan, result)

    if output_file:
        output_file.write_text(formatted)
        console.print(f"[green]Results written to: {output_file}[/green]")
    else:
        console.print(formatted)

    # Check fail-on threshold
    if fail_on:
        exit_code = _check_fail_threshold(result, fail_on)
        if exit_code:
            raise typer.Exit(exit_code)


@app.command("list")
def scan_list(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of scans to show"),
):
    """List recent scans."""
    require_auth()

    async def list_scans():
        client = BlockSecOpsClient()
        contracts = await client.list_contracts(limit=limit)
        return contracts

    try:
        contracts = asyncio.run(list_scans())
    except AuthenticationError as e:
        console.print(f"[red]Authentication error: {e}[/red]")
        raise typer.Exit(1)
    except APIError as e:
        console.print(f"[red]API error: {e}[/red]")
        raise typer.Exit(1)

    if not contracts:
        console.print("[dim]No contracts found[/dim]")
        return

    from rich.table import Table

    table = Table(title="Recent Contracts")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Network")
    table.add_column("Created")

    for contract in contracts:
        table.add_row(
            str(contract.id)[:8],
            contract.name or "-",
            contract.network or "-",
            contract.created_at.strftime("%Y-%m-%d %H:%M") if contract.created_at else "-",
        )

    console.print(table)


def _check_fail_threshold(result, fail_on: str) -> int:
    """Check if results exceed fail threshold. Returns exit code."""
    thresholds = {
        "critical": (result.critical_count, 1),
        "high": (result.critical_count + result.high_count, 1),
        "medium": (
            result.critical_count + result.high_count + result.medium_count,
            1,
        ),
        "low": (
            result.critical_count
            + result.high_count
            + result.medium_count
            + result.low_count,
            1,
        ),
    }

    fail_on = fail_on.lower()
    if fail_on not in thresholds:
        console.print(f"[yellow]Warning: Unknown severity '{fail_on}', ignoring --fail-on[/yellow]")
        return 0

    count, exit_code = thresholds[fail_on]
    if count > 0:
        console.print(
            f"[red]Found vulnerabilities at or above {fail_on} severity[/red]"
        )
        return exit_code

    return 0
