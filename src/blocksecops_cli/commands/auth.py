"""Authentication commands."""

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from ..api.client import APIError, AuthenticationError, BlockSecOpsClient
from ..config import clear_api_key, get_api_key, get_api_url, set_api_key, set_api_url

app = typer.Typer(help="Authentication commands")
console = Console()


@app.command()
def login(
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        "-k",
        help="API key (will prompt if not provided)",
        hide_input=True,
    ),
    api_url: Optional[str] = typer.Option(
        None,
        "--api-url",
        "-u",
        help="API URL (defaults to production)",
    ),
):
    """Authenticate with the BlockSecOps API."""
    if api_url:
        set_api_url(api_url)
        console.print(f"[dim]API URL set to: {api_url}[/dim]")

    if not api_key:
        api_key = typer.prompt("Enter your API key", hide_input=True)

    if not api_key:
        console.print("[red]Error: API key is required[/red]")
        raise typer.Exit(1)

    # Validate the API key
    console.print("[dim]Validating API key...[/dim]")

    async def validate():
        client = BlockSecOpsClient(api_key=api_key)
        return await client.validate_api_key(api_key)

    try:
        is_valid = asyncio.run(validate())
    except Exception as e:
        console.print(f"[red]Error connecting to API: {e}[/red]")
        raise typer.Exit(1)

    if not is_valid:
        console.print("[red]Invalid API key[/red]")
        raise typer.Exit(1)

    # Store the API key
    set_api_key(api_key)
    console.print("[green]Successfully authenticated![/green]")


@app.command()
def logout():
    """Remove stored credentials."""
    clear_api_key()
    console.print("[green]Logged out successfully[/green]")


@app.command()
def whoami():
    """Show current user information."""
    api_key = get_api_key()
    if not api_key:
        console.print("[yellow]Not logged in. Run 'blocksecops auth login' first.[/yellow]")
        raise typer.Exit(1)

    async def get_user():
        client = BlockSecOpsClient()
        return await client.whoami()

    try:
        user = asyncio.run(get_user())
    except AuthenticationError as e:
        console.print(f"[red]Authentication error: {e}[/red]")
        console.print("[dim]Try running 'blocksecops auth login' to re-authenticate[/dim]")
        raise typer.Exit(1)
    except APIError as e:
        console.print(f"[red]API error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    panel_content = f"""
[bold]Email:[/bold] {user.email}
[bold]User ID:[/bold] {user.id}
[bold]Plan:[/bold] {user.plan or 'free'}
[bold]API URL:[/bold] {get_api_url()}
"""

    console.print(Panel(panel_content.strip(), title="Current User", border_style="blue"))


@app.command()
def status():
    """Check authentication status and API connectivity."""
    api_key = get_api_key()
    api_url = get_api_url()

    console.print(f"[bold]API URL:[/bold] {api_url}")

    if not api_key:
        console.print("[yellow]Status: Not authenticated[/yellow]")
        console.print("[dim]Run 'blocksecops auth login' to authenticate[/dim]")
        raise typer.Exit(0)

    console.print("[dim]Checking API connectivity...[/dim]")

    async def check():
        client = BlockSecOpsClient()
        return await client.whoami()

    try:
        user = asyncio.run(check())
        console.print(f"[green]Status: Authenticated as {user.email}[/green]")
    except AuthenticationError:
        console.print("[red]Status: API key invalid or expired[/red]")
        console.print("[dim]Run 'blocksecops auth login' to re-authenticate[/dim]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Status: Connection error - {e}[/red]")
        raise typer.Exit(1)
