"""BlockSecOps CLI - Command line interface for smart contract security scanning."""

import typer
from rich.console import Console

from .commands.auth import app as auth_app
from .commands.scan import app as scan_app

app = typer.Typer(
    name="blocksecops",
    help="BlockSecOps CLI - Smart contract security scanning",
    no_args_is_help=True,
)
console = Console()

# Add subcommands
app.add_typer(auth_app, name="auth")
app.add_typer(scan_app, name="scan")


@app.command()
def version():
    """Show version information."""
    from . import __version__

    console.print(f"blocksecops-cli version {__version__}")


@app.callback()
def main():
    """
    BlockSecOps CLI - Smart contract security scanning.

    Get started:

        blocksecops auth login    # Authenticate with your API key

        blocksecops scan run contract.sol    # Scan a contract

        blocksecops scan results <scan-id>   # Get scan results
    """
    pass


def cli():
    """CLI entry point."""
    app()


if __name__ == "__main__":
    cli()
