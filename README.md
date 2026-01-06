# BlockSecOps CLI

Command-line interface for BlockSecOps smart contract security scanning.

## Installation

```bash
pip install blocksecops-cli
```

## Quick Start

1. **Authenticate with your API key:**
   ```bash
   blocksecops auth login
   ```

2. **Scan a smart contract:**
   ```bash
   blocksecops scan run contract.sol
   ```

3. **Get scan results:**
   ```bash
   blocksecops scan results <scan-id>
   ```

## Commands

### Authentication

```bash
# Login with API key
blocksecops auth login

# Check authentication status
blocksecops auth status

# Show current user info
blocksecops auth whoami

# Logout
blocksecops auth logout
```

### Scanning

```bash
# Scan a contract file
blocksecops scan run contract.sol

# Scan with specific output format
blocksecops scan run contract.sol --output json
blocksecops scan run contract.sol --output sarif
blocksecops scan run contract.sol --output junit

# Save results to file
blocksecops scan run contract.sol --output sarif --output-file results.sarif

# Fail on specific severity level
blocksecops scan run contract.sol --fail-on high

# Use specific scanners
blocksecops scan run contract.sol --scanner slither --scanner aderyn

# Start scan without waiting
blocksecops scan run contract.sol --no-wait

# Check scan status
blocksecops scan status <scan-id>

# Get results for completed scan
blocksecops scan results <scan-id>

# List recent scans
blocksecops scan list
```

## Output Formats

- **table** (default): Rich terminal output with colors
- **json**: Machine-readable JSON format
- **sarif**: Static Analysis Results Interchange Format for CI/CD integration
- **junit**: JUnit XML format for test reporting

## Pre-commit Integration

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/blocksecops/blocksecops-cli
    rev: v0.1.0
    hooks:
      - id: blocksecops-scan
```

Or use the standalone hook:

```bash
# Copy the hook to your repo
cp hooks/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Environment Variables

- `BLOCKSECOPS_API_KEY`: API key for authentication
- `BLOCKSECOPS_API_URL`: Custom API URL (default: https://api.blocksecops.com)
- `BLOCKSECOPS_FAIL_ON`: Default severity threshold for pre-commit hooks (default: high)

## Configuration

Configuration is stored in:
- Linux/macOS: `~/.config/blocksecops/`
- Windows: `%APPDATA%\blocksecops\`

API keys are stored securely using the system keyring.

## License

MIT License
