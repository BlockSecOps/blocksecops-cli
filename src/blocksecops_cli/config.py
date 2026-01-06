"""Configuration management for BlockSecOps CLI."""

import json
import os
from pathlib import Path
from typing import Optional

import keyring
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

# Constants
APP_NAME = "blocksecops"
CONFIG_DIR = Path.home() / ".blocksecops"
CONFIG_FILE = CONFIG_DIR / "config.json"


class Config(BaseModel):
    """User configuration stored in ~/.blocksecops/config.json"""
    api_url: str = Field(default="https://api.blocksecops.com")
    default_output: str = Field(default="table")  # table, json, sarif, junit
    default_severity_threshold: str = Field(default="high")  # critical, high, medium, low
    ci_mode: bool = Field(default=False)
    color: bool = Field(default=True)


class Settings(BaseSettings):
    """Environment-based settings (for CI/CD)."""
    blocksecops_api_key: Optional[str] = Field(default=None, alias="BLOCKSECOPS_API_KEY")
    blocksecops_api_url: Optional[str] = Field(default=None, alias="BLOCKSECOPS_API_URL")
    ci: bool = Field(default=False, alias="CI")

    class Config:
        env_file = ".env"
        extra = "ignore"


def get_config_dir() -> Path:
    """Get or create the config directory."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR


def load_config() -> Config:
    """Load configuration from file."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            data = json.load(f)
            return Config(**data)
    return Config()


def save_config(config: Config) -> None:
    """Save configuration to file."""
    get_config_dir()
    with open(CONFIG_FILE, "w") as f:
        json.dump(config.model_dump(), f, indent=2)


def get_api_key() -> Optional[str]:
    """
    Get API key from (in order of precedence):
    1. Environment variable BLOCKSECOPS_API_KEY
    2. System keyring
    """
    settings = Settings()

    # Check environment variable first
    if settings.blocksecops_api_key:
        return settings.blocksecops_api_key

    # Try keyring
    try:
        key = keyring.get_password(APP_NAME, "api_key")
        if key:
            return key
    except Exception:
        pass

    return None


def set_api_key(api_key: str) -> None:
    """Store API key in system keyring."""
    try:
        keyring.set_password(APP_NAME, "api_key", api_key)
    except Exception as e:
        # Fallback to file-based storage if keyring not available
        key_file = get_config_dir() / ".api_key"
        key_file.write_text(api_key)
        key_file.chmod(0o600)  # Read/write for owner only


def delete_api_key() -> None:
    """Remove API key from storage."""
    try:
        keyring.delete_password(APP_NAME, "api_key")
    except Exception:
        pass

    # Also remove file-based key if exists
    key_file = get_config_dir() / ".api_key"
    if key_file.exists():
        key_file.unlink()


def get_api_url() -> str:
    """Get API URL from config or environment."""
    settings = Settings()
    if settings.blocksecops_api_url:
        return settings.blocksecops_api_url

    config = load_config()
    return config.api_url


def is_ci_mode() -> bool:
    """Check if running in CI mode."""
    settings = Settings()
    if settings.ci:
        return True

    config = load_config()
    return config.ci_mode


def set_api_url(url: str) -> None:
    """Set API URL in config."""
    config = load_config()
    config.api_url = url
    save_config(config)


def clear_api_key() -> None:
    """Clear stored API key (alias for delete_api_key)."""
    delete_api_key()
