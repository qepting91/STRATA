"""Application settings, loaded from environment / .env via pydantic-settings."""

from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """STRATA runtime configuration.

    Values are sourced from environment variables and, if present, a local
    ``.env`` file (gitignored — see SECURITY.md for secrets handling).
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    nvd_api_key: SecretStr | None = None
    data_dir: Path = Path("data")
    db_path: Path = Path("data/strata.db")
    allowlist_path: Path = Path("config/allowlist.txt")
    sources_config_path: Path = Path("config/sources.toml")
    offline: bool = False

    @model_validator(mode="after")
    def _default_db_path(self) -> Settings:
        """Default db_path to data_dir/strata.db unless overridden."""
        if self.db_path == Path("data/strata.db") and self.data_dir != Path("data"):
            self.db_path = self.data_dir / "strata.db"
        return self


def get_settings() -> Settings:
    """Return a freshly loaded Settings instance."""
    return Settings()
