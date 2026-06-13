from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Service configuration.

    All variables use the NEOSHIELD_ prefix. Secrets are never logged.
    """

    model_config = SettingsConfigDict(
        env_prefix="NEOSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Public origin of the Next.js app, reachable inside the Docker network.
    web_url: str = "http://localhost:3000"

    # Issued in the web UI (Settings -> Worker tokens) or by the bootstrap call.
    # The plaintext token only lives in this process's environment/memory.
    worker_token: str | None = None

    # Optional first-boot registration. Prefer issuing the token in the UI.
    bootstrap_token: str | None = None
    workspace_id: str | None = None
    worker_name: str = "neoshield-worker"

    # Direct database access with the restricted worker role. Drizzle in the
    # web app remains the only migration authority.
    database_url: str | None = None

    # GitHub App used to mint short-lived installation tokens for tarballs.
    github_app_id: str | None = None
    github_app_private_key: str | None = None

    # Operational tuning.
    heartbeat_interval_seconds: int = 30
    request_timeout_seconds: float = 10.0
    log_level: str = "INFO"

    # Scanner provisioning. Binaries are pinned and fetched on startup.
    scanner_dir: str = "/opt/neoshield/scanners"
    scanner_auto_install: bool = True

    # Job loop.
    job_poll_interval_seconds: float = 5.0
    job_lease_seconds: int = 600
    job_max_attempts_default: int = 3

    # Safety limits (stricter Phase 1 profile, chosen by the operator).
    max_archive_bytes: int = 50 * 1024 * 1024
    max_extracted_files: int = 5000
    max_file_bytes: int = 5 * 1024 * 1024
    max_extracted_bytes: int = 200 * 1024 * 1024
    tool_timeout_seconds: int = 180
    stale_finding_absences: int = 2

    @property
    def github_private_key(self) -> str | None:
        if not self.github_app_private_key:
            return None
        return self.github_app_private_key.replace("\\n", "\n")


@lru_cache
def get_settings() -> Settings:
    return Settings()
