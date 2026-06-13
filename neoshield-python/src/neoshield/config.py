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

    # Domain checks (DNS, TLS, redirects, security headers).
    domain_timeout_seconds: float = 15.0
    domain_max_redirects: int = 5
    domain_certificate_warning_days: int = 30

    # ------------------------------------------------------------------
    # Wazuh endpoint monitoring (Phase 2)
    #
    # Credentials stay in this process's environment. The web UI never sees
    # them and only toggles ingestion for a project. The indexer and manager
    # ports must stay private (localhost or the Docker network).
    # ------------------------------------------------------------------
    wazuh_enabled: bool = False
    wazuh_indexer_url: str | None = None
    wazuh_indexer_username: str | None = None
    wazuh_indexer_password: str | None = None
    # Optional bearer token instead of basic auth (e.g. a read-only API key).
    wazuh_indexer_api_token: str | None = None
    wazuh_indexer_verify_tls: bool = True
    wazuh_indexer_ca_path: str | None = None
    wazuh_index_pattern: str = "wazuh-alerts-*"
    wazuh_min_level: int = 5
    wazuh_poll_interval_seconds: int = 60
    wazuh_initial_lookback_minutes: int = 60
    wazuh_endpoint_lookback_hours: int = 24
    wazuh_max_alerts_per_poll: int = 200
    wazuh_request_timeout_seconds: float = 20.0

    # Optional manager API for agent inventory/status. Alerts themselves come
    # from the indexer above.
    wazuh_manager_url: str | None = None
    wazuh_manager_username: str | None = None
    wazuh_manager_password: str | None = None
    wazuh_manager_verify_tls: bool = True

    # ------------------------------------------------------------------
    # Authorized network discovery (Phase 2)
    # ------------------------------------------------------------------
    nmap_path: str | None = None
    # Smallest network the worker will accept (/24 = at most 256 addresses).
    network_max_prefix_length: int = 24
    network_max_hosts: int = 256
    network_scan_timeout_seconds: int = 480
    network_host_timeout_seconds: int = 60
    network_max_output_bytes: int = 8 * 1024 * 1024
    # Service detection is capped so one broad range cannot occupy a worker.
    network_max_service_hosts: int = 64
    # Conservative, explicit port set. No top-1000 sweep, no NSE scripts.
    network_ports: str = (
        "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,2375,"
        "3306,3389,5432,5900,6379,8080,8443,9200,11211,27017"
    )
    # Kept false: public ranges are always refused. There is no UI override.
    network_allow_public: bool = False

    @property
    def wazuh_configured(self) -> bool:
        if not self.wazuh_enabled or not self.wazuh_indexer_url:
            return False
        return bool(
            self.wazuh_indexer_api_token
            or (self.wazuh_indexer_username and self.wazuh_indexer_password)
        )

    @property
    def wazuh_manager_configured(self) -> bool:
        return bool(
            self.wazuh_manager_url
            and self.wazuh_manager_username
            and self.wazuh_manager_password
        )

    @property
    def github_private_key(self) -> str | None:
        if not self.github_app_private_key:
            return None
        return self.github_app_private_key.replace("\\n", "\n")


@lru_cache
def get_settings() -> Settings:
    return Settings()
