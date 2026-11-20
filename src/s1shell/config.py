"""Runtime configuration, filesystem paths, and conservative operational defaults."""

from __future__ import annotations

import contextlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from s1shell import __version__

DEFAULT_PROJECT_URL = "https://github.com/willygailo/ProjectPY"
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB
DEFAULT_MAX_CONCURRENCY = 1
DEFAULT_CVE_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
DEFAULT_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_AI_PROVIDER = "anthropic"
DEFAULT_OLLAMA_API_URL = "http://127.0.0.1:11434/v1/chat/completions"
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"
DEFAULT_OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_OSV_API_URL = "https://api.osv.dev/v1/querybatch"
DEFAULT_GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
DEFAULT_VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
DEFAULT_GREYNOISE_API_URL = "https://api.greynoise.io/v3/community"
DEFAULT_URLSCAN_API_URL = "https://urlscan.io/api/v1/search/"
DEFAULT_CRTSH_API_URL = "https://crt.sh/"
DEFAULT_RDAP_BASE_URL = "https://rdap.org"
DEFAULT_TOR_SOCKS_URL = "socks5h://127.0.0.1:9050"
DEFAULT_TOR_DOH_URL = "https://cloudflare-dns.com/dns-query"
SUPPORTED_AI_PROVIDERS = ("anthropic", "ollama", "openai_compat", "gemini")


def parse_dotenv(text: str) -> dict[str, str]:
    """Parse simple KEY=VALUE lines from a `.env` file."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[6:].lstrip()
        if "=" not in line:
            continue
        key, raw_val = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        val = raw_val.strip()
        if len(val) >= 2 and (
            (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")
        ):
            val = val[1:-1]
        values[key] = val
    return values


def load_dotenv_file(path: Path) -> dict[str, str]:
    """Load variables from a `.env` file if readable, returning `{}` otherwise."""
    try:
        if not path.is_file():
            return {}
        return parse_dotenv(path.read_text(encoding="utf-8"))
    except OSError:
        return {}


def mask_api_key(key: str) -> str:
    """Return a redacted preview of an API key suitable for terminal/report output."""
    stripped = key.strip()
    if len(stripped) > 14:
        return f"{stripped[:10]}...{stripped[-4:]}"
    return "***"


def classify_anthropic_key(key: str | None) -> str:
    """Classify an Anthropic API key as `unset`, `admin`, `standard`, or `custom`."""
    if not key or not key.strip():
        return "unset"
    stripped = key.strip()
    if stripped.startswith("sk-ant-admin"):
        return "admin"
    if stripped.startswith("sk-ant-api") or stripped.startswith("sk-ant-"):
        return "standard"
    return "custom"


def resolve_home_dir(home_override: Path | str | None = None) -> Path:
    """Determine the S1shell state directory (`--home` > `S1SHELL_HOME` > `~/.s1shell`)."""
    if home_override is not None:
        return Path(home_override).expanduser().resolve()
    env_home = os.environ.get("S1SHELL_HOME")
    if env_home and env_home.strip():
        return Path(env_home).expanduser().resolve()
    return (Path.home() / ".s1shell").resolve()


def ensure_private_dir(path: Path) -> Path:
    """Create a directory if needed and tighten permissions to owner-only (0700)."""
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)
    return path


def chmod_private_file(path: Path) -> None:
    """Tighten file permissions to owner read/write only (0600)."""
    if path.exists():
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)


def atomic_write_private(
    path: Path,
    content: str,
    *,
    private_parent: bool = False,
) -> None:
    """Atomically write UTF-8 text to `path` with owner-only `0600` permissions from creation."""
    if private_parent:
        ensure_private_dir(path.parent)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp_path, flags, 0o600)
    fd_owned = True
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd_owned = False
            handle.write(content)
            handle.flush()
            with contextlib.suppress(OSError):
                os.fsync(handle.fileno())
        chmod_private_file(tmp_path)
        os.replace(tmp_path, path)
    except BaseException:
        if fd_owned:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


@dataclass(frozen=True)
class RuntimeConfig:
    """Immutable runtime settings passed across S1shell services."""

    home_dir: Path
    scope_file: Path
    audit_log: Path
    cache_db: Path
    env_file: Path
    project_env_file: Path | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY
    cve_cache_ttl_seconds: int = DEFAULT_CVE_CACHE_TTL_SECONDS
    project_url: str = DEFAULT_PROJECT_URL
    anthropic_api_url: str = DEFAULT_ANTHROPIC_API_URL
    ollama_api_url: str = DEFAULT_OLLAMA_API_URL
    openai_api_url: str = DEFAULT_OPENAI_API_URL
    gemini_api_url: str = DEFAULT_GEMINI_API_URL
    cisa_kev_url: str = DEFAULT_CISA_KEV_URL
    epss_api_url: str = DEFAULT_EPSS_API_URL
    osv_api_url: str = DEFAULT_OSV_API_URL
    github_advisories_url: str = DEFAULT_GITHUB_ADVISORIES_URL
    virustotal_api_url: str = DEFAULT_VIRUSTOTAL_API_URL
    greynoise_api_url: str = DEFAULT_GREYNOISE_API_URL
    urlscan_api_url: str = DEFAULT_URLSCAN_API_URL
    crtsh_api_url: str = DEFAULT_CRTSH_API_URL
    rdap_base_url: str = DEFAULT_RDAP_BASE_URL
    tor_enabled: bool = False
    tor_targets: bool = False
    tor_proxy: str = DEFAULT_TOR_SOCKS_URL
    tor_doh_url: str = DEFAULT_TOR_DOH_URL

    @classmethod
    def from_env(
        cls,
        home_override: Path | str | None = None,
        scope_file_override: Path | str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        tor_enabled: bool | None = None,
        tor_targets: bool | None = None,
        tor_proxy: str | None = None,
    ) -> RuntimeConfig:
        """Build a RuntimeConfig honoring CLI overrides and environment variables."""
        home = resolve_home_dir(home_override)
        scope_path = (
            Path(scope_file_override).expanduser().resolve()
            if scope_file_override is not None
            else home / "scope.yaml"
        )
        env_home = os.environ.get("S1SHELL_HOME", "").strip()
        project_env = (
            (Path.cwd() / ".env").resolve() if (home_override is None and not env_home) else None
        )
        env_tor = os.environ.get("S1SHELL_TOR", "").strip().lower() in {"1", "true", "yes", "on"}
        env_tor_targets = os.environ.get("S1SHELL_TOR_TARGETS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        env_tor_proxy = os.environ.get("S1SHELL_TOR_PROXY", "").strip()
        resolved_tor = env_tor if tor_enabled is None else bool(tor_enabled)
        resolved_tor_targets = env_tor_targets if tor_targets is None else bool(tor_targets)
        resolved_tor_proxy = (
            tor_proxy.strip()
            if tor_proxy and tor_proxy.strip()
            else (env_tor_proxy or DEFAULT_TOR_SOCKS_URL)
        )
        return cls(
            home_dir=home,
            scope_file=scope_path,
            audit_log=home / "audit.log",
            cache_db=home / "cache.db",
            env_file=home / ".env",
            project_env_file=project_env,
            timeout_seconds=timeout_seconds,
            tor_enabled=resolved_tor,
            tor_targets=resolved_tor_targets,
            tor_proxy=resolved_tor_proxy,
        )

    def get_env_var(self, name: str) -> tuple[str | None, str]:
        """Resolve an environment variable from process env, project `.env`, or home `.env`."""
        env_val = os.environ.get(name, "").strip()
        if env_val:
            return env_val, "environment"
        if self.project_env_file is not None:
            proj_val = load_dotenv_file(self.project_env_file).get(name, "").strip()
            if proj_val:
                return proj_val, str(self.project_env_file)
        home_val = load_dotenv_file(self.env_file).get(name, "").strip()
        if home_val:
            return home_val, str(self.env_file)
        return None, "unset"

    def get_nvd_api_key(self) -> tuple[str | None, str]:
        """Resolve `NVD_API_KEY` across process env and `.env` files."""
        return self.get_env_var("NVD_API_KEY")

    def get_github_token(self) -> tuple[str | None, str]:
        """Resolve `GITHUB_TOKEN` across process env and `.env` files."""
        return self.get_env_var("GITHUB_TOKEN")

    def get_virustotal_api_key(self) -> tuple[str | None, str]:
        """Resolve `VIRUSTOTAL_API_KEY` across process env and `.env` files."""
        return self.get_env_var("VIRUSTOTAL_API_KEY")

    def get_greynoise_api_key(self) -> tuple[str | None, str]:
        """Resolve `GREYNOISE_API_KEY` across process env and `.env` files."""
        return self.get_env_var("GREYNOISE_API_KEY")

    def get_urlscan_api_key(self) -> tuple[str | None, str]:
        """Resolve `URLSCAN_API_KEY` across process env and `.env` files."""
        return self.get_env_var("URLSCAN_API_KEY")

    def get_anthropic_api_key(self) -> tuple[str | None, str]:
        """Resolve `ANTHROPIC_API_KEY` and return `(value, source)`."""
        return self.get_env_var("ANTHROPIC_API_KEY")

    def get_anthropic_model(self) -> str:
        """Resolve `ANTHROPIC_MODEL` or return the default Anthropic model."""
        model, _ = self.get_env_var("ANTHROPIC_MODEL")
        return model or DEFAULT_ANTHROPIC_MODEL

    def get_ai_provider(self) -> str:
        """Resolve active AI provider (`anthropic`, `ollama`, `openai_compat`, `gemini`)."""
        provider, _ = self.get_env_var("S1SHELL_AI_PROVIDER")
        norm = (provider or DEFAULT_AI_PROVIDER).strip().lower()
        return norm if norm in SUPPORTED_AI_PROVIDERS else DEFAULT_AI_PROVIDER

    def get_ai_base_url(self, provider: str | None = None) -> str:
        """Resolve endpoint URL for the given AI provider."""
        prov = (provider or self.get_ai_provider()).strip().lower()
        override, _ = self.get_env_var("S1SHELL_AI_BASE_URL")
        if override:
            return override
        if prov == "ollama":
            url, _ = self.get_env_var("OLLAMA_API_URL")
            return url or self.ollama_api_url
        if prov == "openai_compat":
            url, _ = self.get_env_var("OPENAI_API_URL")
            return url or self.openai_api_url
        if prov == "gemini":
            url, _ = self.get_env_var("GEMINI_API_URL")
            return url or self.gemini_api_url
        return self.anthropic_api_url

    def get_ai_api_key(self, provider: str | None = None) -> tuple[str | None, str]:
        """Resolve API key and source for the requested AI provider."""
        prov = (provider or self.get_ai_provider()).strip().lower()
        if prov == "anthropic":
            return self.get_anthropic_api_key()
        if prov == "openai_compat":
            return self.get_env_var("OPENAI_API_KEY")
        if prov == "gemini":
            return self.get_env_var("GEMINI_API_KEY")
        if prov == "ollama":
            return self.get_env_var("OLLAMA_API_KEY")
        return None, "unset"

    def get_ai_model(self, provider: str | None = None) -> str:
        """Resolve default model ID for the requested AI provider."""
        prov = (provider or self.get_ai_provider()).strip().lower()
        if prov == "anthropic":
            return self.get_anthropic_model()
        if prov == "ollama":
            model, _ = self.get_env_var("OLLAMA_MODEL")
            return model or DEFAULT_OLLAMA_MODEL
        if prov == "openai_compat":
            model, _ = self.get_env_var("OPENAI_MODEL")
            return model or DEFAULT_OPENAI_MODEL
        if prov == "gemini":
            model, _ = self.get_env_var("GEMINI_MODEL")
            return model or DEFAULT_GEMINI_MODEL
        return self.get_anthropic_model()

    @property
    def signatures_dir(self) -> Path:
        """Optional directory for user-supplied passive fingerprint YAML files."""
        return self.home_dir / "signatures.d"

    @property
    def skills_dir(self) -> Path:
        """Optional directory for user-supplied defensive AI skill YAML files."""
        return self.home_dir / "skills.d"

    @property
    def user_agent(self) -> str:
        """Standard honest User-Agent required on every outbound HTTP request."""
        return f"S1shell/{__version__} (authorized assessment; +{self.project_url})"
