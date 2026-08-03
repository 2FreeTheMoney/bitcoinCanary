"""Environment-driven configuration.

canaryEW deploys under systemd with an ``EnvironmentFile``, so configuration
is read from ``CANARYEW_*`` environment variables rather than a config-file
format.

The CLI reads the same file systemd does: when run outside systemd,
``/etc/canaryew/canaryew.env`` (override with ``CANARYEW_ENV_FILE``) is
loaded first, with real environment variables taking precedence. Without
this, every hand-run command -- ``pgp-import``, ``test-alert``, ``import``
-- would silently see defaults instead of the operator's configuration,
because systemd is the only thing that loads an EnvironmentFile. This keeps the config surface
greppable in one place and avoids inventing a parser in a security tool.

What belongs where:

- **Sealed store** (needs the passphrase): SMTP password. Anything an attacker
  could use to impersonate the operator.
- **Environment / EnvironmentFile (0600, root-readable only)**: everything
  else, including the brrr webhook secret. The brrr secret is *deliberately*
  outside the sealed store because the LOCKED boot notice must be deliverable
  before the passphrase is available (DESIGN S6). The accepted trade: an
  attacker who reads it can send noise to the operator's phone, but cannot
  fabricate an authenticated all-clear, which requires the sealed HMAC key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when configuration is malformed enough that startup must stop."""


DEFAULT_ENV_FILE = "/etc/canaryew/canaryew.env"


def _read_env_file(path: Path) -> dict[str, str]:
    """Parse an EnvironmentFile-style ``KEY=VALUE`` file.

    Tolerant by design: comments, blank lines, an optional ``export`` prefix,
    and single/double quotes around values are accepted; anything else is
    skipped. Only ``CANARYEW_*`` keys are taken -- this function must never
    become a way to inject arbitrary environment. An unreadable or missing
    file reads as empty rather than erroring, because the file legitimately
    does not exist on development machines.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    entries: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        if not key.startswith("CANARYEW_"):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        entries[key] = value
    return entries


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}.") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}.")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}.")


@dataclass(frozen=True)
class SmtpSettings:
    """Non-secret SMTP configuration. The password lives in the sealed store."""

    mode: str = "disabled"
    """One of ``smtp | console | file | disabled``. Console/file exist so the
    alert path can be exercised end-to-end without a mail server."""
    host: str = ""
    port: int = 587
    username: str = ""
    from_addr: str = ""
    to_addrs: tuple[str, ...] = ()
    starttls: bool = True
    """STARTTLS is mandatory in smtp mode unless the port is 465 (implicit TLS)."""
    timeout: float = 30.0
    file_path: str = ""
    """Where the ``file`` transport appends rendered messages."""
    helo_name: str = ""
    """Hostname announced in EHLO, and the Message-ID domain. Empty means
    derive it from the sender's domain -- see SmtpChannel._helo_name for why
    the library default is unusable on a typical Debian host."""


@dataclass(frozen=True)
class Config:
    """Resolved runtime configuration."""

    home: Path
    state_path: Path
    boot_state_path: Path
    snapshot_path: Path
    control_socket_path: Path

    bitcoin_rpc_url: str
    bitcoin_rpc_cookie_file: Path | None
    bitcoin_rpc_user: str
    bitcoin_rpc_password: str

    poll_interval_seconds: int
    heartbeat_interval_seconds: int
    redaction: str

    brrr_secret: str
    smtp: SmtpSettings = field(default_factory=SmtpSettings)
    pgp_recipient: str = ""
    gnupg_home: Path | None = None

    env_file: Path | None = None
    """Env file consulted, if any. Provenance matters: a config silently
    falling back to defaults looks identical to a config with nothing in it."""
    env_file_loaded: bool = False

    def describe_env_file(self) -> str:
        """One line stating where configuration came from."""
        if self.env_file is None:
            return "env file: none consulted (explicit environment only)"
        if self.env_file_loaded:
            return f"env file: {self.env_file} (loaded)"
        return f"env file: {self.env_file} (NOT FOUND OR UNREADABLE -- using defaults)"


def load_config(environ: dict[str, str] | None = None) -> Config:
    """Build a :class:`Config` from the environment plus the env file.

    Precedence: real environment variables beat the env file, which beats
    built-in defaults. With ``environ=None`` (production) the file at
    ``CANARYEW_ENV_FILE`` or :data:`DEFAULT_ENV_FILE` is consulted. An
    explicit ``environ`` (tests) is hermetic: no file is read unless that
    mapping itself sets ``CANARYEW_ENV_FILE``.
    """
    if environ is None:
        merged = dict(os.environ)
        env_file: str = merged.get("CANARYEW_ENV_FILE", DEFAULT_ENV_FILE)
    else:
        merged = dict(environ)
        env_file = merged.get("CANARYEW_ENV_FILE", "")
    loaded = False
    if env_file:
        entries = _read_env_file(Path(env_file))
        loaded = bool(entries)
        for key, value in entries.items():
            merged.setdefault(key, value)

    saved = os.environ.copy()
    os.environ.clear()
    os.environ.update(merged)
    try:
        config = _build_config()
    finally:
        os.environ.clear()
        os.environ.update(saved)

    return replace(
        config,
        env_file=Path(env_file) if env_file else None,
        env_file_loaded=loaded,
    )


def _build_config() -> Config:
    home = Path(_env("CANARYEW_HOME", str(Path.home() / ".canaryew"))).expanduser()

    cookie_raw = _env("CANARYEW_RPC_COOKIE_FILE", str(Path.home() / ".bitcoin/.cookie"))
    rpc_user = _env("CANARYEW_RPC_USER")
    rpc_password = _env("CANARYEW_RPC_PASSWORD")
    cookie_file: Path | None = None
    if not (rpc_user and rpc_password):
        cookie_file = Path(cookie_raw).expanduser()

    to_raw = _env("CANARYEW_SMTP_TO")
    smtp = SmtpSettings(
        mode=_env("CANARYEW_SMTP_MODE", "disabled").lower(),
        host=_env("CANARYEW_SMTP_HOST"),
        port=_env_int("CANARYEW_SMTP_PORT", 587),
        username=_env("CANARYEW_SMTP_USER"),
        from_addr=_env("CANARYEW_SMTP_FROM"),
        to_addrs=tuple(a.strip() for a in to_raw.split(",") if a.strip()),
        starttls=_env_bool("CANARYEW_SMTP_STARTTLS", True),
        timeout=float(_env_int("CANARYEW_SMTP_TIMEOUT_SECONDS", 30)),
        file_path=_env("CANARYEW_SMTP_FILE_PATH", str(home / "outbox.log")),
        helo_name=_env("CANARYEW_SMTP_HELO"),
    )

    redaction = _env("CANARYEW_REDACTION", "minimal").lower()
    if redaction not in ("minimal", "standard", "full"):
        raise ConfigError(
            f"CANARYEW_REDACTION must be minimal|standard|full, got {redaction!r}."
        )

    gnupg_raw = _env("CANARYEW_GNUPG_HOME", str(home / "gnupg"))

    return Config(
        home=home,
        state_path=Path(_env("CANARYEW_STATE_PATH", str(home / "state.json"))).expanduser(),
        boot_state_path=Path(
            _env("CANARYEW_BOOT_STATE_PATH", str(home / "boot.json"))
        ).expanduser(),
        snapshot_path=Path(
            _env("CANARYEW_SNAPSHOT_PATH", str(home / "status.json"))
        ).expanduser(),
        control_socket_path=Path(
            _env("CANARYEW_CONTROL_SOCKET", str(home / "control.sock"))
        ).expanduser(),
        bitcoin_rpc_url=_env("CANARYEW_RPC_URL", "http://127.0.0.1:8332"),
        bitcoin_rpc_cookie_file=cookie_file,
        bitcoin_rpc_user=rpc_user,
        bitcoin_rpc_password=rpc_password,
        poll_interval_seconds=_env_int("CANARYEW_POLL_INTERVAL_SECONDS", 600),
        heartbeat_interval_seconds=_env_int("CANARYEW_HEARTBEAT_INTERVAL_SECONDS", 21_600),
        redaction=redaction,
        brrr_secret=_env("CANARYEW_BRRR_SECRET"),
        smtp=smtp,
        pgp_recipient=_env("CANARYEW_PGP_RECIPIENT"),
        gnupg_home=Path(gnupg_raw).expanduser() if gnupg_raw else None,
    )
