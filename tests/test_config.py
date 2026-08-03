"""Configuration parsing: defaults, overrides, and rejection of nonsense."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew.config import ConfigError, load_config


def test_defaults_are_sane() -> None:
    config = load_config({})
    assert config.poll_interval_seconds == 600
    assert config.heartbeat_interval_seconds == 21_600
    assert config.redaction == "minimal"
    assert config.smtp.mode == "disabled"
    assert config.smtp.starttls is True
    assert config.bitcoin_rpc_url == "http://127.0.0.1:8332"
    assert config.bitcoin_rpc_cookie_file is not None  # cookie auth by default
    assert config.brrr_secret == ""


def test_overrides_and_paths_derive_from_home() -> None:
    config = load_config(
        {
            "CANARYEW_HOME": "/srv/canaryew",
            "CANARYEW_POLL_INTERVAL_SECONDS": "120",
            "CANARYEW_HEARTBEAT_INTERVAL_SECONDS": "3600",
            "CANARYEW_REDACTION": "standard",
            "CANARYEW_BRRR_SECRET": "br_usr_test",
        }
    )
    assert config.state_path == Path("/srv/canaryew/state.json")
    assert config.boot_state_path == Path("/srv/canaryew/boot.json")
    assert config.snapshot_path == Path("/srv/canaryew/status.json")
    assert config.control_socket_path == Path("/srv/canaryew/control.sock")
    assert config.gnupg_home == Path("/srv/canaryew/gnupg")
    assert config.poll_interval_seconds == 120
    assert config.redaction == "standard"
    assert config.brrr_secret == "br_usr_test"


def test_explicit_rpc_credentials_disable_cookie() -> None:
    config = load_config(
        {"CANARYEW_RPC_USER": "watcher", "CANARYEW_RPC_PASSWORD": "hunter2"}
    )
    assert config.bitcoin_rpc_cookie_file is None
    assert config.bitcoin_rpc_user == "watcher"


def test_smtp_recipient_list_parses() -> None:
    config = load_config(
        {
            "CANARYEW_SMTP_MODE": "smtp",
            "CANARYEW_SMTP_TO": "a@example.org, b@example.org,,",
        }
    )
    assert config.smtp.to_addrs == ("a@example.org", "b@example.org")


@pytest.mark.parametrize(
    "environ",
    [
        {"CANARYEW_POLL_INTERVAL_SECONDS": "not-a-number"},
        {"CANARYEW_POLL_INTERVAL_SECONDS": "0"},
        {"CANARYEW_REDACTION": "everything"},
        {"CANARYEW_SMTP_STARTTLS": "maybe"},
    ],
)
def test_malformed_config_fails_at_startup(environ: dict[str, str]) -> None:
    """Bad config must stop startup, not surface as odd behavior later."""
    with pytest.raises(ConfigError):
        load_config(environ)


# ---------------------------------------------------------------- env file --- #

def test_env_file_is_loaded_for_cli_use(tmp_path: Path) -> None:
    """Hand-run CLI commands must see the same config systemd loads."""
    env_file = tmp_path / "canaryew.env"
    env_file.write_text(
        "# comment line\n"
        "\n"
        "CANARYEW_HOME=/srv/canaryew\n"
        'CANARYEW_PGP_RECIPIENT="ops@example.org"\n'
        "export CANARYEW_POLL_INTERVAL_SECONDS=120\n"
        "PATH=/evil/bin\n"                    # non-CANARYEW keys ignored
        "not a key value line\n"
    )
    config = load_config({"CANARYEW_ENV_FILE": str(env_file)})
    assert config.home == Path("/srv/canaryew")
    assert config.pgp_recipient == "ops@example.org"   # quotes stripped
    assert config.poll_interval_seconds == 120         # export prefix ok


def test_real_environment_beats_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / "canaryew.env"
    env_file.write_text("CANARYEW_REDACTION=full\nCANARYEW_BRRR_SECRET=from-file\n")
    config = load_config(
        {"CANARYEW_ENV_FILE": str(env_file), "CANARYEW_REDACTION": "minimal"}
    )
    assert config.redaction == "minimal"       # process env wins
    assert config.brrr_secret == "from-file"   # file fills the gaps


def test_missing_env_file_is_silently_ignored(tmp_path: Path) -> None:
    config = load_config({"CANARYEW_ENV_FILE": str(tmp_path / "absent.env")})
    assert config.redaction == "minimal"


def test_env_file_provenance_is_reported(tmp_path: Path) -> None:
    """A silent fallback to defaults is indistinguishable from empty config,
    so the loader records where configuration actually came from."""
    env_file = tmp_path / "canaryew.env"
    env_file.write_text("CANARYEW_BRRR_SECRET=abc\n")

    loaded = load_config({"CANARYEW_ENV_FILE": str(env_file)})
    assert loaded.env_file_loaded is True
    assert "(loaded)" in loaded.describe_env_file()

    missing = load_config({"CANARYEW_ENV_FILE": str(tmp_path / "absent.env")})
    assert missing.env_file_loaded is False
    assert "NOT FOUND" in missing.describe_env_file()

    none_consulted = load_config({})
    assert none_consulted.env_file is None
    assert "none consulted" in none_consulted.describe_env_file()


def test_explicit_environ_without_env_file_reads_no_file() -> None:
    """Tests and callers passing an explicit mapping stay hermetic even on a
    machine where /etc/canaryew/canaryew.env exists."""
    config = load_config({})
    assert config.brrr_secret == ""
