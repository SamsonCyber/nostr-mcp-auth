"""Hard-fail serve policy for open / trust_proxy without force flags."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from nostr_mcp_auth.cli import main
from nostr_mcp_auth.config import AuthConfig, load_config, serve_policy_errors
from nostr_mcp_auth.crypto import generate_private_key_hex, npub_encode, xonly_pubkey_hex


def test_safe_defaults_no_policy_errors():
    cfg = AuthConfig(open=False, trust_proxy=False, allow_pubkeys={"a" * 64})
    assert serve_policy_errors(cfg) == []


def test_open_true_blocked_without_force():
    cfg = AuthConfig(open=True, trust_proxy=False)
    errs = serve_policy_errors(cfg)
    assert len(errs) == 1
    assert "open" in errs[0]
    assert "--force-open" in errs[0]


def test_open_true_allowed_with_force():
    cfg = AuthConfig(open=True)
    assert serve_policy_errors(cfg, force_open=True) == []


def test_trust_proxy_blocked_without_force():
    cfg = AuthConfig(trust_proxy=True)
    errs = serve_policy_errors(cfg)
    assert len(errs) == 1
    assert "trust_proxy" in errs[0]
    assert "--force-trust-proxy" in errs[0]


def test_trust_proxy_allowed_with_force():
    cfg = AuthConfig(trust_proxy=True)
    assert serve_policy_errors(cfg, force_trust_proxy=True) == []


def test_both_footguns_two_errors():
    cfg = AuthConfig(open=True, trust_proxy=True)
    errs = serve_policy_errors(cfg)
    assert len(errs) == 2
    assert serve_policy_errors(cfg, force_open=True, force_trust_proxy=True) == []


def test_load_config_open_still_sets_flag():
    """Policy does not change runtime auth semantics; only serve entry."""
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    cfg = load_config(raw={"auth": {"open": True, "allow_npubs": []}})
    assert cfg.open is True
    assert cfg.is_authorized(pk) == (True, "open")
    assert serve_policy_errors(cfg)


def _write_cfg(tmp: Path, **auth) -> Path:
    data = {
        "auth": {
            "open": False,
            "trust_proxy": False,
            "allow_npubs": [],
            **auth,
        },
        "server": {"host": "127.0.0.1", "port": 18787},
    }
    p = tmp / "mcp-auth.yaml"
    p.write_text(yaml.dump(data), encoding="utf-8")
    return p


def test_cli_serve_refuses_open(tmp_path: Path, monkeypatch):
    cfg_path = _write_cfg(tmp_path, open=True)
    # never actually bind
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("run")))
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--config", str(cfg_path)])
    assert result.exit_code != 0
    assert "force-open" in result.output or "REFUSE" in result.output or "open" in result.output


def test_cli_serve_refuses_trust_proxy(tmp_path: Path, monkeypatch):
    cfg_path = _write_cfg(tmp_path, trust_proxy=True)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("run")))
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--config", str(cfg_path)])
    assert result.exit_code != 0
    assert "trust_proxy" in result.output or "REFUSE" in result.output


def test_cli_serve_allows_safe_config(tmp_path: Path, monkeypatch):
    npub = npub_encode(xonly_pubkey_hex(generate_private_key_hex()))
    cfg_path = _write_cfg(tmp_path, allow_npubs=[npub])
    called: list[tuple] = []

    def fake_run(app, host, port, log_level="info"):
        called.append((host, port, log_level))

    monkeypatch.setattr("uvicorn.run", fake_run)
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    assert called
    assert called[0][0] == "127.0.0.1"


def test_cli_serve_open_with_force_flag(tmp_path: Path, monkeypatch):
    cfg_path = _write_cfg(tmp_path, open=True)
    called: list = []

    def fake_run(*a, **k):
        called.append(True)

    monkeypatch.setattr("uvicorn.run", fake_run)
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--config", str(cfg_path), "--force-open"])
    assert result.exit_code == 0, result.output
    assert called
    assert "open=true" in result.output.lower() or "force-open" in result.output.lower()
