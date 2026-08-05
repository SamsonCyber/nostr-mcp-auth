"""CLI for operators and agents."""
from __future__ import annotations

import json
import os
from pathlib import Path

import click
import yaml

from . import __version__
from .client import call_tool, list_tools
from .config import default_config_dict, load_config
from .crypto import (
    generate_private_key_hex,
    npub_encode,
    nsec_encode,
    xonly_pubkey_hex,
)

DEFAULT_CONFIG_NAMES = ("mcp-auth.yaml", "mcp-auth.yml", ".mcp-auth/config.yaml")


def _find_config(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.is_file() else None
    for name in DEFAULT_CONFIG_NAMES:
        p = Path(name)
        if p.is_file():
            return p
    return None


def _write_secret(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


@click.group()
@click.version_option(__version__, prog_name="nostr-mcp-auth")
def main() -> None:
    """Nostr-authenticated HTTP MCP: fail-closed NIP-98 gate for agents."""


@main.command("quickstart")
@click.option(
    "--dir",
    "out_dir",
    type=click.Path(),
    default=".",
    show_default=True,
    help="Directory for nsec + config",
)
@click.option("--port", default=8787, show_default=True, type=int)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--force", is_flag=True, help="Overwrite existing files")
def quickstart(out_dir: str, port: int, host: str, force: bool) -> None:
    """One-shot: generate identity + config ready to serve.

    Creates caller.nsec, caller.npub, and mcp-auth.yaml with the new npub allowlisted.
    """
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    nsec_path = root / "caller.nsec"
    npub_path = root / "caller.npub"
    cfg_path = root / "mcp-auth.yaml"

    for p in (nsec_path, npub_path, cfg_path):
        if p.exists() and not force:
            raise click.ClickException(f"{p} exists (use --force to overwrite)")

    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    npub = npub_encode(pk)

    _write_secret(nsec_path, sk)
    npub_path.write_text(npub + "\n", encoding="utf-8")

    data = default_config_dict(allow_npub=npub)
    data["auth"]["roles"] = {npub: ["tools:admin"]}
    data["server"] = {"host": host, "port": port}
    cfg_path.write_text(yaml.dump(data, sort_keys=False), encoding="utf-8")

    click.echo("")
    click.secho("  nostr-mcp-auth quickstart ready", fg="green", bold=True)
    click.echo("")
    click.echo(f"  npub   {npub}")
    click.echo(f"  nsec   {nsec_path}  (keep private)")
    click.echo(f"  config {cfg_path}")
    click.echo("")
    click.echo("  Next:")
    click.echo(f"    nostr-mcp-auth serve --config {cfg_path}")
    click.echo(
        f"    nostr-mcp-auth call --url http://{host}:{port}/mcp "
        f"--nsec {nsec_path} --tool whoami"
    )
    click.echo("")


@main.command("gen-key")
@click.option("--write-nsec", type=click.Path(), default=None, help="Write hex nsec to file")
@click.option(
    "--write-npub",
    type=click.Path(),
    default=None,
    help="Write npub to file (default: alongside --write-nsec as .npub)",
)
def gen_key(write_nsec: str | None, write_npub: str | None) -> None:
    """Generate a Nostr keypair for a caller identity."""
    sk = generate_private_key_hex()
    pk = xonly_pubkey_hex(sk)
    nsec = nsec_encode(sk)
    npub = npub_encode(pk)
    click.echo(f"pubkey_hex: {pk}")
    click.echo(f"npub:       {npub}")
    click.echo(f"nsec:       {nsec}")
    if write_nsec:
        path = Path(write_nsec)
        _write_secret(path, sk)
        click.echo(f"wrote nsec -> {path}")
        npub_out = Path(write_npub) if write_npub else path.with_suffix(".npub")
        npub_out.write_text(npub + "\n", encoding="utf-8")
        click.echo(f"wrote npub -> {npub_out}")
        click.echo(f"allowlist:  allow_npubs: [\"{npub}\"]")


@main.command("init")
@click.option("--out", "out_path", type=click.Path(), default="mcp-auth.yaml")
@click.option("--allow-npub", default=None, help="Seed allowlist with this npub")
@click.option("--nsec", "nsec_path", default=None, help="Read npub from this nsec file")
def init_cmd(out_path: str, allow_npub: str | None, nsec_path: str | None) -> None:
    """Write a starter config (prefer `quickstart` for first run)."""
    if nsec_path and not allow_npub:
        from .crypto import load_private_key

        sk = load_private_key(nsec_path)
        allow_npub = npub_encode(xonly_pubkey_hex(sk))
    data = default_config_dict(allow_npub=allow_npub)
    if allow_npub:
        data["auth"]["roles"] = {allow_npub: ["tools:admin"]}
    Path(out_path).write_text(yaml.dump(data, sort_keys=False), encoding="utf-8")
    click.echo(f"wrote {out_path}")
    if allow_npub:
        click.echo(f"allowlisted {allow_npub}")
    else:
        click.echo("Next: nostr-mcp-auth gen-key --write-nsec ./caller.nsec")
        click.echo("      then re-run init --nsec ./caller.nsec  (or use quickstart)")


@main.command("serve")
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Config YAML (default: ./mcp-auth.yaml)",
)
@click.option("--host", default=None)
@click.option("--port", default=None, type=int)
def serve_cmd(config_path: str | None, host: str | None, port: int | None) -> None:
    """Run the authenticated HTTP MCP server."""
    import uvicorn

    from .server import create_app

    found = _find_config(config_path)
    if found is None:
        raise click.ClickException(
            "No config found. Run: nostr-mcp-auth quickstart\n"
            "Or: nostr-mcp-auth serve --config ./mcp-auth.yaml"
        )
    raw = yaml.safe_load(found.read_text(encoding="utf-8")) or {}
    cfg = load_config(raw=raw)
    if not cfg.open and not cfg.allow_pubkeys:
        click.secho(
            "WARNING: allowlist empty and open=false — every call returns 401",
            fg="yellow",
            err=True,
        )
    srv = raw.get("server") or {}
    bind_host = host or srv.get("host") or "127.0.0.1"
    bind_port = int(port or srv.get("port") or 8787)
    app = create_app(cfg)
    click.echo(f"config:    {found}")
    click.echo(f"endpoint:  http://{bind_host}:{bind_port}/mcp")
    click.echo(f"health:    http://{bind_host}:{bind_port}/health")
    click.echo(f"allowlist: {len(cfg.allow_pubkeys)}  open={cfg.open}")
    uvicorn.run(app, host=bind_host, port=bind_port, log_level="info")


@main.command("call")
@click.option(
    "--url",
    default="http://127.0.0.1:8787/mcp",
    show_default=True,
    help="Full MCP URL",
)
@click.option(
    "--nsec",
    "nsec_path",
    default="caller.nsec",
    show_default=True,
    help="nsec file, hex, or nsec1…",
)
@click.option("--tool", default="whoami", show_default=True)
@click.option("--arg", "args", multiple=True, help="key=value (repeatable)")
def call_cmd(url: str, nsec_path: str, tool: str, args: tuple[str, ...]) -> None:
    """Call a protected tool with a real NIP-98 signed request."""
    arguments: dict = {}
    for a in args:
        if "=" not in a:
            raise click.ClickException(f"bad --arg {a}, expected key=value")
        k, v = a.split("=", 1)
        arguments[k] = v
    if not Path(nsec_path).exists() and len(nsec_path) < 20:
        raise click.ClickException(
            f"nsec not found: {nsec_path}\nRun: nostr-mcp-auth quickstart"
        )
    result = call_tool(url, nsec_path, tool, arguments or None)
    click.echo(json.dumps(result, indent=2))
    if int(result.get("status_code") or 0) >= 400:
        raise SystemExit(1)


@main.command("list-tools")
@click.option("--url", default="http://127.0.0.1:8787/mcp", show_default=True)
@click.option("--nsec", "nsec_path", default="caller.nsec", show_default=True)
def list_tools_cmd(url: str, nsec_path: str) -> None:
    """List tools on a protected MCP endpoint (signed)."""
    result = list_tools(url, nsec_path)
    click.echo(json.dumps(result, indent=2))
    if int(result.get("status_code") or 0) >= 400:
        raise SystemExit(1)


@main.command("doctor")
@click.option("--config", "config_path", type=click.Path(), default=None)
@click.option("--nsec", "nsec_path", default="caller.nsec", show_default=True)
def doctor_cmd(config_path: str | None, nsec_path: str) -> None:
    """Check local files and whether this nsec is on the allowlist."""
    from .crypto import load_private_key

    ok = True
    found = _find_config(config_path)
    if found is None:
        click.secho("config:  MISSING (run quickstart)", fg="red")
        ok = False
    else:
        cfg = load_config(path=found)
        click.secho(f"config:  {found}", fg="green")
        click.echo(f"  open={cfg.open} allowlist={len(cfg.allow_pubkeys)} trust_proxy={cfg.trust_proxy}")
        if not cfg.open and not cfg.allow_pubkeys:
            click.secho("  WARNING: empty allowlist — all calls denied", fg="yellow")
            ok = False

    nsec_p = Path(nsec_path)
    if not nsec_p.is_file() and len(nsec_path) < 64:
        click.secho(f"nsec:    MISSING ({nsec_path})", fg="red")
        ok = False
        npub = None
    else:
        try:
            sk = load_private_key(nsec_path)
            npub = npub_encode(xonly_pubkey_hex(sk))
            click.secho(f"nsec:    ok -> {npub}", fg="green")
        except Exception as exc:
            click.secho(f"nsec:    INVALID ({exc})", fg="red")
            ok = False
            npub = None

    if found and npub:
        cfg = load_config(path=found)
        from .crypto import normalize_pubkey

        pk = normalize_pubkey(npub)
        allowed, reason = cfg.is_authorized(pk)
        if allowed:
            click.secho(f"allow:   yes ({reason})", fg="green")
        else:
            click.secho(f"allow:   no ({reason})", fg="red")
            ok = False

    if ok:
        click.secho("\ndoctor: ready to serve / call", fg="green", bold=True)
    else:
        click.secho("\ndoctor: fix issues above, or re-run quickstart", fg="red", bold=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
