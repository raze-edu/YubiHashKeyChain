"""
Command Line Interface for YubiHashKeyChain Vault.
Designed with Typer to be clean, modular, and easy to wrap by other interfaces or scripts.

Every vault command accepts ``--lab-dir`` (or the ``YUBIHASH_LAB_DIR`` environment
variable) to run against a non-Active-Directory lab environment instead of the
live AD / DPAPI-NG backends. See ``yubihash lab --help``.
"""

from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Optional, Tuple
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from yubihash.backends.live.active_directory import LiveActiveDirectory
from yubihash.backends.live.dpapi_ng import LiveDpapiNg
from yubihash.backends.live.yubikey import LiveYubiKey
from yubihash.backends.local.local_directory import DirectoryEntryNotFound
from yubihash.cli_lab import lab_app, lab_dir_option, open_lab
from yubihash.lab import LabEnvironment, LabError
from yubihash.ledger.storage import VaultStorage
from yubihash.vault import VaultOrchestrator

app = typer.Typer(
    name="yubihash",
    help="Serverless AD + YubiKey Hash-Chain Vault CLI",
    add_completion=False,
)
app.add_typer(lab_app, name="lab")
console = Console()


def get_default_user_sid() -> str:
    """Retrieves current Windows user SID via whoami /user."""
    if sys.platform == "win32":
        try:
            import subprocess
            out = subprocess.check_output(["whoami", "/user"], text=True)
            for line in out.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("S-1-5-"):
                    return parts[1]
        except Exception:
            pass
    return "S-1-5-21-DEFAULT-USER"


def get_orchestrator(
    vault_dir: Path,
    lab: Optional[LabEnvironment] = None,
    user_sid: Optional[str] = None,
) -> VaultOrchestrator:
    if lab is not None:
        if not user_sid:
            raise LabError("A lab user is required to build a lab orchestrator")
        return lab.orchestrator(vault_dir, user_sid)

    storage = VaultStorage(vault_dir)
    yubikey = LiveYubiKey()
    dpapi_ng = LiveDpapiNg()
    directory = LiveActiveDirectory()
    return VaultOrchestrator(storage, yubikey, dpapi_ng, directory)


def build_context(
    vault_dir: Path,
    lab_dir: Optional[Path],
    user_ref: Optional[str],
) -> Tuple[VaultOrchestrator, str, Optional[LabEnvironment]]:
    """
    Resolves the acting user and builds the orchestrator for live (AD) or lab mode.
    In lab mode the user defaults to the signed-in lab session user.
    """
    if lab_dir is None:
        u_sid = user_ref or get_default_user_sid()
        return get_orchestrator(vault_dir), u_sid, None

    lab = open_lab(lab_dir)
    try:
        u_sid = lab.resolve_acting_user(user_ref)
        name = lab.directory.name_of(u_sid) or u_sid
        console.print(f"[magenta]LAB MODE[/magenta] (no Active Directory) - acting as {escape(name)} ({u_sid})")
        return get_orchestrator(vault_dir, lab, u_sid), u_sid, lab
    except (LabError, DirectoryEntryNotFound) as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1)


@app.command("init")
def init_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    group_sid: str = typer.Option(..., "--group-sid", "-g", help="Active Directory Security Group SID (lab mode: group name or SID)"),
    input_file: Path = typer.Option(..., "--input-file", "-i", help="Initial plaintext file to encrypt into vault"),
    creator_sid: Optional[str] = typer.Option(None, "--creator-sid", help="SID of creator (defaults to current user; lab mode: name or SID)"),
    pin: Optional[str] = typer.Option(None, "--pin", "-p", help="YubiKey PIN (if required)"),
    lab_dir: Optional[Path] = lab_dir_option(required=False),
):
    """
    Initializes a new vault on the SMB share with Genesis Block and encrypted payload.
    """
    if not input_file.exists():
        console.print(f"[red]Error: Input file {input_file} does not exist.[/red]")
        raise typer.Exit(1)

    orch, c_sid, lab = build_context(vault_dir, lab_dir, creator_sid)
    if lab is not None:
        try:
            group_sid = lab.directory.resolve_group(group_sid)
        except DirectoryEntryNotFound as e:
            console.print(f"[red]{escape(str(e))}[/red]")
            raise typer.Exit(1)

    with open(input_file, "rb") as f:
        data = f.read()

    console.print(f"[bold green]Initializing vault at {vault_dir}...[/bold green]")

    try:
        genesis = orch.init_vault(
            group_sid=group_sid,
            initial_payload=data,
            creator_sid=c_sid,
            pin=pin,
        )
        console.print(f"[green]Vault initialized successfully![/green]")
        console.print(f"Genesis Block Hash: [cyan]{genesis.block_hash()}[/cyan]")
    except Exception as e:
        console.print(f"[red]Failed to initialize vault: {escape(str(e))}[/red]")
        raise typer.Exit(1)


@app.command("open")
def open_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    output_file: Path = typer.Option(..., "--output-file", "-o", help="Path to save decrypted payload"),
    user_sid: Optional[str] = typer.Option(None, "--user-sid", help="Current user SID (defaults to whoami; lab mode: name or SID)"),
    pin: Optional[str] = typer.Option(None, "--pin", "-p", help="YubiKey PIN (if required)"),
    no_auto_sync: bool = typer.Option(False, "--no-auto-sync", help="Disable peer-to-peer auto-sync of AD members"),
    no_auto_rotate: bool = typer.Option(False, "--no-auto-rotate", help="Disable automatic epoch rotation on member removal"),
    lab_dir: Optional[Path] = lab_dir_option(required=False),
):
    """
    Unwraps keys using AD DPAPI-NG and physical YubiKey, and decrypts the payload.
    """
    orch, u_sid, lab = build_context(vault_dir, lab_dir, user_sid)

    console.print("[yellow]Verifying DAG ledger and contacting AD Domain Controller / YubiKey...[/yellow]")
    try:
        decrypted = orch.open_and_decrypt(
            current_user_sid=u_sid,
            pin=pin,
            auto_sync=not no_auto_sync,
            auto_rotate=not no_auto_rotate,
        )
        with open(output_file, "wb") as f:
            f.write(decrypted)
        console.print(f"[bold green]Payload decrypted successfully into {output_file}![/bold green]")
    except Exception as e:
        console.print(f"[red]Decryption failed: {escape(str(e))}[/red]")
        raise typer.Exit(1)


@app.command("inspect")
def inspect_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    lab_dir: Optional[Path] = lab_dir_option(required=False),
):
    """
    Inspects vault state, epoch, authorized members, and block DAG history.
    """
    storage = VaultStorage(vault_dir)
    blocks = storage.load_all_blocks()
    if not blocks:
        console.print(f"[yellow]No blocks found in {vault_dir}[/yellow]")
        raise typer.Exit(0)

    from yubihash.ledger.chain import ChainStateProjector
    projector = ChainStateProjector()
    try:
        state = projector.project(blocks)
    except Exception as e:
        console.print(f"[red]Chain validation error: {escape(str(e))}[/red]")
        raise typer.Exit(1)

    # In lab mode, show friendly names next to SIDs
    lab = open_lab(lab_dir) if lab_dir else None

    def label(sid: str) -> str:
        name = lab.directory.name_of(sid) if lab else None
        return f"{sid} ({name})" if name else sid

    console.print(f"[bold cyan]=== Vault Inspection ===[/bold cyan]")
    console.print(f"Group SID: [green]{escape(label(state.group_sid))}[/green]")
    console.print(f"Epoch: [green]{state.epoch}[/green]")
    console.print(f"Total Blocks: [green]{len(blocks)}[/green]")
    console.print(f"DAG Tips: [green]{escape(str(list(state.tips)))}[/green]")

    table = Table(title="Authorized Active Members")
    table.add_column("User SID", style="cyan")
    table.add_column("Permissions", style="green")

    for sid, m in state.members.items():
        table.add_row(escape(label(sid)), ", ".join(m.permissions))

    console.print(table)


@app.command("sync")
def sync_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    user_sid: Optional[str] = typer.Option(None, "--user-sid", help="Current user SID (defaults to whoami; lab mode: name or SID)"),
    pin: Optional[str] = typer.Option(None, "--pin", "-p", help="YubiKey PIN (if required)"),
    allow_epoch_rotation: bool = typer.Option(False, "--allow-epoch-rotation", help="Allow automatic epoch rotation if member removal is detected"),
    lab_dir: Optional[Path] = lab_dir_option(required=False),
):
    """
    Syncs the vault with Active Directory to onboard new members or rotate departed members.
    """
    orch, u_sid, lab = build_context(vault_dir, lab_dir, user_sid)

    console.print("[yellow]Synchronizing vault state with Active Directory...[/yellow]")
    try:
        # Running open_and_decrypt with auto_sync performs peer discovery while Half_B is in memory
        orch.open_and_decrypt(
            current_user_sid=u_sid,
            pin=pin,
            auto_sync=True,
            auto_rotate=allow_epoch_rotation,
        )
        console.print("[bold green]Sync completed successfully![/bold green]")
    except Exception as e:
        console.print(f"[red]Sync failed: {escape(str(e))}[/red]")
        raise typer.Exit(1)


@app.command("rotate-epoch")
def rotate_epoch_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    payload_file: Path = typer.Option(..., "--payload-file", "-i", help="Plaintext payload file to re-encrypt for the new epoch"),
    user_sid: Optional[str] = typer.Option(None, "--user-sid", help="Current user SID (defaults to whoami; lab mode: name or SID)"),
    pin: Optional[str] = typer.Option(None, "--pin", "-p", help="YubiKey PIN (if required)"),
    lab_dir: Optional[Path] = lab_dir_option(required=False),
):
    """
    Explicitly rotates vault keys (FEK, Half_A, Half_B) and increments epoch.
    """
    if not payload_file.exists():
        console.print(f"[red]Payload file {payload_file} does not exist.[/red]")
        raise typer.Exit(1)

    orch, u_sid, lab = build_context(vault_dir, lab_dir, user_sid)
    with open(payload_file, "rb") as f:
        data = f.read()

    console.print("[yellow]Rotating epoch and re-encrypting payload...[/yellow]")
    try:
        block = orch.rotate_epoch(
            current_user_sid=u_sid,
            payload_plaintext=data,
            pin=pin,
        )
        console.print(f"[bold green]Epoch rotated successfully to Epoch {block.epoch}![/bold green]")
        console.print(f"Block Hash: [cyan]{block.block_hash()}[/cyan]")
    except Exception as e:
        console.print(f"[red]Epoch rotation failed: {escape(str(e))}[/red]")
        raise typer.Exit(1)


@app.command("onboard")
def onboard_cmd(
    user_sid: Optional[str] = typer.Option(None, "--user-sid", help="Target user SID in Active Directory (defaults to whoami; lab mode: name or SID)"),
    publish_ad: bool = typer.Option(True, "--publish-ad/--no-publish-ad", help="Publish certificates directly to Active Directory userCertificate"),
    lab_dir: Optional[Path] = lab_dir_option(required=False),
):
    """
    Phase 1: Exports Slot 9c, Slot 9d, and Slot f9 Attestation certificates from physical YubiKey
    and uploads them to the user's Active Directory userCertificate attribute.
    """
    if lab_dir is not None:
        # Lab mode: re-read the user's bound YubiKey and re-publish to the lab directory
        lab = open_lab(lab_dir)
        try:
            u_sid = lab.resolve_acting_user(user_sid)
            if publish_ad:
                lab.publish_certificates(u_sid)
                console.print(f"[bold green]Certificates re-published to lab directory for {u_sid}[/bold green]")
            else:
                yk = lab.yubikey_for(u_sid)
                console.print(f"[green]YubiKey #{yk.get_serial()} readable. Skipping publication (--no-publish-ad).[/green]")
        except Exception as e:
            console.print(f"[red]Onboarding failed: {escape(str(e))}[/red]")
            raise typer.Exit(1)
        return

    from cryptography.hazmat.primitives import serialization
    yk = LiveYubiKey()
    u_sid = user_sid or get_default_user_sid()

    console.print("[yellow]Reading certificates and hardware attestation from YubiKey...[/yellow]")
    try:
        cert_9c = yk.get_signing_certificate()
        cert_9d = yk.get_decryption_certificate()
        attest_9d = yk.get_attestation_certificate("9d")

        der_9c = cert_9c.public_bytes(serialization.Encoding.DER)
        der_9d = cert_9d.public_bytes(serialization.Encoding.DER)
        der_attest = attest_9d.public_bytes(serialization.Encoding.DER)

        console.print(f"Found Slot 9c Cert (Signing)")
        console.print(f"Found Slot 9d Cert (Decryption)")
        console.print(f"Found Slot f9 Attestation Cert")

        if publish_ad:
            directory = LiveActiveDirectory()
            console.print(f"[yellow]Publishing certificates to Active Directory for SID {u_sid}...[/yellow]")
            directory.publish_user_certificate(u_sid, der_9c)
            directory.publish_user_certificate(u_sid, der_9d)
            directory.publish_user_certificate(u_sid, der_attest)
            console.print("[bold green]Certificates published to Active Directory successfully![/bold green]")
        else:
            console.print("[green]Export complete. Skipping AD publication (--no-publish-ad specified).[/green]")
    except Exception as e:
        console.print(f"[red]Onboarding failed: {escape(str(e))}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
