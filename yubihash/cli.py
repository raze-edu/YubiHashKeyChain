"""
Command Line Interface for YubiHashKeyChain Vault.
Designed with Typer to be clean, modular, and easy to wrap by other interfaces or scripts.
"""

from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from yubihash.backends.live.active_directory import LiveActiveDirectory
from yubihash.backends.live.dpapi_ng import LiveDpapiNg
from yubihash.backends.live.yubikey import LiveYubiKey
from yubihash.ledger.storage import VaultStorage
from yubihash.vault import VaultOrchestrator

app = typer.Typer(
    name="yubihash",
    help="Serverless AD + YubiKey Hash-Chain Vault CLI",
    add_completion=False,
)
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


def get_orchestrator(vault_dir: Path) -> VaultOrchestrator:
    storage = VaultStorage(vault_dir)
    yubikey = LiveYubiKey()
    dpapi_ng = LiveDpapiNg()
    directory = LiveActiveDirectory()
    return VaultOrchestrator(storage, yubikey, dpapi_ng, directory)


@app.command("init")
def init_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    group_sid: str = typer.Option(..., "--group-sid", "-g", help="Active Directory Security Group SID"),
    input_file: Path = typer.Option(..., "--input-file", "-i", help="Initial plaintext file to encrypt into vault"),
    creator_sid: Optional[str] = typer.Option(None, "--creator-sid", help="SID of creator (defaults to current user)"),
    pin: Optional[str] = typer.Option(None, "--pin", "-p", help="YubiKey PIN (if required)"),
):
    """
    Initializes a new vault on the SMB share with Genesis Block and encrypted payload.
    """
    if not input_file.exists():
        console.print(f"[red]Error: Input file {input_file} does not exist.[/red]")
        raise typer.Exit(1)

    c_sid = creator_sid or get_default_user_sid()
    with open(input_file, "rb") as f:
        data = f.read()

    console.print(f"[bold green]Initializing vault at {vault_dir}...[/bold green]")
    orch = get_orchestrator(vault_dir)

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
        console.print(f"[red]Failed to initialize vault: {e}[/red]")
        raise typer.Exit(1)


@app.command("open")
def open_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    output_file: Path = typer.Option(..., "--output-file", "-o", help="Path to save decrypted payload"),
    user_sid: Optional[str] = typer.Option(None, "--user-sid", help="Current user SID (defaults to whoami)"),
    pin: Optional[str] = typer.Option(None, "--pin", "-p", help="YubiKey PIN (if required)"),
    no_auto_sync: bool = typer.Option(False, "--no-auto-sync", help="Disable peer-to-peer auto-sync of AD members"),
    no_auto_rotate: bool = typer.Option(False, "--no-auto-rotate", help="Disable automatic epoch rotation on member removal"),
):
    """
    Unwraps keys using AD DPAPI-NG and physical YubiKey, and decrypts the payload.
    """
    u_sid = user_sid or get_default_user_sid()
    orch = get_orchestrator(vault_dir)

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
        console.print(f"[red]Decryption failed: {e}[/red]")
        raise typer.Exit(1)


@app.command("inspect")
def inspect_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
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
        console.print(f"[red]Chain validation error: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold cyan]=== Vault Inspection ===[/bold cyan]")
    console.print(f"Group SID: [green]{state.group_sid}[/green]")
    console.print(f"Epoch: [green]{state.epoch}[/green]")
    console.print(f"Total Blocks: [green]{len(blocks)}[/green]")
    console.print(f"DAG Tips: [green]{list(state.tips)}[/green]")

    table = Table(title="Authorized Active Members")
    table.add_column("User SID", style="cyan")
    table.add_column("Permissions", style="green")

    for sid, m in state.members.items():
        table.add_row(sid, ", ".join(m.permissions))

    console.print(table)


@app.command("sync")
def sync_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    user_sid: Optional[str] = typer.Option(None, "--user-sid", help="Current user SID (defaults to whoami)"),
    pin: Optional[str] = typer.Option(None, "--pin", "-p", help="YubiKey PIN (if required)"),
    allow_epoch_rotation: bool = typer.Option(False, "--allow-epoch-rotation", help="Allow automatic epoch rotation if member removal is detected"),
):
    """
    Syncs the vault with Active Directory to onboard new members or rotate departed members.
    """
    u_sid = user_sid or get_default_user_sid()
    orch = get_orchestrator(vault_dir)

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
        console.print(f"[red]Sync failed: {e}[/red]")
        raise typer.Exit(1)


@app.command("rotate-epoch")
def rotate_epoch_cmd(
    vault_dir: Path = typer.Option(..., "--vault-dir", "-v", help="Path to vault folder on SMB share"),
    payload_file: Path = typer.Option(..., "--payload-file", "-i", help="Plaintext payload file to re-encrypt for the new epoch"),
    user_sid: Optional[str] = typer.Option(None, "--user-sid", help="Current user SID (defaults to whoami)"),
    pin: Optional[str] = typer.Option(None, "--pin", "-p", help="YubiKey PIN (if required)"),
):
    """
    Explicitly rotates vault keys (FEK, Half_A, Half_B) and increments epoch.
    """
    if not payload_file.exists():
        console.print(f"[red]Payload file {payload_file} does not exist.[/red]")
        raise typer.Exit(1)

    u_sid = user_sid or get_default_user_sid()
    with open(payload_file, "rb") as f:
        data = f.read()

    orch = get_orchestrator(vault_dir)
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
        console.print(f"[red]Epoch rotation failed: {e}[/red]")
        raise typer.Exit(1)


@app.command("onboard")
def onboard_cmd(
    user_sid: Optional[str] = typer.Option(None, "--user-sid", help="Target user SID in Active Directory (defaults to whoami)"),
    publish_ad: bool = typer.Option(True, "--publish-ad/--no-publish-ad", help="Publish certificates directly to Active Directory userCertificate"),
):
    """
    Phase 1: Exports Slot 9c, Slot 9d, and Slot f9 Attestation certificates from physical YubiKey
    and uploads them to the user's Active Directory userCertificate attribute.
    """
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
        console.print(f"[red]Onboarding failed: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
