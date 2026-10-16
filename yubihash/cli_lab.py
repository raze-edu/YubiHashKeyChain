"""
``yubihash lab`` sub-commands: manage a non-Active-Directory lab environment.

Typical session (PowerShell):

    $env:YUBIHASH_LAB_DIR = "C:\\Temp\\yubihash-lab"
    yubihash lab init
    yubihash lab add-group SG_Vault_Access
    yubihash lab add-user alice -g SG_Vault_Access
    yubihash lab add-user bob   -g SG_Vault_Access
    yubihash lab login alice
    yubihash init -v C:\\Temp\\vault -g SG_Vault_Access -i secrets.txt
    yubihash lab login bob
    yubihash open -v C:\\Temp\\vault -o out.txt

With ``YUBIHASH_LAB_DIR`` set (or ``--lab-dir`` passed), the regular vault
commands (init / open / sync / rotate-epoch / onboard / inspect) run the real
VaultOrchestrator against the lab backends instead of Active Directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from yubihash.backends.local.local_directory import DirectoryEntryNotFound
from yubihash.backends.local.software_yubikey import DEFAULT_PIV_PIN
from yubihash.lab import LabEnvironment, LabError

LAB_DIR_ENVVAR = "YUBIHASH_LAB_DIR"

lab_app = typer.Typer(
    name="lab",
    help=(
        "Non-AD lab environment: a local directory, simulated KDS (DPAPI-NG), and software "
        "or physical YubiKeys for testing the vault without Active Directory."
    ),
    no_args_is_help=True,
)
console = Console()

_USER_ERRORS = (LabError, DirectoryEntryNotFound, ValueError, FileExistsError, FileNotFoundError)

HARDWARE_ATTESTATION_WARNING = (
    "Attestation verification is ON for this lab, and it checks against the lab CA. A physical "
    "YubiKey's attestation chains to Yubico (via the device's f9 intermediate), so init/sync "
    "will skip this user. For labs that mix hardware and software keys, recreate the lab with "
    "'yubihash lab init --no-verify-attestation'."
)


def lab_dir_option(required: bool = True):
    return typer.Option(
        ... if required else None,
        "--lab-dir",
        "-L",
        envvar=LAB_DIR_ENVVAR,
        help=f"Lab environment folder (or set {LAB_DIR_ENVVAR})",
    )


def open_lab(lab_dir: Path) -> LabEnvironment:
    try:
        return LabEnvironment(lab_dir)
    except LabError as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1)


def _fail(e: Exception) -> None:
    console.print(f"[red]Error: {escape(str(e))}[/red]")
    raise typer.Exit(1)


@lab_app.command("init")
def lab_init_cmd(
    lab_dir: Path = lab_dir_option(),
    domain: str = typer.Option("lab.local", "--domain", help="Simulated DNS domain used for UPNs"),
    no_verify_attestation: bool = typer.Option(
        False,
        "--no-verify-attestation",
        help="Disable PIV attestation checks (needed when mixing physical YubiKeys into the lab)",
    ),
):
    """Creates a new lab: simulated directory, KDS root key, and attestation CA."""
    try:
        LabEnvironment.create(lab_dir, domain=domain, verify_attestation=not no_verify_attestation)
    except _USER_ERRORS as e:
        _fail(e)
    console.print(f"[bold green]Lab environment created at {escape(str(lab_dir))}[/bold green]")
    console.print(f"Attestation verification: [cyan]{'off' if no_verify_attestation else 'on (lab CA)'}[/cyan]")
    console.print("[yellow]Lab keys are stored on disk. Use for testing only, never for real secrets.[/yellow]")


@lab_app.command("add-group")
def lab_add_group_cmd(
    name: str = typer.Argument(..., help="Security group name, e.g. SG_Vault_Access"),
    lab_dir: Path = lab_dir_option(),
):
    """Creates a simulated AD security group."""
    lab = open_lab(lab_dir)
    try:
        sid = lab.add_group(name)
    except _USER_ERRORS as e:
        _fail(e)
    console.print(f"[green]Group '{escape(name)}' created:[/green] [cyan]{sid}[/cyan]")


@lab_app.command("add-user")
def lab_add_user_cmd(
    name: str = typer.Argument(..., help="User logon name, e.g. alice"),
    lab_dir: Path = lab_dir_option(),
    group: List[str] = typer.Option([], "--group", "-g", help="Group(s) to join (repeatable)"),
    display_name: Optional[str] = typer.Option(None, "--display-name", help="Display name"),
    pin: str = typer.Option(DEFAULT_PIV_PIN, "--pin", "-p", help="PIV PIN for the software YubiKey"),
    hardware: bool = typer.Option(False, "--hardware", help="Bind a physical YubiKey instead of a software one"),
    serial: Optional[int] = typer.Option(None, "--serial", help="Serial of the physical YubiKey (with --hardware)"),
):
    """
    Creates a user, binds a YubiKey (software by default), and publishes its
    Slot 9c / 9d / attestation certificates to the lab directory.
    """
    lab = open_lab(lab_dir)
    try:
        sid = lab.add_user(
            name,
            groups=group,
            display_name=display_name,
            pin=pin,
            hardware=hardware,
            hardware_serial=serial,
        )
    except _USER_ERRORS as e:
        _fail(e)
    except Exception as e:  # e.g. no YubiKey inserted / slot not provisioned
        _fail(e)

    binding = lab.yubikey_binding(sid) or {}
    console.print(f"[green]User '{escape(name)}' created:[/green] [cyan]{sid}[/cyan]")
    console.print(f"YubiKey: {binding.get('type')} (serial {binding.get('serial')})")
    if group:
        console.print(f"Groups: {escape(', '.join(group))}")
    if hardware and lab.verify_attestation:
        console.print(f"[yellow]Warning: {escape(HARDWARE_ATTESTATION_WARNING)}[/yellow]")


@lab_app.command("join")
def lab_join_cmd(
    user: str = typer.Argument(..., help="User name or SID"),
    group: str = typer.Argument(..., help="Group name or SID"),
    lab_dir: Path = lab_dir_option(),
):
    """Adds a user to a group (like an admin editing AD group membership)."""
    lab = open_lab(lab_dir)
    try:
        changed = lab.join_group(user, group)
    except _USER_ERRORS as e:
        _fail(e)
    msg = "added to" if changed else "is already a member of"
    console.print(f"[green]{escape(user)} {msg} {escape(group)}[/green]")


@lab_app.command("leave")
def lab_leave_cmd(
    user: str = typer.Argument(..., help="User name or SID"),
    group: str = typer.Argument(..., help="Group name or SID"),
    lab_dir: Path = lab_dir_option(),
):
    """Removes a user from a group (triggers epoch rotation on the next sync)."""
    lab = open_lab(lab_dir)
    try:
        changed = lab.leave_group(user, group)
    except _USER_ERRORS as e:
        _fail(e)
    msg = "removed from" if changed else "was not a member of"
    console.print(f"[green]{escape(user)} {msg} {escape(group)}[/green]")


@lab_app.command("login")
def lab_login_cmd(
    user: str = typer.Argument(..., help="User name or SID"),
    lab_dir: Path = lab_dir_option(),
):
    """Signs in as a lab user (stands in for the Windows logon / Kerberos ticket)."""
    lab = open_lab(lab_dir)
    try:
        sid = lab.login(user)
    except _USER_ERRORS as e:
        _fail(e)
    console.print(f"[green]Signed in as {escape(user)}[/green] ([cyan]{sid}[/cyan])")


@lab_app.command("logout")
def lab_logout_cmd(lab_dir: Path = lab_dir_option()):
    """Signs out the current lab user."""
    open_lab(lab_dir).logout()
    console.print("[green]Signed out[/green]")


@lab_app.command("whoami")
def lab_whoami_cmd(lab_dir: Path = lab_dir_option()):
    """Shows the currently signed-in lab user."""
    lab = open_lab(lab_dir)
    sid = lab.current_user_sid()
    if not sid:
        console.print("[yellow]No lab user signed in[/yellow]")
        raise typer.Exit(1)
    console.print(f"{escape(lab.directory.name_of(sid) or '?')} ([cyan]{sid}[/cyan])")


@lab_app.command("status")
def lab_status_cmd(lab_dir: Path = lab_dir_option()):
    """Shows lab users, groups, memberships, and YubiKey bindings."""
    lab = open_lab(lab_dir)
    current = lab.current_user_sid()
    groups = lab.directory.list_groups()

    console.print(f"[bold cyan]=== Lab Environment: {escape(str(lab_dir))} ===[/bold cyan]")
    console.print(f"Domain: [green]{escape(lab.directory.domain)}[/green]")
    console.print(f"Attestation verification: [green]{'on (lab CA)' if lab.verify_attestation else 'off'}[/green]")

    users_table = Table(title="Users")
    users_table.add_column("", width=1)
    users_table.add_column("Name", style="cyan")
    users_table.add_column("SID")
    users_table.add_column("Groups", style="green")
    users_table.add_column("YubiKey")
    users_table.add_column("Certs", justify="right")
    for u in lab.directory.list_users():
        binding = lab.yubikey_binding(u.sid) or {}
        users_table.add_row(
            "*" if u.sid == current else "",
            escape(u.upn),
            u.sid,
            escape(", ".join(groups[g]["name"] for g in u.groups)),
            f"{binding.get('type', '-')} #{binding.get('serial', '-')}",
            str(len(u.certificates)),
        )
    console.print(users_table)

    groups_table = Table(title="Groups")
    groups_table.add_column("Name", style="cyan")
    groups_table.add_column("SID")
    groups_table.add_column("Members", style="green")
    for g_sid, g in groups.items():
        names = [lab.directory.name_of(m) or m for m in g["members"]]
        groups_table.add_row(escape(g["name"]), g_sid, escape(", ".join(names)))
    console.print(groups_table)
    console.print("* = signed-in user")
