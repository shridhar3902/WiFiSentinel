"""
utils/shell.py

Thin, defensive wrapper around subprocess for invoking external
security tools (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng,
hcxdumptool, hcxpcapngtool, hashcat, etc).

All calls go through run_command() so we get consistent logging,
timeouts, and error handling in one place.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from .logger import get_logger

log = get_logger(__name__)


@dataclass
class CommandResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class ToolNotFoundError(RuntimeError):
    """Raised when a required external binary is not installed / on PATH."""


def require_binary(name: str) -> str:
    """Confirm a required binary exists on PATH, return its resolved path."""
    path = shutil.which(name)
    if path is None:
        raise ToolNotFoundError(
            f"Required tool '{name}' was not found on PATH. "
            f"Install it (see README.md > Prerequisites) before continuing."
        )
    return path


def run_command(
    args: List[str],
    timeout: Optional[int] = 60,
    check: bool = False,
    input_text: Optional[str] = None,
) -> CommandResult:
    """
    Run a command and capture its output.

    args: full argv list, e.g. ["airmon-ng", "start", "wlan0"]
    timeout: seconds before the process is killed (None = no timeout)
    check: raise CalledProcessError on non-zero exit if True
    input_text: optional stdin to feed the process
    """
    log.debug("Running command: %s", " ".join(args))
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.TimeoutExpired as exc:
        log.warning("Command timed out after %ss: %s", timeout, " ".join(args))
        return CommandResult(args, returncode=-1, stdout="", stderr=str(exc))

    result = CommandResult(args, proc.returncode, proc.stdout, proc.stderr)

    if check and not result.ok:
        raise subprocess.CalledProcessError(
            proc.returncode, args, output=proc.stdout, stderr=proc.stderr
        )

    return result


def run_background(args: List[str]) -> subprocess.Popen:
    """
    Launch a long-running command (e.g. airodump-ng capture, hcxdumptool)
    in the background and return the Popen handle so the caller can
    manage its lifecycle (poll / terminate / wait).
    """
    log.debug("Launching background process: %s", " ".join(args))
    return subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
