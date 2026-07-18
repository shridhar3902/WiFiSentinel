"""
core/authorization.py

Mandatory authorization gate. WiFiSentinel refuses to run any
active scanning, deauth, capture, or cracking module until the
operator explicitly confirms they hold written authorization to
test the target network(s) listed in their scope file.

This mirrors the same gate pattern used in VulnScout
(github.com/shridhar3902/VulnScout) applied to wireless testing.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml

from ..utils.logger import get_logger

log = get_logger(__name__)

BANNER = r"""
==================================================================
  WiFiSentinel - Wireless Security Auditing Toolkit
==================================================================
  This tool actively interacts with wireless networks (packet
  capture, deauthentication, handshake/PMKID capture, offline
  cracking). Using it against any network you do not own or do
  not have EXPLICIT WRITTEN PERMISSION to test is illegal in most
  jurisdictions (e.g. under the Indian IT Act 2000 Sec. 43/66,
  and equivalent computer-misuse laws elsewhere).

  Only use WiFiSentinel on:
    - Your own home/lab network and hardware, or
    - Networks covered by a signed penetration-testing agreement
      / bug bounty scope that explicitly permits wireless testing.
==================================================================
"""


@dataclass
class Scope:
    """Represents the authorized engagement scope loaded from YAML."""

    client_name: str
    authorized_by: str
    authorization_reference: str
    allowed_bssids: List[str] = field(default_factory=list)
    allowed_essids: List[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"Scope file not found: {path}\n"
                f"Copy config/scope.yaml.example to config/scope.yaml and "
                f"fill in your authorized engagement details."
            )
        data = yaml.safe_load(p.read_text()) or {}
        required = ["client_name", "authorized_by", "authorization_reference"]
        missing = [k for k in required if not data.get(k)]
        if missing:
            raise ValueError(
                f"Scope file is missing required fields: {', '.join(missing)}"
            )
        return cls(
            client_name=data["client_name"],
            authorized_by=data["authorized_by"],
            authorization_reference=data["authorization_reference"],
            allowed_bssids=[b.lower() for b in data.get("allowed_bssids", [])],
            allowed_essids=data.get("allowed_essids", []),
            notes=data.get("notes", ""),
        )

    def permits(self, bssid: str = None, essid: str = None) -> bool:
        """Check whether a discovered target falls inside the defined scope."""
        if not self.allowed_bssids and not self.allowed_essids:
            # An empty scope list means "not yet configured" -> deny by default.
            return False
        if bssid and bssid.lower() in self.allowed_bssids:
            return True
        if essid and essid in self.allowed_essids:
            return True
        return False


def confirm_authorization(scope: Scope, assume_yes: bool = False) -> None:
    """
    Print the banner + loaded scope, and require an explicit typed
    confirmation before any active module is allowed to proceed.
    """
    print(BANNER)
    print(f"  Client / Owner : {scope.client_name}")
    print(f"  Authorized by  : {scope.authorized_by}")
    print(f"  Reference      : {scope.authorization_reference}")
    print(f"  Allowed BSSIDs : {', '.join(scope.allowed_bssids) or '(none listed)'}")
    print(f"  Allowed ESSIDs : {', '.join(scope.allowed_essids) or '(none listed)'}")
    print("==================================================================\n")

    if assume_yes:
        log.warning("Authorization auto-confirmed via --yes flag.")
        return

    answer = input(
        "Type 'I CONFIRM' to proceed, confirming you have written authorization "
        "to test every target listed above: "
    ).strip()

    if answer != "I CONFIRM":
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)

    log.info("Operator confirmed authorization for scope: %s", scope.client_name)
