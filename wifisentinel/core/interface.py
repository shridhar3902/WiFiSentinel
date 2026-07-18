"""
core/interface.py

Wraps airmon-ng to manage wireless adapter modes (managed <-> monitor)
and clear out interfering processes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from ..utils.logger import get_logger
from ..utils.shell import require_binary, run_command

log = get_logger(__name__)


@dataclass
class AdapterInfo:
    interface: str
    driver: str = ""
    chipset: str = ""


class InterfaceManager:
    def __init__(self):
        require_binary("airmon-ng")

    def list_adapters(self) -> List[AdapterInfo]:
        """Parse `airmon-ng` output to list available wireless adapters."""
        result = run_command(["airmon-ng"])
        adapters = []
        for line in result.stdout.splitlines():
            # Typical row: "phy0	wlan0		Realtek RTL8811AU	rtl8812au"
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            if len(parts) >= 2 and parts[0].startswith("phy"):
                iface = parts[1]
                chipset = parts[2] if len(parts) > 2 else ""
                driver = parts[3] if len(parts) > 3 else ""
                adapters.append(AdapterInfo(interface=iface, driver=driver, chipset=chipset))
        return adapters

    def kill_interfering_processes(self) -> None:
        """Equivalent of `airmon-ng check kill` - stops NetworkManager/wpa_supplicant
        so they don't fight over the adapter during monitor-mode capture."""
        log.info("Stopping processes that may interfere with monitor mode...")
        run_command(["airmon-ng", "check", "kill"])

    def start_monitor_mode(self, interface: str) -> Optional[str]:
        """Put an adapter into monitor mode. Returns the resulting monitor
        interface name (often <iface>mon), or None on failure."""
        log.info("Enabling monitor mode on %s", interface)
        result = run_command(["airmon-ng", "start", interface], timeout=30)
        match = re.search(r"monitor mode (?:vif )?enabled.*?\[?(\w+mon)\]?", result.stdout, re.IGNORECASE)
        if match:
            mon_iface = match.group(1)
            log.info("Monitor interface ready: %s", mon_iface)
            return mon_iface
        # Some drivers keep the same interface name in monitor mode.
        log.warning("Could not confirm monitor interface name; assuming '%s'", interface)
        return interface

    def stop_monitor_mode(self, monitor_interface: str) -> None:
        log.info("Disabling monitor mode on %s", monitor_interface)
        run_command(["airmon-ng", "stop", monitor_interface], timeout=30)

    def restart_network_manager(self) -> None:
        log.info("Restarting NetworkManager (best-effort)...")
        run_command(["systemctl", "restart", "NetworkManager"], timeout=15)
