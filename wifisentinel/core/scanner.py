"""
core/scanner.py

Wraps airodump-ng to discover nearby access points and associated
clients, writing CSV capture files that are then parsed into
structured Python objects for the CLI / report layer.
"""

from __future__ import annotations

import csv
import glob
import os
import signal
import tempfile
import time
from dataclasses import dataclass, field
from typing import List

from ..utils.logger import get_logger
from ..utils.shell import require_binary, run_background

log = get_logger(__name__)


@dataclass
class AccessPoint:
    bssid: str
    channel: str
    privacy: str
    power: str
    essid: str
    beacons: str = "0"
    clients: List[str] = field(default_factory=list)


class Scanner:
    def __init__(self, monitor_interface: str, output_dir: str = "captures"):
        require_binary("airodump-ng")
        self.monitor_interface = monitor_interface
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self._proc = None
        self._prefix = None

    def start(self, channel: int = None) -> str:
        """
        Start an airodump-ng scan in the background, writing CSV output.
        Returns the file prefix used for output files.
        """
        self._prefix = os.path.join(self.output_dir, f"scan_{int(time.time())}")
        args = ["airodump-ng", "--write", self._prefix, "--output-format", "csv"]
        if channel:
            args += ["--channel", str(channel)]
        args.append(self.monitor_interface)

        log.info("Starting airodump-ng scan on %s (channel=%s)", self.monitor_interface, channel or "all")
        self._proc = run_background(args)
        return self._prefix

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            log.info("Stopping scan")
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()

    def scan_for(self, seconds: int = 30, channel: int = None) -> List[AccessPoint]:
        """Convenience helper: scan for a fixed duration, then parse results."""
        self.start(channel=channel)
        time.sleep(seconds)
        self.stop()
        return self.parse_results()

    def parse_results(self) -> List[AccessPoint]:
        """Parse the most recent airodump-ng CSV file into AccessPoint objects."""
        if not self._prefix:
            return []
        csv_files = sorted(glob.glob(f"{self._prefix}-*.csv"))
        if not csv_files:
            log.warning("No airodump-ng CSV output found for prefix %s", self._prefix)
            return []

        aps: List[AccessPoint] = []
        with open(csv_files[0], newline="", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # airodump-ng CSV has two sections (APs, then Stations) separated
        # by a blank line; we only need the AP section here.
        ap_section = content.split("\r\n\r\n")[0]
        reader = csv.reader(ap_section.splitlines())
        rows = list(reader)
        if len(rows) < 2:
            return aps

        header = [h.strip() for h in rows[0]]
        for row in rows[1:]:
            if len(row) < len(header):
                continue
            record = dict(zip(header, [c.strip() for c in row]))
            bssid = record.get("BSSID", "")
            if not bssid or bssid.lower() == "bssid":
                continue
            aps.append(
                AccessPoint(
                    bssid=bssid,
                    channel=record.get("channel", ""),
                    privacy=record.get("privacy", ""),
                    power=record.get("power", ""),
                    essid=record.get("essid", ""),
                    beacons=record.get("# beacons", "0"),
                )
            )
        log.info("Parsed %d access point(s) from scan", len(aps))
        return aps
