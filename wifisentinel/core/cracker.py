"""
core/cracker.py

Offline dictionary/mask cracking against captured handshakes (.cap) or
PMKID hashes (.22000), using aircrack-ng (CPU) or hashcat (GPU-accelerated,
recommended for anything beyond small test wordlists).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional

from ..utils.logger import get_logger
from ..utils.shell import require_binary, run_command

log = get_logger(__name__)


@dataclass
class CrackResult:
    success: bool
    key: Optional[str]
    engine: str
    seconds_elapsed: float
    message: str = ""


class Cracker:
    def __init__(self):
        pass

    def crack_with_aircrack(self, cap_file: str, bssid: str, wordlist: str) -> CrackResult:
        require_binary("aircrack-ng")
        start = time.time()
        log.info("Running aircrack-ng against %s using wordlist %s", cap_file, wordlist)
        result = run_command(
            ["aircrack-ng", "-a", "2", "-b", bssid, "-w", wordlist, cap_file],
            timeout=None,
        )
        elapsed = time.time() - start
        match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
        if match:
            return CrackResult(True, match.group(1), "aircrack-ng", elapsed, "Key found.")
        return CrackResult(False, None, "aircrack-ng", elapsed, "Key not found in wordlist.")

    def crack_with_hashcat(
        self,
        hash_file: str,
        wordlist: str,
        mode: str = "22000",
        rules_file: Optional[str] = None,
    ) -> CrackResult:
        """
        mode 22000 covers both WPA-EAPOL and WPA-PMKID hashes produced by
        hcxpcapngtool / hcxtools (the modern unified hashcat format).
        """
        require_binary("hashcat")
        start = time.time()
        args = ["hashcat", "-m", mode, "-a", "0", hash_file, wordlist, "--potfile-disable"]
        if rules_file:
            args += ["-r", rules_file]
        log.info("Running hashcat (mode %s) against %s", mode, hash_file)
        result = run_command(args, timeout=None)
        elapsed = time.time() - start

        show = run_command(["hashcat", "-m", mode, hash_file, "--show"], timeout=30)
        if show.stdout.strip():
            key = show.stdout.strip().split(":")[-1]
            return CrackResult(True, key, "hashcat", elapsed, "Key found.")
        return CrackResult(
            False, None, "hashcat", elapsed,
            "Key not found in wordlist." if result.ok else "hashcat run failed - check GPU/OpenCL setup.",
        )
