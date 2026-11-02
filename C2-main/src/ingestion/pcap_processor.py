import os
import shutil
import subprocess
from datetime import datetime, timezone
from src.utils.logging_config import logger

class ZeekNotAvailableError(Exception):
    """Raised when Zeek binary is not found on system PATH."""
    pass

def verify_zeek_installed() -> str:
    """Verifies zeek is available on PATH and returns its path."""
    zeek_bin = shutil.which("zeek")
    if not zeek_bin:
        raise ZeekNotAvailableError("Zeek is not installed or not on PATH — see README for setup instructions.")
    return zeek_bin

def process_pcap_with_zeek(pcap_path: str, output_base_dir: str = "data/zeek") -> str:
    """
    Processes a PCAP file with Zeek and outputs logs to a dedicated directory.
    Returns path to output directory containing generated .log files.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    ext = os.path.splitext(pcap_path)[1].lower()
    if ext not in (".pcap", ".pcapng"):
        raise ValueError(f"Invalid file extension '{ext}'. Must be .pcap or .pcapng")

    zeek_bin = verify_zeek_installed()

    abs_pcap = os.path.abspath(pcap_path)
    base_name = os.path.splitext(os.path.basename(pcap_path))[0]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.abspath(os.path.join(output_base_dir, f"{base_name}_{timestamp}"))
    os.makedirs(out_dir, exist_ok=True)

    logger.info(f"Invoking Zeek on {abs_pcap} into {out_dir}")
    try:
        res = subprocess.run(
            [zeek_bin, "-r", abs_pcap],
            cwd=out_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=True
        )
        logger.info(f"Zeek processing completed successfully for {base_name}")
        return out_dir
    except subprocess.CalledProcessError as e:
        logger.error(f"Zeek process returned error code {e.returncode}: {e.stderr}")
        raise RuntimeError(f"Zeek processing failed for {pcap_path}: {e.stderr}")
