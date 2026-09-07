from typing import Any
from src.utils.config_loader import load_detection_rules

def check_suspicious_port(
    destination_port: int | None,
    rules_cfg: dict | None = None
) -> dict[str, Any] | None:
    """
    Checks if a destination port is in watch_ports or outside common_ports.
    Emits signal "unusual port observed" if matched.
    Note: Under no circumstances is the string "malicious port" used.
    """
    if destination_port is None:
        return None

    if rules_cfg is None:
        rules_cfg = load_detection_rules()

    common_ports = rules_cfg.get("common_ports", [80, 443, 53, 22, 25, 110, 143, 993, 995, 3389])
    watch_ports = rules_cfg.get("watch_ports", [4444, 8080, 8443, 1337, 6667, 6666, 31337])

    port = int(destination_port)
    is_watch = port in watch_ports
    is_unusual = port not in common_ports

    if is_watch or is_unusual:
        detail_reason = f"Port {port} is in watch list" if is_watch else f"Port {port} not in common allowed ports"
        return {
            "signal_name": "unusual_port_observed",
            "destination_port": port,
            "contributes_points": 10,
            "detail": detail_reason
        }

    return None
