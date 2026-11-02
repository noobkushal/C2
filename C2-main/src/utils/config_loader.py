import os
import yaml
from src.utils.logging_config import logger

DEFAULT_APP_CONFIG = {
    "application": {
        "db_path": "data/netwatch.db",
        "log_level": "INFO",
        "log_file": "data/processed/netwatch.log",
        "capture_interface_default": "eth0",
        "analysis_window_hours": 24
    }
}

DEFAULT_DETECTION_RULES = {
    "common_ports": [80, 443, 53, 22, 25, 110, 143, 993, 995, 3389],
    "watch_ports": [4444, 8080, 8443, 1337, 6667, 6666, 31337],
    "beacon": {
        "min_connections": 4,
        "max_cv": 0.15,
        "high_frequency_threshold": 60
    },
    "dns": {
        "long_domain_length": 50,
        "high_frequency_threshold": 20,
        "rare_domain_max_count": 2,
        "max_unique_subdomains": 5
    },
    "rare_destination": {
        "max_occurrence_pct": 0.05,
        "max_absolute_count": 10
    },
    "connection_frequency": {
        "threshold_per_minute": 10
    },
    "severity_bands": [
        {"min": 0, "max": 29, "name": "LOW"},
        {"min": 30, "max": 59, "name": "MEDIUM"},
        {"min": 60, "max": 79, "name": "HIGH"},
        {"min": 80, "max": 100, "name": "CRITICAL"}
    ]
}

def load_app_config(config_path: str = "config/application.yaml") -> dict:
    """Loads and validates application config, falling back to defaults if invalid."""
    if not os.path.exists(config_path):
        logger.warning(f"App config file {config_path} not found. Using defaults.")
        return DEFAULT_APP_CONFIG
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        if not isinstance(cfg, dict) or "application" not in cfg:
            logger.warning(f"Invalid app config format in {config_path}. Using defaults.")
            return DEFAULT_APP_CONFIG
        return cfg
    except Exception as e:
        logger.warning(f"Failed to parse app config {config_path}: {e}. Using defaults.")
        return DEFAULT_APP_CONFIG

def load_detection_rules(config_path: str = "config/detection_rules.yaml") -> dict:
    """Loads and validates detection rules config, falling back to defaults if invalid."""
    if not os.path.exists(config_path):
        logger.warning(f"Detection rules file {config_path} not found. Using defaults.")
        return DEFAULT_DETECTION_RULES
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        if not isinstance(cfg, dict) or "beacon" not in cfg or "dns" not in cfg:
            logger.warning(f"Invalid detection rules format in {config_path}. Using defaults.")
            return DEFAULT_DETECTION_RULES
        return cfg
    except Exception as e:
        logger.warning(f"Failed to parse detection rules {config_path}: {e}. Using defaults.")
        return DEFAULT_DETECTION_RULES
