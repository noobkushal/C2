import os
import yaml
from src.utils.logging_config import logger

HEDGE_NOTE = "Technique potentially relevant to investigation — behavioral detection alone does not confirm this technique was used."

DEFAULT_MITRE_MAPPING = {
    "BEACONING": [
        {"technique_id": "T1071", "name": "Application Layer Protocol", "note": HEDGE_NOTE},
        {"technique_id": "T1568", "name": "Dynamic Resolution", "note": HEDGE_NOTE}
    ],
    "DNS_ANOMALY": [
        {"technique_id": "T1071.004", "name": "DNS", "note": HEDGE_NOTE}
    ],
    "RARE_DESTINATION": [
        {"technique_id": "T1071", "name": "Application Layer Protocol", "note": HEDGE_NOTE}
    ],
    "HIGH_FREQUENCY": [
        {"technique_id": "T1499", "name": "Endpoint Denial of Service", "note": HEDGE_NOTE}
    ],
    "SUSPICIOUS_PORT": [
        {"technique_id": "T1571", "name": "Non-Standard Port", "note": HEDGE_NOTE}
    ]
}

def load_mitre_mapping(yaml_path: str = "data/mitre/attack_mapping.yaml") -> dict:
    """Loads static MITRE ATT&CK mapping YAML file."""
    if not os.path.exists(yaml_path):
        logger.warning(f"MITRE mapping file {yaml_path} not found. Using defaults.")
        return DEFAULT_MITRE_MAPPING
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
            if isinstance(cfg, dict):
                return cfg
    except Exception as e:
        logger.warning(f"Failed to parse MITRE mapping YAML: {e}. Using defaults.")
    return DEFAULT_MITRE_MAPPING

def get_mitre_context(alert_type: str, yaml_path: str = "data/mitre/attack_mapping.yaml") -> list[dict]:
    """Retrieves MITRE ATT&CK techniques mapped to an alert type with mandatory hedge note."""
    mapping = load_mitre_mapping(yaml_path)
    techniques = mapping.get(alert_type.upper(), [])
    
    # Guarantee hedge wording on returned objects
    results = []
    for t in techniques:
        results.append({
            "technique_id": t.get("technique_id", "T1071"),
            "name": t.get("name", "Behavioral Anomaly"),
            "note": HEDGE_NOTE
        })
    return results
