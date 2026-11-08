import json
import os

CONFIG_FILE = "/etc/csfv2/auto_update.json"

DEFAULTS = {
    "auto_check": True,
    "check_interval_hours": 12,
    "auto_install": False,
}


def load():
    try:
        with open(CONFIG_FILE) as f:
            data = json.load(f)
        cfg = dict(DEFAULTS)
        cfg.update(data)
        return cfg
    except Exception:
        return dict(DEFAULTS)


def save(cfg):
    merged = dict(DEFAULTS)
    merged.update(cfg)
    # Validate types
    merged["auto_check"] = bool(merged["auto_check"])
    merged["auto_install"] = bool(merged["auto_install"])
    merged["check_interval_hours"] = max(1, int(merged["check_interval_hours"]))
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(merged, f, indent=2)
    return merged
