import sys
import subprocess
sys.path.insert(0, '/opt/csfv2')
from csf_backend import updater
from csf_backend import auto_update as auto_update_cfg

cfg = auto_update_cfg.load()

if not cfg.get("auto_check", True):
    sys.exit(0)

info = updater.get_version_info(force=True)

if info.get("update_available"):
    print(f"CSF-eUI update available: {info['current']} -> {info['latest']}")
    if cfg.get("auto_install", False):
        print("Auto-install enabled — running update...")
        for line in updater.run_update_stream(force=False):
            line = line.strip()
            if line.startswith("data: ") and not line.startswith("data: __"):
                print(line[6:])
        print("Auto-install complete.")
