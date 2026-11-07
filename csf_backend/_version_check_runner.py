import sys
sys.path.insert(0, '/opt/csfv2')
from csf_backend import updater
info = updater.get_version_info(force=True)
if info.get('update_available'):
    print(f"CSF-eUI update available: {info['current']} -> {info['latest']}")
