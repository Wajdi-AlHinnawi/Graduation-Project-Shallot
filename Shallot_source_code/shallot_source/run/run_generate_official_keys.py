import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.key_exchange import ensure_official_relay_keys, DIRECTORY_PATH, KEYS_PATH

if __name__ == "__main__":
    ensure_official_relay_keys()
    print(f"Official relay public keys written to: {DIRECTORY_PATH}")
    print(f"Official relay private keys stored locally in: {KEYS_PATH}")
    print("Do NOT copy relay_keys_dev.json to contributor VMs/users.")
