import asyncio
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ["RELAY_NAME"] = os.getenv("RELAY_NAME", "vm-middle1")
os.environ["RELAY_HOST"] = os.getenv("RELAY_HOST", "0.0.0.0")
os.environ["RELAY_PORT"] = os.getenv("RELAY_PORT", "9022")

from relays.middle_relay import main

if __name__ == "__main__":
    asyncio.run(main())
