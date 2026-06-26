import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.contributor_relay import start_contributor_relay
from shared.security import start_directory_refresher

async def main():
    start_directory_refresher()
    await start_contributor_relay()
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
