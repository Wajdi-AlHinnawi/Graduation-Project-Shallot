
import asyncio, os
os.environ.setdefault("RELAY_NAME", "entry1")
os.environ.setdefault("RELAY_PORT", "9001")
os.environ.setdefault("RELAY_HOST", "127.0.0.1")
from relays.entry_relay import main
if __name__ == "__main__":
    asyncio.run(main())
