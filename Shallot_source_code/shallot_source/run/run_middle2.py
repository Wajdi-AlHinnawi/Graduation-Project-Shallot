
import asyncio, os
os.environ.setdefault("RELAY_NAME", "middle2")
os.environ.setdefault("RELAY_PORT", "9012")
os.environ.setdefault("RELAY_HOST", "127.0.0.1")
from relays.middle_relay import main
if __name__ == "__main__":
    asyncio.run(main())
