
import asyncio, os
os.environ.setdefault("RELAY_NAME", "middle1")
os.environ.setdefault("RELAY_PORT", "9002")
os.environ.setdefault("RELAY_HOST", "127.0.0.1")
from relays.middle_relay import main
if __name__ == "__main__":
    asyncio.run(main())
