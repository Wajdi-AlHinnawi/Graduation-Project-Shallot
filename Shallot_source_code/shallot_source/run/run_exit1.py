
import asyncio, os
os.environ.setdefault("RELAY_NAME", "exit1")
os.environ.setdefault("RELAY_PORT", "9003")
os.environ.setdefault("RELAY_HOST", "127.0.0.1")
from relays.exit_relay import main
if __name__ == "__main__":
    asyncio.run(main())
