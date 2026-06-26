
import asyncio, os
os.environ.setdefault("RELAY_NAME", "exit2")
os.environ.setdefault("RELAY_PORT", "9013")
os.environ.setdefault("RELAY_HOST", "127.0.0.1")
from relays.exit_relay import main
if __name__ == "__main__":
    asyncio.run(main())
