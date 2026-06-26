from dataclasses import dataclass


@dataclass(frozen=True)
class Hop:
    host: str
    port: int


CLIENT_PROXY_HOST = "127.0.0.1"
CLIENT_PROXY_PORT = 8080

CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 7070

TEST_SERVER_HOST = "127.0.0.1"
TEST_SERVER_PORT = 8000

ENTRY_HOP = Hop("127.0.0.1", 9001)
MIDDLE_HOP = Hop("127.0.0.1", 9002)
EXIT_HOP = Hop("127.0.0.1", 9003)

ENTRY_HOST = ENTRY_HOP.host
ENTRY_PORT = ENTRY_HOP.port
MIDDLE_HOST = MIDDLE_HOP.host
MIDDLE_PORT = MIDDLE_HOP.port
EXIT_HOST = EXIT_HOP.host
EXIT_PORT = EXIT_HOP.port

TUNNEL_POLL_INTERVAL = 0.25
STREAM_READ_SIZE = 1024
STREAM_READ_TIMEOUT = 0.10
TUNNEL_IDLE_LOG_EVERY = 40
EXIT_POLL_LOG_EVERY = 20

TUNNEL_BROWSER_EOF_DRAIN_SECONDS = 8.0
TUNNEL_POST_CLOSE_GRACE_SECONDS = 1.0

# Raw browser/destination bytes carried inside one onion stream_data message.
# Keep this smaller than the padded cell size because JSON/base64/encryption metadata
# also has to fit inside the same relay-to-relay transport cell.
MAX_STREAM_CHUNK_SIZE = 1024

# Optional high-privacy mode. When enabled from the extension/control API, every
# relay-to-relay JSON frame is padded to this exact byte length. This avoids the
# earlier 4096/8192/16384 hop-size fingerprinting problem.
PADDED_CELL_SIZE = 16384

# Kept for compatibility with earlier helper signatures; the upgraded code now
# uses transport-cell padding rather than different encrypted layer sizes.
ONION_CELL_PLAINTEXT_SIZE = 4096

RELAY_KEYS_PATH = "relay_keys_dev.json"

# Security hardening settings.
CONTROL_TOKEN_PATH = "control_token_dev.txt"
CONTROL_TOKEN_JS_PATH = "extension/control_token.js"
CONTROL_API_REQUIRE_TOKEN = True
REPLAY_WINDOW_SECONDS = 30
REPLAY_NONCE_CACHE_SECONDS = 90
MAX_RELAY_FRAME_SIZE = 20 * 1024 * 1024
EXIT_SESSION_IDLE_TIMEOUT_SECONDS = 300
EXIT_SESSION_CLEANUP_INTERVAL_SECONDS = 30
AUTO_ROTATE_MIN_SECONDS = 300
AUTO_ROTATE_JITTER_PERCENT = 0.15

# --- Additional hardening settings ---

# Flaw 15 — Browser proxy request limits.
# Header section is capped tightly. POST/PUT bodies are read up to a separate
# explicit cap so memory cannot be exhausted by an oversized body.
HTTP_REQUEST_HEADERS_MAX_BYTES = 8192
HTTP_REQUEST_BODY_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
HTTP_REQUEST_BODY_READ_TIMEOUT_SECONDS = 30

# Flaw 19 — Exit HTTP response cap. Stops a malicious destination from
# returning an unbounded stream and exhausting the exit relay's memory.
EXIT_HTTP_RESPONSE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB
EXIT_HTTP_RESPONSE_TIMEOUT_SECONDS = 60
# When plain HTTP is forced through a CONNECT-style tunnel (padding mode),
# the client polls the tunnel until EOF. If the destination never sends EOF
# (some servers leave the socket open after the response is delivered) we
# fall back to declaring the response complete after this many seconds of
# empty polls. Generous so big responses with slow tails still finish.
EXIT_HTTP_RESPONSE_TIMEOUT_SECONDS_NO_DATA = 5

# Flaw 17 — Relay connection caps. Each relay process limits the number of
# concurrent client connections it will service, and applies a simple per-IP
# rate limit (max new connections per IP within a sliding window).
RELAY_MAX_CONCURRENT_CONNECTIONS = 1000
RELAY_PER_IP_MAX_CONNECTIONS_PER_WINDOW = 1000
RELAY_PER_IP_RATE_LIMIT_WINDOW_SECONDS = 10


# Contributor relay mode. A user who enables contribution runs a local middle
# relay on this port and registers it in the directory server if
# SP_DIRECTORY_SERVER_URL is set.
CONTRIBUTOR_DEFAULT_PORT = 9022
CONTRIBUTOR_MAX_HOPS = 3
CONTRIBUTOR_HEARTBEAT_INTERVAL_SECONDS = 20
CONTRIBUTOR_OFFLINE_AFTER_SECONDS = 60
CONTRIBUTOR_REMOVE_AFTER_SECONDS = 300
DIRECTORY_SERVER_HOST = "0.0.0.0"
DIRECTORY_SERVER_PORT = 7071

# Directory cache + signing
DIRECTORY_CACHE_TTL_SECONDS = 30
DIRECTORY_RESPONSE_MAX_AGE_SECONDS = 300
DIRECTORY_FETCH_TIMEOUT_SECONDS = 3
