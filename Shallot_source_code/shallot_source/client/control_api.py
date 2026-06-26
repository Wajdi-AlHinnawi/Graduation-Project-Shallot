from shared.logging_utils import log_error, log_info
from shared.config import CONTROL_API_REQUIRE_TOKEN
import asyncio
import json
import os
import time
from client.contributor_relay import start_contributor_relay, stop_contributor_relay, contributor_status

from shared.config import CLIENT_PROXY_HOST, CLIENT_PROXY_PORT

_SYSTEM_PROXY_PREVIOUS = None


def _apply_windows_proxy_settings(enable: bool) -> dict:
    """Set/clear the current user's Windows proxy settings.

    This is used because some Chromium/Edge builds do not reliably apply
    chrome.proxy settings from unpacked extensions. The operation is per-user
    Windows Internet Settings, so Edge/Chrome will immediately use it.
    On non-Windows systems this is a no-op.
    """
    if os.name != "nt":
        return {"ok": True, "changed": False, "platform": os.name, "message": "non_windows_noop"}

    import ctypes
    import winreg

    global _SYSTEM_PROXY_PREVIOUS
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    proxy_server = f"{CLIENT_PROXY_HOST}:{CLIENT_PROXY_PORT}"

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        if enable:
            if _SYSTEM_PROXY_PREVIOUS is None:
                def read_value(name, default=None):
                    try:
                        return winreg.QueryValueEx(key, name)
                    except FileNotFoundError:
                        return (default, None)

                _SYSTEM_PROXY_PREVIOUS = {
                    "ProxyEnable": read_value("ProxyEnable", 0),
                    "ProxyServer": read_value("ProxyServer", ""),
                    "ProxyOverride": read_value("ProxyOverride", ""),
                }

            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.0.0.1;<local>")
        else:
            if _SYSTEM_PROXY_PREVIOUS is not None:
                for name, previous in _SYSTEM_PROXY_PREVIOUS.items():
                    value, value_type = previous
                    if value_type is None:
                        try:
                            winreg.DeleteValue(key, name)
                        except FileNotFoundError:
                            pass
                    else:
                        winreg.SetValueEx(key, name, 0, value_type, value)
                _SYSTEM_PROXY_PREVIOUS = None
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)

    return {
        "ok": True,
        "changed": True,
        "proxy": proxy_server,
        "message": "windows_proxy_enabled" if enable else "windows_proxy_restored_or_disabled",
    }


def apply_system_proxy_for_browser() -> dict:
    """Intentionally a no-op on Enable.

    Earlier versions tried to programmatically set the Windows Internet
    Settings proxy registry keys when the user clicked Enable. That works
    in some Windows builds but was unreliable on Windows 11 25H2 + modern
    Edge/Chrome (the browsers do not always pick up legacy WinINET registry
    changes). A misleading "success" log made it appear the proxy had been
    enabled when in fact traffic was still going direct.

    Better behavior: do nothing here, and let the popup's prominent "System
    proxy required" banner handle the user instruction. Disable still cleans
    up the registry on the way out so we don't leave the system pointed at
    a dead proxy.
    """
    log_info("CONTROL", "System/browser proxy auto-enable is intentionally disabled; user must configure proxy manually")
    return {
        "ok": True,
        "changed": False,
        "manual_required": True,
        "message": "Set the system or browser proxy to 127.0.0.1:8080 manually for browsing to enter the onion network.",
    }


def clear_system_proxy_for_browser() -> dict:
    try:
        result = _apply_windows_proxy_settings(False)
        log_info("CONTROL", f"System/browser proxy cleared/restored: {result}")
        return result
    except Exception as exc:
        log_error("CONTROL", f"Failed to clear system/browser proxy: {exc}")
        return {"ok": False, "error": "system_proxy_clear_failed"}



def http_json(status_code: int, payload: dict) -> bytes:
    body = json.dumps(payload, indent=2).encode("utf-8")
    reason = {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }.get(status_code, "OK")
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        "Content-Type: application/json; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Methods: GET, POST, OPTIONS",
        "Access-Control-Allow-Headers: Content-Type, Authorization",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("utf-8") + body


async def read_http_request(reader: asyncio.StreamReader):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 1024 * 1024:
            raise ValueError("Control API request too large")

    head, _, rest = data.partition(b"\r\n\r\n")
    head_text = head.decode("iso-8859-1")
    lines = head_text.split("\r\n")
    if not lines or len(lines[0].split()) < 3:
        raise ValueError("Invalid HTTP request line")

    method, path, version = lines[0].split(maxsplit=2)
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    content_length = int(headers.get("content-length", "0"))
    body = rest
    while len(body) < content_length:
        chunk = await reader.read(content_length - len(body))
        if not chunk:
            break
        body += chunk

    return method.upper(), path, version, headers, body


async def handle_control_api(reader, writer, state):
    peer = writer.get_extra_info("peername")
    try:
        method, path, _version, headers, body = await read_http_request(reader)
        log_info("CONTROL", f"{peer} -> {method} {path}")

        if method == "OPTIONS":
            writer.write(http_json(200, {"ok": True}))
            await writer.drain()
            return

        expected_token = getattr(state, "control_token", "")
        auth_header = headers.get("authorization", "")
        supplied_token = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
        if CONTROL_API_REQUIRE_TOKEN and supplied_token != expected_token:
            writer.write(http_json(401, {"ok": False, "error": "unauthorized"}))
            await writer.drain()
            return

        if method == "GET" and path == "/status":
            writer.write(http_json(200, state.get_status()))
        elif method == "GET" and path == "/route":
            writer.write(http_json(200, state.get_route()))
        elif method == "GET" and path == "/sessions":
            writer.write(http_json(200, state.get_sessions()))
        elif method == "GET" and path == "/stats":
            writer.write(http_json(200, state.get_stats()))
        elif method == "GET" and path == "/directory":
            writer.write(http_json(200, state.get_directory()))
        elif method == "GET" and path == "/contributor-status":
            writer.write(http_json(200, {"ok": True, "contributor": contributor_status()}))
        elif method == "GET" and path == "/directory-cache-status":
            from shared.security import directory_cache_status
            writer.write(http_json(200, {"ok": True, "cache": directory_cache_status()}))
        elif method == "GET" and path == "/dashboard":
            writer.write(http_json(200, state.get_dashboard()))
        elif method == "POST" and path == "/set-directory-server-url":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                writer.write(http_json(400, {"ok": False, "error": "Invalid JSON body"}))
                await writer.drain()
                return
            url = str(payload.get("directory_server_url") or "").strip()
            result = state.set_directory_server_url(url)
            # Brief wait so the immediate refresh completes and the dashboard
            # we return reflects the new URL.
            try:
                from shared.security import directory_cache_status
                deadline = time.time() + 1.5
                while time.time() < deadline:
                    await asyncio.sleep(0.05)
                    s = directory_cache_status()
                    if s.get("source") == "directory_server" and (s.get("age_seconds") or 99) < 2:
                        break
            except Exception:
                pass
            writer.write(http_json(200, {"ok": True, **result, "dashboard": state.get_dashboard()}))
        elif method == "POST" and path == "/enable":
            state.enabled = True
            proxy_result = apply_system_proxy_for_browser()
            state.log_state_summary("Onion routing ENABLED")
            writer.write(http_json(200, {
                "ok": True,
                "enabled": True,
                "message": "Onion routing enabled",
                "system_proxy": proxy_result,
            }))
        elif method == "POST" and path == "/disable":
            state.enabled = False
            # IMPORTANT: do NOT auto-clear the Windows system proxy here.
            # If we did, browsers would stop routing through 127.0.0.1:8080
            # and traffic would go DIRECTLY to the internet — meaning
            # "Disable" silently became "browse in the clear with no
            # onion routing", which is worse than no protection. The user
            # set the system proxy manually; they need to keep using it
            # so that the local proxy's fail-closed response runs and
            # blocks traffic when onion routing is off.
            state.log_state_summary("Onion routing DISABLED - fail closed (proxy stays at 127.0.0.1:8080; browser requests will get fail-closed responses until re-enabled)")
            writer.write(http_json(200, {
                "ok": True,
                "enabled": False,
                "message": "Onion routing disabled. Browser requests through 127.0.0.1:8080 will receive a fail-closed error page until re-enabled. The system proxy was intentionally left set so that traffic does not leak direct to the internet.",
                "system_proxy": {"changed": False, "manual_required": True, "kept_at": f"{CLIENT_PROXY_HOST}:{CLIENT_PROXY_PORT}"},
            }))
        elif method == "POST" and path == "/new-circuit":
            try:
                circuit_id = state.new_circuit()
                state.log_state_summary("Manual new circuit built")
                writer.write(http_json(200, {"ok": True, "message": "New circuit built", "circuit_id": circuit_id, "route": state.get_route()["route"]}))
            except ValueError as exc:
                writer.write(http_json(503, {"ok": False, "error": "directory_unavailable", "message": str(exc)}))
        elif method == "POST" and path == "/reset-sessions":
            reset_info = state.reset_sessions(close_active=True)
            log_info(
                "CONTROL",
                f"Sessions closed/reset | cleared={reset_info['cleared_sessions']} "
                f"active_before={reset_info['active_sessions_before_reset']} "
                f"close_requested={reset_info.get('close_requested', 0)}",
            )
            writer.write(http_json(200, {"ok": True, "message": "Active sessions closed and session history cleared", **reset_info, "dashboard": state.get_dashboard()}))
        elif method == "POST" and path == "/set-entry":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                writer.write(http_json(400, {"ok": False, "error": "Invalid JSON body"}))
                await writer.drain()
                return
            entry_id = payload.get("entry_id")
            if entry_id in ("", None, "random", "any", "auto"):
                circuit_id = state.set_entry_preference("", rebuild=True)
                state.log_state_summary("Preferred entry cleared; random entry selection restored")
                writer.write(http_json(200, {"ok": True, "selected_entry": None, "circuit_id": circuit_id, "message": "Preferred entry cleared. New routes will choose a random entry relay."}))
            else:
                circuit_id = state.set_entry_preference(entry_id, rebuild=True)
                state.log_state_summary(f"Preferred entry set to {entry_id}")
                writer.write(http_json(200, {"ok": True, "selected_entry": entry_id, "circuit_id": circuit_id, "message": "Preferred entry applied and circuit rebuilt."}))
        elif method == "POST" and path == "/set-auto-rotate":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                writer.write(http_json(400, {"ok": False, "error": "Invalid JSON body"}))
                await writer.drain()
                return
            state.set_auto_rotate(bool(payload.get("enabled", True)), payload.get("interval_seconds"))
            state.log_state_summary("Auto-rotation settings updated")
            writer.write(http_json(200, {"ok": True, "message": "Auto-rotation settings saved", "auto_rotate": state.get_dashboard()["auto_rotate"]}))
        elif method == "POST" and path == "/set-contributor-mode":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                writer.write(http_json(400, {"ok": False, "error": "Invalid JSON body"}))
                await writer.drain()
                return

            enabled = bool(payload.get("enabled", False))
            # The directory server URL is baked into directory_config.json
            # at install time. We do not accept it from the popup anymore.
            try:
                if enabled:
                    result = await start_contributor_relay(
                        public_host=payload.get("public_host") or payload.get("host"),
                        port=payload.get("port"),
                        relay_id=payload.get("relay_id"),
                    )
                    state.set_contributor_mode(True, contributor_id=result.get("relay_id"))
                    state.reload_directory()
                    try:
                        circuit_id = state.new_circuit()
                    except ValueError:
                        circuit_id = None
                    state.log_state_summary("Contributor middle relay ENABLED and registered")
                    writer.write(http_json(200, {
                        "ok": True,
                        "message": "Contributor middle relay enabled and registered",
                        "contributor": result,
                        "circuit_id": circuit_id,
                        "dashboard": state.get_dashboard(),
                    }))
                else:
                    result = await stop_contributor_relay()
                    state.set_contributor_mode(False)
                    state.reload_directory()
                    try:
                        circuit_id = state.new_circuit()
                    except ValueError:
                        circuit_id = None
                    state.log_state_summary("Contributor middle relay DISABLED")
                    writer.write(http_json(200, {
                        "ok": True,
                        "message": "Contributor middle relay disabled",
                        "contributor": result,
                        "circuit_id": circuit_id,
                        "dashboard": state.get_dashboard(),
                    }))
            except Exception as exc:
                log_error("CONTROL", f"set-contributor-mode failed: {exc}")
                writer.write(http_json(500, {
                    "ok": False,
                    "error": "contributor_mode_change_failed",
                    "message": str(exc),
                }))
        elif method == "POST" and path == "/set-contributor-path":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                writer.write(http_json(400, {"ok": False, "error": "Invalid JSON body"}))
                await writer.drain()
                return
            enabled = bool(payload.get("enabled", False))
            hops = payload.get("hops", payload.get("contributor_hops", 1))
            # Trigger an immediate background refresh and give the refresher
            # thread a brief moment to complete. Without this, the dashboard
            # we return below would still show the pre-toggle directory cache.
            try:
                from shared.security import request_directory_refresh, directory_cache_status
                request_directory_refresh()
                deadline = time.time() + 1.0
                while time.time() < deadline:
                    await asyncio.sleep(0.05)
                    status = directory_cache_status()
                    if status.get("source") == "directory_server" and (status.get("age_seconds") or 99) < 2:
                        break
            except Exception:
                pass
            circuit_id = state.set_contributor_path(enabled, hops)
            state.log_state_summary("Contributor Path settings updated")
            writer.write(http_json(200, {"ok": True, "message": "Contributor Path settings saved", "circuit_id": circuit_id, "dashboard": state.get_dashboard()}))
        elif method == "POST" and path == "/set-padding":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                writer.write(http_json(400, {"ok": False, "error": "Invalid JSON body"}))
                await writer.drain()
                return
            state.set_padding_mode(bool(payload.get("enabled", False)), payload.get("cell_size"))
            state.log_state_summary("Padding mode setting updated")
            writer.write(http_json(200, {"ok": True, "message": "Padding mode setting saved", "security": state.get_dashboard()["security"]}))
        else:
            writer.write(http_json(404, {"ok": False, "error": "Endpoint not found"}))

        await writer.drain()
    except Exception as exc:
        log_error("CONTROL", f"API handler error: {exc}")
        try:
            writer.write(http_json(500, {"ok": False, "error": "control_api_error"}))
            await writer.drain()
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_control_api(state):
    server = await asyncio.start_server(lambda r, w: handle_control_api(r, w, state), state.control_host, state.control_port)
    log_info("CONTROL", f"API listening on {state.control_host}:{state.control_port}")
    return server
