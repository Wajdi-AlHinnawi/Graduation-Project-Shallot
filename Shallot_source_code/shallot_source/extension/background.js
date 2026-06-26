const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 8080;

function setOnionProxy(sendResponse) {
  const config = {
    mode: "fixed_servers",
    rules: {
      singleProxy: {
        scheme: "http",
        host: PROXY_HOST,
        port: PROXY_PORT
      },
      bypassList: [
        "localhost",
        "127.0.0.1",
        "<local>"
      ]
    }
  };

  chrome.proxy.settings.set(
    {
      value: config,
      scope: "regular"
    },
    () => {
      if (chrome.runtime.lastError) {
        console.error("[ONION EXT] Failed to set proxy:", chrome.runtime.lastError.message);
        sendResponse({
          ok: false,
          error: chrome.runtime.lastError.message
        });
        return;
      }

      console.log("[ONION EXT] Browser proxy set to", `${PROXY_HOST}:${PROXY_PORT}`);

      chrome.proxy.settings.get(
        { incognito: false },
        (details) => {
          console.log("[ONION EXT] Current proxy settings:", details);
          sendResponse({
            ok: true,
            proxy: `${PROXY_HOST}:${PROXY_PORT}`,
            details
          });
        }
      );
    }
  );
}

function clearOnionProxy(sendResponse) {
  chrome.proxy.settings.clear(
    {
      scope: "regular"
    },
    () => {
      if (chrome.runtime.lastError) {
        console.error("[ONION EXT] Failed to clear proxy:", chrome.runtime.lastError.message);
        sendResponse({
          ok: false,
          error: chrome.runtime.lastError.message
        });
        return;
      }

      console.log("[ONION EXT] Browser proxy cleared");

      chrome.proxy.settings.get(
        { incognito: false },
        (details) => {
          console.log("[ONION EXT] Current proxy settings after clear:", details);
          sendResponse({
            ok: true,
            details
          });
        }
      );
    }
  );
}

function getProxyStatus(sendResponse) {
  chrome.proxy.settings.get(
    { incognito: false },
    (details) => {
      if (chrome.runtime.lastError) {
        sendResponse({
          ok: false,
          error: chrome.runtime.lastError.message
        });
        return;
      }

      sendResponse({
        ok: true,
        details
      });
    }
  );
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("[ONION EXT] Received message:", message);

  if (!message || !message.type) {
    sendResponse({
      ok: false,
      error: "Missing message type"
    });
    return false;
  }

  if (message.type === "SET_PROXY") {
    setOnionProxy(sendResponse);
    return true;
  }

  if (message.type === "CLEAR_PROXY") {
    clearOnionProxy(sendResponse);
    return true;
  }

  if (message.type === "GET_PROXY_STATUS") {
    getProxyStatus(sendResponse);
    return true;
  }

  sendResponse({
    ok: false,
    error: `Unknown message type: ${message.type}`
  });

  return false;
});