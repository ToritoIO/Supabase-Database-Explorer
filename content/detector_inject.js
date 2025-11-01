(() => {
  const SUPABASE_HOST_FRAGMENT = ".supabase.co";
  const MESSAGE_TYPE = "SBDE_SUPABASE_REQUEST";

  const cleanApiKey = (raw) => {
    if (!raw || typeof raw !== "string") return null;
    const trimmed = raw.trim();
    if (!trimmed) return null;
    return trimmed.startsWith("Bearer ") ? trimmed.slice(7).trim() : trimmed;
  };

  const sendDetection = (url, apiKey, schema) => {
    const key = cleanApiKey(apiKey);
    if (!key) return;
    try {
      chrome.runtime.sendMessage({
        type: MESSAGE_TYPE,
        url: url || "",
        apiKey: key,
        schema: schema || undefined,
      });
    } catch (error) {
      // Ignore failures (e.g., extension unloaded)
    }
  };

  const hasSupabaseHost = (url) => {
    if (!url) return false;
    try {
      const { hostname } = new URL(url, window.location.href);
      return hostname.includes(SUPABASE_HOST_FRAGMENT);
    } catch (error) {
      return url.includes(SUPABASE_HOST_FRAGMENT);
    }
  };

  // Hook fetch
  const originalFetch = window.fetch;
  if (typeof originalFetch === "function") {
    window.fetch = function patchedFetch(input, init) {
      try {
        const request = input instanceof Request ? input : null;
        const url = request ? request.url : typeof input === "string" ? input : String(input);
        if (hasSupabaseHost(url)) {
          const headers = new Headers(init?.headers || (request ? request.headers : undefined));
          const apiKey = headers.get("apikey") || headers.get("Authorization");
          const schema = headers.get("Accept-Profile") || headers.get("accept-profile");
          if (apiKey) {
            sendDetection(url, apiKey, schema);
          }
        }
      } catch (error) {
        // Ignore header inspection errors
      }
      return originalFetch.apply(this, arguments);
    };
  }

  // Hook XMLHttpRequest
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function patchedOpen(method, url) {
    try {
      this.__sbdeSupabaseUrl = url;
    } catch (error) {
      this.__sbdeSupabaseUrl = undefined;
    }
    return originalOpen.apply(this, arguments);
  };

  const originalSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.setRequestHeader = function patchedSetRequestHeader(name, value) {
    try {
      if (this.__sbdeSupabaseUrl && hasSupabaseHost(this.__sbdeSupabaseUrl)) {
        const lower = String(name || "").toLowerCase();
        if (lower === "accept-profile") {
          this.__sbdeSupabaseSchema = value;
        }
        if (lower === "apikey" || lower === "authorization") {
          const schema = this.__sbdeSupabaseSchema;
          sendDetection(this.__sbdeSupabaseUrl, value, schema);
        }
      }
    } catch (error) {
      // Ignore detection errors
    }
    return originalSetRequestHeader.apply(this, arguments);
  };
})();
