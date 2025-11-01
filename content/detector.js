(() => {
  try {
    if (window.__sbdeDetectorInjected) {
      return;
    }
    window.__sbdeDetectorInjected = true;
  } catch (error) {
    // Best-effort guard; proceed with injection even if we cannot set the flag.
  }

  const inject = () => {
    const script = document.createElement("script");
    script.src = chrome.runtime.getURL("content/detector_inject.js");
    script.type = "text/javascript";
    script.async = false;
    script.onload = () => {
      try {
        script.remove();
      } catch (error) {
        // Ignore removal errors.
      }
    };
    (document.documentElement || document.head || document.body)?.prepend(script);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", inject, { once: true });
  } else {
    inject();
  }
})();
