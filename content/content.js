;(function () {
  if (window.__sbdeOverlayBridge) {
    window.__sbdeOverlayBridge.open();
    return;
  }

  var OVERLAY_ID = "sbde-explorer-overlay";
  var REFRESH_EVENT = "SBDE_REFRESH_TABLE";
  var overlayFrame = null;

  function postRefresh() {
    if (overlayFrame && overlayFrame.contentWindow) {
      overlayFrame.contentWindow.postMessage({ type: REFRESH_EVENT }, "*");
      return true;
    }
    var frame = document.querySelector("#" + OVERLAY_ID + " iframe");
    if (frame && frame.contentWindow) {
      overlayFrame = frame;
      overlayFrame.contentWindow.postMessage({ type: REFRESH_EVENT }, "*");
      return true;
    }
    return false;
  }

  function createOverlay() {
    if (postRefresh()) {
      return;
    }

    var overlay = document.getElementById(OVERLAY_ID);
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = OVERLAY_ID;
      overlay.style.position = "fixed";
      overlay.style.inset = "0";
      overlay.style.zIndex = "2147483646";
      overlay.style.display = "flex";
      overlay.style.alignItems = "center";
      overlay.style.justifyContent = "center";
      overlay.style.pointerEvents = "none";

      var backdrop = document.createElement("div");
      backdrop.className = "sbde-overlay-backdrop";
      backdrop.style.position = "absolute";
      backdrop.style.inset = "0";
      backdrop.style.background = "rgba(15, 23, 42, 0.65)";
      backdrop.style.backdropFilter = "blur(2px)";
      backdrop.style.pointerEvents = "auto";

      var frameWrapper = document.createElement("div");
      frameWrapper.style.position = "relative";
      frameWrapper.style.width = "90vw";
      frameWrapper.style.height = "90vh";
      frameWrapper.style.maxWidth = "1280px";
      frameWrapper.style.maxHeight = "900px";
      frameWrapper.style.borderRadius = "16px";
      frameWrapper.style.overflow = "hidden";
      frameWrapper.style.boxShadow = "0 24px 60px rgba(8, 15, 35, 0.75)";
      frameWrapper.style.border = "1px solid rgba(148, 163, 184, 0.25)";
      frameWrapper.style.pointerEvents = "auto";

      overlayFrame = document.createElement("iframe");
      overlayFrame.src = chrome.runtime.getURL("explorer/explorer.html");
      overlayFrame.style.border = "none";
      overlayFrame.style.width = "100%";
      overlayFrame.style.height = "100%";
      overlayFrame.style.background = "#0b1220";

      frameWrapper.appendChild(overlayFrame);
      overlay.appendChild(backdrop);
      overlay.appendChild(frameWrapper);
      document.documentElement.appendChild(overlay);

      var closeOnBackdrop = function () {
        removeOverlay();
      };
      backdrop.addEventListener("click", closeOnBackdrop);

      var onKeyDown = function (event) {
        if (event.key === "Escape") {
          removeOverlay();
        }
      };
      document.addEventListener("keydown", onKeyDown, { once: true });
    } else if (!postRefresh()) {
      overlayFrame = overlay.querySelector("iframe");
      postRefresh();
    }
  }

  function removeOverlay() {
    var overlay = document.getElementById(OVERLAY_ID);
    if (overlay && overlay.parentNode) {
      overlay.parentNode.removeChild(overlay);
    }
    overlayFrame = null;
  }

  function openOverlay() {
    createOverlay();
  }

  chrome.runtime.onMessage.addListener(function (message) {
    if (message && message.type === "SBDE_OPEN_OVERLAY") {
      openOverlay();
    }
    if (message && message.type === "SBDE_CLOSE_OVERLAY") {
      removeOverlay();
    }
  });

  window.addEventListener("message", function (event) {
    if (!event?.data || typeof event.data.type !== "string") {
      return;
    }
    if (event.data.type === "SBDE_CLOSE_OVERLAY") {
      removeOverlay();
    }
    if (event.data.type === "SBDE_OPEN_OVERLAY") {
      openOverlay();
    }
  });

  window.__sbdeOverlayBridge = {
    open: openOverlay,
    close: removeOverlay,
    refresh: postRefresh,
  };
})();
