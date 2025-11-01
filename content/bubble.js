(() => {
  const BUBBLE_ID = "supaexplorer-floating-bubble";
  const MESSAGE_ID = "supaexplorer-floating-message";
  const SHOW_EVENT = "SBDE_SHOW_BUBBLE";
  const HIDE_EVENT = "SBDE_HIDE_BUBBLE";

  if (window.__supaexplorerBubbleInjected) {
    return;
  }
  window.__supaexplorerBubbleInjected = true;

  const createBubble = () => {
    const existing = document.getElementById(BUBBLE_ID);
    if (existing) return existing;

    const bubble = document.createElement("div");
    bubble.id = BUBBLE_ID;
    bubble.style.position = "fixed";
    bubble.style.top = "50%";
    bubble.style.right = "24px";
    bubble.style.transform = "translateY(-50%)";
    bubble.style.width = "52px";
    bubble.style.height = "52px";
    bubble.style.borderRadius = "26px";
    bubble.style.boxShadow = "0 18px 40px rgba(15, 23, 42, 0.35)";
    bubble.style.background = "linear-gradient(135deg, rgba(30, 64, 175, 0.95), rgba(14, 116, 144, 0.95))";
    bubble.style.display = "flex";
    bubble.style.alignItems = "center";
    bubble.style.justifyContent = "center";
    bubble.style.cursor = "pointer";
    bubble.style.zIndex = "2147483645";
    bubble.style.opacity = "0";
    bubble.style.pointerEvents = "none";
    bubble.style.transition = "opacity 0.2s ease, transform 0.2s ease";
    bubble.style.transformOrigin = "center";

    const icon = document.createElement("img");
    icon.src = chrome.runtime.getURL("panel/supabase-database-explorer.svg");
    icon.alt = "Open SupaExplorer";
    icon.style.width = "28px";
    icon.style.height = "28px";
    icon.style.pointerEvents = "none";
    icon.style.filter = "invert(1)";

    bubble.appendChild(icon);

    bubble.addEventListener("mouseenter", () => {
      bubble.style.transform = "translateY(-50%) scale(1.05)";
    });
    bubble.addEventListener("mouseleave", () => {
      bubble.style.transform = "translateY(-50%)";
    });
    bubble.addEventListener("click", () => {
      showMessage(true);
    });

    document.documentElement.appendChild(bubble);
    return bubble;
  };

  const bubble = createBubble();
  let messageHideTimer = null;

  const getMessageElement = () => {
    let message = document.getElementById(MESSAGE_ID);
    if (message) return message;

    message = document.createElement("div");
    message.id = MESSAGE_ID;
    message.style.position = "fixed";
    message.style.top = "50%";
    message.style.right = "88px";
    message.style.transform = "translateY(-50%)";
    message.style.maxWidth = "260px";
    message.style.padding = "12px 16px";
    message.style.borderRadius = "16px";
    message.style.background = "rgba(15, 23, 42, 0.92)";
    message.style.boxShadow = "0 18px 40px rgba(15, 23, 42, 0.35)";
    message.style.color = "#f8fafc";
    message.style.fontFamily = "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
    message.style.fontSize = "13px";
    message.style.lineHeight = "1.4";
    message.style.opacity = "0";
    message.style.pointerEvents = "none";
    message.style.transition = "opacity 0.25s ease";
    message.style.zIndex = "2147483644";
    message.textContent = "Supabase detected. Click the SupaExplorer extension icon in the toolbar to open the side panel.";

    document.documentElement.appendChild(message);
    return message;
  };

  const hideMessage = () => {
    const message = document.getElementById(MESSAGE_ID);
    if (!message) return;
    message.style.opacity = "0";
    if (messageHideTimer) {
      clearTimeout(messageHideTimer);
      messageHideTimer = null;
    }
  };

  const showMessage = (force = false) => {
    const message = getMessageElement();
    if (!message) return;
    if (message.style.opacity === "1" && !force) return;
    message.style.opacity = "1";
    if (messageHideTimer) {
      clearTimeout(messageHideTimer);
    }
    messageHideTimer = window.setTimeout(() => {
      hideMessage();
    }, 6000);
  };

  const showBubble = () => {
    if (!bubble) return;
    bubble.style.opacity = "1";
    bubble.style.pointerEvents = "auto";
    showMessage();
  };

  const hideBubble = () => {
    if (!bubble) return;
    bubble.style.opacity = "0";
    bubble.style.pointerEvents = "none";
    hideMessage();
  };

  chrome.runtime.onMessage.addListener((message) => {
    if (!message || typeof message.type !== "string") return;
    if (message.type === SHOW_EVENT) {
      showBubble();
    } else if (message.type === HIDE_EVENT) {
      hideBubble();
    }
  });
})();
