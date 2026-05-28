document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;
  
  const url = new URL(tab.url);
  const site = url.hostname.replace("www.", "");

  try {
    const res = await fetch(`http://127.0.0.1:5000/vault/lookup?site=${site}`);
    const data = await res.json();

    if (data.error) {
      document.getElementById("status").textContent = "No saved password for " + site;
      return;
    }

    document.getElementById("status").style.display = "none";
    document.getElementById("info").style.display = "block";
    document.getElementById("site").textContent = site;
    document.getElementById("username").textContent = data.username;

    document.getElementById("fillBtn").onclick = async () => {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (user, pw) => {
          const setNativeValue = (element, value) => {
            const { set: valueSetter } = Object.getOwnPropertyDescriptor(element, 'value') || {};
            const prototype = Object.getPrototypeOf(element);
            const { set: prototypeValueSetter } = Object.getOwnPropertyDescriptor(prototype, 'value') || {};

            if (prototypeValueSetter && valueSetter !== prototypeValueSetter) {
              prototypeValueSetter.call(element, value);
            } else if (valueSetter) {
              valueSetter.call(element, value);
            } else {
              element.value = value;
            }
          };

          const inputs = document.querySelectorAll("input");
          inputs.forEach(el => {
            const type = el.type.toLowerCase();
            const name = (el.name || "").toLowerCase();
            const id = (el.id || "").toLowerCase();
            const placeholder = (el.placeholder || "").toLowerCase();

            let targetValue = null;

            if (type === "email" || type === "text") {
               if (name.includes("user") || name.includes("email") || name.includes("login") || 
                   id.includes("user") || id.includes("email") ||
                   placeholder.includes("user") || placeholder.includes("phone") || placeholder.includes("email")) {
                 targetValue = user;
               }
            } else if (type === "password") {
               targetValue = pw;
            }

            if (targetValue !== null) {
              // Trigger React/Angular/Vue internal state updates
              setNativeValue(el, targetValue);
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
              el.dispatchEvent(new Event('blur', { bubbles: true }));
            }
          });
        },
        args: [data.username, data.password]
      });
      window.close();
    };
  } catch (e) {
    document.getElementById("status").textContent = "VaultX app not running or locked.";
  }
});
