// script.js
//
// Wires the frontend to the FastAPI backend, handles the EN/AR page
// language toggle, and renders verdicts including the optional
// expandable "technical details" section.
//
// IMPORTANT ORDERING NOTE: everything a function might call must be
// defined ABOVE the first place that function actually gets invoked.
// A previous version called applyLanguage() near the top of the file
// before MAX_CHECKS (used inside it, indirectly) was declared further
// down -- that threw an error that silently stopped the rest of the
// script from running at all, which is why buttons appeared dead.

// IMPORTANT: update this to your deployed backend's real URL once it's
// hosted -- this only works for local testing right now.
const API_BASE_URL = "https://phishing-detector-wcnh.onrender.com";

const RISK_STYLES = {
  safe: { color: "#2DD4A6", bg: "rgba(45, 212, 166, 0.12)", label: { en: "Looks Safe", ar: "يبدو آمناً" }, icon: "✅" },
  suspicious: { color: "#F2B84B", bg: "rgba(242, 184, 75, 0.12)", label: { en: "Suspicious", ar: "مشبوه" }, icon: "⚠️" },
  dangerous: { color: "#FF6B5E", bg: "rgba(255, 107, 94, 0.12)", label: { en: "Dangerous", ar: "خطير" }, icon: "🚨" },
};

const EVIDENCE_PATTERN = /(https?:\/\/[^\s<>"')]+|\b[\w-]+(?:\.[\w-]+)+\.[a-z]{2,}\b)/gi;

function highlightEvidence(text) {
  return text.replace(EVIDENCE_PATTERN, (match) => `<span class="evidence-chip">${match}</span>`);
}

let currentLang = localStorage.getItem("siteLang") || "en";

function t(key) {
  return TRANSLATIONS[currentLang][key] ?? TRANSLATIONS.en[key];
}

// --- Ambient background layer ---------------------------------------------
// Purely decorative -- cybersecurity/phishing-related terms and hex-style
// "ciphertext" that fade in and out behind the page, giving people
// something to look at (especially during the "Analyzing..." wait) without
// changing the site's actual color palette.
const BG_TERMS = [
 "SPF", "DKIM", "DMARC", "PHISHING", "SPOOFED", "VERIFIED",
  "I <3 PHISHY", "PHISHY <3 U", "Bilingual", "sha256:", "base64://",
  "PHISHY <3", "Error 404: Phishy stole my <3", "URGENT", "AI-Powered",
  "social engineering", "nmap", "malicious", "lookalike domain",
  "TLS", "<3 PHISHY <3", "payload", "TEAM PHISHY", "Phishy = 100% My Tool", "MAXXING",
];

function initBackgroundTerms() {
  const container = document.getElementById("bg-terms");
  if (!container) return;

  const termCount = 26;
  for (let i = 0; i < termCount; i++) {
    const span = document.createElement("span");
    span.className = "float-term";
    span.textContent = BG_TERMS[Math.floor(Math.random() * BG_TERMS.length)];
    span.style.left = `${Math.random() * 92}%`;
    span.style.top = `${Math.random() * 96}%`;
    span.style.fontSize = `${11 + Math.random() * 6}px`;
    span.style.animationDuration = `${7 + Math.random() * 8}s`;
    span.style.animationDelay = `${Math.random() * 10}s`;
    container.appendChild(span);
  }
}
// Convenience display only -- the REAL enforcement happens server-side
// (IP-based, in main.py), independent of this. Declared BEFORE
// applyLanguage(), since applyLanguage calls updateChecksRemainingDisplay().
//
// This also resets itself after 24 hours, matching the server's actual
// rate-limit window -- without this, localStorage would keep accumulating
// forever across every test session, eventually showing "0 remaining"
// permanently even on a brand new day.
// --- Client-side "checks remaining" indicator ---------------------------
// Convenience display only -- the REAL enforcement happens server-side
// (IP-based, in main.py), independent of this. Declared BEFORE
// applyLanguage(), since applyLanguage calls updateChecksRemainingDisplay().
const MAX_CHECKS = 5;
const WINDOW_MS = 24 * 60 * 60 * 1000;

function getLocalCheckCount() {
  const windowStart = parseInt(localStorage.getItem("checkWindowStart") || "0", 10);
  if (Date.now() - windowStart > WINDOW_MS) {
    localStorage.setItem("checkWindowStart", String(Date.now()));
    localStorage.setItem("checkCount", "0");
    return 0;
  }
  return parseInt(localStorage.getItem("checkCount") || "0", 10);
}
function incrementLocalCheckCount() {
  if (!localStorage.getItem("checkWindowStart")) {
    localStorage.setItem("checkWindowStart", String(Date.now()));
  }
  localStorage.setItem("checkCount", String(getLocalCheckCount() + 1));
}
function updateChecksRemainingDisplay() {
  const remaining = Math.max(MAX_CHECKS - getLocalCheckCount(), 0);
  document.getElementById("checks-remaining").textContent = t("checksRemaining")(remaining, MAX_CHECKS);
}

// --- Language toggle -----------------------------------------------------
function applyLanguage(lang) {
  currentLang = lang;
  localStorage.setItem("siteLang", lang);

  document.getElementById("html-root").lang = lang;
  document.getElementById("html-root").dir = lang === "ar" ? "rtl" : "ltr";

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    const value = TRANSLATIONS[lang][key];
    if (typeof value === "string") el.textContent = value;
  });

  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    el.placeholder = TRANSLATIONS[lang][key];
  });

  document.querySelectorAll("[data-i18n-alt]").forEach((el) => {
    const key = el.getAttribute("data-i18n-alt");
    el.alt = TRANSLATIONS[lang][key];
  });

  document.getElementById("lang-en").classList.toggle("active", lang === "en");
  document.getElementById("lang-ar").classList.toggle("active", lang === "ar");

  updateChecksRemainingDisplay();
}

// --- Technical details section --------------------------------------------
function renderTechnicalDetails(details) {
  const urls = details.urls_found && details.urls_found.length > 0
    ? details.urls_found.map((u) => `<span class="evidence-chip">${u}</span>`).join(" ")
    : t("noneFound");

  const auth = details.auth_results && Object.keys(details.auth_results).length > 0
    ? Object.entries(details.auth_results)
        .map(([mech, status]) => {
          const passed = status === "pass";
          const failed = status === "fail" || status === "softfail" || status === "permerror";
          const color = passed ? "#2DD4A6" : failed ? "#FF6B5E" : "#8B95AC";
          const shown = status || "—";
          return `<span class="auth-badge" style="color:${color}; border-color:${color};">${mech.toUpperCase()}: ${shown}</span>`;
        })
        .join(" ")
    : `<span style="color:var(--text-muted); font-size:13px;">${t("notAvailable")}</span>`;

  return `
    <details class="tech-details">
      <summary>${t("technicalDetails")}</summary>
      <div class="tech-details-body">
        <div class="tech-row"><strong>${t("senderLabel")}:</strong> ${details.sender_name || t("noneFound")}</div>
        <div class="tech-row"><strong>${t("senderEmailLabel")}:</strong> ${details.sender_email || t("noneFound")}</div>
        <div class="tech-row"><strong>${t("urlsLabel")}:</strong> ${urls}</div>
        <div class="tech-row"><strong>${t("authLabel")}:</strong> ${auth}</div>
      </div>
    </details>
  `;
}

// --- Rendering a verdict --------------------------------------------------
function renderVerdict(data) {
  const style = RISK_STYLES[data.risk_level] || RISK_STYLES.suspicious;
  const resultArea = document.getElementById("result-area");

  let html = "";

  if (data.is_mock) {
    html += `<div class="disclaimer" style="margin-bottom:16px;">${t("mockNotice")}</div>`;
  }

  html += `
    <div class="verdict-card" dir="auto" style="background:${style.bg}; border-color:${style.color};">
      <div class="verdict-title" style="color:${style.color};">${style.icon} ${style.label[currentLang]}</div>
      <div class="verdict-summary" dir="auto">${highlightEvidence(data.summary)}</div>
      <div class="verdict-confidence">${data.confidence}</div>
    </div>
  `;

  if (data.red_flags && data.red_flags.length > 0) {
    html += `<h3 style="margin-top:24px; font-size:18px;">${t("whatWeFound")}</h3>`;
    data.red_flags.forEach((flag) => {
      html += `
        <div class="flag-card" dir="auto">
          <div class="flag-title" dir="auto">${flag.title}</div>
          <div class="flag-explanation" dir="auto">${highlightEvidence(flag.explanation)}</div>
        </div>
      `;
    });
  }

  if (data.reassurance_notes) {
    html += `<p style="margin-top:16px; font-style:italic; color:var(--text-muted);" dir="auto">${data.reassurance_notes}</p>`;
  }

  if (data.technical_details) {
    html += renderTechnicalDetails(data.technical_details);
  }

  resultArea.innerHTML = html;
}

function renderError(message) {
  document.getElementById("result-area").innerHTML = `<div class="error-box">${message}</div>`;
}

async function handleApiResponse(response) {
  if (response.status === 429) {
    const data = await response.json();
    renderError(data.detail || "You've used all your checks for now.");
    return;
  }
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    renderError(data.detail || "Something went wrong while analyzing this email.");
    return;
  }
  const data = await response.json();
  incrementLocalCheckCount();
  updateChecksRemainingDisplay();
  renderVerdict(data);
}

// ===========================================================================
// Everything below this line WIRES UP the page: event listeners and the
// initial render. Placed after every function/constant it depends on.
// ===========================================================================

document.getElementById("lang-en").addEventListener("click", () => applyLanguage("en"));
document.getElementById("lang-ar").addEventListener("click", () => applyLanguage("ar"));

function switchToChannel(channelName) {
  document.querySelectorAll(".channel-btn").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".channel-content").forEach((c) => c.classList.remove("active"));
  document.querySelector(`.channel-btn[data-channel="${channelName}"]`)?.classList.add("active");
  document.getElementById(`channel-${channelName}`)?.classList.add("active");
}

document.querySelectorAll(".channel-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchToChannel(btn.dataset.channel));
});

// --- "Tools" nav dropdown -------------------------------------------------
const navToolsBtn = document.getElementById("nav-tools-btn");
const navToolsMenu = document.getElementById("nav-tools-menu");

navToolsBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  const isOpen = navToolsMenu.classList.toggle("open");
  navToolsBtn.setAttribute("aria-expanded", String(isOpen));
});

// Close the dropdown on any click outside it.
document.addEventListener("click", (e) => {
  if (!e.target.closest("#nav-tools")) {
    navToolsMenu.classList.remove("open");
    navToolsBtn.setAttribute("aria-expanded", "false");
  }
});

document.querySelectorAll(".nav-tools-item[data-goto-channel]").forEach((item) => {
  item.addEventListener("click", () => {
    switchToChannel(item.dataset.gotoChannel);
    navToolsMenu.classList.remove("open");
    navToolsBtn.setAttribute("aria-expanded", "false");
    document.getElementById("tool").scrollIntoView({ behavior: "smooth" });
  });
});

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    // Scoped to the enclosing .channel-content -- without this, switching
    // an SMS tab would also wipe the "active" state of the Email tabs
    // (they share the same .tab-btn/.tab-panel classes), leaving Email
    // with no visible tab the next time you switch back to it.
    const scope = btn.closest(".channel-content") || document;
    scope.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    scope.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

function setupDropZone(dropZoneId, inputId, labelId) {
  const dropZone = document.getElementById(dropZoneId);
  const input = document.getElementById(inputId);
  const label = document.getElementById(labelId);

  input.addEventListener("change", () => {
    if (input.files.length > 0) {
      label.textContent = input.files[0].name;
    }
  });

  // Drag-and-drop needs to be handled explicitly -- without preventDefault()
  // on these events, the browser's default behavior takes over instead
  // (opening the dropped file directly in a new tab).
  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add("drag-active");
    });
  });

  ["dragleave", "dragend"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove("drag-active");
    });
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove("drag-active");

    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles.length > 0) {
      input.files = droppedFiles;
      label.textContent = droppedFiles[0].name;
    }
  });

  return input;
}

const fileInput = setupDropZone("file-drop", "email-file", "file-drop-label");
const imageInput = setupDropZone("image-drop", "email-image", "image-drop-label");
const smsImageInput = setupDropZone("sms-image-drop", "sms-image", "sms-image-drop-label");
const qrImageInput = setupDropZone("qr-image-drop", "qr-image", "qr-image-drop-label");
const voiceAudioInput = setupDropZone("voice-audio-drop", "voice-audio", "voice-audio-drop-label");

document.getElementById("check-text-btn").addEventListener("click", async () => {
  const emailText = document.getElementById("email-text").value.trim();
  if (!emailText) {
    renderError(t("pasteBeforeChecking"));
    return;
  }
  document.getElementById("result-area").innerHTML = `<p style="color:var(--text-muted);">${t("analyzing")}</p>`;

  const formData = new FormData();
  formData.append("email_text", emailText);

  try {
    const response = await fetch(`${API_BASE_URL}/api/check-text`, { method: "POST", body: formData });
    await handleApiResponse(response);
  } catch (err) {
    renderError(t("unreachable"));
  }
});

document.getElementById("check-sms-text-btn").addEventListener("click", async () => {
  const smsText = document.getElementById("sms-text").value.trim();
  if (!smsText) {
    renderError(t("pasteBeforeChecking"));
    return;
  }
  document.getElementById("result-area").innerHTML = `<p style="color:var(--text-muted);">${t("analyzing")}</p>`;

  const formData = new FormData();
  formData.append("sms_text", smsText);

  try {
    const response = await fetch(`${API_BASE_URL}/api/check-sms-text`, { method: "POST", body: formData });
    await handleApiResponse(response);
  } catch (err) {
    renderError(t("unreachable"));
  }
});

document.getElementById("check-sms-image-btn").addEventListener("click", async () => {
  const file = smsImageInput.files[0];
  if (!file) {
    renderError(t("uploadBeforeChecking"));
    return;
  }
  document.getElementById("result-area").innerHTML = `<p style="color:var(--text-muted);">${t("analyzing")}</p>`;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${API_BASE_URL}/api/check-sms-image`, { method: "POST", body: formData });
    await handleApiResponse(response);
  } catch (err) {
    renderError(t("unreachable"));
  }
});

document.getElementById("check-qr-btn").addEventListener("click", async () => {
  const file = qrImageInput.files[0];
  if (!file) {
    renderError(t("uploadBeforeChecking"));
    return;
  }
  document.getElementById("result-area").innerHTML = `<p style="color:var(--text-muted);">${t("analyzing")}</p>`;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${API_BASE_URL}/api/check-qr-image`, { method: "POST", body: formData });
    await handleApiResponse(response);
  } catch (err) {
    renderError(t("unreachable"));
  }
});

document.getElementById("check-image-btn").addEventListener("click", async () => {
  const file = imageInput.files[0];
  if (!file) {
    renderError(t("uploadBeforeChecking"));
    return;
  }
  document.getElementById("result-area").innerHTML = `<p style="color:var(--text-muted);">${t("analyzing")}</p>`;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${API_BASE_URL}/api/check-image`, { method: "POST", body: formData });
    await handleApiResponse(response);
  } catch (err) {
    renderError(t("unreachable"));
  }
});

document.getElementById("check-file-btn").addEventListener("click", async () => {
  const file = fileInput.files[0];
  if (!file) {
    renderError(t("uploadBeforeChecking"));
    return;
  }
  document.getElementById("result-area").innerHTML = `<p style="color:var(--text-muted);">${t("analyzing")}</p>`;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${API_BASE_URL}/api/check-file`, { method: "POST", body: formData });
    await handleApiResponse(response);
  } catch (err) {
    renderError(t("unreachable"));
  }
});

document.getElementById("check-voice-btn").addEventListener("click", async () => {
  const file = voiceAudioInput.files[0];
  if (!file) {
    renderError(t("uploadBeforeChecking"));
    return;
  }
  document.getElementById("result-area").innerHTML = `<p style="color:var(--text-muted);">${t("analyzing")}</p>`;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${API_BASE_URL}/api/check-vishing-audio`, { method: "POST", body: formData });
    await handleApiResponse(response);
  } catch (err) {
    renderError(t("unreachable"));
  }
});

// Initial render -- must come after everything above is defined/attached.
applyLanguage(currentLang);
initBackgroundTerms();
