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

// --- Client-side "checks remaining" indicator ---------------------------
// Convenience display only -- the REAL enforcement happens server-side
// (IP-based, in main.py), independent of this. Declared BEFORE
// applyLanguage(), since applyLanguage calls updateChecksRemainingDisplay().
//
// This also resets itself after 24 hours, matching the server's actual
// rate-limit window -- without this, localStorage would keep accumulating
// forever across every test session, eventually showing "0 remaining"
// permanently even on a brand new day.
const MAX_CHECKS = 10;
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

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

const fileInput = document.getElementById("email-file");
const fileDropLabel = document.getElementById("file-drop-label");
const fileDropZone = document.getElementById("file-drop");

fileInput.addEventListener("change", () => {
  if (fileInput.files.length > 0) {
    fileDropLabel.textContent = fileInput.files[0].name;
  }
});

// Drag-and-drop needs to be handled explicitly -- without preventDefault()
// on these events, the browser's default behavior takes over instead
// (which is exactly what caused it to open the file in a new tab).
["dragenter", "dragover"].forEach((eventName) => {
  fileDropZone.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    fileDropZone.classList.add("drag-active");
  });
});

["dragleave", "dragend"].forEach((eventName) => {
  fileDropZone.addEventListener(eventName, (e) => {
    e.preventDefault();
    e.stopPropagation();
    fileDropZone.classList.remove("drag-active");
  });
});

fileDropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  e.stopPropagation();
  fileDropZone.classList.remove("drag-active");

  const droppedFiles = e.dataTransfer.files;
  if (droppedFiles.length > 0) {
    fileInput.files = droppedFiles;
    fileDropLabel.textContent = droppedFiles[0].name;
  }
});

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

// Initial render -- must come after everything above is defined/attached.
applyLanguage(currentLang);
