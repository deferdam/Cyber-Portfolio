"use strict";

const pages = document.querySelectorAll("[data-page]");
const buttons = document.querySelectorAll("[data-nav]");

function showPage(key) {
  pages.forEach(p => p.classList.toggle("is-active", p.dataset.page === key));
  buttons.forEach(b => b.classList.toggle("is-active", b.dataset.nav === key));
  window.scrollTo(0, 0);

  // Close sidebar on mobile after navigation
  document.body.classList.remove("sidebar-open");
  const hb = document.getElementById("hamburger");
  if (hb) hb.setAttribute("aria-expanded", "false");
}

buttons.forEach(btn => {
  btn.addEventListener("click", () => showPage(btn.dataset.nav));
});

// Hamburger toggle
const hamburger = document.getElementById("hamburger");
if (hamburger) {
  hamburger.addEventListener("click", () => {
    const open = document.body.classList.toggle("sidebar-open");
    hamburger.setAttribute("aria-expanded", open ? "true" : "false");
  });
}

// Close sidebar when clicking overlay area (outside sidebar)
document.addEventListener("click", (e) => {
  if (!document.body.classList.contains("sidebar-open")) return;
  const sidebar = document.getElementById("sidebar");
  const hb = document.getElementById("hamburger");
  if (!sidebar || !hb) return;

  const clickedInsideSidebar = sidebar.contains(e.target);
  const clickedHamburger = hb.contains(e.target);

  if (!clickedInsideSidebar && !clickedHamburger) {
    document.body.classList.remove("sidebar-open");
    hb.setAttribute("aria-expanded", "false");
  }
});

const I18N = {
  en: {
    title: "Cybersecurity Portfolio",
    nav_overview: "Overview",
    nav_projects: "Projects",
    nav_malware: "Malware Analysis",
    nav_soc: "SOC Labs",
    nav_thm: "TryHackMe",
    nav_contact: "Contact",
    open: "Open",
    open_progress: "Open progress notes",
    overview_lead: "I focus on Blue Team fundamentals: malware triage, detection-oriented analysis, and SOC workflows. I maintain an isolated lab (Windows/Linux/Parrot) and publish structured write-ups and tooling notes."
  },
  fr: {
    title: "Portfolio Cybersécurité",
    nav_overview: "Aperçu",
    nav_projects: "Projets",
    nav_malware: "Analyse Malware",
    nav_soc: "SOC Labs",
    nav_thm: "TryHackMe",
    nav_contact: "Contact",
    open: "Ouvrir",
    open_progress: "Ouvrir les notes",
    overview_lead: "Je me concentre sur les fondamentaux Blue Team : triage malware, analyse orientée détection et workflows SOC. Je maintiens un lab isolé (Windows/Linux/Parrot) et publie des write-ups structurés et des notes d’outillage."
  }
};

function applyLang(lang) {
  lang = (lang === "en") ? "en" : "fr"; // force only fr/en
  const dict = I18N[lang] || I18N.en;

  // translate UI strings
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    if (dict[key]) el.textContent = dict[key];
  });

  // update doc links based on language
  document.querySelectorAll("[data-doc-en][data-doc-fr]").forEach(a => {
    const doc = (lang === "en")
      ? a.getAttribute("data-doc-en")
      : a.getAttribute("data-doc-fr");

    a.setAttribute("href", `./doc.html?doc=${encodeURIComponent(doc)}`);
  });

  // highlight selected flag
  document.querySelectorAll(".lang-btn").forEach(btn => {
    btn.classList.toggle("is-active", btn.getAttribute("data-lang") === lang);
  });

  localStorage.setItem("lang", lang);
}


const savedLang = localStorage.getItem("lang") || "en";
applyLang(savedLang);

document.querySelectorAll(".lang-btn").forEach(btn => {
  btn.addEventListener("click", () => applyLang(btn.getAttribute("data-lang")));
});

function resolveDocForLang(path, lang) {
  if (!path) return path;
  if (lang === "en") {
    if (path.endsWith(".en.md")) return path;
    if (path.endsWith(".md")) return path.replace(/\.md$/, ".en.md");
    return path;
  }
  // fr default
  if (path.endsWith(".en.md")) return path.replace(/\.en\.md$/, ".md");
  return path;
}

function applyDocLinksLang(lang) {
  document.querySelectorAll("a[data-doc]").forEach(a => {
    const base = a.getAttribute("data-doc");
    const resolved = resolveDocForLang(base, lang);
    a.setAttribute("href", `./doc.html?doc=${encodeURIComponent(resolved)}`);
  });
}
