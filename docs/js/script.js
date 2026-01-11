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
  fr: {
    // global
    open: "Ouvrir",
    back: "Retour",
    legal: "Contenu défensif et éducatif uniquement. Aucun binaire malveillant n’est hébergé.",
    doc_open_github: "Ouvrir sur GitHub",
    doc_open_raw: "Ouvrir en brut",
    btn_open_progress: "Ouvrir les notes de progression",
    open_progress: "Ouvrir les notes de progression",
    btn_back: "Retour",
    btn_open: "Ouvrir",

    // leads / headers
    overview_lead: "Je me concentre sur les fondamentaux Blue Team : triage malware, analyse orientée détection et workflows SOC. Je maintiens un lab isolé (Windows/Linux/Parrot) et publie des write-ups structurés et des notes sur les outils.",
    projects_lead: "Sélection organisée. Tout est défensif et documenté. Aucun binaire malveillant n’est hébergé.",
    malware_lead: "Reproduit dans un lab isolé, avec une approche orientée détection : IOCs, comportements, et conclusions défensives.",
    soc_lead: "Exercices type SOC : bases réseau, approche triage de logs, playbooks simples et idées de détection.",
    thm_lead: "Progression et notes défensives. Pas de spoilers complets.",

    // sidebar
    nav_overview: "Vue d’ensemble",
    nav_projects: "Projets",
    nav_malware: "Analyse malware",
    nav_soc: "SOC Labs",
    nav_thm: "TryHackMe",
    nav_contact: "Contact",

    // projects
    projects_title: "Projets",
    proj_malware_title: "Analyse malware : reverse shell Linux ELF",
    proj_malware_desc: "Configuration C2 chiffrée, notes de déchiffrement XOR, apprentissage YARA basique.",
    proj_yara_title: "Règles YARA (apprentissage)",
    proj_yara_desc: "Petites signatures défensives construites à partir des notes d’analyse.",
    proj_siem_title: "Mini SIEM (prévu)",
    proj_siem_desc: "En cours : ingestion de logs + vues de détection basiques.",

    // malware section
    scope_title: "Périmètre",
    scope_b1: "Aucun binaire malware publié.",
    scope_b2: "Uniquement texte, captures, notes et pseudocode.",
    scope_b3: "Intention strictement défensive.",
    malware_writeup_title: "Reverse shell Linux ELF — write-up",
    malware_writeup_desc: "Notes de reverse + script de déchiffrement + apprentissage YARA.",

    // SOC
    soc_labs_title: "SOC Labs",
    soc_labs_desc: "Exercices style SOC : bases réseau, triage de logs, playbooks simples et idées de détection.",
    soc_writeup_title: "Write-up SOC / réseau",
    soc_writeup_desc: "DNS, WHOIS, ICMP, couches TCP/IP — notes structurées.",

    // TryHackMe
    thm_status_title: "Statut",
    thm_status_b1: "SOC Level 1 : terminé",
    thm_status_b2: "SOC Level 2 : en cours",
    thm_status_b3: "Classement : top 7%",
    thm_about: "TryHackMe est une plateforme pratique avec des labs guidés et des scénarios type SOC. Je l’utilise pour m’entraîner au triage d’alertes, aux fondamentaux réseau et aux workflows défensifs.",

    // featured
    featured_title: "Projets mis en avant",
    featured_projects_title: "Projets mis en avant",
    feat_vault_title: "Secure File Vault",
    feat_vault_desc: "Outil chiffrement/déchiffrement + threat model + guidelines sécurité.",
    feat_rbd_title: "Ransomware Behavior Detector",
    feat_rbd_desc: "Idée de détection basée sur le comportement + documentation (périmètre défensif).",
    feat_elf_title: "Reverse Shell Linux ELF — analyse",
    feat_elf_desc: "Notes statiques + dynamique basique, extraction d’IOC, conclusions orientées détection.",

    // mini blocks
    current_focus_title: "Focus actuel",
    mini_focus_title: "Focus actuel",
    mini_focus_text: "Approche détection, bases d’analyse malware, scénarios SOC",
    lab_title: "Lab",
    mini_lab_title: "Lab",
    mini_lab_text: "VM uniquement, isolé, pas de réseau public ; périmètre défensif",
    output_title: "Livrables",
    mini_output_title: "Livrables",
    mini_output_text: "Write-ups, IOCs, apprentissages YARA/Sigma",

    // sidebar / badges
    sidebar_role: "Étudiant cybersécurité — Blue Team & Analyse malware",
    badge_soc: "Orienté SOC",
    badge_thm: "TryHackMe top 7%",

    // doc page
    doc_open_github: "Ouvrir sur GitHub",
    doc_open_raw: "Ouvrir en brut",
    doc_note: "Cette page pointe vers le Markdown correspondant dans le dépôt. Aucun binaire n’est hébergé."
  },

  en: {
    // global
    open: "Open",
    back: "Back",
    legal: "Defensive & educational content only. No malware binaries hosted.",
    doc_open_github: "Open on GitHub",
    doc_open_raw: "Open raw",
    btn_open_progress: "Open progress notes",
    open_progress: "Open progress notes",
    btn_back: "Back",
    btn_open: "Open",

    // leads / headers
    projects_lead: "Curated selection. Everything is defensive and documented. No malicious binaries are hosted.",
    malware_lead: "Reproduced in an isolated lab, with a detection-oriented mindset: IOCs, behaviours, and defensive takeaways.",
    soc_lead: "SOC-style exercises: network basics, log triage mindset, simple playbooks, and detection ideas.",
    thm_lead: "Training progress and defensive notes. No full spoilers.",
    overview_lead: "I focus on Blue Team fundamentals: malware triage, detection-oriented analysis, and SOC workflows. I maintain an isolated lab (Windows/Linux/Parrot) and publish structured write-ups and tooling notes.",

    // sidebar
    nav_overview: "Overview",
    nav_projects: "Projects",
    nav_malware: "Malware Analysis",
    nav_soc: "SOC Labs",
    nav_thm: "TryHackMe",
    nav_contact: "Contact",

    // projects
    projects_title: "Projects",
    proj_malware_title: "Malware analysis: Linux ELF reverse shell",
    proj_malware_desc: "Encrypted C2 config, XOR decryption notes, basic YARA learning.",
    proj_yara_title: "YARA rules (learning)",
    proj_yara_desc: "Small defensive signatures built from analysis notes.",
    proj_siem_title: "Mini SIEM (planned)",
    proj_siem_desc: "In progress: log ingestion + basic detection views.",

    // malware section
    scope_title: "Scope",
    scope_b1: "No malware binaries published.",
    scope_b2: "Text, screenshots, notes, and pseudocode only.",
    scope_b3: "Defensive intent only.",
    malware_writeup_title: "Linux ELF reverse shell — write-up",
    malware_writeup_desc: "Reverse engineering notes + decryption script + YARA learning.",

    // SOC
    soc_labs_title: "SOC Labs",
    soc_labs_desc: "SOC-style exercises: network basics, log triage mindset, simple playbooks, and detection ideas.",
    soc_writeup_title: "SOC / network write-up",
    soc_writeup_desc: "DNS, WHOIS, ICMP, TCP/IP layers — structured notes.",

    // TryHackMe
    thm_status_title: "Status",
    thm_status_b1: "SOC Level 1: completed",
    thm_status_b2: "SOC Level 2: in progress",
    thm_status_b3: "Ranking: top 7%",
    thm_about: "TryHackMe is a hands-on platform with guided labs and SOC-style scenarios. I use it to practice alert triage, network fundamentals, and defensive workflows.",

    // featured
    featured_title: "Featured projects",
    featured_projects_title: "Featured projects",
    feat_vault_title: "Secure File Vault",
    feat_vault_desc: "File encryption/decryption tool + threat model + security guidelines.",
    feat_rbd_title: "Ransomware Behavior Detector",
    feat_rbd_desc: "Behavior-based detection idea + documentation (defensive scope).",
    feat_elf_title: "Linux ELF Reverse Shell — analysis",
    feat_elf_desc: "Static + basic dynamic notes, IOC extraction, detection-oriented conclusions.",

    // mini blocks
    current_focus_title: "Current focus",
    mini_focus_title: "Current focus",
    mini_focus_text: "Detection mindset, malware analysis basics, SOC scenarios",
    lab_title: "Lab",
    mini_lab_title: "Lab",
    mini_lab_text: "VM-only, isolated, no public network; defensive scope",
    output_title: "Output",
    mini_output_title: "Output",
    mini_output_text: "Write-ups, IOCs, YARA/Sigma learning artefacts",

    // sidebar / badges
    sidebar_role: "Cybersecurity Student — Blue Team & Malware Analysis",
    badge_soc: "SOC-oriented",
    badge_thm: "TryHackMe top 7%",

    // doc page
    doc_open_github: "Open on GitHub",
    doc_open_raw: "Open raw",
    doc_note: "This page links to the corresponding Markdown in the repository. No binaries are hosted."
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

    const t = (lang === "en")
      ? (a.getAttribute("data-title-en") || "")
      : (a.getAttribute("data-title-fr") || "");

    const qs = new URLSearchParams();
    qs.set("doc", doc);
    if (t) qs.set("title", decodeURIComponent(t)); // note: we store encoded strings, then decode here

    a.setAttribute("href", `./doc.html?${qs.toString()}`);
  });

  // highlight selected flag
  document.querySelectorAll(".lang-btn").forEach(btn => {
    btn.classList.toggle("is-active", btn.getAttribute("data-lang") === lang);
  });

  localStorage.setItem("lang", lang);
}


const savedLang = localStorage.getItem("lang") || "fr";
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

