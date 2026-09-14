"use strict";
/*
 * ctf.js - optional CTF layer for the portfolio (two-level: categories -> exercises).
 *
 * DESIGN CONTRACT (do not violate):
 *  I1 Non-gating        : portfolio is the default view; project links live in
 *                         portfolio mode, public and ungated. Nothing here blocks them.
 *  I2 No client secret  : every challenge relies only on content public by design
 *                         (source, console, robots.txt, base64, a DOM node, or a
 *                         downloadable image carrying the token). token_hash is
 *                         anti-spoiler, NOT security.
 *  I4 Graceful degradation : if this module throws, the portfolio keeps working.
 *  I6 Derived cosmetics  : "solved" green state and progress counters are derived from
 *                         local state only; never a source of security truth.
 *
 * A determined visitor can bypass every check (edit this file, force solved, read the
 * reveal). ACCEPTED: this is a pedagogical ornament, not access control.
 */

(function () {
  try {

    /* ------------------------------------------------------------------ *
     * Registry: categories -> exercises.
     * Exercise ids are GLOBALLY unique (used as solved-set keys).
     * tokenHash = sha256(exact token). Tokens are case-sensitive.
     * asset (optional) = downloadable file the challenge is about.
     * ------------------------------------------------------------------ */
    const CATEGORIES = [
      {
        id: "web",
        title: { fr: "Web / Recon", en: "Web / Recon" },
        blurb: {
          fr: "Le client est public. Tout est deja dans la page : le merite est de savoir ou regarder.",
          en: "The client is public. Everything is already in the page: the merit is knowing where to look."
        },
        exercises: [
          {
            id: "inspect-comment",
            tokenHash: "2f25b3c2fe9a16f03d50c331edd21ef0a046362c30ccd83f255f8b17ed5ad63f",
            i18n: {
              title: { fr: "01 - Lis la source", en: "01 - Read the source" },
              prompt: { fr: "La page d'accueil cache un jeton dans un commentaire HTML. Ouvre la source (Ctrl+U) et trouve-le.", en: "The home page hides a token in an HTML comment. View the source (Ctrl+U) and find it." },
              hint: { fr: "Vue > Source de la page, puis cherche DEFER{", en: "View > Page Source, then search for DEFER{" },
              reveal: { fr: "Le code livre au navigateur est public : commentaires, attributs, scripts. Premiere lecon defensive.", en: "Code shipped to the browser is public: comments, attributes, scripts. First defensive lesson." }
            }
          },
          {
            id: "console-log",
            tokenHash: "389c2b0ff7bd8742591ac3f76f9a67c709c7569762cad0eb1cbcb6b5f4bfca85",
            i18n: {
              title: { fr: "02 - La console parle", en: "02 - The console talks" },
              prompt: { fr: "Ouvre les outils de developpement (F12), onglet Console. Un jeton y est imprime au chargement.", en: "Open developer tools (F12), Console tab. A token is printed there on load." },
              hint: { fr: "F12 > Console. Regarde les messages au chargement.", en: "F12 > Console. Look at the load-time messages." },
              reveal: { fr: "Les messages de console et l'etat JS sont visibles de tous. Jamais de secret la-dedans.", en: "Console messages and JS state are visible to anyone. Never a secret there." }
            }
          },
          {
            id: "robots",
            tokenHash: "c1e13723e2d5f408ad92f8cc30de777c308878f5f4683a928238091ee9144b0f",
            i18n: {
              title: { fr: "03 - Ou sont les robots", en: "03 - Where are the robots" },
              prompt: { fr: "Un fichier standard indique aux crawlers les chemins a ne pas indexer. Consulte-le, suis le chemin interdit.", en: "A standard file tells crawlers which paths not to index. Read it, follow the disallowed path." },
              hint: { fr: "Ajoute /robots.txt a la racine du site.", en: "Append /robots.txt to the site root." },
              reveal: { fr: "robots.txt n'est pas un controle d'acces : c'est une pancarte. Un 'Disallow' signale souvent la cible.", en: "robots.txt is not access control: it is a signpost. A 'Disallow' often advertises the target." }
            }
          },
          {
            id: "base64",
            tokenHash: "2fbf6d751d9c3e68779a9f385db1aecfd7e96b525757140fee61c1c071c3abf5",
            i18n: {
              title: { fr: "04 - Encoder n'est pas chiffrer", en: "04 - Encoding is not encryption" },
              prompt: { fr: "La page d'accueil porte une chaine base64 dans un attribut de donnees. Decode-la.", en: "The home page carries a base64 string in a data attribute. Decode it." },
              hint: { fr: "Cherche data-transmission dans la source, decode avec atob() ou CyberChef.", en: "Search data-transmission in the source, decode with atob() or CyberChef." },
              reveal: { fr: "Base64 est un encodage reversible sans cle, pas du chiffrement. Confondre les deux est une faute d'entretien.", en: "Base64 is reversible keyless encoding, not encryption. Confusing the two is an interview mistake." }
            }
          },
          {
            id: "css-ghost",
            tokenHash: "8a466e11f624bcc2cfc9b7da76c1adafbbbebe200d704856172509093b77775c",
            i18n: {
              title: { fr: "05 - display:none ne cache rien", en: "05 - display:none hides nothing" },
              prompt: { fr: "Un element est masque a l'ecran par CSS mais present dans le DOM. Inspecte-le et lis le jeton.", en: "An element is hidden on screen by CSS but present in the DOM. Inspect it and read the token." },
              hint: { fr: "Clic droit > Inspecter, cherche un noeud de classe ctf-ghost.", en: "Right-click > Inspect, look for a node with class ctf-ghost." },
              reveal: { fr: "Masquer par CSS n'ote rien du DOM. La confidentialite cote client est nulle.", en: "Hiding via CSS removes nothing from the DOM. Client-side confidentiality is zero." }
            }
          }
        ]
      },
      {
        id: "stego",
        title: { fr: "Steganographie", en: "Steganography" },
        blurb: {
          fr: "Telecharge l'image, puis fouille ce que l'oeil ne voit pas : metadonnees, octets caches, contraste.",
          en: "Download the image, then dig into what the eye misses: metadata, hidden bytes, contrast."
        },
        exercises: [
          {
            id: "stego-exif",
            tokenHash: "c43041030ee59d756024030c61d2ffcfa3aefeda10955f6d0d718cdf44eaf9c3",
            asset: "./img/ctf/evidence.jpg",
            i18n: {
              title: { fr: "01 - La metadonnee n'oublie pas", en: "01 - Metadata never forgets" },
              prompt: { fr: "Telecharge l'image. Rien en surface. Le jeton est dans ses metadonnees EXIF.", en: "Download the image. Nothing on the surface. The token is in its EXIF metadata." },
              hint: { fr: "exiftool evidence.jpg, ou un lecteur EXIF en ligne. Regarde UserComment.", en: "exiftool evidence.jpg, or an online EXIF reader. Look at UserComment." },
              reveal: { fr: "Les fichiers portent une memoire cachee (EXIF, auteur, GPS). Toujours nettoyer les metadonnees avant publication.", en: "Files carry hidden memory (EXIF, author, GPS). Always strip metadata before publishing." }
            }
          },
          {
            id: "stego-append",
            tokenHash: "46eda99ea1d71e6be994d3fd6ab81614b1c3937a4f83b67aa8889ef319fc01b1",
            asset: "./img/ctf/carrier.png",
            i18n: {
              title: { fr: "02 - Apres la fin", en: "02 - After the end" },
              prompt: { fr: "Cette image est valide, mais des octets sont ecrits apres sa fin de fichier. Retrouve le jeton.", en: "This image is valid, but bytes are written after its end-of-file marker. Recover the token." },
              hint: { fr: "strings carrier.png | grep DEFER, ou binwalk. L'image se termine au marqueur IEND.", en: "strings carrier.png | grep DEFER, or binwalk. The image ends at the IEND marker." },
              reveal: { fr: "Un fichier valide peut cacher une charge apres sa fin logique. C'est la base du carving et de binwalk.", en: "A valid file can hide a payload after its logical end. This is the basis of carving and binwalk." }
            }
          },
          {
            id: "stego-visual",
            tokenHash: "03bf04ee5a9224584f51951af0793714d2cc464c706eb7b3d80e1b34ce0aab93",
            asset: "./img/ctf/lowcontrast.png",
            i18n: {
              title: { fr: "03 - Monte le contraste", en: "03 - Turn up the contrast" },
              prompt: { fr: "L'image parait presque noire. Un texte s'y cache a un niveau de luminosite tres proche du fond.", en: "The image looks nearly black. Text hides at a brightness level very close to the background." },
              hint: { fr: "Ouvre dans GIMP/Photopea, pousse contraste/niveaux au maximum. Ou augmente la saturation.", en: "Open in GIMP/Photopea, push contrast/levels to the max. Or crank saturation." },
              reveal: { fr: "Un signal peut etre present mais sous le seuil de perception. Rehausser les niveaux le revele.", en: "A signal can be present yet below perception threshold. Boosting levels reveals it." }
            }
          }
        ]
      }
    ];

    const UI = {
      fr: {
        catIntro: "Terrain d'entrainement. Choisis une categorie. Aucun lien projet n'est cache ici - ils restent accessibles cote Portfolio.",
        solved: "resolu",
        complete: "complet",
        submit: "Valider",
        placeholder: "DEFER{...}",
        wrong: "Jeton incorrect.",
        backCats: "< Categories",
        backExos: "< Retour",
        showHint: "Afficher l'indice",
        download: "Telecharger l'image",
        progress: (n, tt) => `${n}/${tt}`,
        allDone: "Tout est resolu. Tu as prouve un point simple : sur un hebergement statique, rien de livre au client n'est confidentiel.",
        noCrypto: "Ce terrain a besoin d'un contexte securise (HTTPS). Il fonctionne sur le site publie, pas en ouverture locale de fichier."
      },
      en: {
        catIntro: "Training ground. Pick a category. No project link is hidden here - they stay reachable in Portfolio mode.",
        solved: "solved",
        complete: "complete",
        submit: "Submit",
        placeholder: "DEFER{...}",
        wrong: "Wrong token.",
        backCats: "< Categories",
        backExos: "< Back",
        showHint: "Show hint",
        download: "Download image",
        progress: (n, tt) => `${n}/${tt}`,
        allDone: "All solved. You proved a simple point: on static hosting, nothing shipped to the client is confidential.",
        noCrypto: "This ground needs a secure context (HTTPS). It works on the published site, not on local file open."
      }
    };

    const STORAGE_KEY = "ctf_solved_v1";
    const main = document.querySelector(".main");
    const root = document.getElementById("ctf-root");
    if (!main || !root) return; // markup absent -> portfolio only (I4)

    const lang = () => (localStorage.getItem("lang") === "en") ? "en" : "fr";
    const t = (node) => node[lang()] || node.en;

    function loadSolved() {
      try { const raw = localStorage.getItem(STORAGE_KEY); return new Set(raw ? JSON.parse(raw) : []); }
      catch (_) { return new Set(); }
    }
    function saveSolved(set) {
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify([...set])); } catch (_) {}
    }
    let solved = loadSolved();

    const catSolvedCount = (cat) => cat.exercises.filter(e => solved.has(e.id)).length;
    const catComplete = (cat) => catSolvedCount(cat) === cat.exercises.length;
    const totalExercises = () => CATEGORIES.reduce((n, c) => n + c.exercises.length, 0);
    const totalSolved = () => CATEGORIES.reduce((n, c) => n + catSolvedCount(c), 0);

    async function sha256Hex(str) {
      const bytes = new TextEncoder().encode(str);
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
    }

    function el(tag, cls, text) {
      const n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text != null) n.textContent = text;
      return n;
    }
    function pill(text, green) {
      return el("span", "pill " + (green ? "pill-green" : "pill-dim"), text);
    }

    // --- views ------------------------------------------------------------
    function renderCategoryList() {
      const L = UI[lang()];
      root.innerHTML = "";
      root.appendChild(el("h1", null, "CTF"));
      root.appendChild(el("p", "lead", L.catIntro));
      root.appendChild(el("p", "muted", L.progress(totalSolved(), totalExercises())));
      if (totalSolved() === totalExercises()) {
        const done = el("div", "callout is-solved");
        done.appendChild(el("div", "callout-title", "DEFER{}"));
        done.appendChild(el("div", null, L.allDone));
        root.appendChild(done);
      }
      const grid = el("div", "grid");
      CATEGORIES.forEach(cat => {
        const complete = catComplete(cat);
        const card = el("article", "card no-thumb ctf-card" + (complete ? " is-solved" : ""));
        const body = el("div", "card-body");
        const title = el("div", "card-title", t(cat.title));
        title.appendChild(document.createTextNode(" "));
        title.appendChild(pill(L.progress(catSolvedCount(cat), cat.exercises.length) + (complete ? " " + L.complete : ""), complete));
        body.appendChild(title);
        body.appendChild(el("div", "card-desc", t(cat.blurb)));
        const link = el("span", "card-link", "->");
        body.appendChild(link);
        card.appendChild(body);
        card.addEventListener("click", () => { location.hash = "#/ctf/" + cat.id; });
        grid.appendChild(card);
      });
      root.appendChild(grid);
    }

    function renderExerciseList(cat) {
      const L = UI[lang()];
      root.innerHTML = "";
      const back = el("button", "btn", L.backCats);
      back.addEventListener("click", () => { location.hash = "#/ctf"; });
      root.appendChild(back);
      root.appendChild(el("h1", null, t(cat.title)));
      root.appendChild(el("p", "lead", t(cat.blurb)));
      root.appendChild(el("p", "muted", L.progress(catSolvedCount(cat), cat.exercises.length)));
      const grid = el("div", "grid");
      cat.exercises.forEach(ex => {
        const isSolved = solved.has(ex.id);
        const card = el("article", "card no-thumb ctf-card" + (isSolved ? " is-solved" : ""));
        const body = el("div", "card-body");
        const title = el("div", "card-title", t(ex.i18n.title));
        if (isSolved) { title.appendChild(document.createTextNode(" ")); title.appendChild(pill(L.solved, true)); }
        body.appendChild(title);
        body.appendChild(el("div", "card-desc", t(ex.i18n.prompt)));
        const link = el("span", "card-link", "->");
        body.appendChild(link);
        card.appendChild(body);
        card.addEventListener("click", () => { location.hash = "#/ctf/" + cat.id + "/" + ex.id; });
        grid.appendChild(card);
      });
      root.appendChild(grid);
    }

    function renderChallenge(cat, ex) {
      const L = UI[lang()];
      root.innerHTML = "";
      const back = el("button", "btn", L.backExos);
      back.addEventListener("click", () => { location.hash = "#/ctf/" + cat.id; });
      root.appendChild(back);
      root.appendChild(el("h1", null, t(ex.i18n.title)));
      root.appendChild(el("p", "lead", t(ex.i18n.prompt)));

      if (ex.asset) {
        const dl = el("a", "btn ctf-download", L.download);
        dl.href = ex.asset;
        dl.setAttribute("download", "");
        root.appendChild(dl);
      }

      if (solved.has(ex.id)) {
        const ok = el("div", "callout is-solved");
        ok.appendChild(el("div", "callout-title", "OK - " + L.solved));
        ok.appendChild(el("div", null, t(ex.i18n.reveal)));
        root.appendChild(ok);
        return;
      }

      const rowc = el("div", "ctf-input-row");
      const input = el("input", "ctf-input");
      input.type = "text"; input.placeholder = L.placeholder;
      input.setAttribute("autocomplete", "off"); input.setAttribute("spellcheck", "false");
      const submit = el("button", "btn ctf-submit", L.submit);
      rowc.appendChild(input); rowc.appendChild(submit);
      root.appendChild(rowc);

      const feedback = el("div", "ctf-feedback");
      root.appendChild(feedback);

      const hintBtn = el("button", "ctf-hint-btn", L.showHint);
      const hintText = el("div", "muted ctf-hint"); hintText.hidden = true;
      hintText.textContent = t(ex.i18n.hint);
      hintBtn.addEventListener("click", () => { hintText.hidden = false; hintBtn.hidden = true; });
      root.appendChild(hintBtn); root.appendChild(hintText);

      async function attempt() {
        const guess = input.value.trim();
        if (!guess) return;
        if (!(window.crypto && crypto.subtle)) { feedback.textContent = L.noCrypto; return; }
        const h = await sha256Hex(guess);
        if (h === ex.tokenHash) {
          solved.add(ex.id); saveSolved(solved);
          renderChallenge(cat, ex); // re-render into solved state (green)
        } else {
          feedback.textContent = L.wrong; input.focus(); input.select();
        }
      }
      submit.addEventListener("click", attempt);
      input.addEventListener("keydown", e => { if (e.key === "Enter") attempt(); });
      input.focus();
    }

    // --- mode + router ----------------------------------------------------
    function goPortfolioView() { main.classList.remove("ctf-active"); setToggle("portfolio"); }
    function goCtfView() { main.classList.add("ctf-active"); setToggle("ctf"); }
    function setToggle(mode) {
      document.querySelectorAll("[data-mode]").forEach(b =>
        b.classList.toggle("is-active", b.getAttribute("data-mode") === mode));
    }

    function route() {
      const h = location.hash || "";
      if (h.indexOf("#/ctf") === 0) {
        goCtfView();
        const rest = h.slice("#/ctf".length).replace(/^\//, ""); // "", "web", "web/robots"
        const parts = rest.split("/");
        const catId = parts[0], exId = parts[1];
        const cat = CATEGORIES.find(c => c.id === catId);
        if (!cat) { renderCategoryList(); return; }
        const ex = exId ? cat.exercises.find(e => e.id === exId) : null;
        if (ex) renderChallenge(cat, ex); else renderExerciseList(cat);
      } else {
        goPortfolioView();
        const page = h.replace(/^#\/?/, "");
        if (page && typeof window.showPage === "function") window.showPage(page);
      }
    }

    document.querySelectorAll("[data-mode]").forEach(b => {
      b.addEventListener("click", () => {
        location.hash = (b.getAttribute("data-mode") === "ctf") ? "#/ctf" : "#/";
      });
    });

    document.addEventListener("click", e => {
      const nav = e.target.closest("[data-nav]");
      if (nav && main.classList.contains("ctf-active")) location.hash = "#/";
    });

    document.querySelectorAll(".lang-btn").forEach(b => {
      b.addEventListener("click", () => { if (main.classList.contains("ctf-active")) route(); });
    });

    window.addEventListener("hashchange", route);

    // Web challenge 02: the console talks (printed once on load).
    try {
      console.log("%cSOC recon:%c the console is public. DEFER{the_console_talks}",
        "color:#e63946;font-weight:bold", "color:inherit");
    } catch (_) {}

    route(); // initial (default = portfolio, I1)

  } catch (err) {
    try {
      const m = document.querySelector(".main"); if (m) m.classList.remove("ctf-active");
      const r = document.getElementById("ctf-root"); if (r) r.hidden = true;
    } catch (_) {}
    if (window.console) console.warn("CTF layer disabled:", err);
  }
})();
