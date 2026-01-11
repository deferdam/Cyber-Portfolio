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
