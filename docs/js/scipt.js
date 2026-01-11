"use strict";

const pages = document.querySelectorAll("[data-page]");
const buttons = document.querySelectorAll("[data-nav]");

function showPage(key) {
  pages.forEach(p => p.classList.toggle("is-active", p.dataset.page === key));
  buttons.forEach(b => b.classList.toggle("is-active", b.dataset.nav === key));
  window.scrollTo(0, 0);
}

buttons.forEach(btn => {
  btn.addEventListener("click", () => showPage(btn.dataset.nav));
});
