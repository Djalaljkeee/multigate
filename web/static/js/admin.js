// Админка MultiGate: минимум ванильного JS, без фреймворков и сборки.
// Три независимые вещи: мобильное меню, подтверждение опасных действий
// и переключение блоков формы под выбранный режим работы.
(function () {
  "use strict";

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  // Мобильное меню: сайдбар выезжает поверх контента, скрим закрывает по клику мимо.
  function initMobileMenu() {
    var toggle = document.getElementById("menu-toggle");
    var sidebar = document.getElementById("sidebar");
    var scrim = document.getElementById("scrim");
    if (!toggle || !sidebar || !scrim) return;

    function setOpen(open) {
      sidebar.classList.toggle("open", open);
      scrim.classList.toggle("open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    }

    toggle.addEventListener("click", function () {
      setOpen(!sidebar.classList.contains("open"));
    });
    scrim.addEventListener("click", function () { setOpen(false); });
    sidebar.addEventListener("click", function (e) {
      if (e.target.tagName === "A") setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") setOpen(false);
    });
  }

  // Формы и кнопки с data-confirm спрашивают подтверждение перед отправкой:
  // блокировки и удаления необратимы или как минимум неприятны по ошибке.
  function initConfirm() {
    document.addEventListener("submit", function (e) {
      var el = e.target;
      if (el instanceof HTMLFormElement && el.hasAttribute("data-confirm")) {
        var msg = el.getAttribute("data-confirm") || "Вы уверены?";
        if (!window.confirm(msg)) {
          e.preventDefault();
        }
      }
    });
  }

  // На страницах мастера настройки и настроек поля панели/зеркала показываются
  // только под выбранный режим: без JS просто остаются видны оба блока.
  function initModeSwitch() {
    var radios = document.querySelectorAll("[data-mode-switch]");
    if (!radios.length) return;

    function apply() {
      var current = document.querySelector("[data-mode-switch]:checked");
      var mode = current ? current.value : "";
      document.querySelectorAll("[data-mode-for]").forEach(function (el) {
        el.classList.toggle("mode-hidden", el.getAttribute("data-mode-for") !== mode);
      });
    }

    radios.forEach(function (r) { r.addEventListener("change", apply); });
    apply();
  }

  ready(function () {
    initMobileMenu();
    initConfirm();
    initModeSwitch();
  });
})();
