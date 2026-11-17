/**
 * chrome.js
 *
 * Layout-free, unstyled behaviors that attach to existing markup via data attributes.
 * Imposes NO section structure, NO CSS layout, NO palette, and NO fonts.
 *
 * Supported data attributes:
 * - [data-chrome-progress]: Reading progress element. Updates width and aria-valuenow on scroll.
 * - [data-chrome-toc]: Table of contents container. Links (a[href^="#"]) receive class "active"
 *   and aria-current="true" when matching sections scroll into view.
 * - [data-chrome-lightbox]: Clickable images. Opens a minimal full-viewport overlay on click.
 * - [data-chrome-reduced-motion]: Automatically detects prefers-reduced-motion and sets
 *   scrollBehavior to auto.
 * - [data-chrome-keyboard]: Keyboard navigation across [data-section] elements using j/k or arrows.
 */
(() => {
  if (typeof window === "undefined" || typeof document === "undefined") return;

  function initProgress() {
    const bar = document.querySelector("[data-chrome-progress]");
    if (!bar) return;

    function update() {
      const scrollH = document.documentElement.scrollHeight - window.innerHeight;
      const progress = scrollH > 0 ? Math.min(1, Math.max(0, window.scrollY / scrollH)) : 0;
      const pct = (progress * 100).toFixed(1) + "%";
      bar.style.width = pct;
      bar.setAttribute("aria-valuenow", Math.round(progress * 100).toString());
    }

    window.addEventListener("scroll", update, { passive: true });
    update();
  }

  function initToc() {
    const toc = document.querySelector("[data-chrome-toc]");
    if (!toc) return;

    const links = Array.from(toc.querySelectorAll('a[href^="#"]'));
    if (links.length === 0) return;

    const targets = links
      .map(a => {
        const id = a.getAttribute("href").slice(1);
        const el = document.getElementById(id);
        return el ? { link: a, el } : null;
      })
      .filter(Boolean);

    if (targets.length === 0) return;

    const observer = new IntersectionObserver(
      entries => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            for (const item of targets) {
              if (item.el === entry.target) {
                item.link.classList.add("active");
                item.link.setAttribute("aria-current", "true");
              } else {
                item.link.classList.remove("active");
                item.link.removeAttribute("aria-current");
              }
            }
          }
        }
      },
      { rootMargin: "-15% 0px -75% 0px" }
    );

    for (const item of targets) {
      observer.observe(item.el);
    }
  }

  function initLightbox() {
    const images = Array.from(
      document.querySelectorAll("[data-chrome-lightbox], [data-lightbox]")
    );
    if (images.length === 0) return;

    let overlay = document.querySelector("[data-chrome-lightbox-dialog]");
    if (!overlay) {
      overlay = document.createElement("dialog");
      overlay.setAttribute("data-chrome-lightbox-dialog", "");
      overlay.style.cssText =
        "position:fixed;inset:0;width:100vw;height:100vh;max-width:100vw;max-height:100vh;margin:0;padding:0;border:none;background:rgba(0,0,0,0.85);display:none;align-items:center;justify-content:center;z-index:9999;";
      const img = document.createElement("img");
      img.style.cssText = "max-width:90vw;max-height:90vh;object-fit:contain;";
      overlay.appendChild(img);

      overlay.addEventListener("click", () => {
        overlay.style.display = "none";
        overlay.close();
      });

      document.body.appendChild(overlay);
    }

    const overlayImg = overlay.querySelector("img");

    for (const img of images) {
      img.style.cursor = "zoom-in";
      img.addEventListener("click", () => {
        const src = img.getAttribute("data-full-src") || img.getAttribute("src");
        if (src && overlayImg) {
          overlayImg.src = src;
          overlayImg.alt = img.alt || "";
          overlay.style.display = "flex";
          overlay.showModal();
        }
      });
    }
  }

  function initReducedMotion() {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    function handle(e) {
      if (e.matches) {
        document.documentElement.style.scrollBehavior = "auto";
        document.documentElement.setAttribute("data-reduced-motion", "true");
      } else {
        document.documentElement.removeAttribute("data-reduced-motion");
      }
    }
    media.addEventListener("change", handle);
    handle(media);
  }

  function initKeyboard() {
    if (!document.querySelector("[data-chrome-keyboard]")) return;

    const sections = Array.from(document.querySelectorAll("[data-section], section[id]"));
    if (sections.length === 0) return;

    window.addEventListener("keydown", e => {
      const activeTag = document.activeElement ? document.activeElement.tagName : "";
      if (["INPUT", "TEXTAREA", "SELECT", "BUTTON"].includes(activeTag)) return;

      if (e.key === "j" || e.key === "ArrowDown") {
        const currentY = window.scrollY;
        const next = sections.find(s => s.getBoundingClientRect().top > 50);
        if (next) {
          e.preventDefault();
          next.scrollIntoView({ behavior: "smooth" });
        }
      } else if (e.key === "k" || e.key === "ArrowUp") {
        const prev = sections.slice().reverse().find(s => s.getBoundingClientRect().top < -50);
        if (prev) {
          e.preventDefault();
          prev.scrollIntoView({ behavior: "smooth" });
        }
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      initProgress();
      initToc();
      initLightbox();
      initReducedMotion();
      initKeyboard();
    });
  } else {
    initProgress();
    initToc();
    initLightbox();
    initReducedMotion();
    initKeyboard();
  }
})();
