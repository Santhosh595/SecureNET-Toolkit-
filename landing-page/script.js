/* SecureNET Landing Page — Scripts */

(function () {
  "use strict";

  /* --- Mobile nav toggle --- */
  const mobileToggle = document.getElementById("mobileToggle");
  const navLinks = document.querySelector(".nav-links");

  if (mobileToggle && navLinks) {
    mobileToggle.addEventListener("click", function () {
      const isHidden = navLinks.style.display === "flex";
      navLinks.style.display = isHidden ? "none" : "flex";
      if (!isHidden) {
        navLinks.style.flexDirection = "column";
        navLinks.style.position = "absolute";
        navLinks.style.top = "64px";
        navLinks.style.left = "0";
        navLinks.style.right = "0";
        navLinks.style.background = "rgba(6, 10, 16, 0.95)";
        navLinks.style.backdropFilter = "blur(16px)";
        navLinks.style.padding = "16px 24px";
        navLinks.style.borderBottom = "1px solid var(--border)";
        navLinks.style.gap = "16px";
      }
    });
  }

  /* --- Scroll-reveal animations --- */
  function initScrollReveal() {
    const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReduced) return;

    const elements = document.querySelectorAll(
      ".feature-card, .tool-card, .arch-box, .hero-content, .section-header, .cta-box"
    );

    elements.forEach(function (el) {
      el.classList.add("fade-up");
    });

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.1, rootMargin: "0px 0px -40px 0px" }
    );

    elements.forEach(function (el) {
      observer.observe(el);
    });
  }

  /* --- Active nav link on scroll --- */
  function initActiveNav() {
    var sections = document.querySelectorAll("section[id]");
    var navAnchors = document.querySelectorAll(".nav-links a[href^='#']");

    var scrollObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            var id = entry.target.getAttribute("id");
            navAnchors.forEach(function (a) {
              a.classList.toggle("active", a.getAttribute("href") === "#" + id);
            });
          }
        });
      },
      { rootMargin: "-40% 0px -60% 0px" }
    );

    sections.forEach(function (s) {
      scrollObserver.observe(s);
    });
  }

  /* --- Smooth scroll for anchor links --- */
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener("click", function (e) {
      var targetId = this.getAttribute("href");
      if (targetId === "#") return;
      var target = document.querySelector(targetId);
      if (target) {
        e.preventDefault();
        var navHeight = 64;
        var top = target.getBoundingClientRect().top + window.scrollY - navHeight;
        window.scrollTo({ top: top, behavior: "smooth" });
      }
    });
  });

  /* --- Init --- */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      initScrollReveal();
      initActiveNav();
    });
  } else {
    initScrollReveal();
    initActiveNav();
  }
})();
