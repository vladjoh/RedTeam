(() => {
  const header = document.querySelector(".site-header");
  if (!header) return;

  const onScroll = () => {
    header.classList.toggle("is-scrolled", window.scrollY > 12);
  };

  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  // Reveal sections on enter viewport
  const sections = document.querySelectorAll(".section");
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("in-view");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12 }
    );
    sections.forEach((s) => {
      s.style.opacity = "0";
      s.style.transform = "translateY(14px)";
      s.style.transition = "opacity 0.55s ease, transform 0.55s ease";
      io.observe(s);
    });
    const style = document.createElement("style");
    style.textContent = `.section.in-view { opacity: 1 !important; transform: none !important; }`;
    document.head.appendChild(style);
  }
})();