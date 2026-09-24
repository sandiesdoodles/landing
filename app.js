(() => {
  const data = window.SANDIES;
  if (!data) {
    console.error("Missing data/litter.js");
    return;
  }

  const money = (n) =>
    n.toLocaleString("en-US", {
      style: "currency",
      currency: data.pricing.currency || "USD",
      maximumFractionDigits: 0,
    });

  const banner = document.getElementById("siteBanner");
  if (banner && data.status?.headline) {
    banner.hidden = false;
    banner.textContent = `${data.status.headline} — ${data.status.note}`;
    banner.classList.toggle("is-live", data.status.mode !== "mock");
  }

  document.getElementById("year").textContent = String(new Date().getFullYear());

  if (data.hero) {
    const hl = document.getElementById("heroHeadline");
    const support = document.getElementById("heroSupport");
    if (hl && data.hero.headline) hl.textContent = data.hero.headline;
    if (support && data.hero.support) support.textContent = data.hero.support;
  }

  const alumni = document.getElementById("alumniNote");
  if (alumni) alumni.textContent = data.alumniNote || "";

  const heroSecondary = document.getElementById("heroSecondary");
  if (heroSecondary && data.heroSecondary) {
    heroSecondary.textContent = data.heroSecondary.label;
    heroSecondary.setAttribute("href", data.heroSecondary.href);
  }

  const nav = document.getElementById("primaryNav");
  const navToggle = document.getElementById("navToggle");
  const header = document.querySelector("[data-elevate]");
  const closeNav = () => {
    if (!nav || !navToggle) return;
    nav.classList.remove("is-open");
    navToggle.setAttribute("aria-expanded", "false");
    header?.classList.remove("is-nav-open");
  };
  if (navToggle && nav) {
    navToggle.addEventListener("click", () => {
      const open = !nav.classList.contains("is-open");
      nav.classList.toggle("is-open", open);
      navToggle.setAttribute("aria-expanded", String(open));
      header?.classList.toggle("is-nav-open", open);
    });
    nav.querySelectorAll("a").forEach((a) => a.addEventListener("click", closeNav));
  }

  const video = document.getElementById("heroVideo");
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (video) {
    if (prefersReduced) {
      video.removeAttribute("autoplay");
      video.pause();
      video.classList.add("is-static");
    } else {
      const markReady = () => video.classList.add("is-ready");
      if (video.readyState >= 2) markReady();
      video.addEventListener("loadeddata", markReady);
      video.addEventListener("canplay", markReady);
      video.addEventListener("error", () => video.classList.add("is-static"));
      const tryPlay = () => video.play().catch(() => {});
      tryPlay();
      document.addEventListener("visibilitychange", () => {
        if (document.hidden) video.pause();
        else tryPlay();
      });
    }
  }

  document.getElementById("processList").innerHTML = data.process
    .map(
      (step) => `
      <li class="reveal-on-scroll">
        <span class="step">${step.step}</span>
        <div>
          <h3>${step.title}</h3>
          <p>${step.text}</p>
        </div>
      </li>`
    )
    .join("");

  const litter = data.currentLitter;
  const litterPanel = document.getElementById("litterPanel");
  if (litter && litterPanel) {
    const girls = (litter.girls || []).join(" · ");
    const boys = (litter.boys || []).join(" · ");
    const nameLines =
      girls || boys
        ? `<p class="litter-names"><strong>Girls:</strong> ${girls || "—"}<br /><strong>Boys:</strong> ${boys || "—"}</p>`
        : "";
    litterPanel.innerHTML = `
      <div class="litter-media reveal-on-scroll">
        <img src="${litter.image}" alt="${litter.imageAlt || ""}" loading="lazy" />
      </div>
      <div class="litter-copy reveal-on-scroll">
        <p class="litter-eyebrow">${litter.eyebrow || ""}</p>
        <h2>${litter.title}</h2>
        <p class="litter-headline">${litter.headline}</p>
        ${nameLines}
        <p>${litter.blurb}</p>
        <a class="btn btn-primary" href="${litter.ctaHref}">${litter.ctaLabel}</a>
      </div>`;
  }

  const litter2Grid = document.getElementById("litter2Grid");
  if (litter2Grid && data.litter2) {
    litter2Grid.innerHTML = data.litter2
      .map(
        (pup) => `
      <button class="pup-card reveal-on-scroll" type="button" data-pup="${pup.id}" data-litter="2">
        <img src="${pup.image}" alt="${pup.name}" loading="lazy" />
        <div class="pup-meta">
          <h3>${pup.name}</h3>
          <p class="meta-line">${pup.sex} · ${pup.collar} · Available</p>
        </div>
      </button>`
      )
      .join("");
  }

  const pupGrid = document.getElementById("pupGrid");
  pupGrid.innerHTML = data.pups
    .map(
      (pup) => `
      <button class="pup-card reveal-on-scroll" type="button" data-pup="${pup.id}" data-litter="1">
        <img src="${pup.image}" alt="${pup.name}" loading="lazy" />
        <div class="pup-meta">
          <h3>${pup.name}</h3>
          <p class="meta-line">${pup.sex} · ${
            pup.status === "placed" ? "Placed · Litter 1" : "Available"
          }</p>
        </div>
      </button>`
    )
    .join("");

  document.getElementById("geneticsLine").textContent =
    `${data.genetics.generation}. ${data.genetics.adultSize}`;

  document.getElementById("parentGrid").innerHTML = data.parents
    .map(
      (p) => `
      <article class="parent reveal-on-scroll">
        <img src="${p.image}" alt="${p.name}" loading="lazy" />
        <div>
          <h3>${p.name}</h3>
          <p class="role">${p.role} · ${p.weight}</p>
          <p>${p.blurb}</p>
        </div>
      </article>`
    )
    .join("");

  document.getElementById("quoteList").innerHTML = data.testimonials
    .map(
      (t) => `
      <blockquote class="quote reveal-on-scroll">
        <p>“${t.quote}”</p>
        <footer>${t.name} · ${t.place}</footer>
      </blockquote>`
    )
    .join("");

  document.getElementById("pricingLabel").textContent = data.pricing.label;
  document.getElementById("pricePanel").innerHTML = `
    <div class="price-hero reveal-on-scroll">
      <div class="amount">${money(data.pricing.base)}</div>
      <div class="deposit">
        Deposit ${money(data.pricing.deposit)} to reserve
        ${
          data.pricing.depositTiming
            ? `<span class="deposit-note">${data.pricing.depositTiming}</span>`
            : ""
        }
      </div>
    </div>
    <ul class="tiers">
      ${data.pricing.tiers
        .map(
          (tier) => `
        <li class="reveal-on-scroll">
          <span><strong>${tier.name}</strong> — ${tier.note}</span>
          <span>${money(tier.price)}</span>
        </li>`
        )
        .join("")}
    </ul>
    <p><strong>Included</strong></p>
    <ul class="includes">
      ${data.pricing.includes.map((item) => `<li>${item}</li>`).join("")}
    </ul>
    <p class="meta-line genetics-note">
      ${data.genetics.generationNote}
    </p>`;

  if (data.transport) {
    const tTitle = document.getElementById("transportTitle");
    const tIntro = document.getElementById("transportIntro");
    if (tTitle) tTitle.textContent = data.transport.title;
    if (tIntro) tIntro.textContent = data.transport.intro;
    document.getElementById("transportPanel").innerHTML = `
      <div class="transport-grid">
        <div class="reveal-on-scroll">
          <h3>Non-negotiables</h3>
          <ul class="includes">
            ${data.transport.rules.map((r) => `<li>${r}</li>`).join("")}
          </ul>
        </div>
        <div class="reveal-on-scroll">
          <h3>Options</h3>
          <ul class="tiers transport-options">
            ${data.transport.options
              .map(
                (o) => `
              <li>
                <span><strong>${o.name}</strong></span>
                <span>${o.note}</span>
              </li>`
              )
              .join("")}
          </ul>
        </div>
      </div>`;
  }

  document.getElementById("faqList").innerHTML = data.faqs
    .map(
      (item) => `
      <details class="reveal-on-scroll">
        <summary>${item.q}</summary>
        <p>${item.a}</p>
      </details>`
    )
    .join("");

  const c = data.contact;
  document.getElementById("contactBlock").innerHTML = `
    Email: <a href="mailto:${c.email}">${c.email}</a><br />
    Call / text: <a href="${c.phoneHref}">${c.phone}</a><br />
    ${c.location}`;

  ["fbLink", "headerFb", "headerFbMobile"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.href = c.facebook;
  });

  const dialog = document.getElementById("pupDialog");
  const dialogBody = document.getElementById("dialogBody");
  document.getElementById("dialogClose").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) dialog.close();
  });

  pupGrid.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-pup]");
    if (!btn) return;
    openPupDialog(btn.dataset.pup, btn.dataset.litter);
  });

  if (litter2Grid) {
    litter2Grid.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-pup]");
      if (!btn) return;
      openPupDialog(btn.dataset.pup, "2");
    });
  }

  function openPupDialog(id, litter) {
    const list = litter === "2" ? data.litter2 || [] : data.pups;
    const pup = list.find((p) => p.id === id);
    if (!pup) return;
    dialogBody.innerHTML = `
      <img src="${pup.image}" alt="${pup.name}" />
      <div class="dialog-copy">
        <h3>${pup.name}</h3>
        <p class="meta-line">${pup.sex} · Collar: ${pup.collar} · ${pup.size || ""}</p>
        <p>${pup.blurb}</p>
        <p class="meta-line">Status: ${
          pup.status === "placed"
            ? "Placed in Litter 1 — alumni, not available"
            : "Available · Litter 2"
        }</p>
        <p class="meta-line"><a href="#waitlist">Join the early list →</a></p>
      </div>`;
    if (typeof dialog.showModal === "function") dialog.showModal();
  }

  const form = document.getElementById("waitlistForm");
  const status = document.getElementById("formStatus");
  const submitBtn = document.getElementById("waitlistSubmit");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    status.textContent = "Sending…";
    submitBtn.disabled = true;

    const fd = new FormData(form);
    const entry = Object.fromEntries(fd.entries());
    entry.budgetReady = fd.get("budgetReady") === "yes";
    entry.savedAt = new Date().toISOString();
    entry.type = "Early list";

    const key = "sandies_early_list";
    const prev = JSON.parse(localStorage.getItem(key) || "[]");
    prev.push(entry);
    localStorage.setItem(key, JSON.stringify(prev));

    const endpoint = data.formspree;
    if (!endpoint) {
      status.textContent = "Saved locally. Add Formspree endpoint to finish email delivery.";
      submitBtn.disabled = false;
      form.reset();
      return;
    }

    try {
      const body = new FormData(form);
      body.set("type", "Early list");
      body.set("budgetReady", entry.budgetReady ? "yes" : "no");
      body.set("litter", "Abby Litter 2");
      body.set("source", window.location.href);
      const res = await fetch(endpoint, {
        method: "POST",
        body,
        headers: { Accept: "application/json" },
      });
      if (!res.ok) throw new Error(`Formspree ${res.status}`);
      form.reset();
      status.textContent = "Got it — redirecting…";
      setTimeout(() => {
        window.location.href = "thank-you.html";
      }, 500);
    } catch (err) {
      console.warn(err);
      status.textContent =
        "Saved on this device. Email send failed for now — we still have your info locally.";
      submitBtn.disabled = false;
    }
  });

  const onScroll = () => {
    header?.classList.toggle("is-elevated", window.scrollY > 12);
  };
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-in");
          io.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.16 }
  );
  document.querySelectorAll(".reveal-on-scroll").forEach((el) => io.observe(el));
})();
