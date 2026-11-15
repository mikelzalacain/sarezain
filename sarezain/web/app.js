(() => {
  "use strict";

  // Modo demo: sin backend, con una red de ejemplo (para la versión online del portfolio).
  const DEMO = window.SAREZAIN_DEMO === true || new URLSearchParams(location.search).has("demo");
  // Sin animaciones si el usuario lo pide al sistema (accesibilidad) o con ?static (capturas).
  const ANIMATE = !new URLSearchParams(location.search).has("static")
    && !window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

  const COLORS = {
    critica: "#ff4d5e", alta: "#ff8a3d", media: "#f5c542", baja: "#5aa9ff", info: "#8f999e", ok: "#3ddc97",
  };
  const LEVEL_LABEL = { critica: "Crítico", alta: "Alto", media: "Medio", baja: "Bajo", info: "Info", ok: "Seguro" };
  const SEVERITIES = ["critica", "alta", "media", "baja", "info"];
  const TYPE_LABEL = {
    router: "Router", pc: "Ordenador", movil: "Móvil / tablet", tv: "TV / streaming", impresora: "Impresora",
    camara: "Cámara IP", iot: "Dispositivo IoT", nas: "NAS", servidor: "Servidor", red: "Equipo de red",
    desconocido: "Desconocido",
  };

  // Iconos de trazo (24x24)
  const ICONS = {
    router: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M12 13V9M8.5 6.5a5 5 0 0 1 7 0M6 4a8.5 8.5 0 0 1 12 0"/>',
    pc: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    movil: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
    tv: '<rect x="2.5" y="5" width="19" height="12" rx="2"/><path d="M8 21h8M9 2.5l3 2.5 3-2.5"/>',
    impresora: '<path d="M7 8V3h10v5"/><rect x="3" y="8" width="18" height="9" rx="2"/><path d="M7 14h10v7H7z"/>',
    camara: '<rect x="2.5" y="7" width="13" height="10" rx="2"/><path d="M15.5 10.5l6-3.5v10l-6-3.5"/>',
    iot: '<path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9c.6.5 1 1.2 1 2.1h5c0-.9.4-1.6 1-2.1A6 6 0 0 0 12 3z"/>',
    nas: '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h8M8 11h8M8 17h.01M12 17h.01"/>',
    servidor: '<rect x="3" y="3.5" width="18" height="7" rx="1.5"/><rect x="3" y="13.5" width="18" height="7" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
    red: '<rect x="2.5" y="9" width="19" height="6" rx="1.5"/><path d="M6 12h.01M9 12h.01M12 12h.01M18 9V5M15 9V6"/>',
    desconocido: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 0 1 4.8 1c0 1.7-2.3 2-2.3 3.5M12 17h.01"/>',
  };

  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const iconSvg = (type, color) =>
    `<svg viewBox="0 0 24 24" style="stroke:${color}" aria-hidden="true">${ICONS[type] || ICONS.desconocido}</svg>`;
  const iconUri = (type, color) =>
    "data:image/svg+xml;utf8," + encodeURIComponent(
      `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ICONS[type] || ICONS.desconocido}</svg>`);
  const displayName = (h) => h.hostname || (h.is_self ? "Este equipo" : null) || h.vendor || TYPE_LABEL[h.type] || h.ip;

  let scan = null;
  let cy = null;
  let selectedIp = null;
  let findingFilter = "todas";
  let pulseTimer = null;

  // ---------------------------------------------------------------- datos

  const api = {
    async latest() {
      if (DEMO) return (await fetch("demo.json")).json();
      const r = await fetch("/api/scans/latest");
      return r.ok ? r.json() : null;
    },
    async info() {
      if (DEMO) return null;
      const r = await fetch("/api/info");
      return r.ok ? r.json() : null;
    },
    async history() {
      if (DEMO) return [];
      const r = await fetch("/api/scans");
      return r.ok ? r.json() : [];
    },
    async load(id) {
      return (await fetch(`/api/scans/${encodeURIComponent(id)}`)).json();
    },
  };

  // ---------------------------------------------------------------- escaneo

  async function startScan() {
    const btn = $("#scan-btn");
    btn.disabled = true;
    $("#empty").hidden = true;
    showProgress(0, "Preparando…");

    if (DEMO) {
      const steps = ["Buscando dispositivos", "Escaneando puertos", "Analizando servicios", "Evaluando riesgos"];
      for (let i = 0; i <= 40; i++) {
        await new Promise((r) => setTimeout(r, 60));
        showProgress(i / 40, steps[Math.min(3, Math.floor(i / 10.01))]);
      }
      hideProgress();
      btn.disabled = false;
      render(await api.latest());
      return;
    }

    const r = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profile: $("#profile").value }),
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      alert(e.detail || "No se pudo iniciar el escaneo.");
      btn.disabled = false;
      hideProgress();
      return;
    }
    const poll = async () => {
      const s = await (await fetch("/api/state")).json();
      if (s.status === "running") {
        showProgress(s.progress, s.label);
        setTimeout(poll, 400);
      } else if (s.status === "done") {
        showProgress(1, "Completado");
        setTimeout(hideProgress, 600);
        btn.disabled = false;
        render(await api.load(s.scan_id));
        refreshHistory();
      } else {
        hideProgress();
        btn.disabled = false;
        alert("Error durante el escaneo: " + (s.error || "desconocido"));
      }
    };
    poll();
  }

  function showProgress(value, label) {
    $("#progress").hidden = false;
    $("#progress-fill").style.width = `${Math.round(value * 100)}%`;
    $("#progress-label").textContent = `${label} · ${Math.round(value * 100)}%`;
  }
  const hideProgress = () => { $("#progress").hidden = true; };

  async function refreshHistory() {
    const items = await api.history();
    const sel = $("#history");
    if (items.length < 2) { sel.hidden = true; return; }
    sel.hidden = false;
    sel.innerHTML = items.map((s) => {
      const d = new Date(s.started);
      const label = d.toLocaleString("es-ES", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
      return `<option value="${esc(s.id)}">${esc(label)} · ${s.hosts} disp. · riesgo ${s.risk}</option>`;
    }).join("");
    if (scan) sel.value = scan.id;
  }

  // ---------------------------------------------------------------- render

  function render(data) {
    scan = data;
    selectedIp = null;
    if (!scan || !scan.hosts?.length) {
      $("#empty").hidden = false;
      $("#legend").hidden = $("#fit-btn").hidden = true;
      $("#view-summary").innerHTML = '<p class="view-empty">Lanza un escaneo para ver el estado de tu red.</p>';
      $("#view-findings").innerHTML = $("#view-device").innerHTML = $("#view-network").innerHTML = "";
      return;
    }
    $("#empty").hidden = true;
    $("#legend").hidden = $("#fit-btn").hidden = false;
    $("#net-chip").textContent = scan.network;
    renderMap();
    renderSummary();
    renderFindings();
    renderNetwork();
    renderDevice();
  }

  let layoutReady = false;
  const layoutWaiters = [];
  const whenLayoutReady = (fn) => (layoutReady ? fn() : layoutWaiters.push(fn));

  function renderMap() {
    layoutReady = false;
    const gw = scan.hosts.find((h) => h.is_gateway) || scan.hosts[0];
    const elements = [];
    for (const h of scan.hosts) {
      const color = COLORS[h.level] || COLORS.ok;
      elements.push({
        data: {
          id: h.ip, label: `${displayName(h)}\n${h.ip}`, color, icon: iconUri(h.type, color),
          size: h.is_gateway ? 74 : 54, isGw: h.is_gateway ? 1 : 0,
        },
        classes: [h.level, h.is_self ? "self" : "", h.new ? "new" : ""].join(" "),
      });
      if (h.ip !== gw.ip) elements.push({ data: { id: `e-${h.ip}`, source: gw.ip, target: h.ip, color } });
    }

    if (cy) cy.destroy();
    cy = cytoscape({
      container: $("#cy"),
      elements,
      minZoom: 0.3, maxZoom: 2.5,
      style: [
        { selector: "node", style: {
          width: "data(size)", height: "data(size)", "background-color": "#181d20",
          "background-image": "data(icon)", "background-fit": "none", "background-clip": "none",
          "background-width": "48%", "background-height": "48%",
          "border-width": 2.5, "border-color": "data(color)",
          label: "data(label)", "text-wrap": "wrap", "text-valign": "bottom", "text-margin-y": 8,
          color: "#c3cacd", "font-size": 11, "font-family": "IBM Plex Sans, system-ui, sans-serif",
          "text-outline-color": "#0e1113", "text-outline-width": 3,
          "transition-property": "border-width, width, height", "transition-duration": "0.25s",
        } },
        { selector: "node.self", style: { "border-style": "double", "border-width": 5 } },
        { selector: "node.new", style: { "border-style": "dashed", "border-color": "#c792ea" } },
        { selector: "node:active", style: { "overlay-opacity": 0 } },
        { selector: "node:selected", style: { "border-width": 5, "underlay-color": "data(color)", "underlay-opacity": 0.18, "underlay-padding": 10, "underlay-shape": "ellipse" } },
        { selector: "edge", style: {
          width: 1.5, "line-color": "data(color)", "line-opacity": 0.35, "curve-style": "straight",
        } },
        { selector: "node.dim", style: { opacity: 0.25 } },
        { selector: "edge.dim", style: { opacity: 0.08 } },
      ],
      layout: { name: "preset" },
    });

    const LAYOUT = {
      name: "concentric", concentric: (n) => (n.data("isGw") ? 10 : 1), levelWidth: () => 1,
      minNodeSpacing: 46, padding: 50,
    };
    let laidOut = false;
    const relayout = (animate) => {
      if (!cy) return;
      cy.resize();
      const box = $("#cy").getBoundingClientRect();
      if (box.width < 50 || box.height < 50) return;  // aún sin tamaño: lo hará el ResizeObserver
      const markReady = () => {
        if (layoutReady) return;
        layoutReady = true;
        layoutWaiters.splice(0).forEach((fn) => fn());
      };
      cy.one("layoutstop", markReady);
      cy.layout({ ...LAYOUT, animate, animationDuration: 600 }).run();
      setTimeout(markReady, animate ? 900 : 0);  // red de seguridad si el evento no llega
      laidOut = true;
    };
    relayout(ANIMATE);

    // Si el contenedor cambia de tamaño (giro del móvil, ventana redimensionada), recolocar el mapa.
    if (window.ResizeObserver) {
      let t;
      const ro = new ResizeObserver(() => {
        clearTimeout(t);
        t = setTimeout(() => {
          if (!laidOut) relayout(ANIMATE);
          else if (!selectedIp) relayout(false);
          else cy.resize();
        }, 150);
      });
      ro.observe($("#cy"));
      cy.one("destroy", () => ro.disconnect());
    }

    cy.on("tap", "node", (e) => selectDevice(e.target.id()));
    cy.on("tap", (e) => { if (e.target === cy) clearSelection(); });

    // Pulso en los dispositivos críticos
    clearInterval(pulseTimer);
    let big = false;
    pulseTimer = setInterval(() => {
      big = !big;
      cy.nodes(".critica").forEach((n) => n.style("border-width", big ? 7 : 2.5));
    }, 900);
  }

  function riskRing(score, level) {
    const r = 46, c = 2 * Math.PI * r;
    const color = COLORS[level] || COLORS.ok;
    return `<div class="ring">
      <svg viewBox="0 0 112 112"><circle class="track" cx="56" cy="56" r="${r}"/>
      <circle class="value" cx="56" cy="56" r="${r}" stroke="${color}" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - score / 100)}"/></svg>
      <div class="ring__num"><div><strong style="color:${color}">${score}</strong><small>/100 riesgo</small></div></div>
    </div>`;
  }

  function renderSummary() {
    const s = scan.summary;
    const total = SEVERITIES.reduce((a, k) => a + s.findings[k], 0);
    const max = Math.max(1, ...SEVERITIES.map((k) => s.findings[k]));
    const verdict = {
      critica: "Hay problemas críticos que conviene corregir cuanto antes.",
      alta: "Hay riesgos importantes en algunos dispositivos.",
      media: "La red está razonablemente bien, con algunos puntos a mejorar.",
      baja: "La red está bien protegida; solo hay detalles menores.",
      ok: "No se han encontrado problemas. ¡Bien hecho!",
    }[s.level];
    const date = new Date(scan.started).toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" });
    const hosts = [...scan.hosts].sort((a, b) => b.risk - a.risk);

    $("#view-summary").innerHTML = `
      <div class="score">${riskRing(s.risk, s.level)}
        <div class="score__text"><h3>Riesgo ${LEVEL_LABEL[s.level].toLowerCase()}</h3><p>${verdict}</p>
        <p style="margin-top:6px;font-size:.78rem">${esc(date)} · ${scan.duration}s</p></div>
      </div>
      <div class="stats">
        <div class="stat"><strong>${s.hosts}</strong><span>dispositivos</span></div>
        <div class="stat"><strong>${s.open_ports}</strong><span>puertos abiertos</span></div>
        <div class="stat"><strong>${total}</strong><span>hallazgos</span></div>
        <div class="stat"><strong>${s.new_hosts}</strong><span>nuevos</span></div>
      </div>
      ${(() => {
        const plan = actionPlan();
        if (!plan.length) return "";
        return `<h4 class="section-title">Plan de acción</h4><ol class="plan">${plan.map((f, i) => `
          <li data-plan="${i}"><div><strong>${esc(f.fix || f.title)}</strong>
          <span>${esc(f.title)} · ${esc(whereOf(f))}</span></div></li>`).join("")}</ol>`;
      })()}
      <h4 class="section-title">Hallazgos por gravedad</h4>
      <div class="sevbars">${SEVERITIES.filter((k) => k !== "info").map((k) => `
        <div class="sevbar"><span>${LEVEL_LABEL[k]}</span>
          <div class="sevbar__track"><span style="width:${(s.findings[k] / max) * 100}%;background:${COLORS[k]}"></span></div>
          <b>${s.findings[k]}</b></div>`).join("")}
      </div>
      <h4 class="section-title">Dispositivos</h4>
      <ul class="devlist">${hosts.map(devItem).join("")}</ul>`;
    bindDevItems($("#view-summary"));
    const plan = actionPlan();
    $("#view-summary").querySelectorAll("[data-plan]").forEach((li) => li.addEventListener("click", () => {
      const f = plan[+li.dataset.plan];
      if (f.host.pseudo) { switchTab("network"); return; }
      selectDevice(f.host.ip);
    }));
  }

  function renderNetwork() {
    const na = scan.network_audit || {};
    const la = scan.local_audit;
    const w = na.wifi;
    const yes = (ok, good, bad) => `<span class="${ok ? "okline" : "badline"}">${ok ? good : bad}</span>`;
    const wifiCard = w ? `<div class="card"><h4>📶 Wi-Fi</h4><dl class="kv">
        <dt>Red</dt><dd>${esc(w.ssid)}${w.isp ? ` · ${esc(w.isp)}` : ""}</dd>
        <dt>Seguridad</dt><dd>${esc(w.auth)} · ${esc(w.cipher)}</dd>
        <dt>Banda</dt><dd>${esc(w.band || "—")} · canal ${esc(w.channel || "—")} · ${esc(w.radio || "")}</dd>
        <dt>Señal</dt><dd>${esc(w.signal || "—")}</dd>
        <dt>Redes gemelas</dt><dd>${w.twins?.length ? '<span class="badline">Sí, revisar</span>' : '<span class="okline">No detectadas</span>'}</dd>
      </dl></div>` : "";
    const dns = na.dns?.length ? `<div class="card"><h4>🧭 DNS</h4><dl class="kv">${na.dns.map((d) => `<dt>${esc(d.server)}</dt><dd>${esc(d.provider)}</dd>`).join("")}</dl></div>` : "";
    const igd = na.upnp_igd;
    const ports = `<div class="card"><h4>🌐 Puertos abiertos a Internet</h4>${igd
      ? (igd.mappings.length ? `<dl class="kv">${igd.mappings.map((m) => `<dt>${m.external_port}/${esc(m.protocol)}</dt><dd>→ ${esc(m.internal_ip)}:${m.internal_port} ${esc(m.description || "")}</dd>`).join("")}</dl>`
        : '<p class="okline" style="font-size:.85rem">El router tiene UPnP pero ningún puerto abierto.</p>')
      : '<p style="font-size:.85rem;color:var(--muted)">El router no expone UPnP-IGD: ningún programa puede abrir puertos automáticamente. ✓</p>'}
      ${igd?.external_ip ? `<p style="font-size:.78rem;color:var(--muted);margin-top:6px">IP pública: ${esc(igd.external_ip)}</p>` : ""}</div>`;
    let local = "";
    if (la) {
      const fw = (la.firewall || []).every((p) => p.enabled);
      const d = la.defender || {};
      local = `<div class="card"><h4>💻 Este equipo</h4><dl class="kv">
        <dt>Sistema</dt><dd>${esc(la.os?.caption || "—")} (build ${la.os?.build || "?"})</dd>
        <dt>Firewall</dt><dd>${yes(fw, "Activo en todos los perfiles", "Desactivado en algún perfil")}</dd>
        <dt>Antivirus</dt><dd>${yes(d.realtime, "Tiempo real activo", "Tiempo real desactivado")} · firmas de hace ${d.sig_age ?? "?"} d</dd>
        <dt>Actualizado</dt><dd>${esc(la.last_update || "—")} ${la.last_update_id ? `(${esc(la.last_update_id)})` : ""}</dd>
        <dt>BitLocker</dt><dd>${la.bitlocker === 1 ? '<span class="okline">Activado</span>' : la.bitlocker === 2 ? '<span class="badline">Desactivado</span>' : "—"}</dd>
        <dt>SMBv1</dt><dd>${yes(!la.smb?.smb1, "Desactivado", "ACTIVADO")}</dd>
        <dt>Escritorio remoto</dt><dd>${la.rdp_enabled ? '<span class="warnline">Activado</span>' : '<span class="okline">Desactivado</span>'}</dd>
        <dt>Escuchando</dt><dd>${(la.listening || []).filter((x) => x.port < 49152).map((x) => `${x.port} (${esc(x.process || "?")})`).join(", ") || "—"}</dd>
      </dl></div>`;
    }
    const list = (arr, label) => arr?.length
      ? `<h4 class="section-title">${label} (${arr.length})</h4><ul class="flist" style="margin-bottom:20px">${arr.map((f) => findingItem({ ...f, host: NET_HOST }, false)).join("")}</ul>` : "";
    $("#view-network").innerHTML = wifiCard + dns + ports + list(na.findings, "Hallazgos de la red") + local + list(la?.findings, "Hallazgos de este equipo");
    bindFindings($("#view-network"));
  }

  function devItem(h) {
    const color = COLORS[h.level] || COLORS.ok;
    const badge = h.new ? '<span class="badge badge--new">Nuevo</span>' : `<span class="badge badge--${h.level}">${LEVEL_LABEL[h.level]}</span>`;
    return `<li class="dev ${h.ip === selectedIp ? "is-selected" : ""}" data-ip="${esc(h.ip)}" tabindex="0">
      <span class="dev__icon">${iconSvg(h.type, color)}</span>
      <span class="dev__main"><span class="dev__name">${esc(displayName(h))}</span><br><span class="dev__ip">${esc(h.ip)} · ${esc(TYPE_LABEL[h.type])}</span></span>
      ${badge}</li>`;
  }

  function bindDevItems(root) {
    root.querySelectorAll(".dev").forEach((el) => {
      el.addEventListener("click", () => selectDevice(el.dataset.ip));
      el.addEventListener("keydown", (e) => { if (e.key === "Enter") selectDevice(el.dataset.ip); });
    });
  }

  const NET_HOST = { ip: "", name: "Tu red", risk: 0, pseudo: "network" };
  const SELF_HOST = { ip: "", name: "Este equipo", risk: 0, pseudo: "local" };

  function allFindings() {
    const out = [];
    for (const f of scan.network_audit?.findings || []) out.push({ ...f, host: NET_HOST });
    for (const f of scan.local_audit?.findings || []) out.push({ ...f, host: SELF_HOST });
    for (const h of scan.hosts) for (const f of h.findings) out.push({ ...f, host: h });
    return out.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || b.host.risk - a.host.risk);
  }

  // Lo importante primero; los hallazgos leves solo rellenan si hay pocos.
  function actionPlan() {
    const all = allFindings();
    const important = all.filter((f) => ["critica", "alta", "media"].includes(f.severity));
    const minor = all.filter((f) => f.severity === "baja");
    return [...important, ...minor].slice(0, Math.max(3, Math.min(5, important.length)));
  }

  const whereOf = (f) => (f.host.pseudo ? f.host.name : `${displayName(f.host)} (${f.host.ip})`);

  function findingItem(f, showHost = true, open = false) {
    const where = [showHost ? whereOf(f) : null, f.port ? `puerto ${f.port}` : null].filter(Boolean).join(" · ");
    const steps = (f.steps || []).length ? `<ol class="steps">${f.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>` : "";
    const cmds = (f.commands || []).map((c) => `
      <div class="cmd"><span class="cmd__label">${esc(c.label)}</span>
        <div class="cmd__box"><pre>${esc(c.code)}</pre><button class="copy" type="button" data-copy="${esc(c.code)}">Copiar</button></div></div>`).join("");
    const cves = (f.cves || []).length ? `<ul class="cves">${f.cves.slice(0, 8).map((c) => `
      <li><a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">${esc(c.id)}</a>
      <span class="cvss" style="color:${COLORS[c.kev ? "critica" : (c.cvss >= 9 ? "critica" : c.cvss >= 7 ? "alta" : c.cvss >= 4 ? "media" : "baja")]}">${c.cvss ?? "?"}${c.kev ? ' <span class="kev">EXPLOTADA</span>' : ""}</span>
      <span title="${esc(c.summary)}">${esc(c.summary)}</span></li>`).join("")}</ul>` : "";
    return `<li class="finding finding--${f.severity} ${open ? "is-open" : ""}">
      <button class="finding__head" type="button" aria-expanded="${open}">
        <span class="finding__top"><span class="finding__title">${esc(f.title)}</span><span class="badge badge--${f.severity}">${LEVEL_LABEL[f.severity]}</span></span>
        ${where ? `<span class="finding__where">${esc(where)}</span>` : ""}
      </button>
      <div class="finding__body">
        <p>${esc(f.detail)}</p>
        ${cves}
        <div class="fix"><strong>Cómo solucionarlo</strong>${esc(f.fix || "")}
          ${f.context ? `<div class="context" style="margin-top:4px">${esc(f.context)}</div>` : ""}
          ${steps}</div>
        ${cmds}
        ${f.ref ? `<a href="${esc(f.ref)}" target="_blank" rel="noopener">Más información ↗</a>` : ""}
        ${showHost && !f.host.pseudo ? `<button class="linkbtn" type="button" data-goto="${esc(f.host.ip)}">Ver dispositivo →</button>` : ""}
        ${showHost && f.host.pseudo ? `<button class="linkbtn" type="button" data-tab-go="network">Ver red y equipo →</button>` : ""}
      </div></li>`;
  }

  function bindFindings(root) {
    root.querySelectorAll(".finding__head").forEach((b) => b.addEventListener("click", () => {
      const li = b.parentElement;
      li.classList.toggle("is-open");
      b.setAttribute("aria-expanded", li.classList.contains("is-open"));
    }));
    root.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => selectDevice(b.dataset.goto)));
    root.querySelectorAll("[data-tab-go]").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tabGo)));
    root.querySelectorAll(".copy").forEach((b) => b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = "Copiado"; b.classList.add("ok"); }
      catch { b.textContent = "Selecciona y copia"; }
      setTimeout(() => { b.textContent = "Copiar"; b.classList.remove("ok"); }, 1600);
    }));
  }

  function renderFindings() {
    const list = allFindings();
    $("#findings-count").textContent = list.filter((f) => f.severity !== "info").length;
    const shown = findingFilter === "todas" ? list : list.filter((f) => f.severity === findingFilter);
    const counts = Object.fromEntries(SEVERITIES.map((k) => [k, list.filter((f) => f.severity === k).length]));
    $("#view-findings").innerHTML = `
      <div class="filters">
        <button class="filter ${findingFilter === "todas" ? "is-active" : ""}" data-f="todas">Todas (${list.length})</button>
        ${SEVERITIES.filter((k) => counts[k]).map((k) => `<button class="filter ${findingFilter === k ? "is-active" : ""}" data-f="${k}">${LEVEL_LABEL[k]} (${counts[k]})</button>`).join("")}
      </div>
      ${shown.length ? `<ul class="flist">${shown.map((f) => findingItem(f)).join("")}</ul>` : '<p class="view-empty">Sin hallazgos. 🎉</p>'}`;
    $("#view-findings").querySelectorAll(".filter").forEach((b) => b.addEventListener("click", () => { findingFilter = b.dataset.f; renderFindings(); }));
    bindFindings($("#view-findings"));
  }

  function renderDevice() {
    const h = scan.hosts.find((x) => x.ip === selectedIp);
    const view = $("#view-device");
    if (!h) {
      view.innerHTML = '<p class="view-empty">Pulsa un dispositivo en el mapa para ver sus detalles.</p>';
      return;
    }
    const color = COLORS[h.level] || COLORS.ok;
    const rows = [
      ["IP", h.ip], ["MAC", h.mac || "—"], ["Fabricante", h.vendor || "—"], ["Nombre", h.hostname || "—"],
      ["Modelo", h.model || "—"], ["Sistema", h.os || "—"], ["Tipo", TYPE_LABEL[h.type]],
      ...(h.workgroup ? [["Grupo de trabajo", h.workgroup]] : []),
      ...(h.mdns_services?.length ? [["Servicios Bonjour", h.mdns_services.join(", ")]] : []),
      ["Detectado por", (h.seen_by || []).join(", ") || "—"],
    ];
    const svc = h.services.map((s) => {
      const what = [s.product && `${s.product}${s.version ? " " + s.version : ""}`, s.title && `“${s.title}”`,
        s.tls_version && `${s.tls_version}${s.cipher ? " · " + s.cipher : ""}`, s.banner && !s.product ? s.banner : null]
        .filter(Boolean).map(esc).join("<br>");
      return `<tr><td>${s.port}</td><td>${esc(s.service)}${what ? `<span class="sub">${what}</span>` : ""}</td></tr>`;
    }).join("");

    view.innerHTML = `
      <div class="dhead"><span class="dev__icon">${iconSvg(h.type, color)}</span>
        <div><h3>${esc(displayName(h))}</h3><p>${esc(TYPE_LABEL[h.type])}${h.is_gateway ? " · puerta de enlace" : ""}${h.is_self ? " · este equipo" : ""}</p></div>
        <span class="badge badge--${h.level}" style="margin-left:auto">${h.risk}/100</span>
      </div>
      <dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
      <h4 class="section-title">Puertos abiertos (${h.services.length})</h4>
      ${h.services.length ? `<table class="ports"><thead><tr><th>Puerto</th><th>Servicio</th></tr></thead><tbody>${svc}</tbody></table>`
        : '<p class="view-empty" style="padding:12px 0 20px">Ningún puerto abierto de los analizados.</p>'}
      <h4 class="section-title">Hallazgos (${h.findings.length})</h4>
      ${h.findings.length ? `<ul class="flist">${h.findings.map((f) => findingItem({ ...f, host: h }, false)).join("")}</ul>`
        : '<p class="view-empty" style="padding:12px 0">Sin hallazgos en este dispositivo.</p>'}`;
    bindFindings(view);
  }

  function selectDevice(ip) {
    selectedIp = ip;
    if (cy) {
      cy.elements().removeClass("dim").unselect();
      const node = cy.getElementById(ip);
      node.select();
      cy.elements().not(node.closedNeighborhood()).addClass("dim");
      const view = { center: { eles: node }, zoom: Math.max(cy.zoom(), 1.1) };
      if (ANIMATE) cy.animate(view, { duration: 350 });
      else { cy.zoom(view.zoom); cy.center(node); }
    }
    renderDevice();
    renderSummary();
    switchTab("device");
  }

  function clearSelection() {
    selectedIp = null;
    if (cy) cy.elements().removeClass("dim").unselect();
    renderDevice();
    renderSummary();
  }

  function switchTab(name) {
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t.dataset.tab === name));
    document.querySelectorAll(".view").forEach((v) => v.classList.toggle("is-active", v.id === `view-${name}`));
  }

  // ---------------------------------------------------------------- init

  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => switchTab(t.dataset.tab)));
  $("#scan-btn").addEventListener("click", startScan);
  document.querySelectorAll('[data-action="scan"]').forEach((b) => b.addEventListener("click", startScan));
  $("#fit-btn").addEventListener("click", () => cy && cy.animate({ fit: { padding: 50 } }, { duration: 350 }));
  $("#history").addEventListener("change", async (e) => render(await api.load(e.target.value)));

  (async () => {
    if (DEMO) {
      document.querySelector(".demo-badge").hidden = false;
      $("#demo-bar").hidden = false;
      document.title = "Sarezain · Demo";
    }
    api.info().then((info) => {
      if (info && !scan) $("#net-chip").textContent = info.local.network;
    }).catch(() => {});
    render(await api.latest().catch(() => null));
    refreshHistory();

    // Enlaces directos: #ip=192.168.1.20 abre esa ficha · #tab=findings abre una pestaña
    const hash = new URLSearchParams(location.hash.slice(1));
    if (scan && hash.get("ip") && scan.hosts.some((h) => h.ip === hash.get("ip"))) {
      whenLayoutReady(() => {
        selectDevice(hash.get("ip"));
        if (hash.get("open")) document.querySelector("#view-device .finding__head")?.click();
      });
    } else if (hash.get("tab")) {
      switchTab(hash.get("tab"));
    }
  })();
})();
