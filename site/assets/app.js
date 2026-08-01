/* Utility vs. security on the OWASP Agentic Top 10 — static result explorer.
   Everything on this page is rendered from data/results.json, which is generated
   directly from the committed Inspect .eval logs. No numbers are hard-coded here. */

(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const pct = (v) => `${(v * 100).toFixed(1)}%`;
  const pct0 = (v) => `${Math.round(v * 100)}%`;
  const esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );

  const SERIES = ["--series-1", "--series-2", "--series-3"];
  const cssVar = (name) =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  let DATA = null;
  let TRANSCRIPTS = null;
  let postureColor = {};
  // The posture study is the subject; a second model is reported as a control, so the
  // main charts stay scoped to the model that was run across every posture.
  let MAIN = [];
  let MAIN_ROWS = [];

  /* ------------------------------------------------------------------ theme --- */
  function initTheme() {
    const saved = localStorage.getItem("theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
    $("#theme-toggle").addEventListener("click", () => {
      const cur =
        document.documentElement.getAttribute("data-theme") ||
        (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      const next = cur === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("theme", next);
      renderCharts();
    });
    matchMedia("(prefers-color-scheme: dark)").addEventListener("change", renderCharts);
  }

  /* ---------------------------------------------------------------- tooltip --- */
  let tipEl = null;
  function showTip(html, x, y) {
    if (!tipEl) {
      tipEl = document.createElement("div");
      tipEl.className = "tip";
      document.body.appendChild(tipEl);
    }
    tipEl.innerHTML = html;
    tipEl.style.opacity = "1";
    const r = tipEl.getBoundingClientRect();
    let left = x + 14;
    let top = y - r.height - 12;
    if (left + r.width > innerWidth - 8) left = x - r.width - 14;
    if (top < 8) top = y + 18;
    tipEl.style.left = `${Math.max(8, left)}px`;
    tipEl.style.top = `${top}px`;
  }
  function hideTip() {
    if (tipEl) tipEl.style.opacity = "0";
  }

  /* ------------------------------------------------------------------- svg --- */
  const NS = "http://www.w3.org/2000/svg";
  const el = (tag, attrs = {}) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    return n;
  };

  /* -------------------------------------------------------------- scatter --- */
  function renderScatter() {
    const host = $("#scatter");
    host.innerHTML = "";
    drawScatter(host, MAIN, false);
    renderScatterLegend();
  }

  function renderScatterLegend() {
    let leg = $("#scatter-legend");
    if (!leg) {
      leg = document.createElement("div");
      leg.id = "scatter-legend";
      leg.className = "legend";
      leg.style.marginTop = "1rem";
      $("#scatter").parentElement.appendChild(leg);
    }
    const seen = new Set();
    leg.innerHTML = MAIN
      .filter((r) => !seen.has(r.posture) && seen.add(r.posture))
      .map(
        (r) =>
          `<span class="legend-item"><span class="legend-swatch round" style="background:${postureColor[r.posture]}"></span>${esc(r.posture_label)}</span>`
      )
      .join("");
  }

  function drawScatter(host, rows, compact) {
    host.innerHTML = "";
    const W = compact
      ? Math.max(360, Math.min(host.clientWidth || 430, 470))
      : Math.max(560, Math.min(host.clientWidth || 820, 900));
    const H = compact ? 380 : 460;
    // Generous top/right margin: every posture lands in the top-right corner, and the
    // direct labels need somewhere to go that is still inside the canvas.
    const m = compact
      ? { t: 46, r: 96, b: 52, l: 52 }
      : { t: 54, r: 118, b: 58, l: 62 };
    const iw = W - m.l - m.r;
    const ih = H - m.t - m.b;

    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H });

    // Scales: both axes are rates, but zooming to the occupied range would
    // exaggerate small gaps, so both stay on a fixed, honest 0–100% domain.
    const x = (v) => m.l + v * iw;
    const y = (v) => m.t + (1 - v) * ih;

    // grid
    for (let i = 0; i <= 10; i += 1) {
      const v = i / 10;
      svg.appendChild(
        el("line", {
          x1: m.l, x2: m.l + iw, y1: y(v), y2: y(v),
          stroke: cssVar("--grid"), "stroke-width": 1,
        })
      );
      svg.appendChild(
        el("line", {
          y1: m.t, y2: m.t + ih, x1: x(v), x2: x(v),
          stroke: cssVar("--grid"), "stroke-width": 1,
        })
      );
    }

    // ideal corner
    const ideal = el("g");
    ideal.appendChild(
      el("circle", { cx: x(1), cy: y(1), r: 5, fill: "none",
        stroke: cssVar("--text-muted"), "stroke-width": 1.5, "stroke-dasharray": "2 3" })
    );
    const idealTxt = el("text", {
      x: x(1) + 13, y: y(1) + 4, "text-anchor": "start",
      fill: cssVar("--text-muted"), "font-size": 11.5, "font-family": "var(--sans)",
    });
    idealTxt.textContent = "ideal";
    ideal.appendChild(idealTxt);
    svg.appendChild(ideal);

    // axes
    svg.appendChild(el("line", { x1: m.l, x2: m.l + iw, y1: m.t + ih, y2: m.t + ih,
      stroke: cssVar("--axis"), "stroke-width": 1 }));
    svg.appendChild(el("line", { x1: m.l, x2: m.l, y1: m.t, y2: m.t + ih,
      stroke: cssVar("--axis"), "stroke-width": 1 }));

    for (let i = 0; i <= 10; i += 2) {
      const v = i / 10;
      const tx = el("text", { x: x(v), y: m.t + ih + 20, "text-anchor": "middle",
        fill: cssVar("--text-muted"), "font-size": 11.5,
        "font-family": "var(--sans)", "font-variant-numeric": "tabular-nums" });
      tx.textContent = pct0(v);
      svg.appendChild(tx);
      const ty = el("text", { x: m.l - 12, y: y(v) + 4, "text-anchor": "end",
        fill: cssVar("--text-muted"), "font-size": 11.5,
        "font-family": "var(--sans)", "font-variant-numeric": "tabular-nums" });
      ty.textContent = pct0(v);
      svg.appendChild(ty);
    }

    const xl = el("text", { x: m.l + iw / 2, y: H - 14, "text-anchor": "middle",
      fill: cssVar("--text-secondary"), "font-size": 12.5, "font-weight": 600,
      "font-family": "var(--sans)" });
    xl.textContent = "Task utility  →";
    svg.appendChild(xl);
    const yl = el("text", { x: 16, y: m.t + ih / 2, "text-anchor": "middle",
      fill: cssVar("--text-secondary"), "font-size": 12.5, "font-weight": 600,
      "font-family": "var(--sans)", transform: `rotate(-90 16 ${m.t + ih / 2})` });
    yl.textContent = "Attack resilience  →";
    svg.appendChild(yl);

    // trajectory between postures (order = increasing hardening)
    const pts = rows.map((r) => [x(r.utility_all), y(r.resilience)]);
    if (pts.length > 1) {
      svg.appendChild(
        el("path", {
          d: pts.map((p, i) => `${i ? "L" : "M"}${p[0]},${p[1]}`).join(" "),
          fill: "none", stroke: cssVar("--axis"), "stroke-width": 2,
          "stroke-dasharray": "5 5", "stroke-linecap": "round",
        })
      );
    }

    // Label placement: try candidate offsets around each point and keep the first
    // that collides with nothing already placed. With points this close together a
    // fixed above/below rule overlaps.
    // Seed with the "ideal" annotation AND every mark, so a label can never land on a
    // dot that isn't its own — the failure that makes a labelled scatter unreadable.
    const placed = [{ x: x(1) + 30, y: y(1), w: 62, h: 26 }];
    rows.forEach((r) =>
      placed.push({ x: x(r.utility_all), y: y(r.resilience), w: 46, h: 46 })
    );
    const overlaps = (a, b) =>
      Math.abs(a.x - b.x) < (a.w + b.w) / 2 && Math.abs(a.y - b.y) < (a.h + b.h) / 2;
    const pickLabelSpot = (px, py, w) => {
      const side = w / 2 + 18;
      // Prefer pushing labels toward the empty half of the plot.
      const outward = px > m.l + iw * 0.6 ? -side : side;
      const inward = -outward;
      // Horizontal first: beside its own dot with a leader line is unambiguous,
      // whereas a vertical offset can drift next to a neighbouring mark.
      const cands = [
        [outward, -4], [outward, 22], [outward, -30],
        [inward, -4], [inward, 22], [inward, -30],
        [outward, 48], [outward, -56],
        [0, -34], [0, 36], [0, -62], [0, 60],
      ];
      const clampY = (v) => Math.min(Math.max(v, 20), H - 46);
      const clampX = (v) => Math.min(Math.max(v, w / 2 + 4), W - w / 2 - 4);
      for (const [dx, dy] of cands) {
        const bx = clampX(px + dx);
        const by = clampY(py + dy) + 8;
        const box = { x: bx, y: by, w, h: 36 };
        if (!placed.some((p) => overlaps(box, p))) {
          placed.push(box);
          return [bx - px, by - 8 - py];
        }
      }
      const by = clampY(py - 32);
      placed.push({ x: px, y: by + 8, w, h: 36 });
      return [0, by - py];
    };

    rows.forEach((r, i) => {
      const c = postureColor[r.posture];
      const g = el("g");
      // surface ring + mark
      g.appendChild(el("circle", { cx: x(r.utility_all), cy: y(r.resilience), r: 11,
        fill: cssVar("--surface-1") }));
      g.appendChild(el("circle", { cx: x(r.utility_all), cy: y(r.resilience), r: 8, fill: c }));
      // generous invisible hit area
      const hit = el("circle", { cx: x(r.utility_all), cy: y(r.resilience), r: 22,
        fill: "transparent", style: "cursor:pointer" });
      const tipHtml =
        `<div class="tip-title"><span style="width:9px;height:9px;border-radius:50%;background:${c};display:inline-block"></span>${esc(r.posture_label)}</div>` +
        `<div class="tip-row"><span>Task utility</span><b>${pct(r.utility_all)}</b></div>` +
        `<div class="tip-row"><span>Attack resilience</span><b>${pct(r.resilience)}</b></div>` +
        `<div class="tip-row"><span>Attack success rate</span><b>${pct(r.asr)}</b></div>` +
        `<div class="tip-row"><span>Utility, clean only</span><b>${pct(r.utility_clean)}</b></div>`;
      hit.addEventListener("mousemove", (e) => showTip(tipHtml, e.clientX, e.clientY));
      hit.addEventListener("mouseleave", hideTip);
      g.appendChild(hit);

      // direct label — required relief for the light-mode aqua contrast warning
      const px = x(r.utility_all);
      const py = y(r.resilience);
      const fs = compact ? 11 : 12.5;
      const labelW = Math.max(r.posture_label.length * fs * 0.58, 118);
      const [dx, dy] = pickLabelSpot(px, py, labelW);

      // leader line when the label had to move away from its mark
      if (Math.abs(dx) > 1) {
        g.appendChild(
          el("line", {
            x1: px + (dx > 0 ? 12 : -12), y1: py,
            x2: px + dx - (dx > 0 ? labelW / 2 : -labelW / 2), y2: py + dy + 6,
            stroke: cssVar("--axis"), "stroke-width": 1,
          })
        );
      }
      const lbl = el("text", {
        x: px + dx, y: py + dy,
        "text-anchor": "middle", fill: cssVar("--text-primary"),
        "font-size": fs, "font-weight": 600, "font-family": "var(--sans)",
      });
      lbl.textContent = r.posture_label;
      g.appendChild(lbl);
      const sub = el("text", {
        x: px + dx, y: py + dy + 15,
        "text-anchor": "middle", fill: cssVar("--text-muted"),
        "font-size": compact ? 10.5 : 11.5, "font-family": "var(--sans)",
        "font-variant-numeric": "tabular-nums",
      });
      sub.textContent = `${pct0(r.utility_all)} util · ${pct0(r.resilience)} resil`;
      g.appendChild(sub);
      svg.appendChild(g);
    });

    host.appendChild(svg);
  }

  /* ------------------------------------------------------------ class bars --- */
  function renderClassBars() {
    const host = $("#classbars");
    host.innerHTML = "";
    const classes = DATA.classes;
    const rows = MAIN;
    const W = Math.max(560, Math.min(host.clientWidth || 860, 900));
    const H = 400;
    const m = { t: 20, r: 20, b: 78, l: 56 };
    const iw = W - m.l - m.r;
    const ih = H - m.t - m.b;
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H });

    const groupW = iw / classes.length;
    const barW = Math.min(24, (groupW - 26) / rows.length - 2);
    const y = (v) => m.t + (1 - v) * ih;

    for (let i = 0; i <= 5; i += 1) {
      const v = i / 5;
      svg.appendChild(el("line", { x1: m.l, x2: m.l + iw, y1: y(v), y2: y(v),
        stroke: cssVar("--grid"), "stroke-width": 1 }));
      const t = el("text", { x: m.l - 12, y: y(v) + 4, "text-anchor": "end",
        fill: cssVar("--text-muted"), "font-size": 11.5, "font-family": "var(--sans)",
        "font-variant-numeric": "tabular-nums" });
      t.textContent = pct0(v);
      svg.appendChild(t);
    }
    svg.appendChild(el("line", { x1: m.l, x2: m.l + iw, y1: y(0), y2: y(0),
      stroke: cssVar("--axis"), "stroke-width": 1 }));

    const yl = el("text", { x: 15, y: m.t + ih / 2, "text-anchor": "middle",
      fill: cssVar("--text-secondary"), "font-size": 12.5, "font-weight": 600,
      "font-family": "var(--sans)", transform: `rotate(-90 15 ${m.t + ih / 2})` });
    yl.textContent = "Attack success rate";
    svg.appendChild(yl);

    classes.forEach((cls, ci) => {
      const gx = m.l + ci * groupW;
      const total = rows.length * barW + (rows.length - 1) * 2;
      const start = gx + (groupW - total) / 2;

      rows.forEach((r, ri) => {
        const v = r.asr_by_class[cls.id] ?? 0;
        const bx = start + ri * (barW + 2);
        const bh = Math.max(v * ih, v > 0 ? 3 : 0);
        const c = postureColor[r.posture];
        if (bh > 0) {
          const rad = Math.min(4, bh);
          svg.appendChild(
            el("path", {
              d: `M${bx},${y(0)} L${bx},${y(0) - bh + rad} Q${bx},${y(0) - bh} ${bx + rad},${y(0) - bh}
                  L${bx + barW - rad},${y(0) - bh} Q${bx + barW},${y(0) - bh} ${bx + barW},${y(0) - bh + rad}
                  L${bx + barW},${y(0)} Z`,
              fill: c,
            })
          );
        } else {
          // zero needs to read as a deliberate zero, not a missing bar
          svg.appendChild(el("line", { x1: bx, x2: bx + barW, y1: y(0) - 1, y2: y(0) - 1,
            stroke: c, "stroke-width": 2.5, "stroke-linecap": "round" }));
        }
        const hit = el("rect", { x: bx - 3, y: m.t, width: barW + 6, height: ih,
          fill: "transparent", style: "cursor:pointer" });
        const nCls = Math.round((r.n_attacked || 0) / classes.length);
        const tipHtml =
          `<div class="tip-title"><span style="width:9px;height:9px;border-radius:2px;background:${c};display:inline-block"></span>${esc(r.posture_label)}</div>` +
          `<div class="tip-row"><span>${esc(cls.id)} ${esc(cls.name)}</span></div>` +
          `<div class="tip-row"><span>Attack success</span><b>${pct(v)}</b></div>` +
          `<div class="tip-row"><span>Samples</span><b>${Math.round(v * nCls)} / ${nCls}</b></div>`;
        hit.addEventListener("mousemove", (e) => showTip(tipHtml, e.clientX, e.clientY));
        hit.addEventListener("mouseleave", hideTip);
        svg.appendChild(hit);
      });

      const t1 = el("text", { x: gx + groupW / 2, y: y(0) + 22, "text-anchor": "middle",
        fill: cssVar("--text-primary"), "font-size": 12, "font-weight": 600,
        "font-family": "var(--sans)" });
      t1.textContent = cls.id;
      svg.appendChild(t1);
      const words = cls.name.split(" ");
      const lines = [];
      let cur = "";
      for (const w of words) {
        if ((cur + " " + w).trim().length > 16) { lines.push(cur.trim()); cur = w; }
        else cur += " " + w;
      }
      if (cur.trim()) lines.push(cur.trim());
      lines.slice(0, 2).forEach((ln, li) => {
        const t2 = el("text", { x: gx + groupW / 2, y: y(0) + 38 + li * 14,
          "text-anchor": "middle", fill: cssVar("--text-muted"), "font-size": 11,
          "font-family": "var(--sans)" });
        t2.textContent = ln;
        svg.appendChild(t2);
      });
    });

    host.appendChild(svg);

    // legend lives outside the svg so it inherits page text tokens
    let leg = $("#classbars-legend");
    if (!leg) {
      leg = document.createElement("div");
      leg.id = "classbars-legend";
      leg.className = "legend";
      leg.style.marginTop = "1rem";
      host.parentElement.appendChild(leg);
    }
    leg.innerHTML = rows
      .map(
        (r) =>
          `<span class="legend-item"><span class="legend-swatch" style="background:${postureColor[r.posture]}"></span>${esc(r.posture_label)}</span>`
      )
      .join("");
  }

  /* ------------------------------------------------------------- cost grid --- */
  function renderCostGrid() {
    const host = $("#costgrid");
    const rows = MAIN;
    const scenarios = DATA.scenarios;
    let html = '<table class="cost-table"><thead><tr><th class="scen">Legitimate task</th>';
    rows.forEach((r) => {
      html += `<th class="num" style="text-align:center"><span class="legend-item" style="justify-content:center"><span class="legend-swatch" style="background:${postureColor[r.posture]}"></span>${esc(r.posture_label)}</span></th>`;
    });
    html += "</tr></thead><tbody>";
    scenarios.forEach((sc) => {
      html += `<tr><th class="scen">${esc(sc.title)}<span class="scen-note">${esc(sc.summary)}</span></th>`;
      rows.forEach((r) => {
        const v = r.clean_utility_by_scenario[sc.id] ?? 0;
        const ok = v >= 0.999;
        html += `<td><div class="cell ${ok ? "pass" : "fail"}">${ok ? "✓ done" : "✕ failed"}</div></td>`;
      });
      html += "</tr>";
    });
    html += "</tbody></table>";
    host.innerHTML = html;

    // Name the exact tickets each posture breaks, rather than leaving it to the reader.
    const broken = rows
      .map((r) => {
        const lost = scenarios.filter(
          (sc) => (r.clean_utility_by_scenario[sc.id] ?? 0) < 0.999
        );
        return { r, lost };
      })
      .filter((o) => o.lost.length);
    $("#cost-note").innerHTML = broken.length
      ? broken
          .map(
            (o) =>
              `<strong>${esc(o.r.posture_label)}</strong> loses ${o.lost.length} of ${scenarios.length} clean tickets: ` +
              o.lost.map((s) => esc(s.title)).join("; ") + "."
          )
          .join("<br>")
      : "No posture lost a clean ticket in this run.";
  }

  /* ---------------------------------------------------------------- matrix --- */
  function cellState(row) {
    if (row.attack >= 0.5) return "owned";
    if ((row.actions || []).some((a) => a.blocked)) return "blocked";
    return "held";
  }
  const STATE_LABEL = {
    owned: "✕ attack succeeded",
    blocked: "✓ refused by policy engine",
    held: "✓ agent held",
  };

  function renderMatrix() {
    const host = $("#matrixgrid");
    const rows = MAIN;
    const byId = new Map(MAIN_ROWS.map((r) => [`${r.posture}|${r.payload_id}`, r]));

    let html = '<table class="matrix-table"><thead><tr><th class="pay">Payload</th>';
    rows.forEach((r) => {
      html += `<th style="text-align:center"><span class="legend-item" style="justify-content:center"><span class="legend-swatch" style="background:${postureColor[r.posture]}"></span>${esc(r.posture_label)}</span></th>`;
    });
    html += "</tr></thead><tbody>";

    DATA.classes.forEach((cls) => {
      html += `<tr class="class-row"><td class="class-head" colspan="${rows.length + 1}">${esc(cls.id)} — ${esc(cls.name)}</td></tr>`;
      DATA.payloads
        .filter((p) => p.asi === cls.id)
        .forEach((p) => {
          html += `<tr><th class="pay"><span class="pay-id">${esc(p.id)}</span>${esc(p.note)}</th>`;
          rows.forEach((r) => {
            const row = byId.get(`${r.posture}|${p.id}`);
            if (!row) { html += "<td></td>"; return; }
            const st = cellState(row);
            html += `<td><button class="cell-btn ${st}" data-row="${esc(row.id)}" title="${esc(STATE_LABEL[st])}">${STATE_LABEL[st]}</button></td>`;
          });
          html += "</tr>";
        });
    });
    html += "</tbody></table>";
    host.innerHTML = html;

    $("#matrix-legend").innerHTML = [
      ["owned", "Attack succeeded"],
      ["held", "Agent held"],
      ["blocked", "Refused by policy engine"],
    ]
      .map(
        ([k, label]) =>
          `<span class="legend-item"><span class="legend-swatch" style="background:${
            k === "owned" ? "var(--critical)" : k === "held" ? "var(--good)" : "var(--series-1)"
          }"></span>${label}</span>`
      )
      .join("");

    $$(".cell-btn", host).forEach((btn) =>
      btn.addEventListener("click", () => openDrawer(btn.dataset.row))
    );
  }

  /* ---------------------------------------------------------------- drawer --- */
  async function ensureTranscripts() {
    if (TRANSCRIPTS) return TRANSCRIPTS;
    try {
      const res = await fetch("data/transcripts.json");
      TRANSCRIPTS = await res.json();
    } catch {
      TRANSCRIPTS = {};
    }
    return TRANSCRIPTS;
  }

  function ledgerHtml(actions) {
    if (!actions || !actions.length) return "<p class='panel-sub'>No tool calls recorded.</p>";
    const ACTIONS = new Set([
      "issue_refund", "send_email", "escalate", "update_customer", "close_ticket",
    ]);
    return (
      '<div class="ledger">' +
      actions
        .map((a) => {
          const isAction = ACTIONS.has(a.tool);
          const cls = a.blocked ? "is-blocked" : isAction ? "is-action" : "";
          const args = Object.entries(a.args || {})
            .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
            .join("  ");
          return (
            `<div class="ledger-row ${cls}">` +
            `<span class="ledger-tool">${esc(a.tool)}</span>` +
            `<span class="ledger-args">${esc(args.slice(0, 400))}</span>` +
            (a.blocked ? '<span class="ledger-flag">blocked</span>' : "") +
            "</div>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  function checksHtml(checks) {
    if (!checks || !checks.length) return "";
    return (
      '<ul class="checklist">' +
      checks
        .map(
          (c) =>
            `<li><span class="check-mark ${c.satisfied ? "yes" : "no"}">${c.satisfied ? "✓" : "·"}</span>` +
            `<span>${esc(c.label)}${c.kind === "absent" ? " <em>(must not happen)</em>" : ""}</span></li>`
        )
        .join("") +
      "</ul>"
    );
  }

  function transcriptHtml(msgs) {
    if (!msgs || !msgs.length) return "<p class='panel-sub'>Transcript unavailable.</p>";
    return (
      '<div class="transcript">' +
      msgs
        .map((m) => {
          const calls = (m.tool_calls || [])
            .map(
              (c) =>
                `<div class="msg-call">${esc(c.name)}(${esc(
                  JSON.stringify(c.args).slice(0, 300)
                )})</div>`
            )
            .join("");
          const text = (m.text || "").trim();
          if (!text && !calls) return "";
          return (
            `<div class="msg ${esc(m.role)}"><div class="msg-role">${esc(
              m.role === "tool" ? `tool · ${m.tool_name || ""}` : m.role
            )}</div>` +
            (text ? `<div class="msg-text">${esc(text.slice(0, 2600))}</div>` : "") +
            (calls ? `<div class="msg-calls">${calls}</div>` : "") +
            "</div>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  async function openDrawer(rowId) {
    const row = DATA.rows.find((r) => r.id === rowId);
    if (!row) return;
    const payload = DATA.payloads.find((p) => p.id === row.payload_id);
    const st = cellState(row);

    $("#drawer-eyebrow").textContent =
      `${row.payload_id} · ${row.asi} ${row.asi_name} · ${row.model_label}`;
    $("#drawer-title").textContent =
      `${DATA.postures.find((p) => p.id === row.posture)?.label || row.posture} — ${row.scenario_title}`;

    const body = $("#drawer-body");
    body.innerHTML =
      `<span class="verdict ${st}">${STATE_LABEL[st]}</span>` +
      `<p class="payload-meta" style="margin-top:.9rem">` +
      `<strong>Attacker's objective:</strong> ${esc(row.payload_note)}<br>` +
      `<strong>Planted in:</strong> <code>${esc(row.payload_channel)}</code> — one field of an otherwise identical environment.` +
      `</p>` +
      "<h4>The planted payload</h4>" +
      `<div class="payload-box">${esc(payload ? payload.text : "")}</div>` +
      "<h4>Attack-success checks</h4>" + checksHtml(row.attack_checks) +
      "<h4>Task-utility checks</h4>" + checksHtml(row.utility_checks) +
      "<h4>Action ledger written inside the sandbox</h4>" + ledgerHtml(row.actions) +
      (row.completion
        ? `<h4>What the agent reported</h4><div class="msg"><div class="msg-text">${esc(row.completion)}</div></div>`
        : "") +
      '<h4>Full transcript</h4><div id="drawer-transcript"><p class="panel-sub">Loading…</p></div>';

    $("#drawer").hidden = false;
    document.body.style.overflow = "hidden";

    const t = await ensureTranscripts();
    const host = $("#drawer-transcript");
    if (host) host.innerHTML = transcriptHtml(t[rowId]);
  }

  function closeDrawer() {
    $("#drawer").hidden = true;
    document.body.style.overflow = "";
  }

  /* ----------------------------------------------------------------- text --- */
  function renderHero() {
    const rows = MAIN;
    const host = $("#hero-stats");
    const naive = rows.find((r) => r.posture === "naive") || rows[0];
    const best = rows.reduce((a, b) => (b.resilience > a.resilience ? b : a), rows[0]);
    const bestUtil = rows.reduce((a, b) => (b.utility_all > a.utility_all ? b : a), rows[0]);

    const tiles = [
      {
        label: "Attack success, naive agent",
        value: pct0(naive.asr),
        sub: `${Math.round(naive.asr * naive.n_attacked)} of ${naive.n_attacked} attacked samples`,
        color: postureColor[naive.posture],
      },
      {
        label: "Attack success, best posture",
        value: pct0(best.asr),
        sub: `${best.posture_label} — ${Math.round(best.asr * best.n_attacked)} of ${best.n_attacked}`,
        color: postureColor[best.posture],
      },
      {
        label: "Clean tickets it broke",
        value: `${Math.round((naive.utility_clean - best.utility_clean) * naive.n_clean)} of ${naive.n_clean}`,
        sub: `legitimate tasks ${best.posture_label} can no longer finish`,
        color: postureColor[best.posture],
      },
      {
        label: "Samples scored",
        value: String(rows.reduce((n, r) => n + r.n_total, 0)),
        sub: `${rows[0].n_total} samples × ${rows.length} postures`,
        color: "var(--text-muted)",
      },
    ];
    host.innerHTML = tiles
      .map(
        (t) =>
          `<div class="stat"><p class="stat-label">${esc(t.label)}</p>` +
          `<div class="stat-value"><span class="stat-dot" style="background:${t.color}"></span>${esc(t.value)}</div>` +
          `<div class="stat-sub">${esc(t.sub)}</div></div>`
      )
      .join("");

    const run = DATA.runs[0] || {};
    $("#hero-note").textContent =
      `Every figure on this page comes from ${DATA.runs.length} Inspect eval runs over ` +
      `${rows[0].n_total} samples each (${rows[0].n_clean} clean, ${rows[0].n_attacked} attacked), ` +
      `on ${DATA.models.map((m) => m.label).join(" and ")}, single attempt per sample, no repeats.`;

    $$("[data-fill]").forEach((n) => {
      const key = n.dataset.fill;
      if (key === "n_total") n.textContent = rows[0].n_total;
      if (key === "n_attacked") n.textContent = rows[0].n_attacked;
      if (key === "n_payloads") n.textContent = DATA.payloads.length;
    });

    $("#footer-meta").textContent =
      `Generated ${new Date(DATA.generated_at).toISOString().slice(0, 10)} from committed .eval logs` +
      (run.log_file ? ` · ${DATA.runs.length} runs` : "");
  }

  function renderClassNotes() {
    $("#class-notes").innerHTML = DATA.classes
      .map(
        (c) =>
          `<div class="class-note"><span class="asi">${esc(c.id)}:2026</span>` +
          `<h4>${esc(c.name)}</h4><p>${esc(c.blurb)}</p></div>`
      )
      .join("");
  }

  function renderMethod() {
    const rows = MAIN;
    const cards = [
      ["Framework", "<strong>Inspect AI</strong> — real <code>Task</code>, <code>Sample</code>s, a <code>react</code> agent, custom <code>@tool</code>s, two custom <code>@scorer</code>s and custom <code>@metric</code>s."],
      ["Model", DATA.models.map((m) => `<strong>${esc(m.label)}</strong>`).join(", ") + " · one attempt per sample, no retries on a completed run."],
      ["Sandbox", "One throwaway Alpine container per sample via Inspect's Docker sandbox, <code>network_mode: none</code>."],
      ["Suite", `<strong>${rows[0].n_total}</strong> samples: ${rows[0].n_clean} clean base scenarios and ${rows[0].n_attacked} attacked variants, 6 per OWASP class.`],
    ];
    $("#method-grid").innerHTML = cards
      .map(([h, p]) => `<div class="method-card"><h4>${h}</h4><p>${p}</p></div>`)
      .join("");

  }

  function renderTables() {
    const rows = MAIN;
    $("#frontier-table").innerHTML =
      "<table><thead><tr><th>Posture</th><th class='num'>Task utility</th>" +
      "<th class='num'>Utility (clean)</th><th class='num'>Utility (attacked)</th>" +
      "<th class='num'>Attack success</th><th class='num'>Resilience</th></tr></thead><tbody>" +
      rows
        .map(
          (r) =>
            `<tr><td>${esc(r.posture_label)}</td><td class="num">${pct(r.utility_all)}</td>` +
            `<td class="num">${pct(r.utility_clean)}</td><td class="num">${pct(r.utility_attacked)}</td>` +
            `<td class="num">${pct(r.asr)}</td><td class="num">${pct(r.resilience)}</td></tr>`
        )
        .join("") +
      "</tbody></table>";

    $("#classes-table").innerHTML =
      "<table><thead><tr><th>OWASP class</th>" +
      rows.map((r) => `<th class='num'>${esc(r.posture_label)}</th>`).join("") +
      "</tr></thead><tbody>" +
      DATA.classes
        .map(
          (c) =>
            `<tr><td>${esc(c.id)} ${esc(c.name)}</td>` +
            rows.map((r) => `<td class="num">${pct(r.asr_by_class[c.id] ?? 0)}</td>`).join("") +
            "</tr>"
        )
        .join("") +
      "</tbody></table>";
  }

  /* ---------------------------------------------------- cross-model control --- */
  function renderCrossModel() {
    const primary = DATA.primary_model || DATA.models[0].id;
    const others = DATA.summary.filter((r) => r.model !== primary);
    if (!others.length) return;

    // Compare like with like: only postures both models actually ran.
    const shared = others
      .map((o) => o.posture)
      .filter((p, i, a) => a.indexOf(p) === i)
      .filter((p) => MAIN.some((m) => m.posture === p));
    if (!shared.length) return;

    const models = DATA.models.filter((m) =>
      DATA.summary.some((r) => r.model === m.id && shared.includes(r.posture))
    );
    const get = (model, posture) =>
      DATA.summary.find((r) => r.model === model && r.posture === posture);

    $("#crossmodel").hidden = false;
    const postureNames = shared
      .map((p) => DATA.postures.find((q) => q.id === p)?.label || p)
      .join(" and ");
    $("#crossmodel-sub").textContent =
      `The same 32 samples and the same ${postureNames} ` +
      `${shared.length > 1 ? "postures" : "posture"}, run on a second model. Where the two ` +
      "columns disagree, the resilience is coming from the model's own training rather than " +
      "from anything I added.";

    let html = "<table><thead><tr><th>Measure</th>" +
      models.map((m) => `<th class='num'>${esc(m.label)}</th>`).join("") +
      "</tr></thead><tbody>";
    const rowsSpec = [
      ["Attack success rate", (s) => pct(s.asr)],
      ["Task utility (all samples)", (s) => pct(s.utility_all)],
      ["Task utility (clean only)", (s) => pct(s.utility_clean)],
      ["Payloads actually retrieved", (s) => `${s.n_exposed} / ${s.n_attacked}`],
    ];
    shared.forEach((posture) => {
      html += `<tr><td colspan="${models.length + 1}"><strong>${esc(
        DATA.postures.find((p) => p.id === posture)?.label || posture
      )} posture</strong></td></tr>`;
      rowsSpec.forEach(([label, fn]) => {
        html += `<tr><td>${esc(label)}</td>`;
        models.forEach((m) => {
          const s = get(m.id, posture);
          html += `<td class="num">${s ? fn(s) : "—"}</td>`;
        });
        html += "</tr>";
      });
      DATA.classes.forEach((c) => {
        html += `<tr><td style="padding-left:1.4rem;color:var(--text-muted)">${esc(c.id)} ${esc(c.name)}</td>`;
        models.forEach((m) => {
          const s = get(m.id, posture);
          html += `<td class="num">${s ? pct(s.asr_by_class[c.id] ?? 0) : "—"}</td>`;
        });
        html += "</tr>";
      });
    });
    html += "</tbody></table>";
    $("#crossmodel-table").innerHTML = html;
  }

  function renderCharts() {
    if (!DATA) return;
    renderScatter();
    renderClassBars();
  }

  /* ------------------------------------------------------------------ boot --- */
  async function boot() {
    initTheme();
    const res = await fetch("data/results.json");
    DATA = await res.json();

    const primary = DATA.primary_model || DATA.models[0].id;
    // Colour follows the posture itself, in the canonical hardening order — never the
    // row's position in whatever subset is on screen. Filtering must not repaint anything.
    const order = DATA.postures.map((p) => p.id);
    DATA.postures.forEach((p, i) => {
      postureColor[p.id] = cssVar(SERIES[i % SERIES.length]);
    });
    MAIN = DATA.summary
      .filter((r) => r.model === primary)
      .sort((a, b) => order.indexOf(a.posture) - order.indexOf(b.posture));
    MAIN_ROWS = DATA.rows.filter((r) => r.model === primary);

    renderHero();
    renderCharts();
    renderClassNotes();
    renderCostGrid();
    renderMatrix();
    renderMethod();
    renderCrossModel();
    renderTables();

    $$(".table-toggle").forEach((btn) => {
      btn.setAttribute("aria-pressed", "false");
      btn.addEventListener("click", () => {
        const t = $(`#${btn.dataset.table}`);
        const open = !t.hidden;
        t.hidden = open;
        btn.setAttribute("aria-pressed", String(!open));
        btn.textContent = open ? "Table view" : "Hide table";
      });
    });

    $$("[data-close]").forEach((n) => n.addEventListener("click", closeDrawer));
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !$("#drawer").hidden) closeDrawer();
    });

    let rt;
    addEventListener("resize", () => {
      clearTimeout(rt);
      rt = setTimeout(renderCharts, 160);
    });
  }

  // Theme changes swap CSS variables; charts must be re-read from the new values.
  boot();
})();
