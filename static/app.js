// Watchtower console behaviour: theme, sortable tables, row links, raw-event drawer,
// live mode, column chooser, and uPlot charts. No inline script anywhere (CSP).
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var css = function (v) { return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); };
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }

  // ---- theme
  var tbtn = $("#theme");
  if (tbtn) tbtn.addEventListener("click", function () {
    var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    store("wt-theme", next);
    drawCharts();
  });

  // ---- row links (whole row clickable, link still works for middle-click)
  document.addEventListener("click", function (ev) {
    var tr = ev.target.closest("tr[data-href]");
    if (tr && !ev.target.closest("a,button,input,form")) location.href = tr.getAttribute("data-href");
  });

  // ---- sortable tables
  function bindSort(root) { $$("table.sortable", root).forEach(function (t) {
    $$("th[data-sort]", t).forEach(function (th) {
      th.tabIndex = 0;
      var go = function () {
        var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
        var dir = th.getAttribute("aria-sort") === "descending" ? 1 : -1;
        $$("th", t).forEach(function (x) { x.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", dir === 1 ? "ascending" : "descending");
        var rows = $$("tbody tr", t).filter(function (r) { return r.children.length > 1; });
        var num = th.getAttribute("data-sort") === "num";
        rows.sort(function (a, b) {
          var ca = a.children[idx], cb = b.children[idx];
          var va = ca.getAttribute("data-v") || ca.textContent.trim(), vb = cb.getAttribute("data-v") || cb.textContent.trim();
          if (num) { va = parseFloat(va) || 0; vb = parseFloat(vb) || 0; return (va - vb) * dir; }
          return va.localeCompare(vb) * dir;
        });
        rows.forEach(function (r) { r.parentNode.appendChild(r); });
      };
      th.addEventListener("click", go);
      th.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
    });
  }); }
  bindSort(document);

  // ---- raw event drawer (opens from the right, closes back to the right)
  var drawer = $("#drawer");
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function openEvent(id) {
    fetch("/api/event/" + id, { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (d) {
      var when = new Date(d.ts * 1000).toLocaleString();
      var kv = [["Time", when], ["Source", d.source], ["Event", d.action], ["Outcome", d.outcome], ["Actor", d.actor],
                ["Source IP", d.src_ip], ["Target", d.target], ["Region / host", d.region], ["ID", d.uid]]
        .filter(function (x) { return x[1]; })
        .map(function (x) { return "<dt>" + x[0] + "</dt><dd class=\"mono\">" + esc(x[1]) + "</dd>"; }).join("");
      $(".drawer-body", drawer).innerHTML = "<dl class=\"kv\">" + kv + "</dl><pre>" + esc(JSON.stringify(d.raw, null, 2)) + "</pre>";
      drawer.hidden = false; drawer.setAttribute("aria-hidden", "false");
      $("#drawer-close").focus({ preventScroll: true });
    });
  }
  function closeDrawer() { if (drawer) { drawer.hidden = true; drawer.setAttribute("aria-hidden", "true"); } }
  document.addEventListener("click", function (ev) {
    var tr = ev.target.closest("table.events tbody tr[data-id]");
    if (tr && !ev.target.closest("a")) openEvent(tr.getAttribute("data-id"));
  });
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") closeDrawer();
    var tr = ev.target.closest && ev.target.closest("table.events tbody tr[data-id]");
    if (tr && ev.key === "Enter") openEvent(tr.getAttribute("data-id"));
  });
  var dc = $("#drawer-close"); if (dc) dc.addEventListener("click", closeDrawer);

  // ---- column chooser (remembered per browser)
  var hidden = {};
  try { hidden = JSON.parse(store("wt-cols") || "{}"); } catch (e) { hidden = {}; }
  function applyCols() {
    $$("[data-col]").forEach(function (c) { c.style.display = hidden[c.getAttribute("data-col")] ? "none" : ""; });
    $$("[data-colpick]").forEach(function (b) { b.checked = !hidden[b.getAttribute("data-colpick")]; });
  }
  $$("[data-colpick]").forEach(function (b) {
    b.addEventListener("change", function () { hidden[b.getAttribute("data-colpick")] = !b.checked; store("wt-cols", JSON.stringify(hidden)); applyCols(); });
  });
  applyCols();

  // ---- live mode: poll for events newer than the newest row, keep current filters
  var live = $("#live"), timer = null;
  if (live) live.addEventListener("click", function () {
    var on = live.getAttribute("aria-pressed") !== "true";
    live.setAttribute("aria-pressed", on ? "true" : "false");
    $("span", live).textContent = on ? "Pause" : "Live";
    if (!on) { clearInterval(timer); return; }
    var poll = function () {
      var p = new URLSearchParams(location.search); p.set("after", live.getAttribute("data-after") || "0");
      fetch("/api/events?" + p.toString(), { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (d) {
        if (!d.n) return;
        live.setAttribute("data-after", d.newest);
        var tb = $("table.events tbody"); var tmp = document.createElement("tbody"); tmp.innerHTML = d.html;
        var empty = $("td.empty", tb); if (empty) empty.parentNode.remove();
        $$("tr", tmp).reverse().forEach(function (r) { r.classList.add("fresh"); tb.insertBefore(r, tb.firstChild); });
        applyCols();
        var ls = $("#live-status"); if (ls) ls.textContent = d.n + " new event" + (d.n === 1 ? "" : "s");
      });
    };
    poll(); timer = setInterval(poll, 5000);
  });

  // ---- charts: thin bars, one series each, hairline grid, hover tooltip
  var plots = [];
  function fmtTime(t, bucket) {
    var d = new Date(t * 1000);
    var hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return bucket >= 86400 ? d.toLocaleDateString([], { month: "short", day: "numeric" }) :
      d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + hm;
  }
  function tooltip(bucket) {
    var tip;
    return {
      hooks: {
        init: function (u) { tip = document.createElement("div"); tip.className = "wt-tip"; tip.hidden = true; u.over.appendChild(tip); },
        setCursor: function (u) {
          var i = u.cursor.idx;
          if (i == null) { tip.hidden = true; return; }
          var v = u.data[1][i];
          tip.hidden = false;
          tip.textContent = fmtTime(u.data[0][i], bucket) + "  " + v.toLocaleString() + " event" + (v === 1 ? "" : "s");
          var x = u.valToPos(u.data[0][i], "x"), w = tip.offsetWidth;
          tip.style.left = Math.min(Math.max(0, x - w / 2), u.over.clientWidth - w) + "px";
          tip.style.top = "-26px";
        }
      }
    };
  }
  function drawCharts() {
    plots.forEach(function (p) { p.destroy(); }); plots = [];
    if (!window.uPlot) return;
    $$(".chart[data-kind=bars]").forEach(function (el) {
      var xs = JSON.parse(el.getAttribute("data-x")), ys = JSON.parse(el.getAttribute("data-y"));
      var bucket = +el.getAttribute("data-bucket"), slot = el.getAttribute("data-slot") || "1";
      var color = css("--s" + slot), grid = css("--grid"), axis = css("--axis"), muted = css("--muted");
      var w = el.clientWidth || 300, h = el.clientHeight || 72, small = h < 100;
      var opts = {
        width: w, height: h, legend: { show: false }, plugins: [tooltip(bucket)],
        cursor: { y: false, points: { show: false }, drag: { x: false, y: false } },
        scales: { x: { time: true }, y: { range: function (u, mn, mx) { return [0, Math.max(1, mx)]; } } },
        axes: [
          { stroke: muted, grid: { show: false }, ticks: { stroke: axis, width: 1, size: 3 }, size: small ? 18 : 24,
            font: "11px Plex Sans, system-ui", show: true, space: small ? 70 : 90 },
          { stroke: muted, grid: { stroke: grid, width: 1 }, ticks: { show: false }, size: 34, font: "11px Plex Sans, system-ui",
            splits: function (u) { var m = u.scales.y.max; return (small || m < 4) ? [0, m] : [0, Math.round(m / 2), m]; },
            values: function (u, v) { return v.map(function (x) { return x >= 1000 ? (x / 1000).toFixed(1) + "k" : Math.round(x); }); } }
        ],
        series: [{}, { stroke: color, fill: color, width: 0, paths: uPlot.paths.bars({ size: [0.7, 8], radius: 0.15 }), points: { show: false } }]
      };
      el.innerHTML = "";
      plots.push(new uPlot(opts, [xs, ys], el));
    });
  }
  window.addEventListener("load", drawCharts);

  // ---- auto refresh (the owner 2026-11-18): Overview and Offenses reload their content every 30 s
  // while the tab is visible and nobody is typing or reading an event, plus an "Updated Xs ago" label.
  var REFRESH = 30000, path = location.pathname.replace(/\/+$/, "") || "/";
  if (path === "/" || path === "/offenses") {
    var stamp = Date.now(), label = document.createElement("span");
    label.className = "updated";
    var tb = $("#theme"); if (tb) tb.parentNode.insertBefore(label, tb);
    var tick = function () {
      var s = Math.round((Date.now() - stamp) / 1000);
      label.textContent = "Updated " + (s < 5 ? "just now" : s < 60 ? s + "s ago" : Math.floor(s / 60) + "m ago");
    };
    var busy = function () {
      var a = document.activeElement;
      return document.hidden || (drawer && !drawer.hidden) || (a && /INPUT|SELECT|TEXTAREA/.test(a.tagName));
    };
    var refresh = function () {
      if (busy()) return;
      fetch(location.href, { credentials: "same-origin", cache: "no-store" }).then(function (r) {
        if (!r.ok || r.redirected) throw new Error("refresh " + r.status);
        return r.text();
      }).then(function (html) {
        var fresh = new DOMParser().parseFromString(html, "text/html").getElementById("main");
        var main = $("#main"); if (!fresh || !main || busy()) return;
        main.innerHTML = fresh.innerHTML;
        bindSort(main); applyCols(); drawCharts();
        stamp = Date.now(); tick(); label.classList.remove("stale");
      }).catch(function () { label.classList.add("stale"); });
    };
    tick(); setInterval(tick, 1000); setInterval(refresh, REFRESH);
    document.addEventListener("visibilitychange", function () { if (!document.hidden && Date.now() - stamp > REFRESH) refresh(); });
  }
  var rt; window.addEventListener("resize", function () { clearTimeout(rt); rt = setTimeout(drawCharts, 150); });
})();
