#!/usr/bin/env node
// Self-check for the operator panel's render path. node ops/panel-check.js
//
// The panel renders attacker-controlled text: Names, payload samples, user
// agents, paths. Nothing else checks that it escapes them, and the panel is
// served to an operator's browser, so an unescaped field is stored XSS.
//
// This extracts the <script> out of index.html, runs it against a synthetic
// stats document with markup in every hostile field, and asserts on what it
// wrote into the DOM. No browser, no server, no real capture.
//
// The script now touches far more of the DOM (sidebar/theme/fullscreen
// chrome, ApexCharts) than the escaping logic itself needs, so the sandbox
// below is a minimal fake DOM sufficient to let it run to completion --
// not a faithful browser. Its job is to not crash before render() runs,
// not to verify the chrome behaves correctly.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const m = html.match(/<script>\s*\(function \(\) \{([\s\S]*?)\}\)\(\);\s*<\/script>/);
if (!m) {
  console.error("panel-check: could not find the render script in index.html");
  process.exit(1);
}

const HOSTILE = '<script>alert(1)</script>';
const CLASS_BAIT = '#dc3545';  // must match CLASS_COLOR.bait in index.html
const stats = {
  generated: "2026-09-16T08:00:00Z",
  window_start: "2026-09-09T07:35:26Z",
  totals: { events: 773181, web: 16347, tcp: 756834, unique_ips: 14285,
            ports_seen: 65371, tls: 111666, contacts: 148, contacts_24h: 21, novel_24h: 1799 },
  hourly: [{ h: "2026-09-16T01:00:00Z", n: 12 }, { h: "2026-09-16T02:00:00Z", n: 400 }],
  contacts_hourly: [{ h: "2026-09-16T01:00:00Z", n: 1 }, { h: "2026-09-16T02:00:00Z", n: 4 }],
  contacts: [{ ip: "203.0.113.7", name: HOSTILE, class: "bait",
               first: "2026-09-16T04:10:00Z", n: 277 }],
  hosts: [{ host: '"><img src=x onerror=alert(1)>', class: "foreign", n: 545 },
          { host: "ops.example", class: "bait", n: 12 }],
  top_ports: [{ port: 445, n: 9012 }, { port: 22, n: 300 }],
  top_ips: [{ ip: "203.0.113.1", n: 900 }],
  top_paths: [{ path: HOSTILE, n: 3 }],
  top_agents: [{ ua: HOSTILE, n: 812 }],
  credentials: [{ user: HOSTILE, n: 44 }],
  novel: [{ shape: "get /a?id=#", n: 1, first: "2026-09-16T03:00:00Z", sample: HOSTILE }],
  countries: [
    { cc: "US", name: "United States", n: 450638, actors: 8083, lat: 38.8, lon: -96.3 },
    { cc: "SG", name: "Singapore", n: 89110, actors: 831, lat: 1.35, lon: 103.8 },
    { cc: "ZZ", name: HOSTILE, n: 5, actors: 1, lat: 10, lon: 10 },
    { cc: "NP", name: "Unplaceable", n: 3, actors: 1, lat: null, lon: null },
  ],
  countries_unknown_events: 106,
  countries_unknown_actors: 1,
  countries_unplaced: 3,
  sensor: { cc: "DE", name: "Germany", lat: 51.08, lon: 10.43 },
};

// recent.json -- the live feed the map animates. Coordinates are real-world
// ones with |lon| > 90, which is what catches a reversed coordsToPoint.
const recent = {
  generated: "2026-09-20T01:00:00Z",
  events: [
    { t: "2026-09-20T00:59:58", ip: "203.0.113.9", cc: "US", lat: 38.8, lon: -96.3, named: false },
    { t: "2026-09-20T00:59:59", ip: HOSTILE, cc: "SG", lat: 1.35, lon: 103.8, named: true },
  ],
};

// --- a minimal fake DOM: enough surface for the script to run, nothing more ---
function makeNode(id) {
  return {
    id, innerHTML: "", textContent: "", className: "", hidden: false,
    classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
    addEventListener() {}, setAttribute() {}, getAttribute: () => null,
    style: {}, dataset: {},
  };
}
const els = {};
const byId = (id) => (els[id] = els[id] || makeNode(id));

// drawArc builds a real <path>; give it just enough SVG to run so the arc
// path is exercised rather than skipped.
const svgChildren = [];
function makeSvgNode() {
  return {
    _attrs: {}, style: {},
    setAttribute(k, v) { this._attrs[k] = v; },
    getAttribute(k) { return this._attrs[k]; },
    getTotalLength: () => 200,
    appendChild(c) { svgChildren.push(c); c.parentNode = this; return c; },
    removeChild(c) { const i = svgChildren.indexOf(c); if (i >= 0) svgChildren.splice(i, 1); },
    querySelectorAll: () => [],
  };
}
const fakeSvg = makeSvgNode();

const chartInstances = [];
function FakeApexCharts(el, opts) {
  this.el = el; this.opts = opts;
  chartInstances.push(this);
}
FakeApexCharts.prototype.render = function () { return Promise.resolve(); };
FakeApexCharts.prototype.updateOptions = function (opts) { this.opts = opts; };

const mapInstances = [];
let tooltipInnerHtmlUsed = false;
function FakeVectorMap(opts) {
  this.opts = opts;
  mapInstances.push(this);
  // Exercise the tooltip callbacks the way the library would, with a tooltip
  // whose text() records whether the innerHTML flag was passed. text(str)
  // writes textContent; text(str, true) writes innerHTML. The panel must
  // never pass the flag.
  const tooltip = { last: "", text(str, useHtml) { this.last = str; if (useHtml) tooltipInnerHtmlUsed = true; } };
  if (opts.onRegionTooltipShow) opts.onRegionTooltipShow({}, tooltip, "US");
  if (opts.onMarkerTooltipShow) {
    (opts.markers || []).forEach((_, i) => opts.onMarkerTooltipShow({}, tooltip, i));
  }
  this.tooltipText = tooltip.last;
}
// The real coordsToPoint takes (lat, lng) and returns false when the first
// argument is not a valid latitude. Mimicking that is what makes a reversed
// call site detectable here instead of only in a browser.
let coordsOutOfRange = 0;
FakeVectorMap.prototype.coordsToPoint = function (lat, lng) {
  if (typeof lat !== "number" || Math.abs(lat) > 90) { coordsOutOfRange++; return false; }
  return { x: 100 + lng, y: 100 - lat };
};
FakeVectorMap.prototype.destroy = function () {};

let intervalCalled = false;
let recentPolls = 0;
const documentElementNode = makeNode("html");
documentElementNode.getAttribute = () => "light";

const sandbox = {
  document: {
    getElementById: byId,
    querySelector: (sel) => (String(sel).indexOf("svg") !== -1 ? fakeSvg : makeNode("q")),
    createElementNS: () => makeSvgNode(),
    querySelectorAll: () => [],
    documentElement: documentElementNode,
    fullscreenElement: null,
    exitFullscreen() {},
  },
  window: { bootstrap: undefined },
  localStorage: { getItem: () => null, setItem() {} },
  ApexCharts: FakeApexCharts,
  jsVectorMap: FakeVectorMap,
  // Fire each interval callback once so the recent-arrivals poll is exercised;
  // in the browser these are 60s and 10s.
  // Fire each interval twice: the arc poll primes on its first call (so a
  // page load does not replay the backlog as a fake flood) and only draws on
  // a later poll that brings something new.
  setInterval: (fn) => { intervalCalled = true; setTimeout(fn, 0); setTimeout(fn, 5); return 0; },
  requestAnimationFrame: (fn) => { setTimeout(fn, 0); return 0; },
  setTimeout,
  Math, Date, JSON, String, Number, Object,
  fetch: (url) => {
    if (String(url).indexOf("recent.json") === -1) {
      return Promise.resolve({ json: () => Promise.resolve(stats) });
    }
    recentPolls++;
    // Second poll brings a genuinely new arrival, which is the only thing
    // that should ever produce an arc.
    const doc = recentPolls === 1 ? recent
      : { generated: recent.generated,
          events: recent.events.concat([{ t: "2026-09-20T01:00:05", ip: "198.51.100.7",
                                          cc: "AU", lat: -25.0, lon: 133.0, named: true }]) };
    return Promise.resolve({ json: () => Promise.resolve(doc) });
  },
  console,
};

const src = m[1].replace(/fetch\("stats\.json\?" \+ Date\.now\(\)\)\.then\(function \(r\) \{ return r\.json\(\); \}\)/,
                         "Promise.resolve(STATS)");
if (src === m[1]) {
  console.error("panel-check: the fetch call changed shape; update this check");
  process.exit(1);
}
sandbox.STATS = stats;
sandbox.RECENT = recent;
vm.createContext(sandbox);
try {
  vm.runInContext("(function () {" + src + "})();", sandbox);
} catch (e) {
  console.error("panel-check: the script threw before rendering: " + e.stack);
  process.exit(1);
}

setTimeout(() => {
  let failed = 0;
  const check = (cond, msg) => { if (!cond) { console.error("  FAIL " + msg); failed++; } };

  check(intervalCalled, "the panel does not poll (setInterval was never called)");
  check(chartInstances.length >= 3, "expected 3 charts (events, classes, ports); got " + chartInstances.length);

  // every section the rollup emits must actually land somewhere
  for (const id of ["tiles", "contacts", "hosts", "topports", "topips",
                    "toppaths", "uas", "creds", "novel", "contact-feed"]) {
    check(byId(id).innerHTML.length > 0, "section '" + id + "' rendered nothing");
  }
  check(byId("contactmeta").textContent.includes("148"), "contact meta missing the total");
  check(byId("tiles").innerHTML.includes("148"), "contacts tile missing");
  check(byId("tiles").innerHTML.includes("21"), "contacts 24h tile missing");
  check(!byId("tiles").innerHTML.includes("new ports"), "retired tile still rendered");
  check(byId("contact-badge").hidden === false && String(byId("contact-badge").textContent) === "21",
        "the notification badge must show the real contacts_24h count");

  // nothing attacker-controlled may reach the DOM as markup
  const all = Object.values(els).map((e) => e.innerHTML).join("");
  // esc() handles & < > " -- so a tag can only appear if escaping was skipped.
  // Attacker text may survive as inert characters; what must never appear is a
  // tag or an attribute boundary that the data opened.
  check(!all.includes("<script"), "an unescaped <script> reached the panel");
  check(!all.includes("<img"), "data opened a tag: escaping was skipped somewhere");
  check(all.includes("&lt;script&gt;"), "hostile text was dropped rather than escaped");
  check(byId("hosts").innerHTML.includes("&quot;&gt;&lt;img"), "a Name was not escaped");
  check(byId("contacts").innerHTML.includes("badge"), "the class column lost its badge");
  check(byId("contact-feed").innerHTML.includes("&lt;script&gt;"),
        "the notification feed renders a real Contact's Name -- it must escape too");

  // real <thead> with labeled, sortable columns -- this was missing entirely
  // before, not just unstyled. Structural checks only; sort/filter click
  // behavior is verified in-browser, since the sandbox's fake DOM has no
  // closest() to support the delegated click handler.
  check(byId("contacts").innerHTML.includes("<thead>"), "Contacts table has no header row");
  check(byId("contacts").innerHTML.includes('scope="col"'), "header cells are missing scope=\"col\"");
  check(byId("contacts").innerHTML.includes(">Actor<") || byId("contacts").innerHTML.includes(">Actor "),
        "the Actor column has no label");
  check(byId("contacts").innerHTML.includes('aria-sort="none"'), "header cells are missing aria-sort");
  check(byId("topports-count").textContent.length > 0, "the row-count indicator never populated");

  // --- icons -----------------------------------------------------------
  // The template's build SUBSETS bootstrap-icons to the ~158 glyphs the
  // template itself used. Any other `bi-*` class is valid markup, loads a
  // real font, and renders nothing at all -- no error, no console warning,
  // just an empty gap where an icon should be. Six sidebar icons shipped
  // that way. This is a static check against the vendored stylesheet, so it
  // catches the next one at build time rather than in a screenshot.
  const cssPath = path.join(__dirname, "assets", "panel.css");
  if (!fs.existsSync(cssPath)) {
    console.log("  (icons: skipped -- ops/assets/panel.css not vendored yet)");
  } else {
    const css = fs.readFileSync(cssPath, "utf8");
    const defined = new Set((css.match(/\.bi-[a-z0-9-]+/g) || []).map((c) => c.slice(4)));
    const used = new Set((html.match(/\bbi bi-[a-z0-9-]+/g) || []).map((c) => c.slice(6)));
    const blank = [...used].filter((i) => !defined.has(i)).sort();
    check(blank.length === 0,
          "icon(s) used but not in the vendored subset, will render blank: " + blank.join(", "));
    check(used.size > 0, "no icons found in the markup at all -- did the selector change?");
  }

  // --- world map -------------------------------------------------------
  check(mapInstances.length >= 1, "the world map was never constructed");
  const map = mapInstances[mapInstances.length - 1] || { opts: {} };
  const regionSeries = (map.opts.series && map.opts.series.regions && map.opts.series.regions[0]) || {};
  const vals = regionSeries.values || {};
  const scale = regionSeries.scale || {};
  check(Object.keys(vals).length > 0, "choropleth values were not populated from countries");
  check(vals.US && vals.SG, "a country with traffic is missing from the choropleth values");
  // jsvectormap's region scale is an ORDINAL lookup: getValue(v) is scale[v].
  // Any value not present as a key renders fill="undefined" -- which is
  // exactly what raw counts did. Every value must resolve.
  const unresolved = Object.keys(vals).filter((cc) => !(vals[cc] in scale));
  check(unresolved.length === 0,
        "choropleth value(s) not present in the scale -- these render as fill=undefined: " +
        unresolved.slice(0, 5).map((cc) => cc + "=" + vals[cc]).join(","));
  check(!("normalizeFunction" in regionSeries),
        "normalizeFunction does not exist in jsvectormap 1.7 and silently does nothing");
  // per-marker style must nest under `initial` or the library ignores it
  const styled = (map.opts.markers || []).filter((m) => m.style && m.style.initial);
  check(styled.length === (map.opts.markers || []).length,
        "a marker style is not nested under `initial` -- it would be silently ignored");
  const markerNames = (map.opts.markers || []).map((m) => m.name);
  check(markerNames.indexOf("sensor") !== -1, "the sensor is not marked on the map");
  check(markerNames.indexOf("SG") !== -1,
        "Singapore has no map region and must still get a marker, or ~8% of events vanish");
  check((map.opts.markers || []).every((m) => m.coords[0] !== null && m.coords[1] !== null),
        "a marker was created with a null coordinate");
  check(markerNames.indexOf("NP") === -1, "a country with no centroid must not become a marker");
  check(byId("mapmeta").textContent.includes("%"),
        "the map does not state how much of the traffic it actually located");
  // The tooltip sink is textContent unless a second argument says otherwise.
  // This is the whole reason attacker-controlled text is safe there.
  check(!tooltipInnerHtmlUsed, "a map tooltip asked for innerHTML -- it must use textContent");

  // the charts themselves take no attacker-controlled strings (numbers, and
  // our own fixed class labels) -- confirm nothing hostile reached them either
  const chartText = chartInstances.map((c) => JSON.stringify(c.opts)).join("");
  check(!chartText.includes("<script"), "attacker text reached a chart's options");
  // A hostile country name reaches the map's marker metadata; it is only safe
  // because it goes out through textContent, never innerHTML.
  const mapText = mapInstances.map((m) => JSON.stringify(m.opts)).join("");
  check(mapText.length > 0, "map options were empty");

  // --- live arcs (checked after the second poll has had a tick) ---------
  setTimeout(() => {
    check(recentPolls >= 2, "the recent-arrivals feed was never polled twice");
    check(coordsOutOfRange === 0,
          "coordsToPoint was called with an out-of-range latitude -- the (lat, lng) " +
          "argument order is reversed, and arcs would silently never draw");
    const arcs = svgChildren.filter((c) => c.getAttribute("d"));
    check(arcs.length >= 1, "a new arrival drew no arc");
    if (arcs.length) {
      const a = arcs[0];
      check(/^M[-\d.]+,[-\d.]+ Q/.test(a.getAttribute("d")),
            "arc path is not a quadratic curve: " + a.getAttribute("d"));
      check(a.getAttribute("stroke") === CLASS_BAIT,
            "an arrival by one of our Names must be drawn distinctly from a scan");
      check(a.getAttribute("pointer-events") === "none",
            "arcs must not swallow pointer events from the map underneath");
    }
    // arcs carry no text, so nothing attacker-controlled can reach the DOM
    // through them even though the feed contains attacker-chosen addresses
    const arcBlob = JSON.stringify(svgChildren.map((c) => c._attrs));
    check(!arcBlob.includes("<script"), "attacker text reached an arc attribute");

    if (failed) { console.error("panel self-check FAILED (" + failed + ")"); process.exit(1); }
    console.log("panel self-check ok");
  }, 60);
}, 0);
