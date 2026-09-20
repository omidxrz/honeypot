---
status: accepted
---

# Cherry-pick the admin template's build output, don't vendor the project

The Operator Panel was rebuilt on puikinsh/Bootstrap-Admin-Template (Metis),
which ships as a 30-page Vite/Node project: full router-driven page set
(User Management, File Manager, Calendar, Order Management, auth screens,
element showcases...), Alpine.js for interactivity, ApexCharts bundled
through Vite's module graph.

Three ways to bring it in: vendor the whole Vite project into the repo and
add a Node build step to `deploy.sh`; cherry-pick the built output of a local
`npm run build` and hand-wire it with vanilla JS; or take only the CSS theme.

Cherry-pick was chosen. The Operator Panel needs one page, not thirty, and
the existing deploy model is deliberately Node-free on the box (`hp-ops` runs
`python3 -m http.server`, and the bait site's own README already established
the precedent of treating a `npm run build` as a one-time local step whose
*output* gets copied over, never the Vite project itself). Vendoring the full
project would mean maintaining a Node build step in `deploy.sh` for a single
internal dashboard, and 29 unused pages' worth of JS and Alpine machinery
shipped to the box for nothing.

Only `panel.css` (renamed from Vite's hashed filename to something stable),
the Inter/Bootstrap-Icons font files it references, `apexcharts.min.js` taken
directly from the `apexcharts` package rather than Vite's bundled chunk, and
`bootstrap.bundle.min.js` from the `bootstrap` package were kept. Every
per-page JS chunk, the Vite/Alpine module graph, and the PWA manifest were
dropped. All of it is self-hosted; none of it makes a third-party request.

## Consequences

The previous rebuild of this panel (commit `1723904`) had done a full Vite
build and manually copied the *entire* `dist-modern/assets/` directory
(30 pages' worth) to the box outside `deploy.sh`'s tracked file list --
untracked drift that would have silently broken the panel if the box were
ever rebuilt, since nothing but the operator's memory connected that
directory to its source. This change replaces it with a small, explicit
asset set that `deploy.sh` deploys like every other file.

Upgrading ApexCharts or Bootstrap later means re-running the vendor step by
hand (re-copy the two dist files) rather than `npm update`; acceptable for a
single internal dashboard, and cheap to redo when it matters.
