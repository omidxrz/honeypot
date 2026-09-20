#!/bin/sh
# Rebuild ops/assets/ from upstream. Run from the repo root.
#
# ops/assets/ is gitignored third-party build output (same treatment as
# bait/), so a fresh clone does not have it and the Operator Panel will not
# render until this has been run once. docs/adr/0006 explains why only a
# subset of the template is taken; this script is that subset, executable.
#
# Needs Node (for the template's Vite build) and network access. Nothing it
# produces is committed; nothing runs on the sensor. Re-run it to pick up a
# newer ApexCharts or Bootstrap.
set -e

TEMPLATE_REPO="https://github.com/puikinsh/Bootstrap-Admin-Template.git"
WORK="${TMPDIR:-/tmp}/hp-vendor-assets"
DEST="ops/assets"

[ -f ops/index.html ] || { echo "run this from the repo root (ops/index.html not found)"; exit 2; }
command -v node >/dev/null || { echo "node is required (the template builds with Vite)"; exit 2; }
command -v npm  >/dev/null || { echo "npm is required"; exit 2; }

echo "== fetch the template =="
rm -rf "$WORK"
git clone --depth 1 "$TEMPLATE_REPO" "$WORK"

echo "== build it =="
( cd "$WORK" && npm ci --no-audit --no-fund && npm run build )

echo "== take only what the panel uses =="
# The compiled stylesheet carries a Vite content hash in its name; find it
# rather than hardcoding one, or this breaks on the next upstream release.
CSS=$(find "$WORK/dist-modern/assets" -maxdepth 1 -name 'main-*.css' | head -1)
[ -n "$CSS" ] || { echo "could not find the built main-*.css in dist-modern/assets"; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST/images" "$DEST/icons"

# Stable name: index.html references ./assets/panel.css, not a hashed name.
cp "$CSS" "$DEST/panel.css"

# The fonts panel.css @font-face's by exact filename, so they keep the hashed
# names upstream gave them. Pull exactly the ones the stylesheet asks for.
for f in $(grep -o 'url([^)]*\.woff2\?[^)]*)' "$DEST/panel.css" \
           | sed 's#url(\./##; s#)##' | sort -u); do
  if [ -f "$WORK/dist-modern/assets/$f" ]; then
    cp "$WORK/dist-modern/assets/$f" "$DEST/$f"
  else
    echo "  warning: panel.css references $f, which the build did not produce"
  fi
done

# Chart engine and Bootstrap's JS straight from their packages -- not Vite's
# bundled chunks, which are tangled into its ESM module graph (ADR-0006).
cp "$WORK/node_modules/apexcharts/dist/apexcharts.min.js" "$DEST/apexcharts.min.js"
cp "$WORK/node_modules/apexcharts/dist/apexcharts.css"    "$DEST/apexcharts.css"
cp "$WORK/node_modules/bootstrap/dist/js/bootstrap.bundle.min.js" "$DEST/bootstrap.bundle.min.js"

# jsvectormap: the world map. Pinned, and taken from the published package
# rather than the template (which does not depend on it). MIT. ~140 KB for the
# library, its stylesheet and the world map data together.
JVM_VER="1.7.0"
JVM="https://cdn.jsdelivr.net/npm/jsvectormap@$JVM_VER/dist"
curl -fsSL -o "$DEST/jsvectormap.min.js"  "$JVM/jsvectormap.min.js"
curl -fsSL -o "$DEST/jsvectormap.min.css" "$JVM/jsvectormap.min.css"
curl -fsSL -o "$DEST/world.js"            "$JVM/maps/world.js"

# Only the two images and the favicon the panel actually references.
cp "$WORK/dist-modern/assets/images/logo.svg"               "$DEST/images/logo.svg"
cp "$WORK/dist-modern/assets/images/avatar-placeholder.svg" "$DEST/images/avatar-placeholder.svg"
cp "$(find "$WORK/dist-modern/assets" -maxdepth 1 -name 'favicon-*.svg' | head -1)" "$DEST/icons/favicon.svg"
cp "$(find "$WORK/dist-modern/assets" -maxdepth 1 -name 'favicon-*.png' | head -1)" "$DEST/icons/favicon.png"

rm -rf "$WORK"

echo "== verify every asset index.html references actually exists =="
missing=0
for ref in $(grep -o '\./assets/[A-Za-z0-9._/-]*' ops/index.html | sed 's#^\./##' | sort -u); do
  [ -f "ops/$ref" ] || { echo "  MISSING: $ref"; missing=$((missing + 1)); }
done
[ "$missing" -eq 0 ] || { echo "$missing referenced asset(s) missing -- not usable"; exit 1; }

echo "wrote $DEST:"
find "$DEST" -type f | sort | sed 's/^/  /'
du -sh "$DEST"
