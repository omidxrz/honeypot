#!/bin/sh
# Rebuild ops/geo/ -- the offline IP-to-country tables. Run from the repo root.
#
# The sensor's egress is default-deny (etc/nftables.conf: no outbound 80/443),
# so geolocation cannot be an API call at runtime; it has to be a local table.
# ops/geo/ is gitignored third-party data, same treatment as ops/assets/ and
# bait/, so a fresh clone does not have it and deploy.sh refuses to run until
# this has been run once.
#
# Runs on your machine, never on the sensor. Needs network access. See
# docs/adr/0007 for why these two datasets and not GeoLite2 or a city-level one.
set -e

DEST="ops/geo"
# PDDL v1.0 -- "free use without attribution". Compiled from RIR delegated
# statistics, BGP routing archives and RFC 8805 geofeeds, chosen by upstream
# specifically to avoid commercial/redistribution restrictions.
IPCC_URL="https://raw.githubusercontent.com/sapics/ip-location-db/main/user-country/user-country-ipv4.csv"
# MIT. Centroid of each country's largest landmass (not a bbox centre, which
# puts France in the Atlantic), derived from public-domain Natural Earth.
CENT_URL="https://raw.githubusercontent.com/gavinr/world-countries-centroids/master/dist/countries.geojson"

[ -f ops/index.html ] || { echo "run this from the repo root (ops/index.html not found)"; exit 2; }
command -v curl >/dev/null || { echo "curl is required"; exit 2; }

mkdir -p "$DEST"

echo "== ip -> country (PDDL) =="
curl -fsSL -o "$DEST/ip-country-ipv4.csv.new" "$IPCC_URL"
mv -f "$DEST/ip-country-ipv4.csv.new" "$DEST/ip-country-ipv4.csv"

echo "== country -> centroid (MIT) =="
curl -fsSL -o "$DEST/centroids.geojson.tmp" "$CENT_URL"
python3 - "$DEST/centroids.geojson.tmp" "$DEST/country-centroids.csv" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
feats = json.load(open(src))["features"]
rows = []
for f in feats:
    p = f.get("properties") or {}
    cc = (p.get("ISO") or "").strip().upper()
    geom = f.get("geometry") or {}
    coords = geom.get("coordinates") or []
    if not cc or len(cc) != 2 or len(coords) != 2:
        continue
    lon, lat = coords[0], coords[1]          # GeoJSON is [lon, lat]
    name = (p.get("COUNTRY") or cc).replace(",", " ").strip()
    rows.append((cc, round(float(lat), 4), round(float(lon), 4), name))
# Codes the IP table uses that the centroid source has no feature for. Without
# these they are silently undrawable -- and HK alone is ~10k events in the live
# capture, so this is a real hole, not a rounding error. Geographic centroids,
# nothing inferred from the data.
SUPPLEMENT = [
    ("AX", 60.1785, 19.9156, "Aland Islands"),
    ("EH", 24.2155, -12.8858, "Western Sahara"),
    ("FX", 46.2276, 2.2137, "France (metropolitan)"),
    ("HK", 22.3193, 114.1694, "Hong Kong"),
    ("MO", 22.1987, 113.5439, "Macao"),
    ("TW", 23.6978, 120.9605, "Taiwan"),
    ("XK", 42.6026, 20.9030, "Kosovo"),
]
have = {r[0] for r in rows}
added = [r for r in SUPPLEMENT if r[0] not in have]
rows.extend(added)

rows.sort()
with open(dst, "w") as out:
    for cc, lat, lon, name in rows:
        out.write("%s,%s,%s,%s\n" % (cc, lat, lon, name))
print("  %d countries (%d from source, %d supplemented: %s)"
      % (len(rows), len(rows) - len(added), len(added), " ".join(r[0] for r in added)))
PY
rm -f "$DEST/centroids.geojson.tmp"

echo "== build the binary index =="
# The CSV takes ~1.0s to parse into Python lists, and hp-recent.timer runs
# every 10 seconds -- ~10% of a core, permanently, to look up a hundred
# addresses. The index is the same table as three packed arrays that load with
# array.fromfile in milliseconds. The CSV stays as the readable source, and the
# thing the index is rebuilt from.
python3 - "$DEST" <<'IDXPY'
import json, sys
from array import array
d = sys.argv[1]

def ip_to_num(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    n = 0
    for p in parts:
        if not p.isdigit():
            return None
        o = int(p)
        if o > 255:
            return None
        n = (n << 8) | o
    return n

starts, ends, ccix = array("I"), array("I"), array("H")
codes, code_id = [], {}
with open(d + "/ip-country-ipv4.csv") as f:
    for line in f:
        parts = line.rstrip("\n").split(",")
        if len(parts) != 3:
            continue
        a, b = ip_to_num(parts[0]), ip_to_num(parts[1])
        if a is None or b is None:
            continue
        cc = parts[2]
        if cc not in code_id:
            code_id[cc] = len(codes)
            codes.append(cc)
        starts.append(a)
        ends.append(b)
        ccix.append(code_id[cc])

with open(d + "/ip-country.idx", "wb") as out:
    # A one-line JSON header keeps the format self-describing, including the
    # byte order the arrays were written in -- the index is built on one
    # machine and read on another.
    header = {"v": 1, "n": len(starts), "codes": codes,
              "little": sys.byteorder == "little"}
    out.write((json.dumps(header, separators=(",", ":")) + "\n").encode())
    starts.tofile(out)
    ends.tofile(out)
    ccix.tofile(out)
print("  %d ranges, %d codes" % (len(starts), len(codes)))
IDXPY

cat > "$DEST/LICENSES.txt" <<'EOF'
ip-country-ipv4.csv
  Source:  https://github.com/sapics/ip-location-db  (user-country)
  License: PDDL v1.0 -- https://opendatacommons.org/licenses/pddl/1.0/
           "free use without attribution"
  Built from RIR delegated statistics, Route Views / RIPE RIS BGP archives,
  and RFC 8805 / RFC 9632 geofeeds.

country-centroids.csv
  Source:  https://github.com/gavinr/world-countries-centroids
  License: MIT
  Derived from Natural Earth, which is public domain.
EOF

echo "== verify =="
python3 - "$DEST" <<'PY'
import sys, collections
d = sys.argv[1]

starts = []
ccs = collections.Counter()
bad = 0
prev = -1
ordered = True
with open(d + "/ip-country-ipv4.csv") as f:
    for line in f:
        parts = line.rstrip("\n").split(",")
        if len(parts) != 3:
            bad += 1; continue
        a, b, cc = parts
        try:
            o = [int(x) for x in a.split(".")]
            n = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]
        except (ValueError, IndexError):
            bad += 1; continue
        if n < prev:
            ordered = False
        prev = n
        starts.append(n); ccs[cc] += 1

print("  ranges: %d, malformed lines: %d, distinct countries: %d" % (len(starts), bad, len(ccs)))
# The lookup is a bisect over the range starts, which is only correct if the
# file really is sorted. Upstream sorts it; this is the check that says so.
assert ordered, "ip-country-ipv4.csv is NOT sorted by start address -- bisect would be wrong"
assert len(starts) > 200000, "suspiciously few ranges (%d) -- truncated download?" % len(starts)
assert len(ccs) > 200, "suspiciously few countries (%d)" % len(ccs)

cent = {}
with open(d + "/country-centroids.csv") as f:
    for line in f:
        cc, lat, lon, name = line.rstrip("\n").split(",", 3)
        cent[cc] = (float(lat), float(lon))
assert len(cent) > 200, "suspiciously few centroids (%d)" % len(cent)

# A country in the IP table with no centroid cannot be drawn. Report the gap
# rather than discovering it as a hole in the map later.
missing = sorted(set(ccs) - set(cent))
covered = sum(n for cc, n in ccs.items() if cc in cent)
drawable = 100.0 * covered / sum(ccs.values())
print("  centroids: %d; IP-table countries with no centroid: %d %s"
      % (len(cent), len(missing), missing[:12] if missing else ""))
print("  ranges drawable: %.2f%%" % drawable)
# A country that cannot be drawn disappears from the map without saying so.
# Upstream adding a new code is fine; a big undrawable share is not.
assert drawable > 99.5, "only %.2f%% of ranges are drawable -- extend SUPPLEMENT above" % drawable
PY

echo "wrote $DEST:"
find "$DEST" -type f | sort | sed 's/^/  /'
du -sh "$DEST"
