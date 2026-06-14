#!/usr/bin/env bash
# check-qurl-link-og-image.sh
# ----------------------------------------------------------------------------
# PR-time guard for the committed qurl.link social preview PNG.
#
# The deployed `og-image.png` is a generated asset: `og-image.svg` supplies the
# card art, and `layerv-wordmark.svg` is composited on top. The post-deploy
# smoke suite also checks the live asset, but this script catches a missing or
# stale committed PNG before merge without depending on a deployed origin.
#
# The check reads the PNG only. Re-rendering the whole SVG in CI would make the
# result depend on the runner's Helvetica/Arial fallbacks because the card SVG
# intentionally keeps editable text. Instead, this guard verifies the stable
# invariants reviewers care about: PNG dimensions and visible LayerV wordmark
# pixels in the documented brand region.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="${REPO_ROOT}/terraform/modules/qurl-link/frontend"
OG_IMAGE="${FRONTEND_DIR}/og-image.png"

BRAND_REGION="${QURL_OG_BRAND_REGION:-290x85+70+55}"
MIN_BRAND_PIXELS="${QURL_OG_MIN_BRAND_PIXELS:-1000}"

if [ ! -f "$OG_IMAGE" ]; then
  echo "ERROR: missing qURL link social preview PNG: $OG_IMAGE" >&2
  exit 1
fi

if command -v magick >/dev/null 2>&1; then
  MAGICK=(magick)
  IDENTIFY=(magick identify)
elif command -v convert >/dev/null 2>&1 && command -v identify >/dev/null 2>&1; then
  MAGICK=(convert)
  IDENTIFY=(identify)
else
  echo "ERROR: ImageMagick is required to inspect $OG_IMAGE." >&2
  echo "       Install ImageMagick 7 for 'magick' or ImageMagick 6 for 'convert'/'identify'." >&2
  exit 2
fi

dimensions="$("${IDENTIFY[@]}" -format '%w %h' "$OG_IMAGE")"
if [ "$dimensions" != "1200 630" ]; then
  echo "ERROR: qURL link og-image.png dimensions are $dimensions; want 1200 630." >&2
  exit 1
fi

# Count bright or saturated pixels in the same brand area documented by the
# README composite (`layerv-wordmark.svg -resize 244x -geometry +80+74`). Keep
# this PR-time committed-file guard in sync with the deployed-origin smoke
# helper in tests/smoke/16_qurl_link_frontend_test.go. A wordmark-less render
# has zero matching pixels in this crop; the current committed LayerV wordmark
# has several thousand, so the threshold has plenty of room for antialiasing
# and palette-compression differences.
brand_pixels="$(
  "${MAGICK[@]}" "$OG_IMAGE" -crop "$BRAND_REGION" -depth 8 txt:- |
    sed -E -n 's/^[0-9]+,[0-9]+: \(([0-9]+),([0-9]+),([0-9]+).*/\1 \2 \3/p' |
    awk '
      {
        max = $1
        min = $1
        if ($2 > max) max = $2
        if ($3 > max) max = $3
        if ($2 < min) min = $2
        if ($3 < min) min = $3
        if (max > 180 || (max > 80 && max - min > 40)) count++
      }
      END { print count + 0 }
    '
)"

if [ "$brand_pixels" -lt "$MIN_BRAND_PIXELS" ]; then
  echo "ERROR: qURL link og-image.png has only $brand_pixels LayerV-brand pixels in $BRAND_REGION; want at least $MIN_BRAND_PIXELS." >&2
  echo "       Regenerate terraform/modules/qurl-link/frontend/og-image.png from the README recipe." >&2
  exit 1
fi

echo "qURL link og-image.png OK: 1200x630 with $brand_pixels LayerV-brand pixels in $BRAND_REGION."
