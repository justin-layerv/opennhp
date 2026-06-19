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

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required to inspect $OG_IMAGE." >&2
  exit 2
fi

export OG_IMAGE BRAND_REGION MIN_BRAND_PIXELS
python3 - <<'PY'
from __future__ import annotations

import os
import re
import struct
import sys
import zlib
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def fail(message: str, status: int = 1) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(status)


def parse_region(value: str) -> tuple[int, int, int, int]:
    match = re.fullmatch(r"(\d+)x(\d+)\+(\d+)\+(\d+)", value)
    if not match:
        # BRAND_REGION is the internal variable; QURL_OG_BRAND_REGION is the
        # public override a caller should set to fix this error.
        fail(f"ERROR: invalid QURL_OG_BRAND_REGION {value!r}; want WIDTHxHEIGHT+X+Y.")
    width, height, x, y = (int(part) for part in match.groups())
    return width, height, x, y


def paeth(left: int, up: int, up_left: int) -> int:
    estimate = left + up - up_left
    left_dist = abs(estimate - left)
    up_dist = abs(estimate - up)
    up_left_dist = abs(estimate - up_left)
    if left_dist <= up_dist and left_dist <= up_left_dist:
        return left
    if up_dist <= up_left_dist:
        return up
    return up_left


def unfilter(filter_type: int, row: bytes, previous: bytes | None, pixel_stride: int) -> bytes:
    output = bytearray(len(row))
    for index, value in enumerate(row):
        left = output[index - pixel_stride] if index >= pixel_stride else 0
        up = previous[index] if previous is not None else 0
        up_left = previous[index - pixel_stride] if previous is not None and index >= pixel_stride else 0

        if filter_type == 0:
            predictor = 0
        elif filter_type == 1:
            predictor = left
        elif filter_type == 2:
            predictor = up
        elif filter_type == 3:
            predictor = (left + up) // 2
        elif filter_type == 4:
            predictor = paeth(left, up, up_left)
        else:
            fail(f"ERROR: unsupported PNG filter type {filter_type}.")

        output[index] = (value + predictor) & 0xFF
    return bytes(output)


def read_png(path: Path) -> tuple[int, int, int, int, list[tuple[int, int, int]], bytes | None, bytes]:
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        fail(f"ERROR: {path} is not a PNG file.")

    offset = len(PNG_SIGNATURE)
    width = height = bit_depth = color_type = interlace = None
    palette: list[tuple[int, int, int]] = []
    transparency = None
    idat_chunks: list[bytes] = []

    while offset + 8 <= len(data):
        chunk_length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        offset += 8
        if offset + chunk_length + 4 > len(data):
            fail(f"ERROR: qURL link og-image.png has a truncated {chunk_type.decode(errors='replace')} chunk.")
        chunk = data[offset : offset + chunk_length]
        offset += chunk_length + 4

        if chunk_type == b"IHDR":
            if len(chunk) != 13:
                fail(f"ERROR: qURL link og-image.png has malformed IHDR length {len(chunk)}; want 13.")
            width, height, bit_depth, color_type, _compression, _filter, interlace = struct.unpack(
                ">IIBBBBB", chunk
            )
        elif chunk_type == b"PLTE":
            if len(chunk) % 3 != 0:
                fail("ERROR: qURL link og-image.png has a malformed PLTE chunk.")
            palette = [
                (chunk[index], chunk[index + 1], chunk[index + 2])
                for index in range(0, len(chunk), 3)
            ]
        elif chunk_type == b"tRNS":
            transparency = chunk
        elif chunk_type == b"IDAT":
            idat_chunks.append(chunk)
        elif chunk_type == b"IEND":
            break

    if width is None or height is None or bit_depth is None or color_type is None or interlace is None:
        fail("ERROR: qURL link og-image.png is missing a valid PNG header.")
    if interlace != 0:
        fail("ERROR: interlaced qURL link og-image.png is not supported by this lint.")
    if bit_depth != 8:
        fail(f"ERROR: qURL link og-image.png has bit depth {bit_depth}; want 8.")
    if transparency is not None:
        # Validate tRNS metadata once, alongside IHDR/PLTE, so pixel_rgb can
        # consume a well-formed transparency chunk without re-checking per pixel.
        if color_type == 0 and len(transparency) < 2:
            fail("ERROR: qURL link og-image.png has a malformed grayscale tRNS chunk.")
        if color_type == 2 and len(transparency) < 6:
            fail("ERROR: qURL link og-image.png has a malformed truecolor tRNS chunk.")

    try:
        inflated = zlib.decompress(b"".join(idat_chunks))
    except zlib.error as exc:
        fail(f"ERROR: qURL link og-image.png has invalid compressed pixel data: {exc}.")

    return width, height, bit_depth, color_type, palette, transparency, inflated


def pixel_rgb(
    row: bytes,
    x: int,
    color_type: int,
    palette: list[tuple[int, int, int]],
    transparency: bytes | None,
) -> tuple[int, int, int] | None:
    if color_type == 0:
        gray = row[x]
        if transparency is not None and gray == int.from_bytes(transparency[:2], "big"):
            return None
        return gray, gray, gray
    if color_type == 2:
        index = x * 3
        rgb = row[index], row[index + 1], row[index + 2]
        if transparency is not None:
            transparent_rgb = (
                int.from_bytes(transparency[0:2], "big"),
                int.from_bytes(transparency[2:4], "big"),
                int.from_bytes(transparency[4:6], "big"),
            )
            if rgb == transparent_rgb:
                return None
        return rgb
    if color_type == 3:
        palette_index = row[x]
        if palette_index >= len(palette):
            fail(f"ERROR: qURL link og-image.png references missing palette index {palette_index}.")
        if transparency is not None and palette_index < len(transparency) and transparency[palette_index] < 128:
            return None
        return palette[palette_index]
    if color_type == 4:
        index = x * 2
        if row[index + 1] < 128:
            return None
        gray = row[index]
        return gray, gray, gray
    if color_type == 6:
        index = x * 4
        if row[index + 3] < 128:
            return None
        return row[index], row[index + 1], row[index + 2]
    fail(f"ERROR: unsupported PNG color type {color_type}.")


def is_brand_pixel(rgb: tuple[int, int, int]) -> bool:
    max_channel = max(rgb)
    min_channel = min(rgb)
    return max_channel > 180 or (max_channel > 80 and max_channel - min_channel > 40)


og_image = Path(os.environ["OG_IMAGE"])
brand_region = os.environ["BRAND_REGION"]
min_brand_pixels = int(os.environ["MIN_BRAND_PIXELS"])

width, height, _bit_depth, color_type, palette, transparency, inflated = read_png(og_image)
if (width, height) != (1200, 630):
    fail(f"ERROR: qURL link og-image.png dimensions are {width} {height}; want 1200 630.")

channels_by_color_type = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
if color_type not in channels_by_color_type:
    fail(f"ERROR: unsupported PNG color type {color_type}.")
pixel_stride = channels_by_color_type[color_type]
row_stride = width * pixel_stride
expected_size = height * (row_stride + 1)
if len(inflated) != expected_size:
    fail(f"ERROR: qURL link og-image.png has malformed pixel data; got {len(inflated)} bytes, want {expected_size}.")

crop_width, crop_height, crop_x, crop_y = parse_region(brand_region)
if crop_x + crop_width > width or crop_y + crop_height > height:
    fail(f"ERROR: qURL link brand region {brand_region} exceeds PNG dimensions {width}x{height}.")

# Count bright or saturated pixels in the same brand area documented by the
# README composite (`layerv-wordmark.svg -resize 244x -geometry +80+74`). Keep
# this PR-time committed-file guard in sync with the deployed-origin smoke
# helper in tests/smoke/16_qurl_link_frontend_test.go. A wordmark-less render
# has zero matching pixels in this crop; the current committed LayerV wordmark
# has several thousand, so the threshold has plenty of room for antialiasing
# and palette-compression differences. If QURL_OG_MIN_BRAND_PIXELS changes,
# calibrate it against this decoder's count, not the old ImageMagick txt output.
#
# PNG filters are row-cumulative, so this pure-stdlib decoder unfilters every
# row through the brand crop even though it only counts crop rows. It can stop
# before rows below the crop, which keeps CI off flaky apt mirrors without doing
# unnecessary per-byte Python work.
brand_pixels = 0
previous_row = None
cursor = 0
crop_bottom = crop_y + crop_height
for y in range(crop_bottom):
    filter_type = inflated[cursor]
    cursor += 1
    row = unfilter(filter_type, inflated[cursor : cursor + row_stride], previous_row, pixel_stride)
    cursor += row_stride
    previous_row = row

    if y < crop_y:
        continue
    for x in range(crop_x, crop_x + crop_width):
        rgb = pixel_rgb(row, x, color_type, palette, transparency)
        if rgb is not None and is_brand_pixel(rgb):
            brand_pixels += 1

if brand_pixels < min_brand_pixels:
    fail(
        f"ERROR: qURL link og-image.png has only {brand_pixels} LayerV-brand pixels in "
        f"{brand_region}; want at least {min_brand_pixels}."
    )

print(f"qURL link og-image.png OK: 1200x630 with {brand_pixels} LayerV-brand pixels in {brand_region}.")
PY
