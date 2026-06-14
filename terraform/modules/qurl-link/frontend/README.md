# qURL Link Frontend Assets

`og-image.svg` is the editable source for the deployed social preview image.
It is composited with the local `layerv-wordmark.svg` asset so the deployed
preview uses the same LayerV logo as the marketing website. After changing it,
regenerate `og-image.png` from this directory with ImageMagick 7 or newer and
commit both files:

```sh
magick \( -background none og-image.svg \) \( -background none layerv-wordmark.svg -resize 244x \) -geometry +80+74 -composite -strip -colors 256 -define png:compression-level=9 og-image.png
```

ImageMagick 7 provides the `magick` CLI; ImageMagick 6 installations generally
expose `convert` instead. For ImageMagick 6, replace the leading `magick` with
`convert`; the flags are the same for this recipe.

The `-colors 256` setting keeps the current artwork small and is acceptable for
its limited gradients. Drop it if the SVG gains richer gradients or photographic
content.

The SVG is authored at 1200x630; the command preserves source dimensions, so
verify `og-image.png` is still 1200x630 after regeneration.

The SVG must paint its own full-canvas background. `-background none` will not
hide a transparent or undersized background shape.

Run `make lint-qurl-link-og-image` after regenerating the PNG. The lint checks
the committed image dimensions and verifies visible LayerV wordmark pixels in
the documented brand region before the smoke suite sees the deployed asset.
