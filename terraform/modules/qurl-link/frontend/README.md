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

## Browser NHP Agent Bundle

`nhp-agent.min.js` is generated from the `endpoints/js-agent` package and is
only uploaded by the qURL link Terraform module when `js_agent_enabled` is true.
Sandbox enables it so the qURL relay browser cutover can load the reviewed
agent from the existing same-origin `qurl.link` distribution without introducing
a new public host; prod keeps the upload disabled until the full browser cutover
is proven and deliberately enabled.

After changing the JS agent source or bundle configuration, regenerate and copy
the bundle from the repository root:

```sh
cd endpoints/js-agent
npm ci
npm run bundle
cp dist/nhp-agent.min.js ../../terraform/modules/qurl-link/frontend/nhp-agent.min.js
```

Then run `npm test` from `endpoints/js-agent`. The bundle test rebuilds the
agent in memory and fails if the committed qURL link copy drifts from the
production bundle configuration. That byte-for-byte comparison also covers
dependency and toolchain updates, including esbuild and lockfile bumps, so
regenerate the committed copy in the same change when the bundler version or
any minification-affecting input changes.
