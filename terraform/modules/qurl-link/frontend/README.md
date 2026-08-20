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
Keep the regenerated PNG 8-bit and non-interlaced; the repository lint uses a
small stdlib decoder with those constraints so hosted runners do not need
ImageMagick installed.

The SVG must paint its own full-canvas background. `-background none` will not
hide a transparent or undersized background shape.

Run `make lint-qurl-link-og-image` after regenerating the PNG. The lint checks
the committed image dimensions and verifies visible LayerV wordmark pixels in
the documented brand region before the smoke suite sees the deployed asset.

## Browser NHP Agent Bundle

`index.html` is the verifier source that Terraform renders and pins with
`script-src 'sha256-...'` source expressions. Terraform computes active hashes
from every non-empty executable inline script body in the rendered template,
then carries two pre-#2701 compatibility hashes so cached old HTML keeps working
while the first strict-CSP response-header rollout propagates. Remove those
temporary compatibility hashes via #2717 after the first prod strict-CSP rollout
completes.

Prod does not run a qurl.link deploy-time smoke for this CSP posture; the prod
safety property is structural. Terraform hashes the same rendered `index.html`
script bodies that it uploads as S3 object content, so the emitted CSP and
served bytes share one source value.

`nhp-agent.min.js` is generated from the `endpoints/js-agent` package and is
only uploaded by the qURL link Terraform module when `js_agent_enabled` is true.
Sandbox enables it so the qURL relay browser cutover can load the reviewed
agent from the existing same-origin `qurl.link` distribution without introducing
a new public host; prod keeps the upload disabled until the full browser cutover
is proven and deliberately enabled.

When `js_agent_enabled` is true, Terraform also requires
`relay_connect_src_origin` plus the NHP server public key, renders those values
into `index.html`, and emits a `connect-src` directive for the relay origin
only. Keep the relay value paired with `relay_dns_name`; without it, the browser
blocks the agent's `POST /relay/{serverId}` before the backend sees the request.
The qurl-service qv1 bootstrap bundle also carries its intended relay origin;
the page accepts it only when it matches this Terraform-rendered static origin.

For qURL v2, the page recognizes qv2-looking fragments only to enter verifier
mode and clear the sensitive fragment from browser history. It passes the whole
fragment to `knockQurlV2`; the bundle's focused transport decoder is the single
owner of the `qv2t1` counts/chunks grammar and restores the exact inner qv2
artifact before signature verification. Do not duplicate that decoder in
`index.html`, and do not log caught parser errors because they may describe
credential-derived input.

Terraform reads `nhp-agent.min.js.sri` to render the browser agent script tag's
`integrity="sha384-..."` metadata. Do not hand-edit the hash. Regenerate the
bundle instead; the package test and deploy smoke test recompute SHA-384 from
the bundle bytes and fail if the served artifact and HTML metadata drift. CSP
hash-pins the inline verifier scripts with `sha256` source expressions; when the
agent is mounted, `script-src` adds `'self'` for this same-origin module. The
external bundle's exact-byte pin stays on the script tag's SRI metadata rather
than as a CSP hash-source. Terraform serves the HTML and bundle with `no-cache`
so browsers revalidate the SRI-pinned pair during bundle rotations.

After changing the JS agent source or bundle configuration, regenerate and copy
the bundle from the repository root:

```sh
cd endpoints/js-agent
npm ci
npm run bundle
npm run sync:qurl-link
```

Then run `npm test` from `endpoints/js-agent`. The bundle test rebuilds the
agent in memory and fails if the committed qURL link copy drifts from the
production bundle configuration. That byte-for-byte comparison also covers
dependency and toolchain updates, including esbuild and lockfile bumps, so
regenerate the committed copy in the same change when the bundler version or
any minification-affecting input changes.
