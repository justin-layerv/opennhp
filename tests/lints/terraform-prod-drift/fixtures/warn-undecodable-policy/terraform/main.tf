# cr round 3 fence: the IAM-coverage lint emits a `::warning` when a
# policy attached to the canonical github_actions role uses a form the
# parser can't decode. Without this fence, a future refactor that hides
# actions inside an undecoded form (e.g., `policy = file(...)`) would
# silently drop the actions from the coverage union.
