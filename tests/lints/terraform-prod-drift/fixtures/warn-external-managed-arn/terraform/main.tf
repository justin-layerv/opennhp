# cr round 3 fence: the IAM-coverage lint emits a `::warning` when an
# attachment binds an out-of-tree managed policy ARN (AWS-managed or
# cross-account customer-managed) to the canonical github_actions role.
# Without this fence, a future PR that swaps an inline grant for an
# AWS-managed attachment would silently delete the action from the
# coverage union.
