# Superseded: take the NHP server private (#2628)

This rollout must not be executed. The design was superseded when direct UDP
SDK routing became a product requirement: an SDK connects to the public NHP NLB
of its assigned cell, using UDP 62206.

The supported topology therefore keeps each cell's server NLB internet-facing
with exactly one inbound NHP listener, UDP 62206. The stateless relay is an
HTTPS-only DMZ for browser/qURL traffic and owns no public UDP listener or NLB.
It reaches the cell over the internal NLB on UDP 62206; the server returns an
authenticated relay response over the private UDP 62207 path.

The `take_server_private` Terraform input and the obsolete
`/{env}/nhp/server/take-server-private` SSM cutover marker have both been
removed. Blue/green switching requires the public UDP listener directly.

See `docs/design/NHP_RELAY_TOPOLOGY.md` for the current authority.
