# NHP Relay Topology

## Decision

The stateless relay is an HTTPS-only DMZ component. It serves browser/JS-agent
requests through a public ALB on TCP 443 and has no public UDP listener, public
NLB, or public IP.

Upcoming UDP SDKs use the control plane to discover their assigned cell and
then connect directly to that cell's public NHP server NLB. Each cell server
NLB exposes exactly one UDP listener, 62206. UDP 62207 is never a public NHP
listener.

## Data paths

```text
Browser / JS agent
  -> HTTPS 443 relay ALB
  -> HTTPS 8080 relay instance
  -> private UDP 62206 internal server NLB
  -> assigned NHP server
  -> authenticated RelayReturnMsg to relay UDP 62207

UDP SDK
  -> assignment / cell discovery
  -> assigned-cell public NHP server NLB UDP 62206
  -> assigned NHP server
```

The relay wraps browser payloads in authenticated `NHP_RLY` messages. It sends
to the server's internal-NLB UDP 62206 path and receives authenticated returns
on its private UDP 62207 socket; those relay-specific paths are reachable only
over VPC peering. Direct SDK UDP reaches the separate public server-NLB 62206
path and does not traverse the relay or use the relay identity.

## DMZ boundary

- Public relay ingress: ALB HTTPS 443 only.
- Relay backend ingress: HTTPS 8080 from the ALB SG only.
- Relay server egress: UDP 62206 to exact main-private subnet CIDRs.
- Relay return ingress: UDP 62207 from the canonical server SG only.
- Relay AWS egress: TCP 443 to reviewed interface endpoints and the S3 prefix
  list; no NAT or default route.
- Direct SDK ingress: assigned-cell server NLB UDP 62206 only.

The public server NLB and the relay ALB are separate trust and scaling
boundaries. WAF applies to the relay HTTPS path, not to SDK UDP. SDK UDP relies
on NHP protocol authentication, server admission controls, the exact NLB/SG
shape, and cell observability.

## Cell routing

Browser requests identify the destination server/cell in the HTTPS route, so
the relay can select a configured internal server endpoint. UDP SDKs do not ask
the relay to infer a cell from a raw datagram; assignment gives them the cell's
public server endpoint before they send UDP.

This keeps the relay stateless and avoids a cross-cell native-UDP routing table
or sticky UDP state in the DMZ.

## Deployment contract

Terraform and CI must prove:

1. The relay module owns exactly one public load balancer, the HTTPS ALB, and
   exactly one listener, HTTPS 443.
2. The relay ASG attaches only to the HTTPS target group.
3. The assigned-cell compute module retains its internet-facing server NLB,
   instance UDP 62206 target group, and exactly one public UDP listener on
   62206.
4. The internal server NLB remains available on UDP 62206 for browser-relay
   traffic.
5. Relay UDP 62207 ingress is SG-to-SG from the server and is never public.

The live structural detector inventories the same shape. Functional relay
health checks only the HTTPS relay target group. External UDP smoke targets the
assigned cell's public server NLB; a listener/SG inspection proves UDP 62207 is
not exposed.

## Rollout and rollback

The relay DMZ can be deployed or rolled back independently of the cell server
public UDP surface. A relay rollback changes the browser path only. It must not
remove or repoint the cell server NLB used by UDP SDKs.

Before enabling UDP SDK traffic in an environment, prove cell assignment returns
the correct server NLB endpoint, run a real external NHP UDP 62206 round trip,
and retain evidence that no public UDP listener other than 62206 exists on the
assigned cell edge.

Issue [#3184](https://github.com/layervai/nhp/issues/3184) tracks direct
assigned-cell server-edge availability under spoofed UDP floods and must be
resolved before production rollout of UDP SDK traffic.
