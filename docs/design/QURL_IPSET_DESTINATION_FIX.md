# QURL ipset Fix

## Problem

QURL fails when adding firewall rule:

```
ipset add defaultset 75.40.184.115,443,ac.nhp.layerv.xyz
error: ac.nhp.layerv.xyz resolves to multiple addresses
```

**Why it fails:**
1. ipset needs IP address, not hostname
2. NLB hostname has 3 IPs (one per AZ)
3. NLB IPs can change over time

## How Traffic Flows

```
User ──► NLB ──► AC ──► Traefik ──► Target
         │       │
         │       └── AC sees: dest = 10.0.1.50 (its private IP)
         │
         └── Public IP: ac.nhp.layerv.xyz
```

**Key point:** After NLB forwards traffic, the AC sees its own private IP as destination, not the NLB IP.

## Solution

Use `0.0.0.0` to mean "this AC". The AC replaces it with its own IP.

### QURL API returns:
```json
{ "addr": { "ip": "0.0.0.0", "port": 443 } }
```

### AC does:
```go
if dstAddr.Ip == "0.0.0.0" {
    dstAddr.Ip = a.getLocalIP()  // e.g., "10.0.1.50"
}
```

## Why This Way

| Question | Answer |
|----------|--------|
| Why not remove destination from ipset? | Less secure. User could access any destination. |
| Why not store real IP? | IPs change. QURLs can last days/weeks. |
| Why `0.0.0.0`? | Clear signal. AC knows to use its own IP. |
| What about IPv6 (`::`)? | QURL currently uses IPv4 only. If IPv6 support is added, `::` should also be treated as a sentinel. |

## Changes Needed

| Component | Change |
|-----------|--------|
| QURL API (Console) | Return `"ip": "0.0.0.0"` for QURL resources |
| AC (`msghandler.go`) | Replace `0.0.0.0` with local IP before ipset add |
| Tests | Add test for this case |
