# Cloudflare Trusted Ingress Adapter

This example is the first concrete adapter for the trusted ingress contract in
[docs/trusted-ingress-signal-contract.md](../../../docs/trusted-ingress-signal-contract.md).

It keeps vendor-specific logic out of the Rust proxy. The Worker sits at the
edge, strips forged `X-Eidolon-*` headers, normalizes Cloudflare bot signals,
and forwards the request to Eidolon.

For zones that do not want a Worker, this directory also includes a request
header Transform Rules payload:

- [eidolon-request-header-transform-rules.json](./eidolon-request-header-transform-rules.json)

## What It Maps

Cloudflare fields used:

- `request.cf.botManagement.score`
- `request.cf.botManagement.verifiedBot`
- `request.cf.botManagement.signedAgent`
- `request.cf.botManagement.detectionIds`
- `request.cf.verifiedBotCategory`

Normalized outbound headers:

- `X-Eidolon-Ingress-Identity-Source`
- `X-Eidolon-Ingress-Trust-Tier`
- `X-Eidolon-Ingress-Transport-Auth`
- `X-Eidolon-Ingress-Verification-Strength`
- `X-Eidolon-Ingress-Actor-Kind`
- `X-Eidolon-Ingress-Verified-Category`
- `X-Eidolon-Ingress-Vendor-Score`
- `X-Eidolon-Ingress-Vendor-Score-Kind`
- `X-Eidolon-Ingress-Vendor-Score-Scale`
- `X-Eidolon-Ingress-Detection-Ids`
- `X-Eidolon-Ingress-Edge-Action`

The Worker intentionally does not invent trust from a score alone. Risk-only
traffic gets raw score and detection metadata, but no `source` or `trust_tier`.

## Behavior

- signed agent -> `source=signed_agent`, `trust_tier=signed_attested`
- verified bot -> `source=verified_bot`, `trust_tier=edge_verified`
- verified bot category -> mapped to Eidolon `actor_kind` when recognized
- bot score/detection IDs -> always preserved when Bot Management provides them
- client-supplied `X-Eidolon-*` headers -> always removed before forwarding
- trusted identity headers -> only honored when the proxy is configured with
  the same transport-auth secret

## Usage

Bind:

- the protected Eidolon origin as `EIDOLON_ORIGIN`
- an explicit comma-separated allowlist of permitted origin hosts as
  `EIDOLON_ALLOWED_ORIGIN_HOSTS`
- the proxy's shared transport secret as `EIDOLON_INGRESS_TRANSPORT_AUTH`

Then deploy the Worker in front of it.

The Worker forwards method, path, query, headers, and body to that origin after
header normalization and transport-auth attachment. The allowlist is enforced
before forwarding so the Worker only proxies to approved upstream hosts even if
the binding is misconfigured.

## Transform Rules Variant

The Transform Rules variant is for operators who want Cloudflare-native header
normalization without running a Worker.

What it does:

- removes all currently reserved `X-Eidolon-Ingress-*` headers by explicit name
- attaches `X-Eidolon-Ingress-Transport-Auth: replace-me-shared-secret`
- forwards Bot Management score, score semantics, detection IDs, and verified
  bot category
- maps:
  - `cf.bot_management.verified_bot -> verified_bot / edge_verified / high`
  - `cf.bot_management.signed_agent -> signed_agent / signed_attested / cryptographic`
- maps supported verified bot categories into Eidolon `actor_kind`
- sets `X-Eidolon-Ingress-Edge-Action` to `observe` for risk-only traffic and
  `allow` for verified or signed traffic

What it cannot do:

- remove an arbitrary future `X-Eidolon-*` prefix wildcard; Transform Rules can
  only target named headers
- populate `identity_label` or `attestation_ref`, because Cloudflare does not
  expose a matching request-header Transform Rules field for those values
- express richer conditional logic as cleanly as the Worker path

Use the Worker when you need prefix-wide scrubbing or richer per-request logic.

The payload uses `http.host eq "replace-me.example.com"` as a placeholder scope.
Replace that expression and `replace-me-shared-secret` before applying it via
dashboard, API, or Terraform. The same secret must be configured in the proxy
via `--ingress-transport-auth-secret-file`.

Cloudflare notes that request header modifications are only visible at the
origin side, not in browser devtools or Logpush request headers. Validate them
at the origin or with Cloudflare Trace.

## Local Test

Run the local mapping test with:

```sh
examples/edge/test-cloudflare-worker.sh
```

Run the Transform Rules payload test with:

```sh
examples/edge/test-cloudflare-transform-rules.sh
```
