import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const payload = JSON.parse(
  await readFile(
    new URL("./eidolon-request-header-transform-rules.json", import.meta.url),
    "utf8",
  ),
);

const RESERVED_HEADERS = [
  "X-Eidolon-Ingress-Identity-Source",
  "X-Eidolon-Ingress-Trust-Tier",
  "X-Eidolon-Ingress-Identity-Label",
  "X-Eidolon-Ingress-Identity-Expires-At",
  "X-Eidolon-Ingress-Transport-Auth",
  "X-Eidolon-Ingress-Verification-Strength",
  "X-Eidolon-Ingress-Actor-Kind",
  "X-Eidolon-Ingress-Verified-Category",
  "X-Eidolon-Ingress-Attestation-Ref",
  "X-Eidolon-Ingress-Vendor-Score",
  "X-Eidolon-Ingress-Vendor-Score-Kind",
  "X-Eidolon-Ingress-Vendor-Score-Scale",
  "X-Eidolon-Ingress-Detection-Ids",
  "X-Eidolon-Ingress-Edge-Action",
];

function rule(description) {
  const match = payload.rules.find((entry) => entry.description === description);
  assert.ok(match, `missing rule: ${description}`);
  return match;
}

test("payload targets Cloudflare request header transform phase", () => {
  assert.equal(payload.kind, "zone");
  assert.equal(payload.phase, "http_request_late_transform");
  assert.ok(Array.isArray(payload.rules));
  assert.ok(payload.rules.length >= 6);
});

test("sanitizer rule removes every currently reserved Eidolon ingress header", () => {
  const sanitizer = rule(
    "Remove client-supplied Eidolon ingress headers that Cloudflare can target by explicit name",
  );
  const headers = sanitizer.action_parameters.headers;

  assert.equal(sanitizer.action, "rewrite");
  for (const headerName of RESERVED_HEADERS) {
    assert.deepEqual(headers[headerName], { operation: "remove" });
  }
});

test("score forwarding rule preserves raw Cloudflare risk metadata", () => {
  const scoreRule = rule(
    "Forward Cloudflare Bot Management score and raw detection IDs without inventing trust",
  );
  const headers = scoreRule.action_parameters.headers;

  assert.equal(
    headers["X-Eidolon-Ingress-Vendor-Score"].expression,
    "to_string(cf.bot_management.score)",
  );
  assert.equal(
    headers["X-Eidolon-Ingress-Vendor-Score-Kind"].value,
    "automation_likelihood_inverse",
  );
  assert.equal(headers["X-Eidolon-Ingress-Vendor-Score-Scale"].value, "1-99");
  assert.equal(
    headers["X-Eidolon-Ingress-Detection-Ids"].expression,
    "join(cf.bot_management.detection_ids, \",\")",
  );
});

test("payload attaches the shared transport auth header expected by Eidolon", () => {
  const authRule = rule(
    "Attach the shared transport auth header expected by Eidolon",
  );

  assert.equal(
    authRule.action_parameters.headers["X-Eidolon-Ingress-Transport-Auth"].value,
    "replace-me-shared-secret",
  );
});

test("verified and signed identities are normalized with the expected trust tiers", () => {
  const verifiedRule = rule(
    "Normalize verified bots into Eidolon trusted ingress headers",
  );
  const signedRule = rule(
    "Normalize signed agents into Eidolon trusted ingress headers",
  );

  assert.equal(
    verifiedRule.action_parameters.headers["X-Eidolon-Ingress-Identity-Source"].value,
    "verified_bot",
  );
  assert.equal(
    verifiedRule.action_parameters.headers["X-Eidolon-Ingress-Trust-Tier"].value,
    "edge_verified",
  );
  assert.equal(
    verifiedRule.action_parameters.headers["X-Eidolon-Ingress-Edge-Action"].value,
    "allow",
  );

  assert.equal(
    signedRule.action_parameters.headers["X-Eidolon-Ingress-Identity-Source"].value,
    "signed_agent",
  );
  assert.equal(
    signedRule.action_parameters.headers["X-Eidolon-Ingress-Trust-Tier"].value,
    "signed_attested",
  );
  assert.equal(
    signedRule.action_parameters.headers["X-Eidolon-Ingress-Verification-Strength"].value,
    "cryptographic",
  );
});

test("verified bot categories cover the actor-kind mapping used by the Worker adapter", () => {
  const actorKindRules = new Map(
    payload.rules
      .filter((entry) => entry.description.includes("verified bot category to Eidolon actor kind"))
      .map((entry) => [
        entry.action_parameters.headers["X-Eidolon-Ingress-Actor-Kind"].value,
        entry.expression,
      ]),
  );

  assert.equal(actorKindRules.get("assistant"), "http.host eq \"replace-me.example.com\" and cf.verified_bot_category eq \"AI Assistant\"");
  assert.equal(actorKindRules.get("crawler"), "http.host eq \"replace-me.example.com\" and cf.verified_bot_category eq \"AI Crawler\"");
  assert.equal(actorKindRules.get("autonomous_agent"), "http.host eq \"replace-me.example.com\" and cf.verified_bot_category eq \"Autonomous Agent\"");
  assert.equal(actorKindRules.get("agentic_browser"), "http.host eq \"replace-me.example.com\" and cf.verified_bot_category eq \"Agentic Browser\"");
});

test("risk-only traffic remains observe-only when Cloudflare has no strong identity", () => {
  const observeRule = rule(
    "Mark untrusted Bot Management traffic as observe-only at the edge",
  );

  assert.match(observeRule.expression, /not cf\.bot_management\.verified_bot/);
  assert.match(observeRule.expression, /not cf\.bot_management\.signed_agent/);
  assert.equal(
    observeRule.action_parameters.headers["X-Eidolon-Ingress-Edge-Action"].value,
    "observe",
  );
});
