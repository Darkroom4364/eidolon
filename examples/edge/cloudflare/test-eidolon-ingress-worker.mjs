import test from "node:test";
import assert from "node:assert/strict";

import {
  applyCloudflareBotSignals,
  buildOriginRequest,
  EIDOLON_HEADERS,
  stripClientEidolonHeaders,
} from "./eidolon-ingress-worker.mjs";

test("stripClientEidolonHeaders removes forged ingress headers but keeps unrelated headers", () => {
  const headers = stripClientEidolonHeaders({
    "X-Eidolon-Ingress-Identity-Source": "signed_agent",
    "X-EIDOLON-INGRESS-TRUST-TIER": "signed_attested",
    "X-Custom-Trace": "keep-me",
  });

  assert.equal(headers.get(EIDOLON_HEADERS.source), null);
  assert.equal(headers.get(EIDOLON_HEADERS.trustTier), null);
  assert.equal(headers.get("X-Custom-Trace"), "keep-me");
});

test("applyCloudflareBotSignals maps signed agents to strong trusted ingress headers", () => {
  const headers = applyCloudflareBotSignals(new Headers(), {
    botManagement: {
      score: 92,
      signedAgent: true,
      verifiedBot: false,
      detectionIds: ["3355446", "553648158"],
    },
  });

  assert.equal(headers.get(EIDOLON_HEADERS.source), "signed_agent");
  assert.equal(headers.get(EIDOLON_HEADERS.trustTier), "signed_attested");
  assert.equal(headers.get(EIDOLON_HEADERS.verificationStrength), "cryptographic");
  assert.equal(headers.get(EIDOLON_HEADERS.vendorScore), "92");
  assert.equal(headers.get(EIDOLON_HEADERS.vendorScoreKind), "automation_likelihood_inverse");
  assert.equal(headers.get(EIDOLON_HEADERS.vendorScoreScale), "1-99");
  assert.equal(headers.get(EIDOLON_HEADERS.detectionIds), "3355446,553648158");
  assert.equal(headers.get(EIDOLON_HEADERS.edgeAction), "allow");
});

test("applyCloudflareBotSignals maps verified bot category into actor kind", () => {
  const headers = applyCloudflareBotSignals(new Headers(), {
    verifiedBotCategory: "AI Assistant",
    botManagement: {
      score: 74,
      signedAgent: false,
      verifiedBot: true,
      detectionIds: [],
    },
  });

  assert.equal(headers.get(EIDOLON_HEADERS.source), "verified_bot");
  assert.equal(headers.get(EIDOLON_HEADERS.trustTier), "edge_verified");
  assert.equal(headers.get(EIDOLON_HEADERS.verificationStrength), "high");
  assert.equal(headers.get(EIDOLON_HEADERS.verifiedCategory), "AI Assistant");
  assert.equal(headers.get(EIDOLON_HEADERS.actorKind), "assistant");
  assert.equal(headers.get(EIDOLON_HEADERS.edgeAction), "allow");
  assert.equal(headers.get(EIDOLON_HEADERS.detectionIds), null);
});

test("applyCloudflareBotSignals preserves risk-only signals without inventing trust", () => {
  const headers = applyCloudflareBotSignals(new Headers(), {
    botManagement: {
      score: 17,
      signedAgent: false,
      verifiedBot: false,
      detectionIds: ["991"],
    },
  });

  assert.equal(headers.get(EIDOLON_HEADERS.source), null);
  assert.equal(headers.get(EIDOLON_HEADERS.trustTier), null);
  assert.equal(headers.get(EIDOLON_HEADERS.vendorScore), "17");
  assert.equal(headers.get(EIDOLON_HEADERS.detectionIds), "991");
  assert.equal(headers.get(EIDOLON_HEADERS.edgeAction), "observe");
});

test("buildOriginRequest rewrites the origin and applies sanitized trusted ingress headers", () => {
  const request = new Request(
    "https://edge.example.com/openapi.json?view=full",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Eidolon-Ingress-Identity-Source": "forged",
        "X-Request-Id": "req-123",
      },
      body: JSON.stringify({ hello: "world" }),
    },
  );
  Object.defineProperty(request, "cf", {
    value: {
      verifiedBotCategory: "Agentic Browser",
      botManagement: {
        score: 81,
        signedAgent: false,
        verifiedBot: true,
        detectionIds: ["7"],
      },
    },
  });

  const forwarded = buildOriginRequest(request, {
    EIDOLON_ORIGIN: "https://eidolon.internal:9102/base-path",
    EIDOLON_INGRESS_TRANSPORT_AUTH: "edge-secret",
  });

  assert.equal(forwarded.url, "https://eidolon.internal:9102/openapi.json?view=full");
  assert.equal(forwarded.headers.get("X-Request-Id"), "req-123");
  assert.equal(forwarded.headers.get(EIDOLON_HEADERS.source), "verified_bot");
  assert.equal(forwarded.headers.get(EIDOLON_HEADERS.transportAuth), "edge-secret");
  assert.equal(forwarded.headers.get(EIDOLON_HEADERS.actorKind), "agentic_browser");
  assert.equal(forwarded.headers.get(EIDOLON_HEADERS.vendorScore), "81");
  assert.equal(forwarded.headers.get(EIDOLON_HEADERS.edgeAction), "allow");
});

test("buildOriginRequest requires an explicit origin binding", () => {
  const request = new Request("https://edge.example.com/docs");

  assert.throws(
    () => buildOriginRequest(request, { EIDOLON_INGRESS_TRANSPORT_AUTH: "edge-secret" }),
    /missing required EIDOLON_ORIGIN binding/,
  );
});

test("buildOriginRequest requires an explicit transport auth binding", () => {
  const request = new Request("https://edge.example.com/docs");

  assert.throws(
    () => buildOriginRequest(request, { EIDOLON_ORIGIN: "https://eidolon.internal:9102" }),
    /missing required EIDOLON_INGRESS_TRANSPORT_AUTH binding/,
  );
});
