const EIDOLON_HEADER_PREFIX = "x-eidolon-";
const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

export const EIDOLON_HEADERS = {
  source: "X-Eidolon-Ingress-Identity-Source",
  trustTier: "X-Eidolon-Ingress-Trust-Tier",
  label: "X-Eidolon-Ingress-Identity-Label",
  transportAuth: "X-Eidolon-Ingress-Transport-Auth",
  verificationStrength: "X-Eidolon-Ingress-Verification-Strength",
  actorKind: "X-Eidolon-Ingress-Actor-Kind",
  verifiedCategory: "X-Eidolon-Ingress-Verified-Category",
  vendorScore: "X-Eidolon-Ingress-Vendor-Score",
  vendorScoreKind: "X-Eidolon-Ingress-Vendor-Score-Kind",
  vendorScoreScale: "X-Eidolon-Ingress-Vendor-Score-Scale",
  detectionIds: "X-Eidolon-Ingress-Detection-Ids",
  edgeAction: "X-Eidolon-Ingress-Edge-Action",
};

const VERIFIED_CATEGORY_TO_ACTOR_KIND = new Map([
  ["AI Assistant", "assistant"],
  ["AI Crawler", "crawler"],
  ["Autonomous Agent", "autonomous_agent"],
  ["Agentic Browser", "agentic_browser"],
]);

export function stripClientEidolonHeaders(source) {
  const headers = new Headers(source);

  for (const name of Array.from(headers.keys())) {
    if (name.toLowerCase().startsWith(EIDOLON_HEADER_PREFIX)) {
      headers.delete(name);
    }
  }

  return headers;
}

export function applyCloudflareBotSignals(headers, cf = null) {
  const next = new Headers(headers);
  const bot = cf?.botManagement ?? null;
  const verifiedCategory = normalizeString(cf?.verifiedBotCategory);
  const actorKind = VERIFIED_CATEGORY_TO_ACTOR_KIND.get(verifiedCategory) ?? null;

  let source = null;
  let trustTier = null;
  let verificationStrength = null;
  let edgeAction = null;

  if (bot?.signedAgent === true) {
    source = "signed_agent";
    trustTier = "signed_attested";
    verificationStrength = "cryptographic";
    edgeAction = "allow";
  } else if (bot?.verifiedBot === true) {
    source = "verified_bot";
    trustTier = "edge_verified";
    verificationStrength = "high";
    edgeAction = "allow";
  } else if (bot !== null) {
    edgeAction = "observe";
  }

  setHeader(next, EIDOLON_HEADERS.source, source);
  setHeader(next, EIDOLON_HEADERS.trustTier, trustTier);
  setHeader(next, EIDOLON_HEADERS.verificationStrength, verificationStrength);
  setHeader(next, EIDOLON_HEADERS.verifiedCategory, verifiedCategory);
  setHeader(next, EIDOLON_HEADERS.actorKind, actorKind);

  const score = normalizeFiniteNumber(bot?.score);
  if (score !== null) {
    setHeader(next, EIDOLON_HEADERS.vendorScore, String(score));
    setHeader(
      next,
      EIDOLON_HEADERS.vendorScoreKind,
      "automation_likelihood_inverse",
    );
    setHeader(next, EIDOLON_HEADERS.vendorScoreScale, "1-99");
  }

  const detectionIds = normalizeDetectionIds(bot?.detectionIds);
  if (detectionIds !== null) {
    setHeader(next, EIDOLON_HEADERS.detectionIds, detectionIds);
  }

  setHeader(next, EIDOLON_HEADERS.edgeAction, edgeAction);

  return next;
}

export function buildOriginRequest(request, env) {
  const targetUrl = buildOriginUrl(request, env);
  const transportAuth = buildTransportAuth(env);
  const headers = applyCloudflareBotSignals(
    stripClientEidolonHeaders(request.headers),
    request.cf ?? null,
  );
  headers.set(EIDOLON_HEADERS.transportAuth, transportAuth);
  const hasBody = !BODYLESS_METHODS.has(request.method.toUpperCase());

  return new Request(targetUrl, {
    method: request.method,
    headers,
    body: hasBody ? request.body : undefined,
    duplex: hasBody ? "half" : undefined,
    redirect: request.redirect,
  });
}

function buildOriginUrl(request, env) {
  const origin = normalizeString(env?.EIDOLON_ORIGIN);
  if (origin === null) {
    throw new Error("missing required EIDOLON_ORIGIN binding");
  }

  const upstream = new URL(origin);
  const incoming = new URL(request.url);
  upstream.pathname = incoming.pathname;
  upstream.search = incoming.search;
  return upstream.toString();
}

function buildTransportAuth(env) {
  const transportAuth = normalizeString(env?.EIDOLON_INGRESS_TRANSPORT_AUTH);
  if (transportAuth === null) {
    throw new Error("missing required EIDOLON_INGRESS_TRANSPORT_AUTH binding");
  }

  return transportAuth;
}

function normalizeString(value) {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

function normalizeFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function normalizeDetectionIds(value) {
  if (!Array.isArray(value)) {
    return null;
  }

  const values = value
    .map((entry) => normalizeString(String(entry)))
    .filter((entry) => entry !== null);

  return values.length === 0 ? null : values.join(",");
}

function setHeader(headers, name, value) {
  if (value === null || value === undefined || value === "") {
    headers.delete(name);
    return;
  }

  headers.set(name, value);
}

export default {
  async fetch(request, env) {
    return fetch(buildOriginRequest(request, env));
  },
};
