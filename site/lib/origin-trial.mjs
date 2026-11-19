// Origin-trial tokens for the WebMCP trial. Chrome's parser (trial_token.cc) reads:
//   base64( version:1 | signature:64 | payload_length:4, big endian | payload JSON )
// with version 2 or 3, and a payload carrying origin, feature, expiry (Unix seconds),
// and optionally isSubdomain, isThirdParty and usage. This module decodes that and
// checks the claims a token must satisfy for stoop.build. It cannot verify the
// signature, which needs Chrome's trial key; Chrome does that at load time.
export const REGISTRATION_URL = "https://developer.chrome.com/origintrials";
export const FEATURE = "WebMCP";
const DAY = 24 * 60 * 60 * 1000;
const SIGNATURE_BYTES = 64;
const PAYLOAD_OFFSET = 1 + SIGNATURE_BYTES + 4;

export function decodeToken(token) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(token)) throw new Error("the token is not standard base64");
  const bytes = Buffer.from(token, "base64");
  if (bytes.length < PAYLOAD_OFFSET) throw new Error("the token is too short to hold a payload");
  const version = bytes[0];
  if (version !== 2 && version !== 3) throw new Error(`token version ${version} is not one Chrome reads (2 or 3)`);
  const declared = bytes.readUInt32BE(1 + SIGNATURE_BYTES);
  if (declared !== bytes.length - PAYLOAD_OFFSET) throw new Error("the declared payload length does not match the token");
  let payload;
  try {
    payload = JSON.parse(bytes.subarray(PAYLOAD_OFFSET).toString("utf8"));
  } catch (error) {
    throw new Error(`the payload is not JSON (${error.message})`);
  }
  return { version, payload };
}

const parseUrl = (value) => {
  try {
    return new URL(value);
  } catch {
    return null;
  }
};

// state: "absent" (nothing configured, which is allowed), "ok", or "fail".
export function checkToken(token, { now = Date.now(), site = "https://stoop.build", days = 21 } = {}) {
  if (!token) {
    return {
      state: "absent",
      message: `no origin-trial token is configured, so WebMCP stays off for visitors in Chrome until one is registered at ${REGISTRATION_URL} for ${site} and saved in site/webmcp-origin-trial.txt`,
    };
  }
  let decoded;
  try {
    decoded = decodeToken(token);
  } catch (error) {
    return { state: "fail", message: `origin-trial token: ${error.message}` };
  }
  const { payload } = decoded;
  const problems = [];
  const siteUrl = new URL(site);

  if (payload.feature !== FEATURE) problems.push(`the token is for feature ${JSON.stringify(payload.feature)}, expected ${FEATURE}`);

  const tokenOrigin = parseUrl(String(payload.origin ?? ""));
  if (!tokenOrigin) {
    problems.push(`the token origin ${JSON.stringify(payload.origin)} is not a URL`);
  } else {
    const exact = tokenOrigin.origin === siteUrl.origin;
    const parent = payload.isSubdomain === true && tokenOrigin.protocol === "https:"
      && (siteUrl.hostname === tokenOrigin.hostname || siteUrl.hostname.endsWith(`.${tokenOrigin.hostname}`));
    if (!exact && !parent) problems.push(`the token origin ${payload.origin} does not cover ${siteUrl.origin}`);
  }

  const expiresMs = Number(payload.expiry) * 1000;
  const expires = Number.isFinite(expiresMs) ? new Date(expiresMs).toISOString() : "unknown";
  if (!Number.isFinite(expiresMs)) {
    problems.push("the token has no expiry");
  } else if (expiresMs <= now) {
    problems.push(`the token expired on ${expires}; register a new one at ${REGISTRATION_URL}`);
  } else if (expiresMs - now < days * DAY) {
    problems.push(`the token expires ${expires}, within ${days} days; renew it at ${REGISTRATION_URL} and replace site/webmcp-origin-trial.txt`);
  }

  if (problems.length) return { state: "fail", message: problems.join("; ") };
  const notes = payload.usage === "subset" ? " (the trial is limited to a subset of users)" : "";
  return { state: "ok", message: `origin-trial token for ${payload.origin}, feature ${payload.feature}, expires ${expires}${notes}` };
}
