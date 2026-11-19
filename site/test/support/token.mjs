// Builds origin-trial tokens in Chrome's layout (version, 64-byte signature, big-endian
// payload length, JSON payload). The signature is a stand-in: the site decodes but does not
// verify it, because verification needs Chrome's trial key. Nothing here is a real token.
import { FEATURE } from "../../lib/origin-trial.mjs";

export const DAY = 24 * 60 * 60 * 1000;
export const SECONDS = (ms) => Math.floor(ms / 1000);

export function makeToken(payload, { version = 3, signature = Buffer.alloc(64, 7), declaredLength } = {}) {
  const json = Buffer.from(typeof payload === "string" ? payload : JSON.stringify(payload), "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(declaredLength ?? json.length, 0);
  return Buffer.concat([Buffer.from([version]), signature, length, json]).toString("base64");
}

// A token for stoop.build that expires `days` after `now`.
export const tokenFor = (now, days, overrides = {}) => makeToken({
  origin: "https://stoop.build:443",
  feature: FEATURE,
  expiry: SECONDS(now + days * DAY),
  ...overrides,
});
