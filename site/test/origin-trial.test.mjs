// Origin-trial token checks: each rule has a positive case and a negative case, and each
// negative case must fail. Tokens come from support/token.mjs, in Chrome's byte layout.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkToken, decodeToken, FEATURE, REGISTRATION_URL } from "../lib/origin-trial.mjs";
import { makeToken, tokenFor, DAY, SECONDS } from "./support/token.mjs";

const NOW = Date.UTC(2026, 10, 18);
const good = (overrides = {}) => ({ origin: "https://stoop.build:443", feature: FEATURE, expiry: SECONDS(NOW + 200 * DAY), ...overrides });

test("a token for stoop.build with a distant expiry is accepted and reported", () => {
  const result = checkToken(makeToken(good()), { now: NOW });
  assert.equal(result.state, "ok");
  assert.match(result.message, /feature WebMCP/);
});

test("the decoder reads Chrome's layout: version, signature, big-endian length, JSON payload", () => {
  const decoded = decodeToken(makeToken(good(), { version: 2 }));
  assert.equal(decoded.version, 2);
  assert.equal(decoded.payload.feature, "WebMCP");
  assert.equal(checkToken(tokenFor(NOW, 200), { now: NOW }).state, "ok");
});

test("no configured token is absent, which passes and says so, and points at the registration", () => {
  for (const token of [null, undefined, ""]) {
    const result = checkToken(token, { now: NOW });
    assert.equal(result.state, "absent");
    assert.match(result.message, /no origin-trial token is configured/);
    assert.ok(result.message.includes(REGISTRATION_URL));
  }
});

test("malformed tokens fail: not base64, too short, a version Chrome does not read, a wrong length, a payload that is not JSON", () => {
  assert.equal(checkToken("not base64!", { now: NOW }).state, "fail");
  assert.equal(checkToken(Buffer.from("short").toString("base64"), { now: NOW }).state, "fail");
  assert.match(checkToken(makeToken(good(), { version: 9 }), { now: NOW }).message, /version 9/);
  assert.match(checkToken(makeToken(good(), { declaredLength: 3 }), { now: NOW }).message, /declared payload length/);
  assert.match(checkToken(makeToken("{not json"), { now: NOW }).message, /not JSON/);
});

test("a token for another origin fails, while the exact origin passes with or without its port", () => {
  const wrong = checkToken(makeToken(good({ origin: "https://example.com:443" })), { now: NOW });
  assert.equal(wrong.state, "fail");
  assert.match(wrong.message, /does not cover https:\/\/stoop\.build/);
  assert.equal(checkToken(makeToken(good({ origin: "http://stoop.build:80" })), { now: NOW }).state, "fail");
  assert.equal(checkToken(makeToken(good({ origin: "https://stoop.build" })), { now: NOW }).state, "ok");
});

test("a parent domain covers stoop.build only when the token says it applies to subdomains", () => {
  const sub = (origin, isSubdomain) => checkToken(makeToken(good({ origin, isSubdomain })), { now: NOW });
  assert.equal(sub("https://build:443", true).state, "ok");
  assert.equal(sub("https://build:443", false).state, "fail");
  assert.equal(sub("https://other.org:443", true).state, "fail");
});

test("a token for the wrong feature fails", () => {
  const result = checkToken(makeToken(good({ feature: "ModelContext" })), { now: NOW });
  assert.equal(result.state, "fail");
  assert.match(result.message, /feature "ModelContext", expected WebMCP/);
});

test("a token that expires within 21 days fails and names the registration URL", () => {
  const result = checkToken(makeToken(good({ expiry: SECONDS(NOW + 20 * DAY) })), { now: NOW });
  assert.equal(result.state, "fail");
  assert.match(result.message, /within 21 days/);
  assert.ok(result.message.includes(REGISTRATION_URL));
});

test("the 21-day window has an edge: a token expiring just beyond it passes, and just inside it fails", () => {
  assert.equal(checkToken(makeToken(good({ expiry: SECONDS(NOW + 21 * DAY + 60_000) })), { now: NOW }).state, "ok");
  assert.equal(checkToken(makeToken(good({ expiry: SECONDS(NOW + 21 * DAY - 60_000) })), { now: NOW }).state, "fail");
});

test("an expired token fails and names the registration URL", () => {
  const result = checkToken(makeToken(good({ expiry: SECONDS(NOW - DAY) })), { now: NOW });
  assert.equal(result.state, "fail");
  assert.match(result.message, /expired/);
  assert.ok(result.message.includes(REGISTRATION_URL));
});

test("a token without an expiry fails", () => {
  const { expiry, ...rest } = good();
  assert.match(checkToken(makeToken(rest), { now: NOW }).message, /no expiry/);
});

test("a subset-usage token passes with a note that the trial reaches a subset of users", () => {
  const result = checkToken(makeToken(good({ usage: "subset" })), { now: NOW });
  assert.equal(result.state, "ok");
  assert.match(result.message, /subset of users/);
});
