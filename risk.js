'use strict';
const db = require('./db');
const geo = require('./geo');

const POINTS = Object.freeze({
  device_registered: 10,
  device_replaced: 20,
  device_removed: 15,
  country_change: 5,
  rapid_country_flip: 20,
  stream_takeover: 5,
  key_mismatch: 25,
});
const STEP_UP_AT = 50;
const REVIEW_AT = 100;

/** Records an event and raises flags. Never bans. */
async function record(userId, type, ip, meta = {}) {
  await db.insertEvent(userId, type, POINTS[type] ?? 0, ip, meta);
  const score = await db.currentRiskScore(userId);
  const requiresStepUp = score >= STEP_UP_AT;
  if (requiresStepUp) {
    await db.raiseRiskFlags(userId, { stepUp: true, review: score >= REVIEW_AT });
  }
  return { score, requiresStepUp };
}

/** Country-level signal only. Returns true if this request pushed the account into step-up. */
async function checkLocation(user, reqOrIp) {
  const country = geo.country(reqOrIp);
  const ip = typeof reqOrIp === 'object' && reqOrIp ? reqOrIp.ip : reqOrIp;
  if (!country || country === user.last_country) return false;

  let flagged = false;
  if (user.last_country) {
    const rapid = user.country_age_min !== null && user.country_age_min < 120;
    ({ requiresStepUp: flagged } = await record(
      user.id,
      rapid ? 'rapid_country_flip' : 'country_change',
      ip,
      { from: user.last_country, to: country }
    ));
  }
  await db.setLastCountry(user.id, country);
  return flagged;
}

async function clearAfterStepUp(userId, ip) {
  await db.insertEvent(userId, 'step_up_passed', 0, ip);
  await db.clearStepUp(userId);
}

module.exports = { record, checkLocation, clearAfterStepUp, POINTS, STEP_UP_AT, REVIEW_AT };
