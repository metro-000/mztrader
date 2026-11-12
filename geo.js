'use strict';
/**
 * geo.js: Country-level IP signal ($0.00).
 * Reads Cloudflare / reverse-proxy country headers if present, or optional MaxMind GeoLite2 DB.
 */
let reader = null;

if (process.env.GEOIP_DB_PATH) {
  try {
    const maxmind = require('maxmind');
    maxmind.open(process.env.GEOIP_DB_PATH)
      .then((r) => { reader = r; })
      .catch((err) => console.error('GeoIP disabled:', err.message));
  } catch {
    // maxmind optional
  }
}

exports.country = (reqOrIp) => {
  try {
    if (reqOrIp && typeof reqOrIp === 'object' && typeof reqOrIp.get === 'function') {
      const cfCountry = reqOrIp.get('CF-IPCountry') || reqOrIp.get('X-Country-Code');
      if (cfCountry && /^[A-Z]{2}$/i.test(cfCountry) && cfCountry.toUpperCase() !== 'XX') {
        return cfCountry.toUpperCase();
      }
      const ip = String(reqOrIp.ip ?? '').replace(/^::ffff:/, '');
      return reader?.get(ip)?.country?.iso_code ?? null;
    }
    const ip = String(reqOrIp ?? '').replace(/^::ffff:/, '');
    return reader?.get(ip)?.country?.iso_code ?? null;
  } catch {
    return null;
  }
};
