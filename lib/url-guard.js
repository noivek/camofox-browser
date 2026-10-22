// URL guard: server-side defense against the browser being pointed at
// infrastructure. The orchestrator has its own client-side guard
// (browse_agent.guard_url); this module is the browser's own last line — it
// holds even when the caller is a compromised or misbehaving client.
//
// Two layers:
//   assertNavigableUrl(url)  — async, full check incl. DNS resolution of the
//                              hostname (ALL resolved addresses must be
//                              public). Used at explicit navigation entry
//                              points (POST /tabs, navigate, open_url).
//   isRequestAllowed(url)    — sync, literal checks only (scheme, credentials,
//                              hostname literals). Used as a Playwright
//                              request interceptor so redirects, popups and
//                              subresources are covered without a DNS lookup
//                              on every request.
//
// Both reject: non-http(s), credentials-in-URL, localhost/.local/.internal/
// bare single-label hosts, and any non-globally-routable IP (loopback, RFC1918,
// link-local, CGNAT, multicast, 0.0.0.0, IPv6 equivalents incl. IPv4-mapped).
// CONFIG.urlGuardAllowHosts can exempt specific hosts (exact match, no wildcards).

import dns from 'node:dns/promises';

const CACHE_TTL_MS = 60_000;
const dnsCache = new Map(); // hostname -> { verdict: boolean, at: number }

function isPublicIpv4(ip) {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  if (o[0] === 0 || o[0] === 10 || o[0] === 127) return false; // this-network, private, loopback
  if (o[0] === 169 && o[1] === 254) return false; // link-local
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false; // private
  if (o[0] === 192 && o[1] === 168) return false; // private
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return false; // CGNAT
  if (o[0] >= 224) return false; // multicast + reserved
  return true;
}

function isPublicIpv6(ip) {
  const bare = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (bare === '::' || bare === '::1') return false; // unspecified, loopback
  if (/^fe[89ab]/.test(bare)) return false; // link-local
  if (/^f[cd]/.test(bare)) return false; // unique-local
  if (bare.startsWith('ff')) return false; // multicast
  if (bare.startsWith('::ffff:')) return isPublicIpv4(bare.slice(7)); // IPv4-mapped
  const v4Bytes = (hex) => {
    const pairs = hex.replace(/:/g, '').slice(0, 8).match(/.{1,2}/g);
    return pairs ? pairs.map((h) => parseInt(h, 16)).join('.') : '';
  };
  if (bare.startsWith('::ffff:0:')) return isPublicIpv4(bare.slice(9)); // IPv4-mapped (hex form)
  if (bare.startsWith('64:ff9b:')) return isPublicIpv4(v4Bytes(bare.slice(8))); // NAT64
  if (bare.startsWith('2002:')) return isPublicIpv4(v4Bytes(bare.slice(5))); // 6to4
  return true;
}

function hostIsBlockedLiteral(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return 'empty host';
  if (host === 'localhost') return 'localhost';
  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.home.arpa')) return 'internal TLD';
  if (!host.includes('.') && !host.includes(':')) return 'single-label host';
  if (host.includes(':') || host.startsWith('[')) {
    return isPublicIpv6(host) ? null : 'non-public IPv6';
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return isPublicIpv4(host) ? null : 'non-public IPv4';
  }
  return null;
}

function checkUrlParts(url, allowHosts) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return `invalid URL: ${url}`;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return `blocked URL scheme: ${parsed.protocol} (only http/https allowed)`;
  }
  if (parsed.username || parsed.password) return 'credentials in URL';
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (allowHosts && allowHosts.includes(host)) return null;
  const literal = hostIsBlockedLiteral(parsed.hostname);
  if (literal) return `blocked target: ${parsed.hostname} (${literal})`;
  return null;
}

/// Sync, literal-only check for the request interceptor.
export function isRequestAllowed(url, { allowHosts = [] } = {}) {
  return checkUrlParts(url, allowHosts) === null;
}

/// Async, full check: literal checks + DNS resolution (every resolved address
/// must be public — defeats DNS rebinding to private space at entry time).
export async function assertNavigableUrl(url, { allowHosts = [] } = {}) {
  const base = checkUrlParts(url, allowHosts);
  if (base) return base;
  const host = new URL(url).hostname.toLowerCase().replace(/\.$/, '');
  if (allowHosts.includes(host)) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) return null; // literal already checked

  const cached = dnsCache.get(host);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) {
    return cached.verdict ? null : 'hostname resolves to a non-public address';
  }

  let addresses = [];
  try {
    addresses = await dns.lookup(host, { all: true, verbatim: true });
  } catch {
    dnsCache.set(host, { verdict: false, at: Date.now() });
    return 'hostname does not resolve';
  }
  const verdict = addresses.length > 0 && addresses.every((a) => (
    a.family === 4 ? isPublicIpv4(a.address) : isPublicIpv6(a.address)
  ));
  dnsCache.set(host, { verdict, at: Date.now() });
  return verdict ? null : 'hostname resolves to a non-public address';
}
