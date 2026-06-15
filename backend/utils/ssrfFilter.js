const dns = require('dns').promises;
const { URL } = require('url');
const config = require('./config');

/**
 * Checks if a given IP address belongs to a private, loopback, or link-local range.
 * @param {string} ip - The IPv4 or IPv6 address.
 * @returns {boolean} - True if the IP is private/local, false otherwise.
 */
function isPrivateIp(ip) {
  // IPv4 Loopback (127.0.0.0/8)
  if (/^127\./.test(ip)) return true;

  // IPv4 Private networks:
  // 10.0.0.0/8
  // 172.16.0.0/12
  // 192.168.0.0/16
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;

  // IPv4 Link-local (169.254.0.0/16)
  if (/^169\.254\./.test(ip)) return true;

  // IPv4 Broadcast/Placeholder:
  // 0.0.0.0
  // 255.255.255.255
  if (ip === '0.0.0.0' || ip === '255.255.255.255') return true;

  // IPv6 check:
  // Loopback (::1)
  // Link-local (fe80::)
  // Unique local addresses (fc00::)
  if (ip === '::1' || ip === '::') return true;
  if (/^fe[8-9a-b]/i.test(ip)) return true;
  if (/^fc[0-9a-f]/i.test(ip) || /^fd[0-9a-f]/i.test(ip)) return true;

  return false;
}

/**
 * Validates a target URL against Server-Side Request Forgery (SSRF).
 * It resolves the domain name to its target IP address and checks if it belongs to restricted subnet ranges.
 * @param {string} urlStr - The target URL string.
 * @returns {Promise<{isValid: boolean, error?: string, ip?: string}>}
 */
async function validateUrlForSsrf(urlStr) {
  try {
    const parsedUrl = new URL(urlStr);
    
    // Only permit HTTP and HTTPS protocols
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return { isValid: false, error: 'Only HTTP and HTTPS protocols are allowed' };
    }

    const hostname = parsedUrl.hostname;
    
    // Check if development-only SSRF bypass is enabled
    const allowLocal = config.NODE_ENV === 'development' && config.ALLOW_LOCAL_SCANS === 'true';

    // Check if it is a raw IP address first
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipv4Regex.test(hostname)) {
      if (isPrivateIp(hostname)) {
        if (allowLocal) {
          console.log(`[SSRF DEV MODE] Local scan allowed for: ${urlStr}`);
          return { isValid: true, ip: hostname };
        }
        return { isValid: false, error: 'Access to loopback/private IP ranges is prohibited', ip: hostname };
      }
      return { isValid: true, ip: hostname };
    }

    // Resolve DNS hostname
    const lookupResult = await dns.lookup(hostname);
    const ip = lookupResult.address;

    if (isPrivateIp(ip)) {
      if (allowLocal) {
        console.log(`[SSRF DEV MODE] Local scan allowed for: ${urlStr}`);
        return { isValid: true, ip };
      }
      return { isValid: false, error: `Domain resolves to a restricted IP: ${ip}`, ip };
    }

    return { isValid: true, ip };
  } catch (err) {
    return { isValid: false, error: `URL resolution failed: ${err.message}` };
  }
}

module.exports = {
  isPrivateIp,
  validateUrlForSsrf
};
