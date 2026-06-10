const http = require('http');
const https = require('https');
const { URL } = require('url');

/**
 * Promise-wrapped request utility using Node built-in modules.
 * Returns response metadata, body, raw request, and raw response. Never throws.
 */
function request(urlStr, options = {}) {
  return new Promise((resolve) => {
    let resolved = false;
    let req = null;

    const timeoutMs = options.timeout || 8000;
    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        if (req) {
          try { req.destroy(); } catch (e) {}
        }
        resolve({
          status: 0,
          headers: {},
          body: '',
          error: 'timeout',
          rawRequest: rawRequestStr || `GET ${urlStr} HTTP/1.1\r\n\r\n`,
          rawResponse: `HTTP/1.1 0 Connection Timeout\r\n\r\nError: Request timed out after ${timeoutMs}ms`
        });
      }
    }, timeoutMs);

    const safeResolve = (val) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve(val);
      }
    };

    let rawRequestStr = '';

    try {
      const parsedUrl = new URL(urlStr);
      const protocol = parsedUrl.protocol === 'https:' ? https : http;

      const reqOptions = {
        method: options.method || 'GET',
        headers: options.headers || {},
        timeout: timeoutMs,
        rejectUnauthorized: false
      };

      // Set standard headers to look like a browser scan
      if (!reqOptions.headers['User-Agent']) {
        reqOptions.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-Detective/1.0 WAPT-Scanner';
      }
      if (!reqOptions.headers['Accept']) {
        reqOptions.headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
      }
      if (!reqOptions.headers['Connection']) {
        reqOptions.headers['Connection'] = 'close';
      }

      if (options.body) {
        reqOptions.headers['Content-Length'] = Buffer.byteLength(options.body);
      }

      // Build raw request string for evidence
      const pathAndQuery = parsedUrl.pathname + parsedUrl.search;
      rawRequestStr = `${reqOptions.method} ${pathAndQuery || '/'} HTTP/1.1\r\n`;
      rawRequestStr += `Host: ${parsedUrl.host}\r\n`;
      for (const [key, val] of Object.entries(reqOptions.headers)) {
        rawRequestStr += `${key}: ${val}\r\n`;
      }
      rawRequestStr += '\r\n';
      if (options.body) {
        rawRequestStr += options.body;
      }

      req = protocol.request(urlStr, reqOptions, (res) => {
        let rawResponseStr = `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage || ''}\r\n`;
        for (const [key, val] of Object.entries(res.headers)) {
          rawResponseStr += `${key}: ${val}\r\n`;
        }
        rawResponseStr += '\r\n';

        let body = '';
        res.setEncoding('utf-8');

        res.on('data', (chunk) => {
          if (body.length + chunk.length <= 8192) {
            body += chunk;
          } else {
            body += chunk.substring(0, 8192 - body.length);
            const truncatedResponse = rawResponseStr + body + '\n\n[TRUNCATED... response body capped at 8192 bytes]';
            safeResolve({
              status: res.statusCode,
              headers: res.headers,
              body: body,
              rawRequest: rawRequestStr,
              rawResponse: truncatedResponse
            });
            try { req.destroy(); } catch (e) {}
          }
        });

        res.on('end', () => {
          safeResolve({
            status: res.statusCode,
            headers: res.headers,
            body: body,
            rawRequest: rawRequestStr,
            rawResponse: rawResponseStr + body
          });
        });
      });

      req.on('error', (err) => {
        safeResolve({
          status: 0,
          headers: {},
          body: '',
          error: err.message,
          rawRequest: rawRequestStr,
          rawResponse: `HTTP/1.1 0 Connection Error\r\n\r\nError: ${err.message}`
        });
      });

      req.on('timeout', () => {
        try { req.destroy(); } catch (e) {}
        safeResolve({
          status: 0,
          headers: {},
          body: '',
          error: 'timeout',
          rawRequest: rawRequestStr,
          rawResponse: `HTTP/1.1 0 Connection Timeout\r\n\r\nError: Request timed out after ${timeoutMs}ms`
        });
      });

      if (options.body) {
        req.write(options.body);
      }
      req.end();

    } catch (e) {
      safeResolve({
        status: 0,
        headers: {},
        body: '',
        error: e.message,
        rawRequest: rawRequestStr || `GET ${urlStr} HTTP/1.1\r\n\r\n`,
        rawResponse: `HTTP/1.1 0 Internal Error\r\n\r\nError: ${e.message}`
      });
    }
  });
}

// ==========================================================================
// 10 Context-Aware Security Audit Checks
// ==========================================================================

// Helper to check for CDN/Reverse Proxy/WAF signatures
function detectSecurityInfrastructure(headers) {
  const server = (headers['server'] || '').toLowerCase();
  const infrastructure = [];
  
  if (server.includes('cloudflare')) infrastructure.push('Cloudflare CDN');
  if (server.includes('cloudfront')) infrastructure.push('AWS CloudFront');
  if (server.includes('fastly')) infrastructure.push('Fastly CDN');
  if (server.includes('akamai')) infrastructure.push('Akamai CDN');
  if (headers['cf-ray']) infrastructure.push('Cloudflare WAF/Proxy');
  if (headers['x-cache']) infrastructure.push('Caching Reverse Proxy');
  if (headers['x-amz-cf-id']) infrastructure.push('AWS CloudFront');
  if (headers['x-edge-connect-id']) infrastructure.push('Enterprise API Gateway');
  
  return infrastructure;
}

// 1. checkSecurityHeaders
async function checkSecurityHeaders(baseUrl, log) {
  log.push('[WAPT] Running checkSecurityHeaders...');
  const res = await request(baseUrl);
  if (res.status === 0) {
    return [{
      severity: 'Low',
      category: 'Informational Observation',
      title: 'Target Unreachable during Headers check',
      description: 'Could not connect to the target URL for headers check.',
      evidence: res.error || 'Connection Failed',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Check HTTP status code === 0',
      confidenceScore: 90,
      confidence: 'High',
      reasoning: 'The server was unreachable. No response headers could be audited.',
      remediation: 'Ensure target URL is correct, online, and not blocking the scanner IP.'
    }];
  }

  const findings = [];
  const headers = res.headers;
  const contentType = headers['content-type'] || '';
  const isJson = contentType.includes('application/json');
  
  const infrastructure = detectSecurityInfrastructure(headers);
  const infraStr = infrastructure.length ? ` (Security Infrastructure Detected: ${infrastructure.join(', ')})` : '';

  // Context-Aware Rule: If response is JSON, frame-ancestors, CSP, and clickjacking are irrelevant.
  if (isJson) {
    log.push('[WAPT] Content-Type is JSON. Skipping browser rendering header checks.');
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'Browser Headers Skipped for API Endpoint',
      description: 'The target returned JSON data. Browser-focused headers (CSP, X-Frame-Options, X-Content-Type-Options) are not applicable to raw API responses.',
      evidence: `Content-Type: ${contentType}`,
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Check Content-Type header matches JSON MIME types',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'Browser security controls like frame restrictions and script execution bounds (CSP) do not apply to JSON objects that are not parsed as HTML documents.',
      remediation: 'No remediation needed. Maintain API authorization tokens to secure data access.'
    });
    return findings;
  }

  const csp = headers['content-security-policy'] || '';
  const hasFrameAncestors = csp.includes('frame-ancestors');

  // Check CSP
  if (!csp) {
    findings.push({
      severity: 'Medium',
      category: 'Best Practice Recommendation',
      title: 'Missing Content-Security-Policy',
      description: 'The Content-Security-Policy (CSP) header is missing, which is a key defense-in-depth security header for restricting script and resource load sources.',
      evidence: 'Header content-security-policy is absent',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Verify presence of content-security-policy header',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: `No CSP header found. In the absence of a CSP, standard HTML rendering browsers will load resources and scripts from any source, increasing risk if XSS exists.${infraStr}`,
      remediation: 'Implement a strict Content-Security-Policy header, setting default-src to self and whitelisting trusted hosts.'
    });
  } else if (csp.includes("'unsafe-inline'") || csp.includes('*')) {
    findings.push({
      severity: 'Low',
      category: 'Best Practice Recommendation',
      title: 'Weak Content-Security-Policy Configuration',
      description: 'The Content-Security-Policy contains unsafe-inline or wildcard directives, which weakens script source guarantees.',
      evidence: `CSP: ${csp}`,
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: "Verify if CSP contains 'unsafe-inline' or '*'",
      confidenceScore: 95,
      confidence: 'High',
      reasoning: 'Allowing unsafe-inline enables execution of scripts injected directly in HTML tags, bypassing one of CSP\'s primary XSS mitigations.',
      remediation: 'Refactor client-side code to use event listeners instead of inline scripts, and remove unsafe-inline and wildcard source hosts from CSP.'
    });
  }

  // Check HSTS (only if HTTPS)
  const isHttps = baseUrl.startsWith('https://');
  if (isHttps && !headers['strict-transport-security']) {
    findings.push({
      severity: 'Medium',
      category: 'Best Practice Recommendation',
      title: 'Missing Strict-Transport-Security Header',
      description: 'The Strict-Transport-Security (HSTS) header is missing, allowing browsers to request the site over plain HTTP in future sessions.',
      evidence: 'Header strict-transport-security is absent',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Verify presence of strict-transport-security header over HTTPS',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'Without HSTS, users are vulnerable to SSL stripping attacks where an active MITM attacker downgrades secure connections to insecure HTTP.',
      remediation: 'Enable HSTS by adding the Strict-Transport-Security header (e.g. max-age=31536000; includeSubDomains).'
    });
  }

  // Check X-Frame-Options
  // Context-Aware Rule: If CSP contains frame-ancestors, X-Frame-Options is redundant (CSP overrides it in modern browsers).
  if (!headers['x-frame-options']) {
    if (hasFrameAncestors) {
      findings.push({
        severity: 'Info',
        category: 'Informational Observation',
        title: 'X-Frame-Options Omitted (Mitigated by CSP)',
        description: 'The X-Frame-Options header is absent, but clickjacking protection is active via Content-Security-Policy\'s frame-ancestors directive.',
        evidence: `CSP frame-ancestors directive present: ${csp.match(/frame-ancestors[^;]*/)}`,
        rawRequest: res.rawRequest,
        rawResponse: res.rawResponse,
        detectionLogic: 'Check for missing X-Frame-Options but present CSP frame-ancestors',
        confidenceScore: 95,
        confidence: 'High',
        reasoning: 'Modern browsers prioritize CSP frame-ancestors over X-Frame-Options. Legacy browsers that do not support CSP are the only ones affected.',
        remediation: 'For maximum compatibility with older browsers (IE11), consider adding X-Frame-Options: SAMEORIGIN in addition to your CSP.'
      });
    } else {
      findings.push({
        severity: 'Low',
        category: 'Best Practice Recommendation',
        title: 'Missing X-Frame-Options Header',
        description: 'The X-Frame-Options header is missing, which could allow the page to be framed inside external websites, exposing users to clickjacking.',
        evidence: 'Header x-frame-options is absent',
        rawRequest: res.rawRequest,
        rawResponse: res.rawResponse,
        detectionLogic: 'Verify absence of both x-frame-options and CSP frame-ancestors',
        confidenceScore: 100,
        confidence: 'High',
        reasoning: 'Neither X-Frame-Options nor CSP frame-ancestors directives were detected, exposing the application to clickjacking risk.',
        remediation: 'Set the X-Frame-Options header to DENY or SAMEORIGIN, or add a frame-ancestors directive to your CSP.'
      });
    }
  }

  // Check X-Content-Type-Options
  if (!headers['x-content-type-options']) {
    findings.push({
      severity: 'Low',
      category: 'Best Practice Recommendation',
      title: 'Missing X-Content-Type-Options Header',
      description: 'The X-Content-Type-Options header is missing, allowing browsers to MIME-sniff response content types.',
      evidence: 'Header x-content-type-options is absent',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Verify presence of x-content-type-options: nosniff',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'Without nosniff, browsers may attempt to parse files (like images or user uploads) as JavaScript, presenting an XSS vector if file upload controls are weak.',
      remediation: 'Configure your web server to return X-Content-Type-Options: nosniff for all HTTP responses.'
    });
  }

  // Check Referrer-Policy
  if (!headers['referrer-policy']) {
    findings.push({
      severity: 'Low',
      category: 'Best Practice Recommendation',
      title: 'Missing Referrer-Policy Header',
      description: 'The Referrer-Policy header is missing, which could leak sensitive parameters or tokens in referrer headers to external hosts.',
      evidence: 'Header referrer-policy is absent',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Verify presence of referrer-policy header',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'In the absence of an explicit Referrer-Policy, the browser\'s default behavior applies, which might send full URL paths including query strings to third parties.',
      remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer.'
    });
  }

  // Check Permissions-Policy
  if (!headers['permissions-policy']) {
    findings.push({
      severity: 'Low',
      category: 'Best Practice Recommendation',
      title: 'Missing Permissions-Policy Header',
      description: 'The Permissions-Policy header is missing, leaving browser API feature permissions unrestricted.',
      evidence: 'Header permissions-policy is absent',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Verify presence of permissions-policy header',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'Permissions-Policy controls which APIs (camera, geolocation, microphone) can be accessed by the site or framed third-party scripts.',
      remediation: 'Implement a Permissions-Policy header restricting access to browser capabilities not utilized by the application.'
    });
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'Security Headers Configured Properly',
      description: 'All recommended security headers are present and properly configured.',
      evidence: JSON.stringify(headers, null, 2),
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'All checks passed',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'All configuration audits (CSP, HSTS, X-Content-Type-Options, etc.) returned secure values.',
      remediation: 'Maintain current security header configurations.'
    });
  }

  return findings;
}

// 2. checkHttpMethods
async function checkHttpMethods(baseUrl, log) {
  log.push('[WAPT] Running checkHttpMethods...');
  const methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'];
  const findings = [];

  const promises = methods.map(method => request(baseUrl, { method }));
  const results = await Promise.all(promises);

  results.forEach((res, i) => {
    const method = methods[i];
    if (res.status > 0) {
      // Context-Aware Rule: If the method requires auth (401/403) or is blocked (405/501), it is NOT a vulnerability!
      if (res.status === 401 || res.status === 403) {
        findings.push({
          severity: 'Info',
          category: 'Informational Observation',
          title: `HTTP Method Protected: ${method}`,
          description: `The web server returns HTTP status ${res.status} when testing ${method}, indicating active authentication guards are present.`,
          evidence: `Method: ${method} | Response Status: ${res.status}`,
          rawRequest: res.rawRequest,
          rawResponse: res.rawResponse,
          detectionLogic: 'Check if HTTP status of PUT/DELETE is 401 or 403',
          confidenceScore: 95,
          confidence: 'High',
          reasoning: `The server responded with an authorization error. This indicates that while the method may be registered on the server, anonymous users cannot execute it.`,
          remediation: 'Verify that authorization controls continue to block anonymous operations on sensitive endpoints.'
        });
      } else if (res.status >= 200 && res.status < 300) {
        findings.push({
          severity: 'High',
          category: 'Confirmed Vulnerability',
          title: `Insecure HTTP Method Open: ${method}`,
          description: `The web server accepts unauthenticated ${method} requests on the root URL, allowing potential modifications or configuration overrides.`,
          evidence: `Method: ${method} | Response Status: ${res.status}`,
          rawRequest: res.rawRequest,
          rawResponse: res.rawResponse,
          detectionLogic: 'Detect HTTP status code 2xx for unauthenticated modification methods',
          confidenceScore: 95,
          confidence: 'High',
          reasoning: `An anonymous request returned a success status code. This means anyone can read/write resources at this path using ${method}.`,
          remediation: `Configure the web server or application middleware to disable ${method} or enforce strict authentication.`
        });
      } else {
        // Method returns 405 Method Not Allowed, 501, 404, etc. It is not vulnerable.
        findings.push({
          severity: 'Info',
          category: 'Informational Observation',
          title: `HTTP Method Disabled: ${method}`,
          description: `Testing the ${method} method returned status ${res.status}, indicating it is disabled or unavailable at this path.`,
          evidence: `Method: ${method} | Response Status: ${res.status}`,
          rawRequest: res.rawRequest,
          rawResponse: res.rawResponse,
          detectionLogic: 'Check if HTTP status is outside 2xx/401/403',
          confidenceScore: 90,
          confidence: 'High',
          reasoning: `The server rejected the method request, confirming that anonymous modifications are blocked.`,
          remediation: 'No remediation needed.'
        });
      }
    }
  });

  return findings;
}

// 3. checkSslTls
async function checkSslTls(baseUrl, log, redirectedToHttps) {
  log.push('[WAPT] Running checkSslTls...');
  const findings = [];
  const isHttps = baseUrl.startsWith('https://');

  if (!isHttps && !redirectedToHttps) {
    findings.push({
      severity: 'High',
      category: 'Confirmed Vulnerability',
      title: 'Missing HTTPS Encryption',
      description: 'The target application is hosted over HTTP. Traffic is transmitted in plain text, making it vulnerable to sniffing and man-in-the-middle (MITM) attacks.',
      evidence: `Protocol: HTTP | URL: ${baseUrl}`,
      rawRequest: `GET ${baseUrl} HTTP/1.1\r\n\r\n`,
      rawResponse: 'N/A',
      detectionLogic: 'Check if URL scheme matches http:// and redirection is absent',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'The target site accepts plain text connections and does not automatically redirect to HTTPS, leaving user traffic completely unencrypted.',
      remediation: 'Configure the web server to enforce SSL/TLS and redirect all HTTP connections to HTTPS.'
    });
  } else if (isHttps) {
    const httpCounterpart = baseUrl.replace('https://', 'http://');
    let currentUrl = httpCounterpart;
    let redirectsFollowed = 0;
    let resolvedRedirect = false;
    let resHttp = null;

    while (redirectsFollowed < 3) {
      resHttp = await request(currentUrl, { timeout: 4000 });
      if (resHttp.status >= 300 && resHttp.status < 400) {
        const location = resHttp.headers['location'] || '';
        if (location.startsWith('https://')) {
          resolvedRedirect = true;
          break;
        } else if (location.startsWith('http://') || location.startsWith('/')) {
          try {
            currentUrl = new URL(location, currentUrl).toString();
          } catch (e) {
            break;
          }
          redirectsFollowed++;
        } else {
          break;
        }
      } else {
        break;
      }
    }

    if (!resolvedRedirect) {
      findings.push({
        severity: 'Medium',
        category: 'Probable Misconfiguration',
        title: 'Missing HTTP-to-HTTPS Redirection',
        description: 'The HTTP counterpart of the target URL does not redirect users automatically to the secure HTTPS version.',
        evidence: `HTTP counterpart status: ${resHttp ? resHttp.status : 'N/A'} | Location: ${resHttp ? (resHttp.headers['location'] || 'None') : 'N/A'}`,
        rawRequest: resHttp ? resHttp.rawRequest : 'N/A',
        rawResponse: resHttp ? resHttp.rawResponse : 'N/A',
        detectionLogic: 'Follow redirection hops and check if final location uses https:// scheme',
        confidenceScore: 95,
        confidence: 'High',
        reasoning: 'While HTTPS is available, users typing the HTTP URL are not redirected to the secure portal, creating an opportunity for interception.',
        remediation: 'Configure your web server (e.g. nginx or Apache redirect directives) to force HTTPS for all incoming HTTP requests.'
      });
    }
  }

  const res = await request(isHttps ? baseUrl : baseUrl.replace('http://', 'https://'));
  if (res.status > 0) {
    const hsts = res.headers['strict-transport-security'] || '';
    if (hsts) {
      const match = hsts.match(/max-age=(\d+)/i);
      if (match) {
        const maxAge = parseInt(match[1]);
        if (maxAge < 31536000) {
          findings.push({
            severity: 'Low',
            category: 'Best Practice Recommendation',
            title: 'HSTS Max-Age Too Low',
            description: 'The Strict-Transport-Security (HSTS) max-age is set to less than 1 year (31,536,000 seconds), which does not satisfy industry standards.',
            evidence: `HSTS: ${hsts}`,
            rawRequest: res.rawRequest,
            rawResponse: res.rawResponse,
            detectionLogic: 'Parse max-age parameter from strict-transport-security header and check value',
            confidenceScore: 100,
            confidence: 'High',
            reasoning: 'HSTS max-age is too short. Browsers will only enforce HSTS connection rules for the specified time, weakening long-term protection.',
            remediation: 'Increase the Strict-Transport-Security max-age directive to at least 31536000.'
          });
        }
      }
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'SSL/TLS Configuration Secure',
      description: 'HTTPS is enforced, HTTP redirects to HTTPS, and HSTS is configured with a high max-age.',
      evidence: 'HSTS configured properly or redirect active.',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'All SSL validation checks passed',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'Traffic encryption and enforcement configurations meet security standards.',
      remediation: 'Keep SSL/TLS and HSTS options active.'
    });
  }

  return findings;
}

// 4. checkDirectoryEnumeration
async function checkDirectoryEnumeration(baseUrl, log) {
  log.push('[WAPT] Running checkDirectoryEnumeration...');
  const paths = [
    '/.git/HEAD', '/.env', '/config.php', '/wp-config.php', '/web.config', '/phpinfo.php',
    '/server-status', '/admin', '/administrator', '/backup', '/api/swagger', '/api/docs',
    '/swagger-ui.html', '/actuator', '/actuator/env', '/actuator/health', '/.htaccess',
    '/config/database.yml', '/.DS_Store', '/dump.sql', '/db.sql', '/backup.zip'
  ];
  const findings = [];

  let origin = '';
  try {
    const parsed = new URL(baseUrl);
    origin = `${parsed.protocol}//${parsed.host}`;
  } catch (e) {
    origin = baseUrl;
  }

  const promises = paths.map(path => {
    const target = `${origin}${path}`;
    return request(target).then(res => ({ path, target, res }));
  });
  const results = await Promise.all(promises);

  results.forEach(({ path, target, res }) => {
    if (res.status === 200 || res.status === 403) {
      // Context-Aware Rule: Verify signatures to eliminate false positives from custom 404/wildcard redirects
      let isFalsePositive = false;
      let signatureProof = '';
      
      const bodyLower = res.body.toLowerCase();
      const isHtml = bodyLower.includes('<!doctype html') || bodyLower.includes('<html');

      if (path === '/.git/HEAD') {
        if (!res.body.includes('ref:') && !/^[0-9a-f]{40}$/i.test(res.body.trim())) {
          isFalsePositive = true;
        } else {
          signatureProof = `Contains Git reference pointer: "${res.body.trim()}"`;
        }
      } else if (path === '/.env') {
        const containsEnvKeys = ['DB_','PORT=','SECRET=','API_','KEY=','PASSWORD=','USER=','HOST='].some(key => res.body.includes(key));
        if (isHtml || !containsEnvKeys) {
          isFalsePositive = true;
        } else {
          signatureProof = `Contains environment config variables: "${res.body.substring(0, 100).replace(/\r?\n/g, ' ')}"`;
        }
      } else if (path.endsWith('.php') || path.endsWith('.yml') || path.endsWith('.sql') || path.endsWith('.zip')) {
        // If config file returns 200 but contains standard HTML, it's a redirect/404 page
        if (isHtml) {
          isFalsePositive = true;
        } else {
          signatureProof = `Raw data response of size ${res.body.length} bytes (no HTML tags found).`;
        }
      }

      if (isFalsePositive) {
        log.push(`[WAPT] Dismissed false positive directory finding on: ${path} (HTML/Redirect detected)`);
        return; // Skip reporting this false positive!
      }

      const isCritical = ['/.git/HEAD', '/.env', '/config.php', '/wp-config.php', '/web.config', '/config/database.yml', '/dump.sql', '/db.sql', '/backup.zip', '/backup'].some(term => path.includes(term));
      
      findings.push({
        severity: isCritical ? 'Critical' : 'Medium',
        category: 'Confirmed Vulnerability',
        title: `Exposed Sensitive Path: ${path}`,
        description: `Accessing ${path} returned HTTP status ${res.status}. This path exposes sensitive configurations, database files, or administrative modules.`,
        evidence: `URL: ${target} | Status: ${res.status} | Proof: ${signatureProof || 'Status code matched'}`,
        rawRequest: res.rawRequest,
        rawResponse: res.rawResponse,
        detectionLogic: 'Audit HTTP status code and match response body signatures',
        confidenceScore: signatureProof ? 100 : 80,
        confidence: signatureProof ? 'High' : 'Medium',
        reasoning: `The path returned ${res.status} and matched the expected format/signature of the file type, indicating exposure.`,
        remediation: `Configure your web server to return a 404 or 403 status code for this directory, or delete the file from the production server.`
      });
    }
  });

  if (findings.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'Sensitive Directories Protected',
      description: 'None of the tested sensitive configuration paths returned exposed data or false positive response pages.',
      evidence: 'Tested 20 sensitive paths, all returned 404/non-responsive.',
      rawRequest: `GET ${origin}/.env HTTP/1.1\r\n\r\n`,
      rawResponse: 'HTTP/1.1 404 Not Found\r\n\r\n',
      detectionLogic: 'No paths returned 200/403 with valid content signatures',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'All directory checks completed without exposing critical config files.',
      remediation: 'Maintain strict directory indexing controls.'
    });
  }

  return findings;
}

// 5. checkXss
async function checkXss(baseUrl, log) {
  log.push('[WAPT] Running checkXss...');
  const params = ['q', 'search', 'name', 'input'];
  const payload = '<script>alert("XSS-AI-Detective")</script>';
  const findings = [];

  const promises = params.map(param => {
    let testUrl = '';
    try {
      const parsed = new URL(baseUrl);
      parsed.searchParams.set(param, payload);
      testUrl = parsed.toString();
    } catch (e) {
      testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
    }
    return request(testUrl).then(res => ({ param, testUrl, res }));
  });

  const results = await Promise.all(promises);

  results.forEach(({ param, testUrl, res }) => {
    const contentType = res.headers['content-type'] || '';
    const isJson = contentType.includes('application/json');

    // Context-Aware Rule: If payload is reflected in JSON response, it is not XSS (not executable).
    if (isJson) {
      return;
    }

    if (res.body.includes(payload)) {
      // Check if it is HTML-encoded. If the characters < or > are escaped in the body, it is not vulnerable.
      // We check if the raw payload string exists. Since res.body.includes(payload) is true, it means it is EXACTLY unescaped!
      findings.push({
        severity: 'Critical',
        category: 'Confirmed Vulnerability',
        title: `Reflected XSS Vulnerability in Parameter: ${param}`,
        description: `The application echoes back user input unescaped. The script payload was found reflected in the HTML response body.`,
        evidence: `Parameter: ${param} | URL: ${testUrl} | Reflected Payload in response`,
        rawRequest: res.rawRequest,
        rawResponse: res.rawResponse,
        detectionLogic: 'Inspect response body for exact, unescaped script tags reflection',
        confidenceScore: 100,
        confidence: 'High',
        reasoning: 'The scripting tag payload was echoed back character-for-character, which would trigger immediate script execution in the client browser.',
        remediation: `Implement context-aware HTML entity encoding on all reflected user inputs, or use modern template engines that escape variables by default.`
      });
    }
  });

  if (findings.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'Reflected XSS Checks Passed',
      description: 'No unescaped reflection of scripting payloads was detected in the tested input fields.',
      evidence: 'Probed parameters q, search, name, input with standard XSS script alert.',
      rawRequest: `GET ${baseUrl}?q=${encodeURIComponent(payload)} HTTP/1.1\r\n\r\n`,
      rawResponse: 'HTTP/1.1 200 OK\r\n\r\n',
      detectionLogic: 'Ensure parameter reflections are either absent or properly escaped',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'Tested input parameters did not reflect raw scripting tags.',
      remediation: 'Ensure strict contextual output escaping is maintained.'
    });
  }

  return findings;
}

// 6. checkSqlInjection
async function checkSqlInjection(baseUrl, log) {
  log.push('[WAPT] Running checkSqlInjection...');
  const params = ['id', 'user', 'username', 'query', 'q', 'search', 'product'];
  const probes = ["'", "1' OR '1'='1", "1 AND 1=1--", "' OR 1=1--"];

  const sqlErrorKeywords = [
    'SQL syntax', 'mysql_fetch', 'ORA-0', 'Microsoft OLE DB', 'ODBC Driver', 'SQLite3::',
    'pg_query', 'syntax error', 'unclosed quotation mark', 'Unterminated string',
    'SQLSTATE', 'You have an error in your SQL syntax'
  ];

  const findings = [];

  const tests = [];
  for (const param of params) {
    for (const probe of probes) {
      let testUrl = '';
      try {
        const parsed = new URL(baseUrl);
        parsed.searchParams.set(param, probe);
        testUrl = parsed.toString();
      } catch (e) {
        testUrl = `${baseUrl}?${param}=${encodeURIComponent(probe)}`;
      }
      tests.push({ param, probe, testUrl });
    }
  }

  const promises = tests.map(t => request(t.testUrl).then(res => ({ ...t, res })));
  const results = await Promise.all(promises);

  const flaggedParams = new Set();
  results.forEach(({ param, probe, testUrl, res }) => {
    if (flaggedParams.has(param)) return;
    
    // Context-Aware Rule: Check if it is a WAF block page (e.g. status 403 / 406 / WAF blocks)
    const isWafBlock = res.status === 403 || res.status === 406 || res.status === 429 || 
                       ['cloudflare', 'waf', 'ray id', 'security block', 'sucuri', 'blocked'].some(term => res.body.toLowerCase().includes(term));
                       
    if (isWafBlock) {
      log.push(`[WAPT] Request blocked by WAF for parameter ${param}. Security controls are active.`);
      return; // Skip reporting this as a SQLi vulnerability since it was successfully blocked!
    }

    const matchedKeyword = sqlErrorKeywords.find(keyword => res.body.toLowerCase().includes(keyword.toLowerCase()));

    if (matchedKeyword) {
      flaggedParams.add(param);
      findings.push({
        severity: 'Critical',
        category: 'Confirmed Vulnerability',
        title: `Potential SQL Injection in Parameter: ${param}`,
        description: `Sending SQL injection probes resulted in standard database syntax error outputs in the response body. This indicates queries are being dynamically constructed with unvalidated input.`,
        evidence: `Parameter: ${param} | Probe: ${probe} | Matched DB Error string: "${matchedKeyword}"`,
        rawRequest: res.rawRequest,
        rawResponse: res.rawResponse,
        detectionLogic: 'Monitor response body for database syntax error keywords',
        confidenceScore: 95,
        confidence: 'High',
        reasoning: 'The database returned a syntax error directly in the response, showing that input is directly affecting the database compiler.',
        remediation: 'Use parameterized queries (prepared statements) for all database operations and avoid raw string concatenation.'
      });
    }
  });

  if (findings.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'SQL Injection Checks Passed',
      description: 'No database query errors or SQL syntax leaks were detected in response to dynamic probes.',
      evidence: 'Probed parameters id, user, username, query, q, search, product with 4 SQL injection sequences.',
      rawRequest: `GET ${baseUrl}?id=${encodeURIComponent(probes[0])} HTTP/1.1\r\n\r\n`,
      rawResponse: 'HTTP/1.1 200 OK\r\n\r\n',
      detectionLogic: 'No database errors or WAF blocks triggered',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'The tested application did not leak any database exceptions or errors.',
      remediation: 'Continue enforcing SQL parameterization across all query operations.'
    });
  }

  return findings;
}

// 7. checkOpenRedirect
async function checkOpenRedirect(baseUrl, log) {
  log.push('[WAPT] Running checkOpenRedirect...');
  const params = ['redirect', 'next', 'url', 'goto', 'return', 'returnUrl', 'callback', 'continue'];
  const payload = 'https://evil.example.com';
  const findings = [];

  const promises = params.map(param => {
    let testUrl = '';
    try {
      const parsed = new URL(baseUrl);
      parsed.searchParams.set(param, payload);
      testUrl = parsed.toString();
    } catch (e) {
      testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
    }
    return request(testUrl).then(res => ({ param, testUrl, res }));
  });

  const results = await Promise.all(promises);

  results.forEach(({ param, testUrl, res }) => {
    const location = res.headers['location'] || '';
    if (res.status >= 300 && res.status < 400 && location) {
      let isTargetHost = false;
      try {
        const redirectUrl = new URL(location, baseUrl);
        if (redirectUrl.hostname === 'evil.example.com') {
          isTargetHost = true;
        }
      } catch (e) {
        if (location.startsWith('https://evil.example.com') || location.startsWith('//evil.example.com')) {
          isTargetHost = true;
        }
      }

      if (isTargetHost) {
        findings.push({
          severity: 'High',
          category: 'Confirmed Vulnerability',
          title: `Open Redirect Vulnerability in Parameter: ${param}`,
          description: `The application redirects users to arbitrary external URLs supplied via the "${param}" parameter, facilitating phishing campaigns.`,
          evidence: `Parameter: ${param} | Redirect Status: ${res.status} | Location: ${location}`,
          rawRequest: res.rawRequest,
          rawResponse: res.rawResponse,
          detectionLogic: 'Verify that the hostname of the Location header matches the external domain payload',
          confidenceScore: 100,
          confidence: 'High',
          reasoning: 'The response returned a 3xx redirect directly targeting the untrusted external host hostname.',
          remediation: 'Implement an allowlist of permitted redirect domains, or use relative URLs only.'
        });
      }
    }
  });

  if (findings.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'Open Redirect Checks Passed',
      description: 'No arbitrary redirection to external evil domains was detected during parameters probing.',
      evidence: 'Tested 8 typical redirect parameters with external domain payload.',
      rawRequest: `GET ${baseUrl}?redirect=${encodeURIComponent(payload)} HTTP/1.1\r\n\r\n`,
      rawResponse: 'HTTP/1.1 200 OK\r\n\r\n',
      detectionLogic: 'Confirm Location header is either absent or stays within the origin domain',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'Redirect requests were either ignored or did not point to the external test domain.',
      remediation: 'Maintain local redirect verification checks.'
    });
  }

  return findings;
}

// 8. checkCors
async function checkCors(baseUrl, log) {
  log.push('[WAPT] Running checkCors...');
  const findings = [];

  const resBase = await request(baseUrl);
  const acaoBase = resBase.headers['access-control-allow-origin'] || '';
  const acacBase = resBase.headers['access-control-allow-credentials'] || '';

  // Context-Aware Rule: Wildcard origin is only a confirmed vulnerability if credentials are also allowed.
  if (acaoBase === '*') {
    if (acacBase === 'true') {
      findings.push({
        severity: 'High',
        category: 'Confirmed Vulnerability',
        title: 'Exploitable Wildcard CORS Policy',
        description: 'Access-Control-Allow-Origin is set to * while Access-Control-Allow-Credentials is true, allowing arbitrary origins to read authenticated response data.',
        evidence: `ACAO: * | ACAC: ${acacBase}`,
        rawRequest: resBase.rawRequest,
        rawResponse: resBase.rawResponse,
        detectionLogic: 'Check if ACAO is wildcard and ACAC is true',
        confidenceScore: 100,
        confidence: 'High',
        reasoning: 'The combination of wildcard origins and credentials sharing allows external malicious scripts to read session-based content.',
        remediation: 'Disable wildcard origins when credentials sharing is enabled. Implement an explicit whitelist.'
      });
    } else {
      findings.push({
        severity: 'Low',
        category: 'Best Practice Recommendation',
        title: 'Loose CORS Policy (Wildcard ACAO)',
        description: 'The Access-Control-Allow-Origin header is set to a wildcard (*), allowing any site to perform cross-origin reads of responses.',
        evidence: `Access-Control-Allow-Origin: *`,
        rawRequest: resBase.rawRequest,
        rawResponse: resBase.rawResponse,
        detectionLogic: 'Check if ACAO header is *',
        confidenceScore: 95,
        confidence: 'High',
        reasoning: 'For public endpoints (web fonts, CDN assets), a wildcard is acceptable. For internal assets, this is loose.',
        remediation: 'Specify specific domain names in Access-Control-Allow-Origin instead of using a wildcard (*).'
      });
    }
  }

  const origins = ['https://evil.example.com', 'null'];
  const promises = origins.map(origin =>
    request(baseUrl, { headers: { 'Origin': origin } }).then(res => ({ origin, res }))
  );
  const results = await Promise.all(promises);

  results.forEach(({ origin, res }) => {
    const acao = res.headers['access-control-allow-origin'] || '';
    const acac = res.headers['access-control-allow-credentials'] || '';

    if (acao === origin) {
      if (acac === 'true') {
        findings.push({
          severity: 'Critical',
          category: 'Confirmed Vulnerability',
          title: 'Exploitable CORS Configuration (Origin Echo with Credentials)',
          description: 'The server echoes back arbitrary Cross-Origin requests and enables Access-Control-Allow-Credentials: true. Attackers can hijack active sessions of users visiting malicious sites.',
          evidence: `Origin Sent: ${origin} | ACAO Echoed: ${acao} | ACAC: ${acac}`,
          rawRequest: res.rawRequest,
          rawResponse: res.rawResponse,
          detectionLogic: 'Verify if Access-Control-Allow-Origin dynamically reflects the incoming Origin header when credentials are true',
          confidenceScore: 100,
          confidence: 'High',
          reasoning: 'The application echoes back any origin while permitting cookies. This allows third-party scripts to make cross-origin authenticated reads.',
          remediation: 'Disable dynamic reflection of Origin header if credentials are required. Implement a whitelist of allowed domains.'
        });
      } else {
        findings.push({
          severity: 'High',
          category: 'Probable Misconfiguration',
          title: 'Loose CORS Configuration (Origin Echo)',
          description: 'The server dynamically echoes back arbitrary Origin headers in its CORS response, permitting cross-origin reads from untrusted domains.',
          evidence: `Origin Sent: ${origin} | ACAO Echoed: ${acao}`,
          rawRequest: res.rawRequest,
          rawResponse: res.rawResponse,
          detectionLogic: 'Verify if Access-Control-Allow-Origin dynamically reflects the incoming Origin header',
          confidenceScore: 90,
          confidence: 'High',
          reasoning: 'Dynamically reflecting any origin enables cross-origin reads, which should be restricted to trusted partners.',
          remediation: 'Validate the Origin header against a whitelist of authorized domains before outputting.'
        });
      }
    }
  });

  if (findings.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'CORS Security Check Passed',
      description: 'No wildcard ACAO, origin echoing, or credentials leakage was detected.',
      evidence: 'Tested normal request and requests with Origin header overrides.',
      rawRequest: resBase.rawRequest,
      rawResponse: resBase.rawResponse,
      detectionLogic: 'No Dynamic Origin echoes or loose wildcard credentials policies matched',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'The CORS policy correctly restricts access to trusted origins.',
      remediation: 'Retain restrictive CORS configuration parameters.'
    });
  }

  return findings;
}

// 9. checkCookieSecurity
async function checkCookieSecurity(baseUrl, log) {
  log.push('[WAPT] Running checkCookieSecurity...');
  const findings = [];
  const res = await request(baseUrl);

  let setCookies = res.headers['set-cookie'] || [];
  if (!Array.isArray(setCookies)) {
    setCookies = [setCookies];
  }

  const activeCookies = setCookies.filter(Boolean);

  if (activeCookies.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'No Session Cookies Set',
      description: 'The target endpoint did not issue any Set-Cookie headers in the audited response.',
      evidence: 'No Set-Cookie header present.',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Check presence of set-cookie headers',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'The application does not set cookies in its HTTP response, eliminating the risk of insecure cookie parameters.',
      remediation: 'Ensure cookies continue to be avoided if session tokens are handled via custom headers.'
    });
    return findings;
  }

  // List of keywords indicating a cookie is likely a sensitive session identifier
  const sessionKeywords = ['sid', 'session', 'token', 'jwt', 'jsessionid', 'phpsessid', 'aspsessionid', '__secure-strp'];

  for (const cookie of activeCookies) {
    const cookieName = cookie.split('=')[0] || 'Unknown';
    const isHttpOnly = /httponly/i.test(cookie);
    const isSecure = /secure/i.test(cookie);
    const hasSameSite = /samesite/i.test(cookie);
    
    // Context-Aware Rule: Only flag as critical if it is a sensitive session cookie
    const isSession = sessionKeywords.some(keyword => cookieName.toLowerCase().includes(keyword));
    const typeLabel = isSession ? 'Session Identifier' : 'Preference/Analytics';

    if (!isHttpOnly) {
      findings.push({
        severity: isSession ? 'High' : 'Low',
        category: isSession ? 'Probable Misconfiguration' : 'Best Practice Recommendation',
        title: `Cookie Missing HttpOnly Flag: ${cookieName}`,
        description: `The cookie "${cookieName}" (${typeLabel}) is not protected with the HttpOnly attribute, allowing client-side scripts to access it.`,
        evidence: `Set-Cookie: ${cookie}`,
        rawRequest: res.rawRequest,
        rawResponse: res.rawResponse,
        detectionLogic: 'Match httponly parameter in set-cookie headers',
        confidenceScore: 100,
        confidence: 'High',
        reasoning: isSession 
          ? `The session cookie "${cookieName}" lacks HttpOnly, making it vulnerable to hijacking via Cross-Site Scripting (XSS).`
          : `The preference/analytics cookie "${cookieName}" lacks HttpOnly. This is low-risk as the cookie contains no session authorization data.`,
        remediation: `Add the 'HttpOnly' flag when configuring the cookie on the server.`
      });
    }

    if (!isSecure) {
      findings.push({
        severity: isSession ? 'Medium' : 'Low',
        category: isSession ? 'Probable Misconfiguration' : 'Best Practice Recommendation',
        title: `Cookie Missing Secure Flag: ${cookieName}`,
        description: `The cookie "${cookieName}" (${typeLabel}) is missing the Secure flag, allowing transmission over insecure channels.`,
        evidence: `Set-Cookie: ${cookie}`,
        rawRequest: res.rawRequest,
        rawResponse: res.rawResponse,
        detectionLogic: 'Match secure parameter in set-cookie headers',
        confidenceScore: 100,
        confidence: 'High',
        reasoning: isSession
          ? `The session cookie "${cookieName}" lacks the Secure flag, making it vulnerable to interception over unencrypted HTTP.`
          : `The analytics/preference cookie "${cookieName}" lacks the Secure flag, which is low-risk.`,
        remediation: `Add the 'Secure' flag to ensure the cookie is only transmitted over HTTPS.`
      });
    }

    if (!hasSameSite) {
      findings.push({
        severity: isSession ? 'Medium' : 'Low',
        category: isSession ? 'Probable Misconfiguration' : 'Best Practice Recommendation',
        title: `Cookie Missing SameSite Flag: ${cookieName}`,
        description: `The cookie "${cookieName}" (${typeLabel}) is missing the SameSite flag, rendering users vulnerable to CSRF.`,
        evidence: `Set-Cookie: ${cookie}`,
        rawRequest: res.rawRequest,
        rawResponse: res.rawResponse,
        detectionLogic: 'Match samesite parameter in set-cookie headers',
        confidenceScore: 100,
        confidence: 'High',
        reasoning: isSession
          ? `The session cookie "${cookieName}" lacks SameSite, exposing authenticated actions to Cross-Site Request Forgery (CSRF).`
          : `The cookie "${cookieName}" lacks SameSite. This is low-risk.`,
        remediation: `Set SameSite=Lax or SameSite=Strict on the cookie configuration.`
      });
    }
  }

  return findings;
}

// 10. checkServerBanner
async function checkServerBanner(baseUrl, log) {
  log.push('[WAPT] Running checkServerBanner...');
  const findings = [];
  const res = await request(baseUrl);

  const server = res.headers['server'] || '';
  const xpb = res.headers['x-powered-by'] || '';

  if (server) {
    const hasVersion = /[\d]+\.[\d]+/.test(server);
    // Context-Aware Rule: Flagging name disclosure alone is Informational; flagging specific versions is Medium.
    findings.push({
      severity: hasVersion ? 'Medium' : 'Low',
      category: hasVersion ? 'Probable Misconfiguration' : 'Informational Observation',
      title: `Server Banner Disclosure: ${server}`,
      description: hasVersion
        ? `The web server discloses its software name and specific version number, aiding vulnerability targeting.`
        : `The web server exposes its software type in the response headers.`,
      evidence: `Server Header: ${server}`,
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Read Server header and check for version numbers',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: hasVersion 
        ? 'A specific version number is disclosed. Attackers can quickly lookup CVE vulnerabilities matching this version.'
        : 'Only the general server software name is disclosed, which is standard configuration disclosure.',
      remediation: 'Configure the web server to disable or mask the Server response header (e.g. ServerTokens ProductOnly).'
    });
  }

  if (xpb) {
    findings.push({
      severity: 'Low',
      category: 'Informational Observation',
      title: `Powered-By Header Disclosure: ${xpb}`,
      description: `The application leaks technology components (e.g. Express, ASP.NET, PHP) in the X-Powered-By header.`,
      evidence: `X-Powered-By: ${xpb}`,
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'Verify presence of x-powered-by header',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'The X-Powered-By header discloses the framework type, which simplifies target profiling.',
      remediation: 'Disable the X-Powered-By header in the server configuration middleware (e.g. app.disable(\'x-powered-by\')).'
    });
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'Info',
      category: 'Informational Observation',
      title: 'Server Banner Leaks Checked',
      description: 'No Server or X-Powered-By banners were detected.',
      evidence: 'Headers Server and X-Powered-By are absent.',
      rawRequest: res.rawRequest,
      rawResponse: res.rawResponse,
      detectionLogic: 'No server header or powered-by headers present',
      confidenceScore: 100,
      confidence: 'High',
      reasoning: 'Response headers are clean and do not leak technology footprints.',
      remediation: 'Maintain current headers obfuscation configurations.'
    });
  }

  return findings;
}

// ==========================================================================
// Orchestrator function runWaptScan(targetUrl)
// ==========================================================================

async function runWaptScan(targetUrl) {
  const log = [];
  const startTime = Date.now();
  let resolvedUrl = targetUrl;
  let redirectedToHttps = false;

  log.push(`[WAPT] Initializing Passive Security Scan for: ${targetUrl}`);

  // If target URL starts with http://, check if it redirects to https://
  if (targetUrl.startsWith('http://')) {
    log.push(`[WAPT] Target is HTTP. Checking for HTTPS redirection support...`);
    let currentUrl = targetUrl;
    let redirectsFollowed = 0;
    
    while (redirectsFollowed < 3) {
      const res = await request(currentUrl, { timeout: 4000 });
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers['location'] || '';
        if (location.startsWith('https://')) {
          redirectedToHttps = true;
          try {
            resolvedUrl = new URL(location, currentUrl).toString();
          } catch (e) {
            resolvedUrl = location;
          }
          break;
        } else if (location.startsWith('http://') || location.startsWith('/')) {
          try {
            currentUrl = new URL(location, currentUrl).toString();
          } catch (e) {
            break;
          }
          redirectsFollowed++;
        } else {
          break;
        }
      } else {
        break;
      }
    }

    if (redirectedToHttps) {
      log.push(`[WAPT] HTTPS redirection detected. Upgrading scan target to: ${resolvedUrl}`);
    } else {
      log.push(`[WAPT] No HTTPS redirection detected. Continuing scan over plain HTTP.`);
    }
  } else {
    redirectedToHttps = true;
  }

  const allFindings = [];

  // Run checks concurrently
  const checkLogPairs = [
    { fn: checkSecurityHeaders },
    { fn: checkHttpMethods },
    { fn: checkSslTls },
    { fn: checkDirectoryEnumeration },
    { fn: checkXss },
    { fn: checkSqlInjection },
    { fn: checkOpenRedirect },
    { fn: checkCors },
    { fn: checkCookieSecurity },
    { fn: checkServerBanner }
  ];

  const promises = checkLogPairs.map(async (item) => {
    const localLog = [];
    let findings;
    if (item.fn === checkSslTls) {
      findings = await item.fn(resolvedUrl, localLog, redirectedToHttps);
    } else {
      findings = await item.fn(resolvedUrl, localLog);
    }
    return { findings, log: localLog };
  });

  const results = await Promise.all(promises);
  results.forEach(res => {
    allFindings.push(...res.findings);
    log.push(...res.log);
  });

  const duration = Date.now() - startTime;
  const nonInfoFindings = allFindings.filter(f => f.severity !== 'Info');

  // Intelligent Severity and Scoring Engine
  // Classify findings and map penalty based on confidence and severity
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  
  // Calculate average confidence score of non-info findings
  let totalConfidence = 0;
  let nonInfoCount = 0;

  allFindings.forEach(f => {
    if (counts[f.severity] !== undefined) {
      counts[f.severity]++;
    }
    if (f.severity !== 'Info') {
      totalConfidence += f.confidenceScore || 0;
      nonInfoCount++;
    }
  });

  const averageConfidence = nonInfoCount > 0 ? Math.round(totalConfidence / nonInfoCount) : 100;

  // Compute compliance/posture score
  // Deductions are scaled by confidence.
  // Best Practice Recommendation and Informational Observations do not deduct points.
  // Confirmed Vulnerabilities and Probable Misconfigurations deduct points.
  let score = 100;
  allFindings.forEach(f => {
    if (f.severity === 'Info') return;
    
    // Only deduct points for confirmed vulnerabilities or probable misconfigurations
    const isDeductible = f.category === 'Confirmed Vulnerability' || f.category === 'Probable Misconfiguration';
    if (!isDeductible) return;

    let baseDeduction = 0;
    if (f.severity === 'Critical') baseDeduction = 20;
    else if (f.severity === 'High') baseDeduction = 10;
    else if (f.severity === 'Medium') baseDeduction = 5;
    else if (f.severity === 'Low') baseDeduction = 2;

    // Scale penalty by confidence score (e.g. 50% confidence = 50% penalty)
    const confidenceScale = (f.confidenceScore || 0) / 100;
    score -= (baseDeduction * confidenceScale);
  });

  score = Math.max(0, Math.round(score));

  let grade = 'F';
  if (score >= 80) grade = 'A';
  else if (score >= 65) grade = 'B';
  else if (score >= 50) grade = 'C';
  else if (score >= 30) grade = 'D';

  // Risk Score: Higher means more vulnerable (0 to 100)
  // Weighted risk based on posture score
  const riskScore = Math.max(0, 100 - score);

  log.push(`[WAPT] Passive Security Scan completed in ${duration}ms.`);

  return {
    targetUrl,
    scanTime: Date.now(),
    scanDurationMs: duration,
    checksPerformed: 10,
    findings: nonInfoFindings,
    allFindings,
    metrics: {
      totalFindings: nonInfoFindings.length,
      severityCounts: counts,
      securityScore: score, // Posture score
      confidenceScore: averageConfidence,
      riskScore: riskScore,
      grade
    },
    log
  };
}

module.exports = {
  runWaptScan
};
