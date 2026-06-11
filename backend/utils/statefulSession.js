const { URL } = require('url');

class StatefulSessionManager {
  constructor(roleName, authConfig, log) {
    this.roleName = roleName; // e.g., 'admin', 'userA'
    this.authConfig = authConfig || { authType: 'none' };
    this.log = log || [];
    this.state = 'UNINITIALIZED'; // UNINITIALIZED, AUTHENTICATED, RESTRICTED, REVOKED
    this.authHeaders = {}; // The current authorization headers (Cookie, Authorization, etc.)
    this.cookies = []; // Parsed cookie list
    this.token = null;
    this.refreshToken = null;
    this.lock = false;
    this.canaryUrl = this.authConfig.canaryUrl || null;
    
    // Parse static headers initially
    if (this.authConfig.authType === 'header' && this.authConfig.staticHeaders) {
      this.authHeaders = { ...this.authConfig.staticHeaders };
      this.state = 'AUTHENTICATED';
    }
  }

  // Get active headers
  getHeaders() {
    return { ...this.authHeaders };
  }

  // Set headers (e.g., if set from browser sync)
  setHeaders(headers) {
    this.authHeaders = { ...headers };
    this.state = 'AUTHENTICATED';
  }

  // Run the health check on the session
  async checkSessionHealth(requestFn, baseUrl) {
    if (this.authConfig.authType === 'none') return true;
    
    // Choose a canary URL
    let checkUrl = this.canaryUrl;
    if (!checkUrl) {
      // Fallback: use root or /dashboard or /profile
      checkUrl = `${baseUrl}/`;
    } else if (!checkUrl.startsWith('http://') && !checkUrl.startsWith('https://')) {
      checkUrl = `${baseUrl}${checkUrl.startsWith('/') ? '' : '/'}${checkUrl}`;
    }

    this.log.push(`[Session:${this.roleName}] Running active health check to: ${checkUrl}`);
    
    // Make request injecting current headers
    const res = await requestFn(checkUrl, {
      method: 'GET',
      headers: { ...this.authHeaders }
    });

    // Determine if response suggests session is active
    if (res.status === 401 || res.status === 403) {
      this.log.push(`[Session:${this.roleName}] Health check returned ${res.status}. Session is dead.`);
      return false;
    }

    // Check if we were redirected to a login page
    if (res.status === 302 || res.status === 301 || res.status === 307) {
      const loc = res.headers['location'] || '';
      if (loc.includes('/login') || loc.includes('/signin') || loc.includes('/auth')) {
        this.log.push(`[Session:${this.roleName}] Health check redirected to login path: ${loc}. Session is dead.`);
        return false;
      }
    }

    // If body looks like a login form (e.g. contains login elements)
    if (res.body && (res.body.includes('name="password"') || res.body.includes('type="password"')) && (res.body.includes('action="/login"') || res.body.includes('login-form'))) {
      this.log.push(`[Session:${this.roleName}] Health check response body contains a login form. Session is dead.`);
      return false;
    }

    this.log.push(`[Session:${this.roleName}] Health check returned status ${res.status}. Session is alive.`);
    return true;
  }

  // Handle a detected 401/403/Redirect during a scan request
  async handleAccessDenied(requestFn, baseUrl) {
    if (this.authConfig.authType === 'none' || this.authConfig.authType === 'header') {
      return false; // Cannot re-authenticate
    }

    // Concurrency lock to prevent multiple parallel threads from starting login concurrently
    if (this.lock) {
      this.log.push(`[Session:${this.roleName}] Auth lock active. Waiting for re-auth...`);
      while (this.lock) {
        await new Promise(r => setTimeout(r, 200));
      }
      return this.state === 'AUTHENTICATED';
    }

    this.lock = true;
    try {
      // Perform active health check to verify if session is actually expired
      const isAlive = await this.checkSessionHealth(requestFn, baseUrl);
      if (isAlive) {
        this.log.push(`[Session:${this.roleName}] Health check succeeded. This was a privilege rejection (RBAC), not session expiry.`);
        this.state = 'RESTRICTED';
        this.lock = false;
        return true; // Session is alive, skip re-auth
      }

      this.log.push(`[Session:${this.roleName}] Session is expired. Attempting re-authentication.`);
      this.state = 'REVOKED';

      // Attempt OAuth token refresh if refresh token URL exists
      if (this.authConfig.authType === 'jwt' && this.refreshToken) {
        const success = await this.attemptTokenRefresh(requestFn, baseUrl);
        if (success) {
          this.state = 'AUTHENTICATED';
          this.lock = false;
          return true;
        }
      }

      // Fallback: Perform standard credential login
      const success = await this.performLogin(requestFn, baseUrl);
      if (success) {
        this.state = 'AUTHENTICATED';
        this.lock = false;
        return true;
      }

      this.state = 'REVOKED';
      this.lock = false;
      return false;
    } catch (err) {
      this.log.push(`[Session:${this.roleName}] Re-auth threw error: ${err.message}`);
      this.state = 'REVOKED';
      this.lock = false;
      return false;
    }
  }

  async attemptTokenRefresh(requestFn, baseUrl) {
    const refreshUrl = this.authConfig.refreshTokenUrl || `${baseUrl}/api/auth/refresh`;
    this.log.push(`[Session:${this.roleName}] Attempting token refresh via: ${refreshUrl}`);

    const res = await requestFn(refreshUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: this.refreshToken })
    });

    if (res.status >= 200 && res.status < 300) {
      try {
        const body = JSON.parse(res.body);
        const token = body.token || body.accessToken || body.access_token || body.jwt;
        if (token) {
          this.authHeaders = { 'Authorization': `Bearer ${token}` };
          if (body.refreshToken) this.refreshToken = body.refreshToken;
          this.log.push(`[Session:${this.roleName}] Token refresh successful.`);
          return true;
        }
      } catch (e) {
        this.log.push(`[Session:${this.roleName}] Failed to parse refresh token response JSON.`);
      }
    }
    this.log.push(`[Session:${this.roleName}] Token refresh failed.`);
    return false;
  }

  async performLogin(requestFn, baseUrl) {
    const creds = this.authConfig.credentials || {};
    const loginUrl = creds.loginUrl || `${baseUrl}/api/auth/login`;
    const usernameField = creds.usernameField || 'email';
    const passwordField = creds.passwordField || 'password';
    const usernameValue = creds.usernameValue;
    const passwordValue = creds.passwordValue;

    if (!usernameValue || !passwordValue) {
      this.log.push(`[Session:${this.roleName}] Cannot perform login: missing credentials.`);
      return false;
    }

    const payload = {
      [usernameField]: usernameValue,
      [passwordField]: passwordValue
    };

    this.log.push(`[Session:${this.roleName}] Sending login request to: ${loginUrl}`);

    // JSON login
    let res = await requestFn(loginUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    // Form encoded login fallback
    if (res.status === 415 || res.status === 400) {
      this.log.push(`[Session:${this.roleName}] JSON login failed. Retrying form-url-encoded...`);
      const formParams = new URLSearchParams();
      formParams.append(usernameField, usernameValue);
      formParams.append(passwordField, passwordValue);
      res = await requestFn(loginUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formParams.toString()
      });
    }

    if (res.status >= 200 && res.status < 300) {
      if (this.authConfig.authType === 'cookie') {
        const setCookieHeaders = res.headers['set-cookie'];
        if (setCookieHeaders) {
          const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
          const cookiePairs = cookies.map(c => c.split(';')[0].trim()).join('; ');
          
          // Monitor cookie expiry
          this.parseCookies(cookies);

          this.authHeaders = { 'Cookie': cookiePairs };
          this.state = 'AUTHENTICATED';
          this.log.push(`[Session:${this.roleName}] Login successful. Cookies captured.`);
          return true;
        }
      } else if (this.authConfig.authType === 'jwt') {
        try {
          const body = JSON.parse(res.body);
          const token = body.token || body.accessToken || body.access_token || body.jwt;
          if (token) {
            this.authHeaders = { 'Authorization': `Bearer ${token}` };
            this.state = 'AUTHENTICATED';
            if (body.refreshToken || body.refresh_token) {
              this.refreshToken = body.refreshToken || body.refresh_token;
            }
            this.log.push(`[Session:${this.roleName}] Login successful. JWT token captured.`);
            return true;
          }
        } catch (e) {
          this.log.push(`[Session:${this.roleName}] Failed to parse login response for JWT.`);
        }
      }
    }
    
    this.log.push(`[Session:${this.roleName}] Login failed with status: ${res.status}.`);
    return false;
  }

  parseCookies(setCookieHeaders) {
    this.cookies = setCookieHeaders.map(c => {
      const parts = c.split(';');
      const nameValue = parts[0].split('=');
      const name = nameValue[0].trim();
      const value = nameValue[1] ? nameValue[1].trim() : '';
      
      let expires = null;
      let maxAge = null;
      
      for (let i = 1; i < parts.length; i++) {
        const item = parts[i].trim().toLowerCase();
        if (item.startsWith('expires=')) {
          expires = new Date(parts[i].split('=')[1].trim());
        } else if (item.startsWith('max-age=')) {
          maxAge = parseInt(parts[i].split('=')[1].trim(), 10);
        }
      }
      return { name, value, expires, maxAge, createdAt: Date.now() };
    });
  }

  // Check if cookies are expired by parsing expiry tags
  isCookieExpired() {
    if (this.authConfig.authType !== 'cookie' || this.cookies.length === 0) return false;
    const now = Date.now();
    for (const cookie of this.cookies) {
      if (cookie.maxAge !== null) {
        const elapsed = (now - cookie.createdAt) / 1000;
        if (elapsed > cookie.maxAge) return true;
      }
      if (cookie.expires !== null && cookie.expires instanceof Date) {
        if (now > cookie.expires.getTime()) return true;
      }
    }
    return false;
  }
}

module.exports = { StatefulSessionManager };
