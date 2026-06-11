class SessionBridge {
  constructor(statefulSessionManager, log) {
    this.sessionManager = statefulSessionManager;
    this.log = log || [];
  }

  // Hook Playwright page events to keep HTTP scanner in sync with browser
  registerPageHooks(page) {
    this.log.push(`[SessionBridge] Registering Playwright hooks for session sync.`);

    // 1. Intercept responses to extract cookies
    page.on('response', async (response) => {
      try {
        const headers = response.headers();
        const setCookie = headers['set-cookie'];
        if (setCookie) {
          const cookies = Array.isArray(setCookie) ? setCookie : setCookie.split('\n');
          this.log.push(`[SessionBridge] Intercepted browser Set-Cookie: ${cookies.join(', ')}`);
          
          // Parse cookies and update session manager headers
          this.sessionManager.parseCookies(cookies);
          const currentHeaders = this.sessionManager.getHeaders();
          
          // Merge new cookies with old ones
          const newCookiePairs = cookies.map(c => c.split(';')[0].trim());
          let existingCookie = currentHeaders['Cookie'] || '';
          
          newCookiePairs.forEach(newPair => {
            const name = newPair.split('=')[0];
            // Remove previous version of this cookie
            let cookiesList = existingCookie ? existingCookie.split(';').map(x => x.trim()) : [];
            cookiesList = cookiesList.filter(c => !c.startsWith(name + '='));
            cookiesList.push(newPair);
            existingCookie = cookiesList.join('; ');
          });
          
          currentHeaders['Cookie'] = existingCookie;
          this.sessionManager.setHeaders(currentHeaders);
        }
      } catch (err) {
        this.log.push(`[SessionBridge] Error in page response hook: ${err.message}`);
      }
    });

    // 2. Intercept requests to extract dynamic headers like X-CSRF-Token or Authorization
    page.on('request', (request) => {
      try {
        const headers = request.headers();
        const customAuthHeaders = {};
        let updated = false;

        if (headers['authorization']) {
          customAuthHeaders['Authorization'] = headers['authorization'];
          updated = true;
        }
        if (headers['x-csrf-token']) {
          customAuthHeaders['X-CSRF-Token'] = headers['x-csrf-token'];
          updated = true;
        }
        if (headers['x-xsrf-token']) {
          customAuthHeaders['X-XSRF-Token'] = headers['x-xsrf-token'];
          updated = true;
        }

        if (updated) {
          const currentHeaders = this.sessionManager.getHeaders();
          const merged = { ...currentHeaders, ...customAuthHeaders };
          this.sessionManager.setHeaders(merged);
          this.log.push(`[SessionBridge] Synchronized request auth headers: ${Object.keys(customAuthHeaders).join(', ')}`);
        }
      } catch (err) {
        this.log.push(`[SessionBridge] Error in page request hook: ${err.message}`);
      }
    });
  }

  // Actively extract tokens from localStorage/sessionStorage inside the browser page context
  async syncFromBrowserStorage(page) {
    this.log.push(`[SessionBridge] Actively querying localStorage/sessionStorage from browser page.`);
    try {
      const storageData = await page.evaluate(() => {
        const data = {};
        // Look for common token key names
        const tokenKeys = ['token', 'accessToken', 'access_token', 'jwt', 'auth', 'auth_token', 'id_token'];
        
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key) {
            const lowerKey = key.toLowerCase();
            if (tokenKeys.some(tk => lowerKey.includes(tk))) {
              data[key] = localStorage.getItem(key);
            }
          }
        }
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          if (key) {
            const lowerKey = key.toLowerCase();
            if (tokenKeys.some(tk => lowerKey.includes(tk))) {
              data[key] = sessionStorage.getItem(key);
            }
          }
        }
        return data;
      });

      let updated = false;
      const currentHeaders = this.sessionManager.getHeaders();
      
      for (const [key, val] of Object.entries(storageData)) {
        if (!val) continue;
        
        // If it looks like a plain JWT or bearer token structure, store as Authorization
        let cleanToken = val.trim();
        // Remove quotes if JSON stringified
        if (cleanToken.startsWith('"') && cleanToken.endsWith('"')) {
          cleanToken = cleanToken.slice(1, -1);
        }

        if (cleanToken.split('.').length === 3) {
          // Looks like a JWT
          currentHeaders['Authorization'] = `Bearer ${cleanToken}`;
          this.log.push(`[SessionBridge] Extracted JWT from browser storage key "${key}"`);
          updated = true;
        } else if (cleanToken.toLowerCase().startsWith('bearer ')) {
          currentHeaders['Authorization'] = cleanToken;
          this.log.push(`[SessionBridge] Extracted Bearer auth from browser storage key "${key}"`);
          updated = true;
        }
      }

      if (updated) {
        this.sessionManager.setHeaders(currentHeaders);
      }
    } catch (err) {
      this.log.push(`[SessionBridge] Error extracting browser storage: ${err.message}`);
    }
  }

  // Synchronize dynamic headers back into a Playwright page before navigation/actions
  async syncToBrowserContext(context, targetUrl) {
    this.log.push(`[SessionBridge] Setting cookies/headers back into Playwright context.`);
    try {
      const headers = this.sessionManager.getHeaders();
      
      // Inject cookies
      if (headers['Cookie']) {
        const cookieStr = headers['Cookie'];
        const domain = new URL(targetUrl).hostname;
        const cookiesToSet = cookieStr.split(';').map(c => {
          const parts = c.trim().split('=');
          return {
            name: parts[0],
            value: parts[1] || '',
            domain: domain,
            path: '/'
          };
        });
        await context.addCookies(cookiesToSet);
      }
    } catch (err) {
      this.log.push(`[SessionBridge] Error setting cookies into browser context: ${err.message}`);
    }
  }
}

module.exports = { SessionBridge };
