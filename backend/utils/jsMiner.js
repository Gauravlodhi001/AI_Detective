class JSMiner {
  constructor(log) {
    this.log = log || [];
  }

  // Mines endpoints from JS code string
  mineEndpoints(jsCode, baseUrl) {
    const endpoints = [];
    const visited = new Set();

    // Pattern 1: axios.method('/path') or http.post('/path')
    const clientPattern = /(?:axios|jQuery|get|post|put|delete|patch|req|request|client|http)\.(get|post|put|delete|patch|options|head)\s*\(\s*['"`](\/(?:api|rest|v[0-9]|auth|graphql|query|admin|user)[a-zA-Z0-9_\-\/{}\[\]:.@]+)['"`]/gi;
    
    let match;
    clientPattern.lastIndex = 0;
    while ((match = clientPattern.exec(jsCode)) !== null) {
      const method = match[1].toUpperCase();
      const path = match[2];
      const key = `${method}:${path}`;
      if (!visited.has(key)) {
        visited.add(key);
        endpoints.push({ path, method });
      }
    }

    // Pattern 2: fetch('/path', { method: 'POST' }) or similar
    const pathRegex = /(?:["'`])(\/(?:api|rest|v[0-9]|auth|graphql|query|admin|user)[a-zA-Z0-9_\-\/{}\[\]:.@]+)(?:["'`])/g;
    pathRegex.lastIndex = 0;
    while ((match = pathRegex.exec(jsCode)) !== null) {
      const path = match[1];
      const matchIndex = match.index;
      
      // Look back 40 characters, look forward 40 characters for methods
      const start = Math.max(0, matchIndex - 40);
      const end = Math.min(jsCode.length, matchIndex + path.length + 40);
      const context = jsCode.substring(start, end).toLowerCase();

      let method = 'GET';
      if (context.includes('post') || /method\s*:\s*['"`]post['"`]/.test(context)) {
        method = 'POST';
      } else if (context.includes('delete') || /method\s*:\s*['"`]delete['"`]/.test(context)) {
        method = 'DELETE';
      } else if (context.includes('put') || /method\s*:\s*['"`]put['"`]/.test(context)) {
        method = 'PUT';
      } else if (context.includes('patch') || /method\s*:\s*['"`]patch['"`]/.test(context)) {
        method = 'PATCH';
      }

      const key = `${method}:${path}`;
      if (!visited.has(key)) {
        visited.add(key);
        endpoints.push({ path, method });
      }
    }

    // Format full URLs
    const formatted = endpoints.map(e => {
      let fullUrl = e.path;
      if (baseUrl) {
        const base = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
        fullUrl = e.path.startsWith('/') ? `${base}${e.path}` : `${base}/${e.path}`;
      }
      return {
        path: e.path,
        fullUrl,
        method: e.method
      };
    });

    this.log.push(`[JSMiner] Mined ${formatted.length} endpoints from JavaScript asset.`);
    return formatted;
  }
}

module.exports = { JSMiner };
