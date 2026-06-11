class JSMiner {
  constructor(log) {
    this.log = log || [];
  }

  // Mines endpoints from JS code string
  mineEndpoints(jsCode, baseUrl) {
    const endpoints = [];
    const visited = new Set();

    // Regex to match API paths in JS strings
    const pathRegex = /(?:["'`])(\/(?:api|v[0-9]|auth|graphql|query|admin|user)[a-zA-Z0-9_\-\/{}\[\]:.@]+)(?:["'`])/g;
    
    let match;
    // Reset regex index
    pathRegex.lastIndex = 0;

    while ((match = pathRegex.exec(jsCode)) !== null) {
      const path = match[1];
      const matchIndex = match.index;
      
      // Skip duplicate findings for same path
      if (visited.has(path)) continue;
      visited.add(path);

      // Inspect surrounding context (e.g., 100 characters before and after)
      const start = Math.max(0, matchIndex - 100);
      const end = Math.min(jsCode.length, matchIndex + path.length + 100);
      const context = jsCode.substring(start, end).toLowerCase();

      let method = 'GET';
      
      // Search for HTTP methods inside context
      if (context.includes('.post') || /method\s*:\s*['"`]post['"`]/.test(context)) {
        method = 'POST';
      } else if (context.includes('.delete') || /method\s*:\s*['"`]delete['"`]/.test(context)) {
        method = 'DELETE';
      } else if (context.includes('.put') || /method\s*:\s*['"`]put['"`]/.test(context)) {
        method = 'PUT';
      } else if (context.includes('.patch') || /method\s*:\s*['"`]patch['"`]/.test(context)) {
        method = 'PATCH';
      }

      // Format full URL
      let fullUrl = path;
      if (baseUrl) {
        const base = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
        fullUrl = path.startsWith('/') ? `${base}${path}` : `${base}/${path}`;
      }

      endpoints.push({
        path,
        fullUrl,
        method
      });
    }

    this.log.push(`[JSMiner] Mined ${endpoints.length} endpoints from JavaScript asset.`);
    return endpoints;
  }
}

module.exports = { JSMiner };
