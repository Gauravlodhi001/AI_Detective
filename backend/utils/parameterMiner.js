class ParameterMiner {
  constructor(log) {
    this.log = log || [];
    this.registry = new Map(); // Map<URL, Set<ParamName>>
    
    // Curated high-probability parameter dictionary for API fuzzing
    this.commonParams = [
      'id', 'user', 'userId', 'accountId', 'invoiceId', 'orderId', 'role', 'admin', 
      'debug', 'file', 'path', 'token', 'key', 'email', 'username', 'password', 
      'page', 'limit', 'search', 'query', 'filter', 'status', 'action', 'type', 
      'uuid', 'ref', 'source', 'redirect', 'url', 'profile', 'config', 'settings'
    ];
  }

  // Register a parameter name for a specific endpoint URL
  register(urlStr, paramName) {
    // Standardize URL by stripping query parameters and hash
    const cleanUrl = urlStr.split('?')[0].split('#')[0];
    if (!this.registry.has(cleanUrl)) {
      this.registry.set(cleanUrl, new Set());
    }
    this.registry.get(cleanUrl).add(paramName);
  }

  // Get list of parameters for an endpoint
  getParameters(urlStr) {
    const cleanUrl = urlStr.split('?')[0].split('#')[0];
    if (this.registry.has(cleanUrl)) {
      return Array.from(this.registry.get(cleanUrl));
    }
    return [];
  }

  // Export the entire parameter registry as a JSON-serializable object
  exportRegistry() {
    const obj = {};
    for (const [url, paramSet] of this.registry.entries()) {
      obj[url] = Array.from(paramSet);
    }
    return obj;
  }

  // Mines parameter names from a JSON response body
  mineFromResponse(urlStr, responseBody) {
    if (!responseBody) return;
    try {
      const data = JSON.parse(responseBody);
      this.extractKeysRecursive(urlStr, data);
    } catch (e) {
      // Not a JSON response, ignore
    }
  }

  // Helper to recursively extract keys from objects/arrays
  extractKeysRecursive(urlStr, obj) {
    if (!obj || typeof obj !== 'object') return;
    
    if (Array.isArray(obj)) {
      obj.forEach(item => this.extractKeysRecursive(urlStr, item));
      return;
    }

    for (const [key, val] of Object.entries(obj)) {
      // Register the key
      this.register(urlStr, key);
      
      // If nested object, recurse
      if (val && typeof val === 'object') {
        this.extractKeysRecursive(urlStr, val);
      }
    }
  }

  // Fuzzes an endpoint to find undocumented query parameters
  async discoverQueryParameters(requestFn, urlStr, headers = {}) {
    this.log.push(`[ParamMiner] Brute-forcing query parameters on: ${urlStr}`);
    
    // Baseline request to get baseline response size and status
    const baselineRes = await requestFn(urlStr, { method: 'GET', headers });
    const baselineLength = baselineRes.body ? baselineRes.body.length : 0;
    const baselineStatus = baselineRes.status;

    const discovered = [];

    // Fuzz each parameter from our dictionary
    for (const param of this.commonParams) {
      const separator = urlStr.includes('?') ? '&' : '?';
      // Inject parameter with a control value
      const testUrl = `${urlStr}${separator}${param}=1`;
      
      const res = await requestFn(testUrl, { method: 'GET', headers });
      
      // Check for changes indicating parameter is processed
      // 1. Different status code
      // 2. Significant change in response length (e.g., more than 10 bytes difference)
      if (res.status !== baselineStatus || Math.abs((res.body ? res.body.length : 0) - baselineLength) > 10) {
        this.log.push(`[ParamMiner] Discovered active query parameter "${param}" on ${urlStr}`);
        this.register(urlStr, param);
        discovered.push(param);
      }
    }

    return discovered;
  }
}

module.exports = { ParameterMiner };
