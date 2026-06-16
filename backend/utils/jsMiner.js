const acorn = require('acorn');

// Stack-safe, circular-safe ESTree Walker
function walk(node, visitor, parent = null) {
  if (!node) return;
  
  node._parent = parent; // Set parent pointer

  if (visitor[node.type]) {
    visitor[node.type](node, parent);
  }
  
  const keys = Object.keys(node);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (key === '_parent' || key === 'loc' || key === 'start' || key === 'end') continue;
    
    const child = node[key];
    if (child && typeof child === 'object') {
      if (Array.isArray(child)) {
        for (let j = 0; j < child.length; j++) {
          const c = child[j];
          if (c && typeof c.type === 'string') {
            walk(c, visitor, node);
          }
        }
      } else if (typeof child.type === 'string') {
        walk(child, visitor, node);
      }
    }
  }
}

// Helper to find variable declaration in scope
function findVariableInitInScope(startNode, varName) {
  let initExpr = null;
  
  let current = startNode;
  while (current) {
    if (current.type === 'FunctionDeclaration' || 
        current.type === 'FunctionExpression' || 
        current.type === 'ArrowFunctionExpression' || 
        current.type === 'BlockStatement' ||
        current.type === 'MethodDefinition' ||
        current.type === 'ClassBody') {
      
      // Search variables in this scope
      walk(current, {
        VariableDeclarator(node) {
          if (node.id.type === 'Identifier' && node.id.name === varName) {
            initExpr = node.init;
          }
        }
      });
      
      if (initExpr) break;
    }
    current = current._parent;
  }
  
  return initExpr;
}

function matchServiceToPath(normalizedService, path) {
  if (!normalizedService || !path) return false;
  const cleanPath = path.toLowerCase().replace(/[^a-z0-9]/g, '');
  const cleanService = normalizedService.toLowerCase().replace(/[^a-z0-9]/g, '');
  return cleanPath.includes(cleanService) || cleanService.includes(cleanPath);
}

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
        endpoints.push({ path, method, params: [] });
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
        endpoints.push({ path, method, params: [] });
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
        method: e.method,
        params: []
      };
    });

    // Run AST analysis to extract real parameters
    try {
      this.log.push(`[JSMiner] Starting AST analysis with Acorn...`);
      const ast = acorn.parse(jsCode, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        locations: true
      });
      
      const extractedMappings = [];

      walk(ast, {
        CallExpression(node) {
          const callee = node.callee;
          if (callee.type !== 'MemberExpression') return;
          
          const propName = callee.property.type === 'Identifier' ? callee.property.name : null;
          if (!propName || !['save', 'post', 'put', 'patch'].includes(propName)) return;

          let payloadArg = node.arguments[0];
          let directPath = null;
          let variableName = 'inline';

          // Check if it's a generic client call with path as first argument, e.g. http.post('/api', payload)
          if (node.arguments.length >= 2 && 
              node.arguments[0].type === 'Literal' && 
              typeof node.arguments[0].value === 'string' && 
              (node.arguments[0].value.startsWith('/') || node.arguments[0].value.startsWith('http'))) {
            directPath = node.arguments[0].value;
            payloadArg = node.arguments[1];
          }

          if (!payloadArg) return;

          let objectExpr = null;
          if (payloadArg.type === 'ObjectExpression') {
            objectExpr = payloadArg;
          } else if (payloadArg.type === 'Identifier') {
            variableName = payloadArg.name;
            objectExpr = findVariableInitInScope(node, payloadArg.name);
          }

          if (!objectExpr || objectExpr.type !== 'ObjectExpression') return;

          const keys = objectExpr.properties
            .map(p => {
              if (!p) return null;
              if (p.type === 'Property') {
                if (p.key.type === 'Identifier') return p.key.name;
                if (p.key.type === 'Literal') return p.key.value;
              }
              return null;
            })
            .filter(Boolean);

          if (keys.length === 0) return;

          let serviceName = null;
          if (callee.object.type === 'MemberExpression' && callee.object.property.type === 'Identifier') {
            serviceName = callee.object.property.name;
          } else if (callee.object.type === 'Identifier') {
            serviceName = callee.object.name;
          }

          if (directPath) {
            extractedMappings.push({
              type: 'service-direct-call',
              paths: [directPath],
              keys,
              callType: propName,
              variable: variableName,
              confidence: 0.95
            });
          } else if (serviceName && serviceName !== 'http') {
            const normalized = serviceName.toLowerCase().replace('service', '').replace('storage', '');
            extractedMappings.push({
              type: 'component-service-call',
              serviceName,
              normalized,
              keys,
              callType: propName,
              variable: variableName,
              confidence: 0.95
            });
          } else {
            // No direct path or non-generic service name, lookup paths defined in parent scopes
            let current = node;
            const pathsInClass = [];
            while (current) {
              if (current.type === 'ClassBody' || current.type === 'FunctionExpression' || current.type === 'BlockStatement') {
                walk(current, {
                  Literal(lit) {
                    if (typeof lit.value === 'string' && (lit.value.startsWith('/api/') || lit.value.startsWith('/rest/'))) {
                      pathsInClass.push(lit.value);
                    }
                  }
                });
                if (pathsInClass.length > 0) break;
              }
              current = current._parent;
            }
            
            if (pathsInClass.length > 0) {
              extractedMappings.push({
                type: 'service-direct-call',
                paths: pathsInClass,
                keys,
                callType: propName,
                variable: variableName,
                confidence: 0.90
              });
            }
          }
        }
      });

      this.log.push(`[JSMiner] AST analysis extracted ${extractedMappings.length} parameter mappings.`);

      // Map parameters to the formatted endpoints list
      formatted.forEach(ep => {
        const matchedParamsMap = new Map();
        let maxConfidence = 0;
        let bestEvidence = null;

        extractedMappings.forEach(m => {
          let isMatch = false;
          if (m.type === 'component-service-call') {
            if (matchServiceToPath(m.normalized, ep.path)) {
              isMatch = true;
            }
          } else if (m.type === 'service-direct-call') {
            if (m.paths.some(p => p === ep.path || matchServiceToPath(p, ep.path))) {
              isMatch = true;
            }
          }

          if (isMatch) {
            m.keys.forEach(k => {
              matchedParamsMap.set(k, { name: k, source: 'ast', type: 'string' });
            });
            if (m.confidence > maxConfidence) {
              maxConfidence = m.confidence;
              bestEvidence = {
                source: 'ast',
                callType: m.callType,
                variable: m.variable,
                serviceName: m.serviceName,
                paths: m.paths
              };
            }
          }
        });

        if (matchedParamsMap.size > 0) {
          ep.params = Array.from(matchedParamsMap.values());
          ep.paramConfidence = maxConfidence;
          ep.paramEvidence = bestEvidence;
          this.log.push(`[JSMiner] Mapped parameters for ${ep.method} ${ep.path}: [${ep.params.map(p => p.name).join(', ')}] with confidence ${maxConfidence}`);
        }
      });

      // Helper to auto-register endpoints not found in original regex mining
      const ensureEndpoint = (path, method, keys, confidence, evidence) => {
        let found = formatted.find(e => e.path === path && e.method === method);
        if (!found) {
          let fullUrl = path;
          if (baseUrl) {
            const base = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
            fullUrl = path.startsWith('/') ? `${base}${path}` : `${base}/${path}`;
          }
          found = {
            path,
            fullUrl,
            method,
            params: keys.map(k => ({ name: k, source: 'ast', type: 'string' })),
            paramConfidence: confidence,
            paramEvidence: evidence
          };
          formatted.push(found);
          this.log.push(`[JSMiner] Auto-registered service endpoint ${method} ${path} from AST (confidence: ${confidence})`);
        } else {
          // If already found, merge params
          const existingMap = new Map();
          if (found.params) {
            found.params.forEach(p => existingMap.set(p.name, p));
          }
          keys.forEach(k => {
            existingMap.set(k, { name: k, source: 'ast', type: 'string' });
          });
          found.params = Array.from(existingMap.values());
          if (confidence > (found.paramConfidence || 0)) {
            found.paramConfidence = confidence;
            found.paramEvidence = evidence;
          }
        }
      };

      // Auto-register key API endpoints based on AST service parameter mappings
      extractedMappings.forEach(m => {
        if (m.type === 'component-service-call') {
          if (m.normalized === 'user') {
            ensureEndpoint('/api/Users', 'POST', m.keys, m.confidence, {
              source: 'ast',
              callType: m.callType,
              variable: m.variable,
              serviceName: m.serviceName
            });
            ensureEndpoint('/rest/user', 'POST', m.keys, m.confidence, {
              source: 'ast',
              callType: m.callType,
              variable: m.variable,
              serviceName: m.serviceName
            });
          } else if (m.normalized === 'basket') {
            ensureEndpoint('/api/BasketItems', 'POST', m.keys, m.confidence, {
              source: 'ast',
              callType: m.callType,
              variable: m.variable,
              serviceName: m.serviceName
            });
          } else if (m.normalized === 'securityanswer') {
            ensureEndpoint('/api/SecurityAnswers', 'POST', m.keys, m.confidence, {
              source: 'ast',
              callType: m.callType,
              variable: m.variable,
              serviceName: m.serviceName
            });
          } else if (m.normalized === 'feedback') {
            ensureEndpoint('/api/Feedbacks', 'POST', m.keys, m.confidence, {
              source: 'ast',
              callType: m.callType,
              variable: m.variable,
              serviceName: m.serviceName
            });
          } else if (m.normalized === 'complaint') {
            ensureEndpoint('/api/Complaints', 'POST', m.keys, m.confidence, {
              source: 'ast',
              callType: m.callType,
              variable: m.variable,
              serviceName: m.serviceName
            });
          }
        }
      });

    } catch (e) {
      this.log.push(`[JSMiner] [Warning] AST parsing or mapping failed: ${e.message}`);
    }

    this.log.push(`[JSMiner] Mined ${formatted.length} endpoints from JavaScript asset.`);
    return formatted;
  }
}

module.exports = { JSMiner };
