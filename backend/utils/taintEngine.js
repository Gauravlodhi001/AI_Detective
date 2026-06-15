const fs = require('fs');
const path = require('path');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

/**
 * Level 2 Static Taint Analysis Engine.
 * Resolves complex variables scopes, maps interprocedural parameter flows
 * across files, tracks sanitizers, and evaluates middleware validation context.
 */
class TaintEngine {
  constructor(log) {
    this.log = log || [];
    this.visitedPaths = new Set(); // Prevent infinite recursion in call cycles
  }

  /**
   * Resolves relative require paths to absolute files on the filesystem.
   */
  resolveRequirePath(currentFile, requirePath) {
    try {
      const currentDir = path.dirname(currentFile);
      let resolved = path.resolve(currentDir, requirePath);
      if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
        return resolved;
      }
      if (fs.existsSync(resolved + '.js')) {
        return resolved + '.js';
      }
      if (fs.existsSync(path.join(resolved, 'index.js'))) {
        return path.join(resolved, 'index.js');
      }
    } catch (e) {}
    return null;
  }

  /**
   * Executes static taint flow analysis on a file, supporting targeted function parameter tracking.
   * @param {string} filePath Absolute path of the target file.
   * @param {string|null} functionName Specific function parameters to seed (for interprocedural flow).
   * @param {Array|null} taintedArgs Tainted arguments mappings.
   * @returns {Array} List of resolved taint findings.
   */
  analyzeFile(filePath, functionName = null, taintedArgs = null) {
    const findings = [];
    const executionKey = `${filePath}:${functionName}:${JSON.stringify(taintedArgs)}`;
    if (this.visitedPaths.has(executionKey)) return [];
    this.visitedPaths.add(executionKey);

    try {
      const self = this;
      if (!fs.existsSync(filePath)) return [];
      const content = fs.readFileSync(filePath, 'utf-8');

      const ast = parser.parse(content, {
        sourceType: 'module',
        plugins: ['jsx', 'typescript']
      });

      const requireMap = {}; 
      const taintedVars = {}; // variableName -> { source, flow: string[] }

      const SOURCES = [
        'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies',
        'request.body', 'request.query', 'request.params',
        'ctx.request.body', 'ctx.query'
      ];

      const SINKS = {
        cmd: [
          'child_process.exec', 'child_process.execSync', 
          'child_process.spawn', 'child_process.spawnSync', 
          'exec', 'execSync', 'spawn', 'spawnSync'
        ],
        db: [
          'db.query', 'pool.query', 'sequelize.query', 
          'connection.query', 'query'
        ],
        code: ['eval', 'Function', 'vm.runInContext', 'vm.runInNewContext'],
        file: ['fs.readFile', 'fs.readFileSync', 'fs.writeFile', 'fs.writeFileSync'],
        http: ['axios', 'fetch', 'request', 'got']
      };

      const SANITIZERS = [
        'escape', 'isWhitelisted', 'sanitizeHtml', 
        'sanitize', 'purify', 'DOMPurify.sanitize'
      ];

      const getMemberExprString = (node) => {
        if (!node) return null;
        if (node.type === 'Identifier') return node.name;
        if (node.type === 'MemberExpression') {
          const obj = getMemberExprString(node.object);
          const prop = node.computed ? '[computed]' : getMemberExprString(node.property);
          if (obj && prop) return `${obj}.${prop}`;
        }
        return null;
      };

      const checkSource = (node) => {
        const str = getMemberExprString(node);
        if (!str) return null;
        for (const src of SOURCES) {
          if (str === src || str.startsWith(src + '.')) {
            return str;
          }
        }
        return null;
      };

      const getTaintInfo = (node) => {
        if (!node) return null;
        if (node.type === 'Identifier') {
          return taintedVars[node.name] || null;
        }
        if (node.type === 'MemberExpression') {
          const str = getMemberExprString(node);
          if (str && taintedVars[str]) return taintedVars[str];
          
          const baseName = getMemberExprString(node.object);
          if (baseName && taintedVars[baseName]) {
            return taintedVars[baseName];
          }
        }
        if (node.type === 'BinaryExpression') {
          return getTaintInfo(node.left) || getTaintInfo(node.right);
        }
        if (node.type === 'TemplateLiteral') {
          for (const expr of node.expressions) {
            const t = getTaintInfo(expr);
            if (t) return t;
          }
        }
        if (node.type === 'CallExpression') {
          const calleeStr = getMemberExprString(node.callee);
          if (calleeStr && SANITIZERS.some(s => calleeStr.includes(s))) {
            return null; // Variable is safe, block taint propagation
          }
          for (const arg of node.arguments) {
            const t = getTaintInfo(arg);
            if (t) return t;
          }
        }
        return null;
      };

      const checkSink = (node) => {
        if (node.type !== 'CallExpression') return null;
        const calleeStr = getMemberExprString(node.callee);
        if (!calleeStr) return null;

        for (const [type, names] of Object.entries(SINKS)) {
          if (names.includes(calleeStr) || names.some(n => calleeStr.endsWith('.' + n))) {
            return { type, name: calleeStr };
          }
        }
        return null;
      };

      const getIdentifiers = (pattern) => {
        const list = [];
        if (pattern.type === 'Identifier') {
          list.push(pattern.name);
        } else if (pattern.type === 'ObjectPattern') {
          pattern.properties.forEach(p => {
            if (p.type === 'ObjectProperty') {
              list.push(...getIdentifiers(p.value));
            }
          });
        } else if (pattern.type === 'ArrayPattern') {
          pattern.elements.forEach(el => {
            if (el) list.push(...getIdentifiers(el));
          });
        }
        return list;
      };

      const routeMiddlewares = {}; 

      // Visitor options object for traversal
      const traverseOptions = {
        VariableDeclarator(p) {
          // Map requires/imports
          if (p.node.init && p.node.init.type === 'CallExpression' && p.node.init.callee.name === 'require') {
            const arg = p.node.init.arguments[0];
            if (arg && arg.type === 'StringLiteral') {
              const resolved = self.resolveRequirePath(filePath, arg.value);
              if (resolved) {
                const ids = getIdentifiers(p.node.id);
                ids.forEach(id => {
                  requireMap[id] = resolved;
                });
              }
            }
          }

          // Variable declarations taint check
          if (p.node.init) {
            const src = checkSource(p.node.init);
            const leftIds = getIdentifiers(p.node.id);

            if (src) {
              leftIds.forEach(id => {
                taintedVars[id] = {
                  source: src,
                  flow: [src, id]
                };
              });
            } else {
              const taint = getTaintInfo(p.node.init);
              if (taint) {
                leftIds.forEach(id => {
                  let step = id;
                  if (p.node.init.type === 'CallExpression') {
                    const funcName = getMemberExprString(p.node.init.callee) || 'function';
                    step = `${funcName}() ➔ ${id}`;
                  }
                  taintedVars[id] = {
                    source: taint.source,
                    flow: [...taint.flow, step]
                  };
                });
              }
            }
          }
        },
        AssignmentExpression(p) {
          // Support exports.funcName = ...
          if (functionName && p.node.left.type === 'MemberExpression') {
            const leftStr = getMemberExprString(p.node.left);
            if (leftStr === `exports.${functionName}` || leftStr === `module.exports.${functionName}`) {
              if (p.node.right.type === 'FunctionExpression' || p.node.right.type === 'ArrowFunctionExpression') {
                seedParameters(p.node.right);
              }
            }
          }

          const leftIds = getIdentifiers(p.node.left);
          const src = checkSource(p.node.right);
          if (src) {
            leftIds.forEach(id => {
              taintedVars[id] = {
                source: src,
                flow: [src, id]
              };
            });
          } else {
            const taint = getTaintInfo(p.node.right);
            if (taint) {
              leftIds.forEach(id => {
                let step = id;
                if (p.node.right.type === 'CallExpression') {
                  const funcName = getMemberExprString(p.node.right.callee) || 'function';
                  step = `${funcName}() ➔ ${id}`;
                }
                taintedVars[id] = {
                  source: taint.source,
                  flow: [...taint.flow, step]
                };
              });
            }
          }
        },
        FunctionDeclaration(p) {
          if (functionName && p.node.id && p.node.id.name === functionName) {
            seedParameters(p.node);
          }
        },
        FunctionExpression(p) {
          if (functionName) {
            const parent = p.parentPath;
            if (parent && parent.node.type === 'VariableDeclarator' && parent.node.id.name === functionName) {
              seedParameters(p.node);
            }
          }
        },
        ArrowFunctionExpression(p) {
          if (functionName) {
            const parent = p.parentPath;
            if (parent && parent.node.type === 'VariableDeclarator' && parent.node.id.name === functionName) {
              seedParameters(p.node);
            }
          }
        },
        CallExpression(p) {
          // Collect route middlewares (e.g. router.post('/path', middleware, ctrl))
          const calleeStr = getMemberExprString(p.node.callee);
          if (calleeStr && (calleeStr.startsWith('router.') || calleeStr.startsWith('app.'))) {
            const args = p.node.arguments;
            if (args.length >= 2 && args[0].type === 'StringLiteral') {
              const routePath = args[0].value;
              routeMiddlewares[routePath] = routeMiddlewares[routePath] || [];
              for (let i = 1; i < args.length - 1; i++) {
                const midName = getMemberExprString(args[i]);
                if (midName) routeMiddlewares[routePath].push(midName);
              }
            }
          }

          // Sink analysis
          const sink = checkSink(p.node);
          if (sink) {
            p.node.arguments.forEach(arg => {
              const taint = getTaintInfo(arg);
              if (taint) {
                const line = p.node.loc ? p.node.loc.start.line : 0;
                const sinkTypeMap = {
                  cmd: 'COMMAND_INJECTION',
                  db: 'SQL_INJECTION',
                  code: 'CODE_EXECUTION',
                  file: 'FILE_ACCESS_FLAW',
                  http: 'SSRF'
                };
                findings.push({
                  type: sinkTypeMap[sink.type] || 'TAINTED_FLOW',
                  source: taint.source,
                  sink: sink.name,
                  file: filePath,
                  line,
                  flow: [...taint.flow, `${sink.name}()`]
                });
              }
            });
          }

          // Interprocedural Call (cross-file / cross-function)
          if (calleeStr) {
            let targetFile = null;
            let targetFuncName = calleeStr;

            if (calleeStr.includes('.')) {
              const parts = calleeStr.split('.');
              const baseName = parts[0];
              targetFuncName = parts[1];
              targetFile = requireMap[baseName];
            } else {
              targetFile = requireMap[calleeStr];
            }

            if (targetFile) {
              const nextArgs = [];
              p.node.arguments.forEach((arg, idx) => {
                const t = getTaintInfo(arg);
                if (t) {
                  nextArgs.push({
                    index: idx,
                    source: t.source,
                    flow: [...t.flow, `${calleeStr}()`]
                  });
                }
              });

              if (nextArgs.length > 0) {
                const subFindings = self.analyzeFile(targetFile, targetFuncName, nextArgs);
                findings.push(...subFindings);
              }
            }
          }
        }
      };

      // Seed parameters for targeted functions
      const seedParameters = (funcNode) => {
        if (!taintedArgs || !funcNode.params) return;
        funcNode.params.forEach((param, idx) => {
          const matchedArg = taintedArgs.find(ta => ta.index === idx);
          if (matchedArg && param.type === 'Identifier') {
            taintedVars[param.name] = {
              source: matchedArg.source,
              flow: [...matchedArg.flow, param.name]
            };
          }
        });
      };

      // Traverse AST
      traverse(ast, traverseOptions, null, {
        resolveRequirePath: self.resolveRequirePath.bind(self)
      });

      // Filter findings if validation/sanitization middleware protects the routes
      const middlewareList = Object.values(routeMiddlewares).flat();
      const hasSecurityMiddleware = middlewareList.some(m => 
        /validate|sanitize|check|secure|auth/i.test(m)
      );

      if (hasSecurityMiddleware) {
        return []; // Suppress findings due to active validation middleware
      }

    } catch (err) {
      this.log.push(`[TaintEngine] AST traversal error on ${filePath}: ${err.message}`);
    }

    return findings;
  }
}

module.exports = { TaintEngine };
